use std::sync::LazyLock;
use unicode_normalization::UnicodeNormalization;

const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
    "COM8", "COM9", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

const WINDOWS_ILLEGAL_CHARS: &[char] = &['<', '>', ':', '"', '/', '\\', '|', '?', '*'];

const INTERNAL_FOLDERS: &[&str] = &[".meta", ".versions", ".multipart"];
const SYSTEM_ROOT: &str = ".myfsio.sys";

static IP_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap());

pub fn validate_object_key(
    object_key: &str,
    max_length_bytes: usize,
    is_windows: bool,
    reserved_prefixes: Option<&[&str]>,
) -> Option<String> {
    if object_key.is_empty() {
        return Some("Object key required".to_string());
    }

    if object_key.contains('\0') {
        return Some("Object key contains null bytes".to_string());
    }

    let normalized: String = object_key.nfc().collect();

    if normalized.len() > max_length_bytes {
        return Some(format!(
            "Object key exceeds maximum length of {} bytes",
            max_length_bytes
        ));
    }

    if normalized.starts_with('/') || normalized.starts_with('\\') {
        return Some("Object key cannot start with a slash".to_string());
    }

    let parts: Vec<&str> = if cfg!(windows) || is_windows {
        normalized.split(['/', '\\']).collect()
    } else {
        normalized.split('/').collect()
    };

    for part in &parts {
        if part.is_empty() {
            continue;
        }

        if *part == ".." {
            return Some("Object key contains parent directory references".to_string());
        }

        if *part == "." {
            return Some("Object key contains invalid segments".to_string());
        }

        if part.len() > 255 {
            return Some(
                "Object key contains a path segment longer than 255 bytes (filesystem backend limit)"
                    .to_string(),
            );
        }

        if part.chars().any(|c| (c as u32) < 32) {
            return Some("Object key contains control characters".to_string());
        }

        if is_windows {
            if part.chars().any(|c| WINDOWS_ILLEGAL_CHARS.contains(&c)) {
                return Some(
                    "Object key contains characters not supported on Windows filesystems"
                        .to_string(),
                );
            }
            if part.ends_with(' ') || part.ends_with('.') {
                return Some(
                    "Object key segments cannot end with spaces or periods on Windows".to_string(),
                );
            }
            let trimmed = part.trim_end_matches(['.', ' ']).to_uppercase();
            if WINDOWS_RESERVED.contains(&trimmed.as_str()) {
                return Some(format!("Invalid filename segment: {}", part));
            }
        }
    }

    let non_empty_parts: Vec<&str> = parts.iter().filter(|p| !p.is_empty()).copied().collect();
    if let Some(top) = non_empty_parts.first() {
        if INTERNAL_FOLDERS.contains(top) || *top == SYSTEM_ROOT {
            return Some("Object key uses a reserved prefix".to_string());
        }

        if let Some(prefixes) = reserved_prefixes {
            for prefix in prefixes {
                if *top == *prefix {
                    return Some("Object key uses a reserved prefix".to_string());
                }
            }
        }
    }

    for part in &non_empty_parts {
        if *part == ".__myfsio_dirobj__"
            || *part == ".__myfsio_empty__"
            || part.starts_with("_index.json")
        {
            return Some("Object key segment uses a reserved internal name".to_string());
        }
    }

    None
}

pub fn validate_bucket_name(bucket_name: &str) -> Option<String> {
    let len = bucket_name.len();
    if len < 3 || len > 63 {
        return Some("Bucket name must be between 3 and 63 characters".to_string());
    }

    let bytes = bucket_name.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return Some("Bucket name must start and end with a lowercase letter or digit".to_string());
    }
    if !bytes[len - 1].is_ascii_lowercase() && !bytes[len - 1].is_ascii_digit() {
        return Some("Bucket name must start and end with a lowercase letter or digit".to_string());
    }

    for &b in bytes {
        if !b.is_ascii_lowercase() && !b.is_ascii_digit() && b != b'.' && b != b'-' {
            return Some(
                "Bucket name can only contain lowercase letters, digits, dots, and hyphens"
                    .to_string(),
            );
        }
    }

    if bucket_name.contains("..") {
        return Some("Bucket name must not contain consecutive periods".to_string());
    }

    if IP_REGEX.is_match(bucket_name) {
        return Some("Bucket name must not be formatted as an IP address".to_string());
    }

    if bucket_name.starts_with("xn--") {
        return Some("Bucket name must not start with the reserved prefix 'xn--'".to_string());
    }
    if bucket_name.ends_with("-s3alias") || bucket_name.ends_with("--ol-s3") {
        return Some("Bucket name must not end with a reserved suffix".to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_bucket_names() {
        assert!(validate_bucket_name("my-bucket").is_none());
        assert!(validate_bucket_name("test123").is_none());
        assert!(validate_bucket_name("my.bucket.name").is_none());
    }

    #[test]
    fn test_invalid_bucket_names() {
        assert!(validate_bucket_name("ab").is_some());
        assert!(validate_bucket_name("My-Bucket").is_some());
        assert!(validate_bucket_name("-bucket").is_some());
        assert!(validate_bucket_name("bucket-").is_some());
        assert!(validate_bucket_name("my..bucket").is_some());
        assert!(validate_bucket_name("192.168.1.1").is_some());
    }

    #[test]
    fn test_valid_object_keys() {
        assert!(validate_object_key("file.txt", 1024, false, None).is_none());
        assert!(validate_object_key("path/to/file.txt", 1024, false, None).is_none());
        assert!(validate_object_key("a", 1024, false, None).is_none());
    }

    #[test]
    fn test_invalid_object_keys() {
        assert!(validate_object_key("", 1024, false, None).is_some());
        assert!(validate_object_key("/leading-slash", 1024, false, None).is_some());
        assert!(validate_object_key("path/../escape", 1024, false, None).is_some());
        assert!(validate_object_key(".myfsio.sys/secret", 1024, false, None).is_some());
        assert!(validate_object_key(".meta/data", 1024, false, None).is_some());
    }

    #[test]
    fn test_object_key_max_length() {
        let too_long_total = "a/".repeat(513) + "a";
        assert!(validate_object_key(&too_long_total, 1024, false, None).is_some());

        let too_long_segment = "a".repeat(256);
        assert!(validate_object_key(&too_long_segment, 1024, false, None).is_some());

        let ok_key = vec!["a".repeat(255); 4].join("/");
        assert_eq!(ok_key.len(), 255 * 4 + 3);
        assert!(validate_object_key(&ok_key, 1024, false, None).is_none());

        let ok_max_segment = "a".repeat(255);
        assert!(validate_object_key(&ok_max_segment, 1024, false, None).is_none());
    }

    #[test]
    fn test_windows_validation() {
        assert!(validate_object_key("CON", 1024, true, None).is_some());
        assert!(validate_object_key("file<name", 1024, true, None).is_some());
        assert!(validate_object_key("file.txt ", 1024, true, None).is_some());
    }
}
