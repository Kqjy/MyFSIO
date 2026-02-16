use pyo3::prelude::*;
use std::sync::LazyLock;
use unicode_normalization::UnicodeNormalization;

const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
    "COM8", "COM9", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
    "LPT9",
];

const WINDOWS_ILLEGAL_CHARS: &[char] = &['<', '>', ':', '"', '/', '\\', '|', '?', '*'];

const INTERNAL_FOLDERS: &[&str] = &[".meta", ".versions", ".multipart"];
const SYSTEM_ROOT: &str = ".myfsio.sys";

static IP_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap());

#[pyfunction]
#[pyo3(signature = (object_key, max_length_bytes=1024, is_windows=false, reserved_prefixes=None))]
pub fn validate_object_key(
    object_key: &str,
    max_length_bytes: usize,
    is_windows: bool,
    reserved_prefixes: Option<Vec<String>>,
) -> PyResult<Option<String>> {
    if object_key.is_empty() {
        return Ok(Some("Object key required".to_string()));
    }

    if object_key.contains('\0') {
        return Ok(Some("Object key contains null bytes".to_string()));
    }

    let normalized: String = object_key.nfc().collect();

    if normalized.len() > max_length_bytes {
        return Ok(Some(format!(
            "Object key exceeds maximum length of {} bytes",
            max_length_bytes
        )));
    }

    if normalized.starts_with('/') || normalized.starts_with('\\') {
        return Ok(Some("Object key cannot start with a slash".to_string()));
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
            return Ok(Some(
                "Object key contains parent directory references".to_string(),
            ));
        }

        if *part == "." {
            return Ok(Some("Object key contains invalid segments".to_string()));
        }

        if part.chars().any(|c| (c as u32) < 32) {
            return Ok(Some(
                "Object key contains control characters".to_string(),
            ));
        }

        if is_windows {
            if part.chars().any(|c| WINDOWS_ILLEGAL_CHARS.contains(&c)) {
                return Ok(Some(
                    "Object key contains characters not supported on Windows filesystems"
                        .to_string(),
                ));
            }
            if part.ends_with(' ') || part.ends_with('.') {
                return Ok(Some(
                    "Object key segments cannot end with spaces or periods on Windows".to_string(),
                ));
            }
            let trimmed = part.trim_end_matches(['.', ' ']).to_uppercase();
            if WINDOWS_RESERVED.contains(&trimmed.as_str()) {
                return Ok(Some(format!("Invalid filename segment: {}", part)));
            }
        }
    }

    let non_empty_parts: Vec<&str> = parts.iter().filter(|p| !p.is_empty()).copied().collect();
    if let Some(top) = non_empty_parts.first() {
        if INTERNAL_FOLDERS.contains(top) || *top == SYSTEM_ROOT {
            return Ok(Some("Object key uses a reserved prefix".to_string()));
        }

        if let Some(ref prefixes) = reserved_prefixes {
            for prefix in prefixes {
                if *top == prefix.as_str() {
                    return Ok(Some("Object key uses a reserved prefix".to_string()));
                }
            }
        }
    }

    Ok(None)
}

#[pyfunction]
pub fn validate_bucket_name(bucket_name: &str) -> Option<String> {
    let len = bucket_name.len();
    if len < 3 || len > 63 {
        return Some("Bucket name must be between 3 and 63 characters".to_string());
    }

    let bytes = bucket_name.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return Some(
            "Bucket name must start and end with a lowercase letter or digit".to_string(),
        );
    }
    if !bytes[len - 1].is_ascii_lowercase() && !bytes[len - 1].is_ascii_digit() {
        return Some(
            "Bucket name must start and end with a lowercase letter or digit".to_string(),
        );
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

    None
}
