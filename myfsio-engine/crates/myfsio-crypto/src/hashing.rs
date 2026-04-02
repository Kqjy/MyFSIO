use md5::{Digest, Md5};
use sha2::Sha256;
use std::io::Read;
use std::path::Path;

const CHUNK_SIZE: usize = 65536;

pub fn md5_file(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Md5::new();
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn md5_bytes(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

pub fn md5_sha256_file(path: &Path) -> std::io::Result<(String, String)> {
    let mut file = std::fs::File::open(path)?;
    let mut md5_hasher = Md5::new();
    let mut sha_hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        md5_hasher.update(&buf[..n]);
        sha_hasher.update(&buf[..n]);
    }
    Ok((
        format!("{:x}", md5_hasher.finalize()),
        format!("{:x}", sha_hasher.finalize()),
    ))
}

pub async fn md5_file_async(path: &Path) -> std::io::Result<String> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || md5_file(&path))
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
}

pub async fn sha256_file_async(path: &Path) -> std::io::Result<String> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || sha256_file(&path))
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
}

pub async fn md5_sha256_file_async(path: &Path) -> std::io::Result<(String, String)> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || md5_sha256_file(&path))
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_md5_bytes() {
        assert_eq!(md5_bytes(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_bytes(b"hello"), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_sha256_bytes() {
        let hash = sha256_bytes(b"hello");
        assert_eq!(hash, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn test_md5_file() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"hello").unwrap();
        tmp.flush().unwrap();
        let hash = md5_file(tmp.path()).unwrap();
        assert_eq!(hash, "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_md5_sha256_file() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"hello").unwrap();
        tmp.flush().unwrap();
        let (md5, sha) = md5_sha256_file(tmp.path()).unwrap();
        assert_eq!(md5, "5d41402abc4b2a76b9719d911017c592");
        assert_eq!(sha, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[tokio::test]
    async fn test_md5_file_async() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"hello").unwrap();
        tmp.flush().unwrap();
        let hash = md5_file_async(tmp.path()).await.unwrap();
        assert_eq!(hash, "5d41402abc4b2a76b9719d911017c592");
    }
}
