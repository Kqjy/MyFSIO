use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use thiserror::Error;

const DEFAULT_CHUNK_SIZE: usize = 65536;
const HEADER_SIZE: usize = 4;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid key size: expected 32 bytes, got {0}")]
    InvalidKeySize(usize),
    #[error("Invalid nonce size: expected 12 bytes, got {0}")]
    InvalidNonceSize(usize),
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed at chunk {0}")]
    DecryptionFailed(u32),
    #[error("HKDF expand failed: {0}")]
    HkdfFailed(String),
}

fn read_exact_chunk(reader: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

fn derive_chunk_nonce(base_nonce: &[u8], chunk_index: u32) -> Result<[u8; 12], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(base_nonce), b"chunk_nonce");
    let mut okm = [0u8; 12];
    hkdf.expand(&chunk_index.to_be_bytes(), &mut okm)
        .map_err(|e| CryptoError::HkdfFailed(e.to_string()))?;
    Ok(okm)
}

pub fn encrypt_stream_chunked(
    input_path: &Path,
    output_path: &Path,
    key: &[u8],
    base_nonce: &[u8],
    chunk_size: Option<usize>,
) -> Result<u32, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeySize(key.len()));
    }
    if base_nonce.len() != 12 {
        return Err(CryptoError::InvalidNonceSize(base_nonce.len()));
    }

    let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
    let key_arr: [u8; 32] = key.try_into().unwrap();
    let nonce_arr: [u8; 12] = base_nonce.try_into().unwrap();
    let cipher = Aes256Gcm::new(&key_arr.into());

    let mut infile = File::open(input_path)?;
    let mut outfile = File::create(output_path)?;

    outfile.write_all(&[0u8; 4])?;

    let mut buf = vec![0u8; chunk_size];
    let mut chunk_index: u32 = 0;

    loop {
        let n = read_exact_chunk(&mut infile, &mut buf)?;
        if n == 0 {
            break;
        }

        let nonce_bytes = derive_chunk_nonce(&nonce_arr, chunk_index)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, &buf[..n])
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let size = encrypted.len() as u32;
        outfile.write_all(&size.to_be_bytes())?;
        outfile.write_all(&encrypted)?;

        chunk_index += 1;
    }

    outfile.seek(SeekFrom::Start(0))?;
    outfile.write_all(&chunk_index.to_be_bytes())?;

    Ok(chunk_index)
}

pub fn decrypt_stream_chunked(
    input_path: &Path,
    output_path: &Path,
    key: &[u8],
    base_nonce: &[u8],
) -> Result<u32, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeySize(key.len()));
    }
    if base_nonce.len() != 12 {
        return Err(CryptoError::InvalidNonceSize(base_nonce.len()));
    }

    let key_arr: [u8; 32] = key.try_into().unwrap();
    let nonce_arr: [u8; 12] = base_nonce.try_into().unwrap();
    let cipher = Aes256Gcm::new(&key_arr.into());

    let mut infile = File::open(input_path)?;
    let mut outfile = File::create(output_path)?;

    let mut header = [0u8; HEADER_SIZE];
    infile.read_exact(&mut header)?;
    let chunk_count = u32::from_be_bytes(header);

    let mut size_buf = [0u8; HEADER_SIZE];
    for chunk_index in 0..chunk_count {
        infile.read_exact(&mut size_buf)?;
        let chunk_size = u32::from_be_bytes(size_buf) as usize;

        let mut encrypted = vec![0u8; chunk_size];
        infile.read_exact(&mut encrypted)?;

        let nonce_bytes = derive_chunk_nonce(&nonce_arr, chunk_index)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let decrypted = cipher
            .decrypt(nonce, encrypted.as_ref())
            .map_err(|_| CryptoError::DecryptionFailed(chunk_index))?;

        outfile.write_all(&decrypted)?;
    }

    Ok(chunk_count)
}

pub async fn encrypt_stream_chunked_async(
    input_path: &Path,
    output_path: &Path,
    key: &[u8],
    base_nonce: &[u8],
    chunk_size: Option<usize>,
) -> Result<u32, CryptoError> {
    let input_path = input_path.to_owned();
    let output_path = output_path.to_owned();
    let key = key.to_vec();
    let base_nonce = base_nonce.to_vec();
    tokio::task::spawn_blocking(move || {
        encrypt_stream_chunked(&input_path, &output_path, &key, &base_nonce, chunk_size)
    })
    .await
    .map_err(|e| CryptoError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?
}

pub async fn decrypt_stream_chunked_async(
    input_path: &Path,
    output_path: &Path,
    key: &[u8],
    base_nonce: &[u8],
) -> Result<u32, CryptoError> {
    let input_path = input_path.to_owned();
    let output_path = output_path.to_owned();
    let key = key.to_vec();
    let base_nonce = base_nonce.to_vec();
    tokio::task::spawn_blocking(move || {
        decrypt_stream_chunked(&input_path, &output_path, &key, &base_nonce)
    })
    .await
    .map_err(|e| CryptoError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.bin");
        let encrypted = dir.path().join("encrypted.bin");
        let decrypted = dir.path().join("decrypted.bin");

        let data = b"Hello, this is a test of AES-256-GCM chunked encryption!";
        std::fs::File::create(&input).unwrap().write_all(data).unwrap();

        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];

        let chunks = encrypt_stream_chunked(&input, &encrypted, &key, &nonce, Some(16)).unwrap();
        assert!(chunks > 0);

        let chunks2 = decrypt_stream_chunked(&encrypted, &decrypted, &key, &nonce).unwrap();
        assert_eq!(chunks, chunks2);

        let result = std::fs::read(&decrypted).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_invalid_key_size() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.bin");
        std::fs::File::create(&input).unwrap().write_all(b"test").unwrap();

        let result = encrypt_stream_chunked(&input, &dir.path().join("out"), &[0u8; 16], &[0u8; 12], None);
        assert!(matches!(result, Err(CryptoError::InvalidKeySize(16))));
    }

    #[test]
    fn test_wrong_key_fails_decrypt() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.bin");
        let encrypted = dir.path().join("encrypted.bin");
        let decrypted = dir.path().join("decrypted.bin");

        std::fs::File::create(&input).unwrap().write_all(b"secret data").unwrap();

        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        encrypt_stream_chunked(&input, &encrypted, &key, &nonce, None).unwrap();

        let wrong_key = [0x43u8; 32];
        let result = decrypt_stream_chunked(&encrypted, &decrypted, &wrong_key, &nonce);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed(_))));
    }
}
