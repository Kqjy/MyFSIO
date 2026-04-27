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

const GCM_TAG_LEN: usize = 16;

pub fn decrypt_stream_chunked_range(
    input_path: &Path,
    output_path: &Path,
    key: &[u8],
    base_nonce: &[u8],
    chunk_plain_size: usize,
    plaintext_size: u64,
    plain_start: u64,
    plain_end_inclusive: u64,
) -> Result<u64, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeySize(key.len()));
    }
    if base_nonce.len() != 12 {
        return Err(CryptoError::InvalidNonceSize(base_nonce.len()));
    }
    if chunk_plain_size == 0 {
        return Err(CryptoError::EncryptionFailed(
            "chunk_plain_size must be > 0".into(),
        ));
    }
    if plaintext_size == 0 {
        let _ = File::create(output_path)?;
        return Ok(0);
    }
    if plain_start > plain_end_inclusive || plain_end_inclusive >= plaintext_size {
        return Err(CryptoError::EncryptionFailed(format!(
            "range [{}, {}] invalid for plaintext size {}",
            plain_start, plain_end_inclusive, plaintext_size
        )));
    }

    let key_arr: [u8; 32] = key.try_into().unwrap();
    let nonce_arr: [u8; 12] = base_nonce.try_into().unwrap();
    let cipher = Aes256Gcm::new(&key_arr.into());

    let n = chunk_plain_size as u64;
    let first_chunk = (plain_start / n) as u32;
    let last_chunk = (plain_end_inclusive / n) as u32;
    let total_chunks = plaintext_size.div_ceil(n) as u32;
    let final_chunk_plain = plaintext_size - (total_chunks as u64 - 1) * n;

    let mut infile = File::open(input_path)?;

    let mut header = [0u8; HEADER_SIZE];
    infile.read_exact(&mut header)?;
    let stored_chunk_count = u32::from_be_bytes(header);
    if stored_chunk_count != total_chunks {
        return Err(CryptoError::EncryptionFailed(format!(
            "chunk count mismatch: header says {}, plaintext_size implies {}",
            stored_chunk_count, total_chunks
        )));
    }

    let mut outfile = File::create(output_path)?;

    let stride = n + GCM_TAG_LEN as u64 + HEADER_SIZE as u64;
    let first_offset = HEADER_SIZE as u64 + first_chunk as u64 * stride;
    infile.seek(SeekFrom::Start(first_offset))?;

    let mut size_buf = [0u8; HEADER_SIZE];
    let mut bytes_written: u64 = 0;

    for chunk_index in first_chunk..=last_chunk {
        infile.read_exact(&mut size_buf)?;
        let ct_len = u32::from_be_bytes(size_buf) as usize;

        let expected_plain = if chunk_index + 1 == total_chunks {
            final_chunk_plain as usize
        } else {
            chunk_plain_size
        };
        let expected_ct = expected_plain + GCM_TAG_LEN;
        if ct_len != expected_ct {
            return Err(CryptoError::EncryptionFailed(format!(
                "chunk {} stored length {} != expected {} (corrupt file or chunk_size mismatch)",
                chunk_index, ct_len, expected_ct
            )));
        }

        let mut encrypted = vec![0u8; ct_len];
        infile.read_exact(&mut encrypted)?;

        let nonce_bytes = derive_chunk_nonce(&nonce_arr, chunk_index)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let decrypted = cipher
            .decrypt(nonce, encrypted.as_ref())
            .map_err(|_| CryptoError::DecryptionFailed(chunk_index))?;

        let chunk_plain_start = chunk_index as u64 * n;
        let chunk_plain_end_exclusive = chunk_plain_start + decrypted.len() as u64;

        let slice_start = plain_start.saturating_sub(chunk_plain_start) as usize;
        let slice_end = (plain_end_inclusive + 1).min(chunk_plain_end_exclusive);
        let slice_end_local = (slice_end - chunk_plain_start) as usize;

        if slice_end_local > slice_start {
            outfile.write_all(&decrypted[slice_start..slice_end_local])?;
            bytes_written += (slice_end_local - slice_start) as u64;
        }
    }

    Ok(bytes_written)
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
        std::fs::File::create(&input)
            .unwrap()
            .write_all(data)
            .unwrap();

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
        std::fs::File::create(&input)
            .unwrap()
            .write_all(b"test")
            .unwrap();

        let result = encrypt_stream_chunked(
            &input,
            &dir.path().join("out"),
            &[0u8; 16],
            &[0u8; 12],
            None,
        );
        assert!(matches!(result, Err(CryptoError::InvalidKeySize(16))));
    }

    fn write_file(path: &Path, data: &[u8]) {
        std::fs::File::create(path).unwrap().write_all(data).unwrap();
    }

    fn make_encrypted_file(
        dir: &Path,
        data: &[u8],
        key: &[u8; 32],
        nonce: &[u8; 12],
        chunk: usize,
    ) -> std::path::PathBuf {
        let input = dir.join("input.bin");
        let encrypted = dir.join("encrypted.bin");
        write_file(&input, data);
        encrypt_stream_chunked(&input, &encrypted, key, nonce, Some(chunk)).unwrap();
        encrypted
    }

    #[test]
    fn test_range_within_single_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let key = [0x33u8; 32];
        let nonce = [0x07u8; 12];
        let encrypted = make_encrypted_file(dir.path(), &data, &key, &nonce, 1024);
        let out = dir.path().join("range.bin");

        let n = decrypt_stream_chunked_range(
            &encrypted,
            &out,
            &key,
            &nonce,
            1024,
            data.len() as u64,
            200,
            399,
        )
        .unwrap();
        assert_eq!(n, 200);
        let got = std::fs::read(&out).unwrap();
        assert_eq!(got, &data[200..400]);
    }

    #[test]
    fn test_range_spanning_multiple_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let key = [0x44u8; 32];
        let nonce = [0x02u8; 12];
        let encrypted = make_encrypted_file(dir.path(), &data, &key, &nonce, 512);
        let out = dir.path().join("range.bin");

        let n = decrypt_stream_chunked_range(
            &encrypted,
            &out,
            &key,
            &nonce,
            512,
            data.len() as u64,
            100,
            2999,
        )
        .unwrap();
        assert_eq!(n, 2900);
        let got = std::fs::read(&out).unwrap();
        assert_eq!(got, &data[100..3000]);
    }

    #[test]
    fn test_range_covers_final_partial_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..1300u32).map(|i| (i % 71) as u8).collect();
        let key = [0x55u8; 32];
        let nonce = [0x0au8; 12];
        let encrypted = make_encrypted_file(dir.path(), &data, &key, &nonce, 512);
        let out = dir.path().join("range.bin");

        let n = decrypt_stream_chunked_range(
            &encrypted,
            &out,
            &key,
            &nonce,
            512,
            data.len() as u64,
            900,
            1299,
        )
        .unwrap();
        assert_eq!(n, 400);
        let got = std::fs::read(&out).unwrap();
        assert_eq!(got, &data[900..1300]);
    }

    #[test]
    fn test_range_full_object() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..2048u32).map(|i| (i % 13) as u8).collect();
        let key = [0x11u8; 32];
        let nonce = [0x33u8; 12];
        let encrypted = make_encrypted_file(dir.path(), &data, &key, &nonce, 512);
        let out = dir.path().join("range.bin");

        let n = decrypt_stream_chunked_range(
            &encrypted,
            &out,
            &key,
            &nonce,
            512,
            data.len() as u64,
            0,
            data.len() as u64 - 1,
        )
        .unwrap();
        assert_eq!(n, data.len() as u64);
        let got = std::fs::read(&out).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn test_range_wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let data = b"range-auth-check".repeat(100);
        let key = [0x66u8; 32];
        let nonce = [0x09u8; 12];
        let encrypted = make_encrypted_file(dir.path(), &data, &key, &nonce, 256);
        let out = dir.path().join("range.bin");

        let wrong = [0x67u8; 32];
        let r = decrypt_stream_chunked_range(
            &encrypted,
            &out,
            &wrong,
            &nonce,
            256,
            data.len() as u64,
            0,
            data.len() as u64 - 1,
        );
        assert!(matches!(r, Err(CryptoError::DecryptionFailed(_))));
    }

    #[test]
    fn test_range_out_of_bounds_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let data = vec![0u8; 100];
        let key = [0x22u8; 32];
        let nonce = [0x44u8; 12];
        let encrypted = make_encrypted_file(dir.path(), &data, &key, &nonce, 64);
        let out = dir.path().join("range.bin");

        let r = decrypt_stream_chunked_range(
            &encrypted,
            &out,
            &key,
            &nonce,
            64,
            data.len() as u64,
            50,
            200,
        );
        assert!(r.is_err());
    }

    #[test]
    fn test_range_mismatched_chunk_size_detected() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..2048u32).map(|i| i as u8).collect();
        let key = [0x77u8; 32];
        let nonce = [0x88u8; 12];
        let encrypted = make_encrypted_file(dir.path(), &data, &key, &nonce, 512);
        let out = dir.path().join("range.bin");

        let r = decrypt_stream_chunked_range(
            &encrypted,
            &out,
            &key,
            &nonce,
            1024,
            data.len() as u64,
            0,
            1023,
        );
        assert!(r.is_err());
    }

    #[test]
    fn test_wrong_key_fails_decrypt() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.bin");
        let encrypted = dir.path().join("encrypted.bin");
        let decrypted = dir.path().join("decrypted.bin");

        std::fs::File::create(&input)
            .unwrap()
            .write_all(b"secret data")
            .unwrap();

        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        encrypt_stream_chunked(&input, &encrypted, &key, &nonce, None).unwrap();

        let wrong_key = [0x43u8; 32];
        let result = decrypt_stream_chunked(&encrypted, &decrypted, &wrong_key, &nonce);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed(_))));
    }
}
