use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use md5::{Digest, Md5};
use rand::RngCore;
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

fn read_exact_chunk<R: Read + ?Sized>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
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

pub struct ReaderEncryptOutcome {
    pub plaintext_size: u64,
    pub chunk_count: u32,
    pub plaintext_md5_hex: String,
}

pub fn encrypt_reader_chunked(
    reader: &mut dyn Read,
    output_path: &Path,
    key: &[u8],
    base_nonce: &[u8],
    chunk_size: Option<usize>,
) -> Result<ReaderEncryptOutcome, CryptoError> {
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

    let mut outfile = File::create(output_path)?;
    outfile.write_all(&[0u8; 4])?;

    let mut hasher = Md5::new();
    let mut buf = vec![0u8; chunk_size];
    let mut chunk_index: u32 = 0;
    let mut plaintext_size: u64 = 0;

    loop {
        let n = read_exact_chunk(reader, &mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        plaintext_size += n as u64;

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
    outfile.sync_all()?;

    Ok(ReaderEncryptOutcome {
        plaintext_size,
        chunk_count: chunk_index,
        plaintext_md5_hex: format!("{:x}", hasher.finalize()),
    })
}

pub type DecryptSink<'a> = &'a mut dyn FnMut(&[u8]) -> std::io::Result<bool>;

fn decrypt_chunked_full_core(
    file: &mut File,
    base_offset: u64,
    key_arr: &[u8; 32],
    nonce_arr: &[u8; 12],
    sink: DecryptSink<'_>,
) -> Result<u32, CryptoError> {
    let cipher = Aes256Gcm::new(key_arr.into());
    file.seek(SeekFrom::Start(base_offset))?;

    let mut header = [0u8; HEADER_SIZE];
    file.read_exact(&mut header)?;
    let chunk_count = u32::from_be_bytes(header);

    let mut size_buf = [0u8; HEADER_SIZE];
    for chunk_index in 0..chunk_count {
        file.read_exact(&mut size_buf)?;
        let chunk_size = u32::from_be_bytes(size_buf) as usize;

        let mut encrypted = vec![0u8; chunk_size];
        file.read_exact(&mut encrypted)?;

        let nonce_bytes = derive_chunk_nonce(nonce_arr, chunk_index)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let decrypted = cipher
            .decrypt(nonce, encrypted.as_ref())
            .map_err(|_| CryptoError::DecryptionFailed(chunk_index))?;

        if !sink(&decrypted)? {
            return Ok(chunk_index + 1);
        }
    }

    Ok(chunk_count)
}

pub fn decrypt_stream_chunked_each(
    input_path: &Path,
    key: &[u8],
    base_nonce: &[u8],
    sink: DecryptSink<'_>,
) -> Result<u32, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeySize(key.len()));
    }
    if base_nonce.len() != 12 {
        return Err(CryptoError::InvalidNonceSize(base_nonce.len()));
    }
    let key_arr: [u8; 32] = key.try_into().unwrap();
    let nonce_arr: [u8; 12] = base_nonce.try_into().unwrap();
    let mut infile = File::open(input_path)?;
    decrypt_chunked_full_core(&mut infile, 0, &key_arr, &nonce_arr, sink)
}

pub fn decrypt_stream_chunked(
    input_path: &Path,
    output_path: &Path,
    key: &[u8],
    base_nonce: &[u8],
) -> Result<u32, CryptoError> {
    let mut outfile = File::create(output_path)?;
    let mut sink = |data: &[u8]| -> std::io::Result<bool> {
        outfile.write_all(data)?;
        Ok(true)
    };
    decrypt_stream_chunked_each(input_path, key, base_nonce, &mut sink)
}

const GCM_TAG_LEN: usize = 16;

#[allow(clippy::too_many_arguments)]
fn decrypt_chunked_range_core(
    file: &mut File,
    base_offset: u64,
    key_arr: &[u8; 32],
    nonce_arr: &[u8; 12],
    chunk_plain_size: usize,
    plaintext_size: u64,
    plain_start: u64,
    plain_end_inclusive: u64,
    sink: DecryptSink<'_>,
) -> Result<u64, CryptoError> {
    if chunk_plain_size == 0 {
        return Err(CryptoError::EncryptionFailed(
            "chunk_plain_size must be > 0".into(),
        ));
    }
    if plaintext_size == 0 {
        return Ok(0);
    }
    if plain_start > plain_end_inclusive || plain_end_inclusive >= plaintext_size {
        return Err(CryptoError::EncryptionFailed(format!(
            "range [{}, {}] invalid for plaintext size {}",
            plain_start, plain_end_inclusive, plaintext_size
        )));
    }

    let cipher = Aes256Gcm::new(key_arr.into());

    let n = chunk_plain_size as u64;
    let first_chunk = (plain_start / n) as u32;
    let last_chunk = (plain_end_inclusive / n) as u32;
    let total_chunks = plaintext_size.div_ceil(n) as u32;
    let final_chunk_plain = plaintext_size - (total_chunks as u64 - 1) * n;

    file.seek(SeekFrom::Start(base_offset))?;
    let mut header = [0u8; HEADER_SIZE];
    file.read_exact(&mut header)?;
    let stored_chunk_count = u32::from_be_bytes(header);
    if stored_chunk_count != total_chunks {
        return Err(CryptoError::EncryptionFailed(format!(
            "chunk count mismatch: header says {}, plaintext_size implies {}",
            stored_chunk_count, total_chunks
        )));
    }

    let stride = n + GCM_TAG_LEN as u64 + HEADER_SIZE as u64;
    let first_offset = base_offset + HEADER_SIZE as u64 + first_chunk as u64 * stride;
    file.seek(SeekFrom::Start(first_offset))?;

    let mut size_buf = [0u8; HEADER_SIZE];
    let mut bytes_written: u64 = 0;

    for chunk_index in first_chunk..=last_chunk {
        file.read_exact(&mut size_buf)?;
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
        file.read_exact(&mut encrypted)?;

        let nonce_bytes = derive_chunk_nonce(nonce_arr, chunk_index)?;
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
            bytes_written += (slice_end_local - slice_start) as u64;
            if !sink(&decrypted[slice_start..slice_end_local])? {
                return Ok(bytes_written);
            }
        }
    }

    Ok(bytes_written)
}

fn validated_keys(key: &[u8], base_nonce: &[u8]) -> Result<([u8; 32], [u8; 12]), CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeySize(key.len()));
    }
    if base_nonce.len() != 12 {
        return Err(CryptoError::InvalidNonceSize(base_nonce.len()));
    }
    Ok((key.try_into().unwrap(), base_nonce.try_into().unwrap()))
}

#[allow(clippy::too_many_arguments)]
pub fn decrypt_stream_chunked_range_each(
    input_path: &Path,
    key: &[u8],
    base_nonce: &[u8],
    chunk_plain_size: usize,
    plaintext_size: u64,
    plain_start: u64,
    plain_end_inclusive: u64,
    sink: DecryptSink<'_>,
) -> Result<u64, CryptoError> {
    let (key_arr, nonce_arr) = validated_keys(key, base_nonce)?;
    let mut infile = File::open(input_path)?;
    decrypt_chunked_range_core(
        &mut infile,
        0,
        &key_arr,
        &nonce_arr,
        chunk_plain_size,
        plaintext_size,
        plain_start,
        plain_end_inclusive,
        sink,
    )
}

#[allow(clippy::too_many_arguments)]
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
    let mut outfile = File::create(output_path)?;
    let mut sink = |data: &[u8]| -> std::io::Result<bool> {
        outfile.write_all(data)?;
        Ok(true)
    };
    decrypt_stream_chunked_range_each(
        input_path,
        key,
        base_nonce,
        chunk_plain_size,
        plaintext_size,
        plain_start,
        plain_end_inclusive,
        &mut sink,
    )
}

pub const PART_BLOCK_PLAIN_SIZE_LEN: usize = 8;
pub const PART_BLOCK_SALT_LEN: usize = 16;
pub const PART_BLOCK_PREFIX_LEN: usize = PART_BLOCK_PLAIN_SIZE_LEN + PART_BLOCK_SALT_LEN;

pub fn derive_part_base_nonce(
    odk: &[u8; 32],
    part_number: u32,
    salt: &[u8],
) -> Result<[u8; 12], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(odk), b"mpu_part_nonce");
    let mut info = Vec::with_capacity(4 + salt.len());
    info.extend_from_slice(&part_number.to_be_bytes());
    info.extend_from_slice(salt);
    let mut okm = [0u8; 12];
    hkdf.expand(&info, &mut okm)
        .map_err(|e| CryptoError::HkdfFailed(e.to_string()))?;
    Ok(okm)
}

pub fn encrypt_part_block(
    input_path: &Path,
    output_path: &Path,
    odk: &[u8; 32],
    part_number: u32,
    chunk_size: Option<usize>,
) -> Result<(u64, u32), CryptoError> {
    let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);

    let mut salt = [0u8; PART_BLOCK_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let base_nonce = derive_part_base_nonce(odk, part_number, &salt)?;

    let key_arr: [u8; 32] = *odk;
    let cipher = Aes256Gcm::new(&key_arr.into());

    let mut infile = File::open(input_path)?;
    let plaintext_size = infile.metadata()?.len();
    let mut outfile = File::create(output_path)?;

    outfile.write_all(&plaintext_size.to_be_bytes())?;
    outfile.write_all(&salt)?;
    outfile.write_all(&[0u8; HEADER_SIZE])?;

    let mut buf = vec![0u8; chunk_size];
    let mut chunk_index: u32 = 0;

    loop {
        let n = read_exact_chunk(&mut infile, &mut buf)?;
        if n == 0 {
            break;
        }

        let nonce_bytes = derive_chunk_nonce(&base_nonce, chunk_index)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, &buf[..n])
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let size = encrypted.len() as u32;
        outfile.write_all(&size.to_be_bytes())?;
        outfile.write_all(&encrypted)?;

        chunk_index += 1;
    }

    outfile.seek(SeekFrom::Start(PART_BLOCK_PREFIX_LEN as u64))?;
    outfile.write_all(&chunk_index.to_be_bytes())?;

    Ok((plaintext_size, chunk_index))
}

pub fn read_part_block_plain_size(
    object_path: &Path,
    block_offset: u64,
) -> Result<u64, CryptoError> {
    let mut f = File::open(object_path)?;
    f.seek(SeekFrom::Start(block_offset))?;
    let mut prefix = [0u8; PART_BLOCK_PLAIN_SIZE_LEN];
    f.read_exact(&mut prefix)?;
    Ok(u64::from_be_bytes(prefix))
}

pub fn read_part_block_salt(
    object_path: &Path,
    block_offset: u64,
) -> Result<[u8; PART_BLOCK_SALT_LEN], CryptoError> {
    let mut f = File::open(object_path)?;
    f.seek(SeekFrom::Start(
        block_offset + PART_BLOCK_PLAIN_SIZE_LEN as u64,
    ))?;
    let mut salt = [0u8; PART_BLOCK_SALT_LEN];
    f.read_exact(&mut salt)?;
    Ok(salt)
}

fn part_block_min_len_check(block_len: u64) -> Result<(), CryptoError> {
    let min_len = (PART_BLOCK_PREFIX_LEN + HEADER_SIZE) as u64;
    if block_len < min_len {
        return Err(CryptoError::EncryptionFailed(format!(
            "part block length {} smaller than minimum {}",
            block_len, min_len
        )));
    }
    Ok(())
}

pub fn decrypt_part_block_each(
    object_path: &Path,
    block_offset: u64,
    block_len: u64,
    odk: &[u8; 32],
    part_number: u32,
    sink: DecryptSink<'_>,
) -> Result<u32, CryptoError> {
    part_block_min_len_check(block_len)?;
    let salt = read_part_block_salt(object_path, block_offset)?;
    let base_nonce = derive_part_base_nonce(odk, part_number, &salt)?;
    let mut file = File::open(object_path)?;
    decrypt_chunked_full_core(
        &mut file,
        block_offset + PART_BLOCK_PREFIX_LEN as u64,
        odk,
        &base_nonce,
        sink,
    )
}

pub fn decrypt_part_block(
    object_path: &Path,
    output_path: &Path,
    block_offset: u64,
    block_len: u64,
    odk: &[u8; 32],
    part_number: u32,
) -> Result<u64, CryptoError> {
    let mut outfile = File::create(output_path)?;
    let mut written: u64 = 0;
    let mut sink = |data: &[u8]| -> std::io::Result<bool> {
        outfile.write_all(data)?;
        written += data.len() as u64;
        Ok(true)
    };
    decrypt_part_block_each(
        object_path,
        block_offset,
        block_len,
        odk,
        part_number,
        &mut sink,
    )?;
    Ok(written)
}

#[allow(clippy::too_many_arguments)]
pub fn decrypt_part_block_range_each(
    object_path: &Path,
    block_offset: u64,
    block_len: u64,
    odk: &[u8; 32],
    part_number: u32,
    chunk_plain_size: usize,
    part_plaintext_size: u64,
    plain_start: u64,
    plain_end_inclusive: u64,
    sink: DecryptSink<'_>,
) -> Result<u64, CryptoError> {
    part_block_min_len_check(block_len)?;
    let salt = read_part_block_salt(object_path, block_offset)?;
    let base_nonce = derive_part_base_nonce(odk, part_number, &salt)?;
    let mut file = File::open(object_path)?;
    decrypt_chunked_range_core(
        &mut file,
        block_offset + PART_BLOCK_PREFIX_LEN as u64,
        odk,
        &base_nonce,
        chunk_plain_size,
        part_plaintext_size,
        plain_start,
        plain_end_inclusive,
        sink,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn decrypt_part_block_range(
    object_path: &Path,
    output_path: &Path,
    block_offset: u64,
    block_len: u64,
    odk: &[u8; 32],
    part_number: u32,
    chunk_plain_size: usize,
    part_plaintext_size: u64,
    plain_start: u64,
    plain_end_inclusive: u64,
) -> Result<u64, CryptoError> {
    let mut outfile = File::create(output_path)?;
    let mut sink = |data: &[u8]| -> std::io::Result<bool> {
        outfile.write_all(data)?;
        Ok(true)
    };
    decrypt_part_block_range_each(
        object_path,
        block_offset,
        block_len,
        odk,
        part_number,
        chunk_plain_size,
        part_plaintext_size,
        plain_start,
        plain_end_inclusive,
        &mut sink,
    )
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
    .map_err(|e| CryptoError::Io(std::io::Error::other(e)))?
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
    .map_err(|e| CryptoError::Io(std::io::Error::other(e)))?
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
        std::fs::File::create(path)
            .unwrap()
            .write_all(data)
            .unwrap();
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

    #[test]
    fn test_derive_part_base_nonce_deterministic_and_distinct() {
        let odk = [0x5au8; 32];
        let salt_a = [0x10u8; PART_BLOCK_SALT_LEN];
        let salt_b = [0x20u8; PART_BLOCK_SALT_LEN];
        let a1 = derive_part_base_nonce(&odk, 1, &salt_a).unwrap();
        let a1b = derive_part_base_nonce(&odk, 1, &salt_a).unwrap();
        let a2 = derive_part_base_nonce(&odk, 2, &salt_a).unwrap();
        assert_eq!(a1, a1b);
        assert_ne!(a1, a2);
        let same_part_other_salt = derive_part_base_nonce(&odk, 1, &salt_b).unwrap();
        assert_ne!(
            a1, same_part_other_salt,
            "same part number with a different salt must produce a distinct nonce"
        );
        let other = derive_part_base_nonce(&[0x5bu8; 32], 1, &salt_a).unwrap();
        assert_ne!(a1, other);
    }

    fn make_part_block(
        dir: &Path,
        data: &[u8],
        odk: &[u8; 32],
        part_number: u32,
        chunk: usize,
    ) -> (std::path::PathBuf, u64) {
        let input = dir.join(format!("plain-{}.bin", part_number));
        let block = dir.join(format!("block-{}.bin", part_number));
        write_file(&input, data);
        let (plain_size, _) =
            encrypt_part_block(&input, &block, odk, part_number, Some(chunk)).unwrap();
        assert_eq!(plain_size, data.len() as u64);
        let block_len = std::fs::metadata(&block).unwrap().len();
        (block, block_len)
    }

    #[test]
    fn test_part_block_roundtrip_full() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let odk = [0x77u8; 32];
        let (block, block_len) = make_part_block(dir.path(), &data, &odk, 3, 1024);

        let prefix_size = read_part_block_plain_size(&block, 0).unwrap();
        assert_eq!(prefix_size, data.len() as u64);

        let out = dir.path().join("dec.bin");
        let n = decrypt_part_block(&block, &out, 0, block_len, &odk, 3).unwrap();
        assert_eq!(n, data.len() as u64);
        assert_eq!(std::fs::read(&out).unwrap(), data);
    }

    #[test]
    fn test_part_block_roundtrip_at_offset() {
        let dir = tempfile::tempdir().unwrap();
        let data_a = vec![0xABu8; 1500];
        let data_b: Vec<u8> = (0..3333u32).map(|i| (i % 97) as u8).collect();
        let odk = [0x21u8; 32];
        let (block_a, len_a) = make_part_block(dir.path(), &data_a, &odk, 1, 512);
        let (block_b, len_b) = make_part_block(dir.path(), &data_b, &odk, 2, 512);

        let object = dir.path().join("object.bin");
        {
            let mut o = File::create(&object).unwrap();
            o.write_all(&std::fs::read(&block_a).unwrap()).unwrap();
            o.write_all(&std::fs::read(&block_b).unwrap()).unwrap();
        }

        let prefix_b = read_part_block_plain_size(&object, len_a).unwrap();
        assert_eq!(prefix_b, data_b.len() as u64);

        let out = dir.path().join("dec_b.bin");
        let n = decrypt_part_block(&object, &out, len_a, len_b, &odk, 2).unwrap();
        assert_eq!(n, data_b.len() as u64);
        assert_eq!(std::fs::read(&out).unwrap(), data_b);
    }

    #[test]
    fn test_part_block_range_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..6000u32).map(|i| (i % 211) as u8).collect();
        let odk = [0x34u8; 32];
        let (block, block_len) = make_part_block(dir.path(), &data, &odk, 7, 512);

        for (s, e) in [
            (0u64, 0u64),
            (100, 399),
            (500, 2999),
            (5000, 5999),
            (0, 5999),
        ] {
            let out = dir.path().join(format!("r-{}-{}.bin", s, e));
            let n = decrypt_part_block_range(
                &block,
                &out,
                0,
                block_len,
                &odk,
                7,
                512,
                data.len() as u64,
                s,
                e,
            )
            .unwrap();
            assert_eq!(n, e - s + 1);
            assert_eq!(std::fs::read(&out).unwrap(), &data[s as usize..=e as usize]);
        }
    }

    #[test]
    fn test_part_block_wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let data = b"per-part-secret".repeat(80);
        let odk = [0x44u8; 32];
        let (block, block_len) = make_part_block(dir.path(), &data, &odk, 1, 256);

        let wrong = [0x45u8; 32];
        let out = dir.path().join("bad.bin");
        let r = decrypt_part_block(&block, &out, 0, block_len, &wrong, 1);
        assert!(matches!(r, Err(CryptoError::DecryptionFailed(_))));

        let r2 = decrypt_part_block_range(
            &block,
            &out,
            0,
            block_len,
            &wrong,
            1,
            256,
            data.len() as u64,
            0,
            data.len() as u64 - 1,
        );
        assert!(matches!(r2, Err(CryptoError::DecryptionFailed(_))));
    }

    #[test]
    fn test_part_block_replacement_uses_distinct_salt_and_ciphertext() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let odk = [0x99u8; 32];

        let input = dir.path().join("plain.bin");
        write_file(&input, &data);
        let block1 = dir.path().join("block1.bin");
        let block2 = dir.path().join("block2.bin");
        encrypt_part_block(&input, &block1, &odk, 5, Some(1024)).unwrap();
        encrypt_part_block(&input, &block2, &odk, 5, Some(1024)).unwrap();

        let b1 = std::fs::read(&block1).unwrap();
        let b2 = std::fs::read(&block2).unwrap();

        let salt1 = &b1[PART_BLOCK_PLAIN_SIZE_LEN..PART_BLOCK_PREFIX_LEN];
        let salt2 = &b2[PART_BLOCK_PLAIN_SIZE_LEN..PART_BLOCK_PREFIX_LEN];
        assert_ne!(
            salt1, salt2,
            "re-encrypting the same part must use a fresh random salt"
        );
        assert_ne!(
            &b1[PART_BLOCK_PREFIX_LEN..],
            &b2[PART_BLOCK_PREFIX_LEN..],
            "same plaintext under the same key/part number must not reuse the AES-GCM nonce stream"
        );

        let out1 = dir.path().join("d1.bin");
        let out2 = dir.path().join("d2.bin");
        decrypt_part_block(&block1, &out1, 0, b1.len() as u64, &odk, 5).unwrap();
        decrypt_part_block(&block2, &out2, 0, b2.len() as u64, &odk, 5).unwrap();
        assert_eq!(std::fs::read(&out1).unwrap(), data);
        assert_eq!(std::fs::read(&out2).unwrap(), data);
    }

    #[test]
    fn test_part_block_envelope_matches_stream_format() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..2048u32).map(|i| i as u8).collect();
        let odk = [0x66u8; 32];

        let input = dir.path().join("p.bin");
        let block = dir.path().join("block.bin");
        write_file(&input, &data);
        encrypt_part_block(&input, &block, &odk, 1, Some(512)).unwrap();

        let block_bytes = std::fs::read(&block).unwrap();
        let salt = &block_bytes[PART_BLOCK_PLAIN_SIZE_LEN..PART_BLOCK_PREFIX_LEN];
        let base_nonce = derive_part_base_nonce(&odk, 1, salt).unwrap();
        let envelope = dir.path().join("env.bin");
        write_file(&envelope, &block_bytes[PART_BLOCK_PREFIX_LEN..]);

        let out = dir.path().join("via_stream.bin");
        decrypt_stream_chunked(&envelope, &out, &odk, &base_nonce).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), data);
    }
}
