use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;
use sha2::Sha256;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

const DEFAULT_CHUNK_SIZE: usize = 65536;
const HEADER_SIZE: usize = 4;

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

fn derive_chunk_nonce(base_nonce: &[u8], chunk_index: u32) -> Result<[u8; 12], String> {
    let hkdf = Hkdf::<Sha256>::new(Some(base_nonce), b"chunk_nonce");
    let mut okm = [0u8; 12];
    hkdf.expand(&chunk_index.to_be_bytes(), &mut okm)
        .map_err(|e| format!("HKDF expand failed: {}", e))?;
    Ok(okm)
}

#[pyfunction]
#[pyo3(signature = (input_path, output_path, key, base_nonce, chunk_size=DEFAULT_CHUNK_SIZE))]
pub fn encrypt_stream_chunked(
    py: Python<'_>,
    input_path: &str,
    output_path: &str,
    key: &[u8],
    base_nonce: &[u8],
    chunk_size: usize,
) -> PyResult<u32> {
    if key.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Key must be 32 bytes, got {}",
            key.len()
        )));
    }
    if base_nonce.len() != 12 {
        return Err(PyValueError::new_err(format!(
            "Base nonce must be 12 bytes, got {}",
            base_nonce.len()
        )));
    }

    let chunk_size = if chunk_size == 0 {
        DEFAULT_CHUNK_SIZE
    } else {
        chunk_size
    };

    let inp = input_path.to_owned();
    let out = output_path.to_owned();
    let key_arr: [u8; 32] = key.try_into().unwrap();
    let nonce_arr: [u8; 12] = base_nonce.try_into().unwrap();

    py.detach(move || {
        let cipher = Aes256Gcm::new(&key_arr.into());

        let mut infile = File::open(&inp)
            .map_err(|e| PyIOError::new_err(format!("Failed to open input: {}", e)))?;
        let mut outfile = File::create(&out)
            .map_err(|e| PyIOError::new_err(format!("Failed to create output: {}", e)))?;

        outfile
            .write_all(&[0u8; 4])
            .map_err(|e| PyIOError::new_err(format!("Failed to write header: {}", e)))?;

        let mut buf = vec![0u8; chunk_size];
        let mut chunk_index: u32 = 0;

        loop {
            let n = read_exact_chunk(&mut infile, &mut buf)
                .map_err(|e| PyIOError::new_err(format!("Failed to read: {}", e)))?;
            if n == 0 {
                break;
            }

            let nonce_bytes = derive_chunk_nonce(&nonce_arr, chunk_index)
                .map_err(|e| PyValueError::new_err(e))?;
            let nonce = Nonce::from_slice(&nonce_bytes);

            let encrypted = cipher
                .encrypt(nonce, &buf[..n])
                .map_err(|e| PyValueError::new_err(format!("Encrypt failed: {}", e)))?;

            let size = encrypted.len() as u32;
            outfile
                .write_all(&size.to_be_bytes())
                .map_err(|e| PyIOError::new_err(format!("Failed to write chunk size: {}", e)))?;
            outfile
                .write_all(&encrypted)
                .map_err(|e| PyIOError::new_err(format!("Failed to write chunk: {}", e)))?;

            chunk_index += 1;
        }

        outfile
            .seek(SeekFrom::Start(0))
            .map_err(|e| PyIOError::new_err(format!("Failed to seek: {}", e)))?;
        outfile
            .write_all(&chunk_index.to_be_bytes())
            .map_err(|e| PyIOError::new_err(format!("Failed to write chunk count: {}", e)))?;

        Ok(chunk_index)
    })
}

#[pyfunction]
pub fn decrypt_stream_chunked(
    py: Python<'_>,
    input_path: &str,
    output_path: &str,
    key: &[u8],
    base_nonce: &[u8],
) -> PyResult<u32> {
    if key.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Key must be 32 bytes, got {}",
            key.len()
        )));
    }
    if base_nonce.len() != 12 {
        return Err(PyValueError::new_err(format!(
            "Base nonce must be 12 bytes, got {}",
            base_nonce.len()
        )));
    }

    let inp = input_path.to_owned();
    let out = output_path.to_owned();
    let key_arr: [u8; 32] = key.try_into().unwrap();
    let nonce_arr: [u8; 12] = base_nonce.try_into().unwrap();

    py.detach(move || {
        let cipher = Aes256Gcm::new(&key_arr.into());

        let mut infile = File::open(&inp)
            .map_err(|e| PyIOError::new_err(format!("Failed to open input: {}", e)))?;
        let mut outfile = File::create(&out)
            .map_err(|e| PyIOError::new_err(format!("Failed to create output: {}", e)))?;

        let mut header = [0u8; HEADER_SIZE];
        infile
            .read_exact(&mut header)
            .map_err(|e| PyIOError::new_err(format!("Failed to read header: {}", e)))?;
        let chunk_count = u32::from_be_bytes(header);

        let mut size_buf = [0u8; HEADER_SIZE];
        for chunk_index in 0..chunk_count {
            infile
                .read_exact(&mut size_buf)
                .map_err(|e| {
                    PyIOError::new_err(format!(
                        "Failed to read chunk {} size: {}",
                        chunk_index, e
                    ))
                })?;
            let chunk_size = u32::from_be_bytes(size_buf) as usize;

            let mut encrypted = vec![0u8; chunk_size];
            infile.read_exact(&mut encrypted).map_err(|e| {
                PyIOError::new_err(format!("Failed to read chunk {}: {}", chunk_index, e))
            })?;

            let nonce_bytes = derive_chunk_nonce(&nonce_arr, chunk_index)
                .map_err(|e| PyValueError::new_err(e))?;
            let nonce = Nonce::from_slice(&nonce_bytes);

            let decrypted = cipher.decrypt(nonce, encrypted.as_ref()).map_err(|e| {
                PyValueError::new_err(format!("Decrypt chunk {} failed: {}", chunk_index, e))
            })?;

            outfile.write_all(&decrypted).map_err(|e| {
                PyIOError::new_err(format!("Failed to write chunk {}: {}", chunk_index, e))
            })?;
        }

        Ok(chunk_count)
    })
}
