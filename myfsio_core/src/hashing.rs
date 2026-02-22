use md5::{Digest, Md5};
use pyo3::exceptions::PyIOError;
use pyo3::prelude::*;
use sha2::Sha256;
use std::fs::File;
use std::io::Read;

const CHUNK_SIZE: usize = 65536;

#[pyfunction]
pub fn md5_file(py: Python<'_>, path: &str) -> PyResult<String> {
    let path = path.to_owned();
    py.detach(move || {
        let mut file = File::open(&path)
            .map_err(|e| PyIOError::new_err(format!("Failed to open file: {}", e)))?;
        let mut hasher = Md5::new();
        let mut buf = vec![0u8; CHUNK_SIZE];
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| PyIOError::new_err(format!("Failed to read file: {}", e)))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    })
}

#[pyfunction]
pub fn md5_bytes(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[pyfunction]
pub fn sha256_file(py: Python<'_>, path: &str) -> PyResult<String> {
    let path = path.to_owned();
    py.detach(move || {
        let mut file = File::open(&path)
            .map_err(|e| PyIOError::new_err(format!("Failed to open file: {}", e)))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; CHUNK_SIZE];
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| PyIOError::new_err(format!("Failed to read file: {}", e)))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    })
}

#[pyfunction]
pub fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[pyfunction]
pub fn md5_sha256_file(py: Python<'_>, path: &str) -> PyResult<(String, String)> {
    let path = path.to_owned();
    py.detach(move || {
        let mut file = File::open(&path)
            .map_err(|e| PyIOError::new_err(format!("Failed to open file: {}", e)))?;
        let mut md5_hasher = Md5::new();
        let mut sha_hasher = Sha256::new();
        let mut buf = vec![0u8; CHUNK_SIZE];
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| PyIOError::new_err(format!("Failed to read file: {}", e)))?;
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
    })
}
