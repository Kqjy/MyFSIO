use md5::{Digest, Md5};
use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;
use std::fs::{self, File};
use std::io::{Read, Write};
use uuid::Uuid;

const DEFAULT_CHUNK_SIZE: usize = 262144;

#[pyfunction]
#[pyo3(signature = (stream, tmp_dir, chunk_size=DEFAULT_CHUNK_SIZE))]
pub fn stream_to_file_with_md5(
    py: Python<'_>,
    stream: &Bound<'_, PyAny>,
    tmp_dir: &str,
    chunk_size: usize,
) -> PyResult<(String, String, u64)> {
    let chunk_size = if chunk_size == 0 {
        DEFAULT_CHUNK_SIZE
    } else {
        chunk_size
    };

    fs::create_dir_all(tmp_dir)
        .map_err(|e| PyIOError::new_err(format!("Failed to create tmp dir: {}", e)))?;

    let tmp_name = format!("{}.tmp", Uuid::new_v4().as_hyphenated());
    let tmp_path_buf = std::path::PathBuf::from(tmp_dir).join(&tmp_name);
    let tmp_path = tmp_path_buf.to_string_lossy().into_owned();

    let mut file = File::create(&tmp_path)
        .map_err(|e| PyIOError::new_err(format!("Failed to create temp file: {}", e)))?;
    let mut hasher = Md5::new();
    let mut total_bytes: u64 = 0;

    let result: PyResult<()> = (|| {
        loop {
            let chunk: Vec<u8> = stream.call_method1("read", (chunk_size,))?.extract()?;
            if chunk.is_empty() {
                break;
            }
            hasher.update(&chunk);
            file.write_all(&chunk)
                .map_err(|e| PyIOError::new_err(format!("Failed to write: {}", e)))?;
            total_bytes += chunk.len() as u64;

            py.check_signals()?;
        }
        file.sync_all()
            .map_err(|e| PyIOError::new_err(format!("Failed to fsync: {}", e)))?;
        Ok(())
    })();

    if let Err(e) = result {
        drop(file);
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }

    drop(file);

    let md5_hex = format!("{:x}", hasher.finalize());
    Ok((tmp_path, md5_hex, total_bytes))
}

#[pyfunction]
pub fn assemble_parts_with_md5(
    py: Python<'_>,
    part_paths: Vec<String>,
    dest_path: &str,
) -> PyResult<String> {
    if part_paths.is_empty() {
        return Err(PyValueError::new_err("No parts to assemble"));
    }

    let dest = dest_path.to_owned();
    let parts = part_paths;

    py.detach(move || {
        if let Some(parent) = std::path::Path::new(&dest).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| PyIOError::new_err(format!("Failed to create dest dir: {}", e)))?;
        }

        let mut target = File::create(&dest)
            .map_err(|e| PyIOError::new_err(format!("Failed to create dest file: {}", e)))?;
        let mut hasher = Md5::new();
        let mut buf = vec![0u8; 1024 * 1024];

        for part_path in &parts {
            let mut part = File::open(part_path)
                .map_err(|e| PyIOError::new_err(format!("Failed to open part {}: {}", part_path, e)))?;
            loop {
                let n = part
                    .read(&mut buf)
                    .map_err(|e| PyIOError::new_err(format!("Failed to read part: {}", e)))?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                target
                    .write_all(&buf[..n])
                    .map_err(|e| PyIOError::new_err(format!("Failed to write: {}", e)))?;
            }
        }

        target.sync_all()
            .map_err(|e| PyIOError::new_err(format!("Failed to fsync: {}", e)))?;

        Ok(format!("{:x}", hasher.finalize()))
    })
}
