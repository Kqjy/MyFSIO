#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReadTuning {
    pub buffer_bytes: usize,
    pub sequential: bool,
}

impl ReadTuning {
    pub fn apply(self, file: &mut tokio::fs::File) {
        if self.buffer_bytes > 0 {
            file.set_max_buf_size(self.buffer_bytes);
        }
        if self.sequential {
            if let Err(error) = platform::advise_sequential(file) {
                tracing::debug!("posix_fadvise(SEQUENTIAL) failed: {}", error);
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::os::fd::AsRawFd;

    pub(super) fn advise_sequential(file: &tokio::fs::File) -> std::io::Result<()> {
        let rc =
            unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL) };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::from_raw_os_error(rc))
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    pub(super) fn advise_sequential(_file: &tokio::fs::File) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn tuned_file_reads_in_buffer_sized_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("obj");
        std::fs::write(&path, vec![9u8; 6 * 1024 * 1024]).unwrap();

        let mut default_file = tokio::fs::File::open(&path).await.unwrap();
        let mut buf = vec![0u8; 8 * 1024 * 1024];
        let n = default_file.read(&mut buf).await.unwrap();
        assert!(n <= 2 * 1024 * 1024);

        let mut tuned = tokio::fs::File::open(&path).await.unwrap();
        ReadTuning {
            buffer_bytes: 4 * 1024 * 1024,
            sequential: true,
        }
        .apply(&mut tuned);
        let n = tuned.read(&mut buf).await.unwrap();
        assert_eq!(n, 4 * 1024 * 1024);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_sequential_advice_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("obj");
        std::fs::write(&path, b"data").unwrap();
        let file = tokio::fs::File::open(&path).await.unwrap();
        platform::advise_sequential(&file).unwrap();
    }
}
