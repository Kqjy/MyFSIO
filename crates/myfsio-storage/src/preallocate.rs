use std::fs::File;
use std::io;

pub const PREALLOCATE_MIN_BYTES: u64 = 4 * 1024 * 1024;
pub const PREALLOCATE_WINDOW_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub struct Preallocator {
    expected: u64,
    reserved: u64,
}

impl Preallocator {
    pub fn new(expected: Option<u64>, enabled: bool) -> Self {
        let expected = match expected {
            Some(len) if enabled && len >= PREALLOCATE_MIN_BYTES => len,
            _ => 0,
        };
        Self {
            expected,
            reserved: 0,
        }
    }

    pub fn disabled() -> Self {
        Self::new(None, false)
    }

    pub fn reserve(&mut self, file: &File, next_end: u64) -> io::Result<()> {
        self.reserve_with(next_end, |offset, len| {
            platform::allocate_keep_size(file, offset, len)
        })
    }

    pub fn finish(&self, file: &File, written: u64) {
        if self.reserved <= written {
            return;
        }
        let trimmed = file
            .set_len(written.saturating_add(1))
            .and_then(|()| file.set_len(written));
        if let Err(error) = trimmed {
            tracing::debug!("could not release unused preallocated space: {}", error);
        }
    }

    fn reserve_with(
        &mut self,
        next_end: u64,
        mut allocate: impl FnMut(u64, u64) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.reserved >= self.expected || next_end <= self.reserved {
            return Ok(());
        }
        let target = next_end
            .saturating_add(PREALLOCATE_WINDOW_BYTES)
            .min(self.expected);
        let offset = self.reserved;
        match allocate(offset, target - offset) {
            Ok(()) => {
                self.reserved = target;
                Ok(())
            }
            Err(error) if is_out_of_space(&error) => Err(error),
            Err(error) => {
                tracing::debug!("upload preallocation disabled for this file: {}", error);
                self.expected = 0;
                Ok(())
            }
        }
    }
}

fn is_out_of_space(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded
    )
}

#[cfg(target_os = "linux")]
mod platform {
    use std::fs::File;
    use std::os::fd::AsRawFd;

    pub(super) fn allocate_keep_size(file: &File, offset: u64, len: u64) -> std::io::Result<()> {
        let offset = libc::off_t::try_from(offset)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let len = libc::off_t::try_from(len)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        loop {
            let rc = unsafe {
                libc::fallocate(file.as_raw_fd(), libc::FALLOC_FL_KEEP_SIZE, offset, len)
            };
            if rc == 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use std::fs::File;

    pub(super) fn allocate_keep_size(_file: &File, _offset: u64, _len: u64) -> std::io::Result<()> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn small_unknown_or_disabled_uploads_never_allocate() {
        for mut pre in [
            Preallocator::new(Some(PREALLOCATE_MIN_BYTES - 1), true),
            Preallocator::new(None, true),
            Preallocator::new(Some(512 * MIB), false),
            Preallocator::disabled(),
        ] {
            pre.reserve_with(MIB, |_, _| panic!("must not allocate"))
                .unwrap();
        }
    }

    #[test]
    fn reserves_bounded_windows_ahead_of_writes_up_to_expected() {
        let mut calls = Vec::new();
        let mut pre = Preallocator::new(Some(150 * MIB), true);
        let mut written = 0u64;
        while written < 150 * MIB {
            written += MIB;
            pre.reserve_with(written, |offset, len| {
                calls.push((offset, len));
                Ok(())
            })
            .unwrap();
        }
        assert_eq!(
            calls,
            vec![(0, 65 * MIB), (65 * MIB, 65 * MIB), (130 * MIB, 20 * MIB)]
        );
    }

    #[test]
    fn out_of_space_is_reported_and_unsupported_disables() {
        let mut pre = Preallocator::new(Some(64 * MIB), true);
        let err = pre
            .reserve_with(MIB, |_, _| Err(io::Error::from(io::ErrorKind::StorageFull)))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::StorageFull);

        let mut pre = Preallocator::new(Some(256 * MIB), true);
        pre.reserve_with(MIB, |_, _| Err(io::Error::from(io::ErrorKind::Unsupported)))
            .unwrap();
        pre.reserve_with(128 * MIB, |_, _| panic!("disabled after unsupported"))
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_reservation_keeps_logical_size() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let file = File::create(dir.path().join("part")).unwrap();
        let mut pre = Preallocator::new(Some(8 * MIB), true);
        pre.reserve(&file, MIB).unwrap();
        let meta = file.metadata().unwrap();
        assert_eq!(pre.reserved, 8 * MIB);
        assert_eq!(meta.len(), 0);
        assert!(meta.blocks() * 512 >= 8 * MIB);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_finish_releases_reservation_past_written_bytes() {
        use std::io::Write;
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let mut file = File::create(dir.path().join("part")).unwrap();
        let mut pre = Preallocator::new(Some(32 * MIB), true);
        pre.reserve(&file, MIB).unwrap();
        file.write_all(&vec![5u8; MIB as usize]).unwrap();
        pre.finish(&file, MIB);
        let meta = file.metadata().unwrap();
        assert_eq!(meta.len(), MIB);
        assert!(meta.blocks() * 512 < 2 * MIB);
    }
}
