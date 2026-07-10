use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncSeekExt, ReadBuf};

pub const SEGMENT_STUB_MAGIC: &[u8; 12] = b"MYFSIO-SEG1\n";
pub const SEGMENTS_DIR: &str = "segments";
pub const META_KEY_SEGMENTS: &str = "__segments__";
pub const SEGMENT_MIN_TOTAL: u64 = 4096;
const STUB_JSON_MAX_LEN: u32 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StubHeader {
    pub v: u32,
    pub segment_id: String,
    pub sizes: Vec<u64>,
    pub total: u64,
    pub etag: String,
}

impl StubHeader {
    pub fn new(segment_id: String, sizes: Vec<u64>, etag: String) -> Self {
        let total = sizes.iter().sum();
        Self {
            v: 1,
            segment_id,
            sizes,
            total,
            etag,
        }
    }
}

#[cfg(windows)]
fn mark_sparse(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let mut bytes_returned: u32 = 0;
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_SPARSE,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn mark_sparse(_file: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

pub fn write_stub(path: &Path, header: &StubHeader) -> std::io::Result<()> {
    let json = serde_json::to_vec(header)?;
    let header_len = SEGMENT_STUB_MAGIC.len() as u64 + 4 + json.len() as u64;
    if header.total < header_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "segment stub header ({} bytes) exceeds logical object size ({} bytes)",
                header_len, header.total
            ),
        ));
    }
    let mut file = std::fs::File::create(path)?;
    file.write_all(SEGMENT_STUB_MAGIC)?;
    file.write_all(&(json.len() as u32).to_le_bytes())?;
    file.write_all(&json)?;
    file.flush()?;
    if let Err(e) = mark_sparse(&file) {
        tracing::debug!(path = %path.display(), error = %e, "could not mark segment stub sparse; stub will occupy its logical size on disk");
    }
    file.set_len(header.total)?;
    Ok(())
}

pub fn read_stub_header(path: &Path) -> std::io::Result<Option<StubHeader>> {
    let mut file = std::fs::File::open(path)?;
    read_stub_header_from(&mut file)
}

pub fn read_stub_header_from(file: &mut std::fs::File) -> std::io::Result<Option<StubHeader>> {
    let mut magic = [0u8; 12];
    let mut read_total = 0;
    while read_total < magic.len() {
        let n = file.read(&mut magic[read_total..])?;
        if n == 0 {
            return Ok(None);
        }
        read_total += n;
    }
    if &magic != SEGMENT_STUB_MAGIC {
        return Ok(None);
    }
    let mut len_buf = [0u8; 4];
    file.read_exact(&mut len_buf)?;
    let json_len = u32::from_le_bytes(len_buf);
    if json_len == 0 || json_len > STUB_JSON_MAX_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "segment stub header length out of range",
        ));
    }
    let mut json = vec![0u8; json_len as usize];
    file.read_exact(&mut json)?;
    let header: StubHeader = serde_json::from_slice(&json).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("segment stub header is not valid JSON: {}", e),
        )
    })?;
    Ok(Some(header))
}

pub fn is_stub_file(path: &Path) -> bool {
    matches!(read_stub_header(path), Ok(Some(_)))
}

#[derive(Debug, Clone)]
pub struct SegmentSet {
    pub dir: PathBuf,
    pub sizes: Vec<u64>,
}

impl SegmentSet {
    pub fn new(dir: PathBuf, sizes: Vec<u64>) -> Self {
        Self { dir, sizes }
    }

    pub fn total(&self) -> u64 {
        self.sizes.iter().sum()
    }

    pub fn seg_file_name(ordinal: usize) -> String {
        format!("seg-{:05}", ordinal + 1)
    }

    pub fn seg_path(&self, ordinal: usize) -> PathBuf {
        self.dir.join(Self::seg_file_name(ordinal))
    }

    pub fn verify_files(&self) -> std::io::Result<()> {
        for (i, expected) in self.sizes.iter().enumerate() {
            let path = self.seg_path(i);
            let meta = std::fs::metadata(&path)?;
            if meta.len() != *expected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "segment {} has size {} but manifest says {}",
                        path.display(),
                        meta.len(),
                        expected
                    ),
                ));
            }
        }
        Ok(())
    }

    fn window(&self, start: u64, len: u64) -> Vec<(usize, u64, u64)> {
        let mut out = Vec::new();
        let mut offset = 0u64;
        let mut remaining = len;
        for (i, size) in self.sizes.iter().copied().enumerate() {
            if remaining == 0 {
                break;
            }
            let seg_end = offset + size;
            if start < seg_end && size > 0 {
                let skip = start.saturating_sub(offset);
                let avail = size - skip;
                let take = avail.min(remaining);
                out.push((i, skip, take));
                remaining -= take;
            }
            offset = seg_end;
        }
        out
    }
}

pub struct SegmentChainRead {
    set: SegmentSet,
    plan: Vec<(usize, u64, u64)>,
    plan_idx: usize,
    current: Option<std::fs::File>,
    seg_remaining: u64,
}

impl SegmentChainRead {
    pub fn new(set: SegmentSet, start: u64, len: u64) -> Self {
        let plan = set.window(start, len);
        Self {
            set,
            plan,
            plan_idx: 0,
            current: None,
            seg_remaining: 0,
        }
    }

    pub fn full(set: SegmentSet) -> Self {
        let total = set.total();
        Self::new(set, 0, total)
    }
}

impl Read for SegmentChainRead {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.current.is_none() {
                let Some(&(ordinal, skip, take)) = self.plan.get(self.plan_idx) else {
                    return Ok(0);
                };
                let mut file = std::fs::File::open(self.set.seg_path(ordinal))?;
                if skip > 0 {
                    file.seek(SeekFrom::Start(skip))?;
                }
                self.current = Some(file);
                self.seg_remaining = take;
            }
            if self.seg_remaining == 0 {
                self.current = None;
                self.plan_idx += 1;
                continue;
            }
            let file = self.current.as_mut().expect("current segment file");
            let want = buf
                .len()
                .min(self.seg_remaining.min(usize::MAX as u64) as usize);
            let n = file.read(&mut buf[..want])?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "segment file ended before manifest size",
                ));
            }
            self.seg_remaining -= n as u64;
            if self.seg_remaining == 0 {
                self.current = None;
                self.plan_idx += 1;
            }
            return Ok(n);
        }
    }
}

pub struct OpenSegmentsRead {
    files: Vec<(std::fs::File, u64)>,
    idx: usize,
    seg_remaining: u64,
}

impl OpenSegmentsRead {
    pub fn new(files: Vec<(std::fs::File, u64)>) -> Self {
        let seg_remaining = files.first().map(|(_, size)| *size).unwrap_or(0);
        Self {
            files,
            idx: 0,
            seg_remaining,
        }
    }

    pub fn with_window(
        files: Vec<(std::fs::File, u64)>,
        start: u64,
        len: u64,
    ) -> std::io::Result<Self> {
        let sizes: Vec<u64> = files.iter().map(|(_, size)| *size).collect();
        let plan = SegmentSet::new(PathBuf::new(), sizes).window(start, len);
        let mut by_ordinal: std::collections::HashMap<usize, std::fs::File> = files
            .into_iter()
            .enumerate()
            .map(|(i, (f, _))| (i, f))
            .collect();
        let mut prepared = Vec::with_capacity(plan.len());
        for (ordinal, skip, take) in plan {
            let mut file = by_ordinal.remove(&ordinal).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "segment ordinal missing")
            })?;
            if skip > 0 {
                file.seek(SeekFrom::Start(skip))?;
            }
            prepared.push((file, take));
        }
        Ok(Self::new(prepared))
    }
}

impl Read for OpenSegmentsRead {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.idx >= self.files.len() {
                return Ok(0);
            }
            if self.seg_remaining == 0 {
                self.idx += 1;
                self.seg_remaining = self.files.get(self.idx).map(|(_, size)| *size).unwrap_or(0);
                continue;
            }
            let want = buf
                .len()
                .min(self.seg_remaining.min(usize::MAX as u64) as usize);
            let n = self.files[self.idx].0.read(&mut buf[..want])?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "segment file ended before manifest size",
                ));
            }
            self.seg_remaining -= n as u64;
            return Ok(n);
        }
    }
}

pub struct SegmentRangeReader {
    files: Vec<(tokio::fs::File, u64)>,
    idx: usize,
    seg_remaining: u64,
}

impl SegmentRangeReader {
    pub async fn open(set: &SegmentSet, start: u64, len: u64) -> std::io::Result<Self> {
        let plan = set.window(start, len);
        let mut files = Vec::with_capacity(plan.len());
        for (ordinal, skip, take) in plan {
            let mut file = tokio::fs::File::open(set.seg_path(ordinal)).await?;
            if skip > 0 {
                file.seek(SeekFrom::Start(skip)).await?;
            }
            files.push((file, take));
        }
        Ok(Self::from_prepared(files))
    }

    pub async fn from_files(
        files: Vec<(tokio::fs::File, u64)>,
        start: u64,
        len: u64,
    ) -> std::io::Result<Self> {
        let sizes: Vec<u64> = files.iter().map(|(_, size)| *size).collect();
        let plan = SegmentSet::new(PathBuf::new(), sizes).window(start, len);
        let mut by_ordinal: std::collections::HashMap<usize, tokio::fs::File> = files
            .into_iter()
            .enumerate()
            .map(|(i, (f, _))| (i, f))
            .collect();
        let mut prepared = Vec::with_capacity(plan.len());
        for (ordinal, skip, take) in plan {
            let mut file = by_ordinal.remove(&ordinal).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "segment ordinal missing")
            })?;
            file.seek(SeekFrom::Start(skip)).await?;
            prepared.push((file, take));
        }
        Ok(Self::from_prepared(prepared))
    }

    fn from_prepared(files: Vec<(tokio::fs::File, u64)>) -> Self {
        let seg_remaining = files.first().map(|(_, take)| *take).unwrap_or(0);
        Self {
            files,
            idx: 0,
            seg_remaining,
        }
    }
}

impl AsyncRead for SegmentRangeReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if self.idx >= self.files.len() {
                return Poll::Ready(Ok(()));
            }
            if self.seg_remaining == 0 {
                self.idx += 1;
                self.seg_remaining = self.files.get(self.idx).map(|(_, take)| *take).unwrap_or(0);
                continue;
            }
            let want = (self.seg_remaining.min(buf.remaining() as u64)) as usize;
            if want == 0 {
                return Poll::Ready(Ok(()));
            }
            let mut limited = buf.take(want);
            let this = self.as_mut().get_mut();
            let idx = this.idx;
            match Pin::new(&mut this.files[idx].0).poll_read(cx, &mut limited) {
                Poll::Ready(Ok(())) => {
                    let n = limited.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "segment file ended before manifest size",
                        )));
                    }
                    unsafe { buf.assume_init(n) };
                    buf.advance(n);
                    this.seg_remaining -= n as u64;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn build_segments(dir: &Path, parts: &[&[u8]]) -> SegmentSet {
        std::fs::create_dir_all(dir).unwrap();
        let mut sizes = Vec::new();
        for (i, data) in parts.iter().enumerate() {
            std::fs::write(dir.join(SegmentSet::seg_file_name(i)), data).unwrap();
            sizes.push(data.len() as u64);
        }
        SegmentSet::new(dir.to_path_buf(), sizes)
    }

    fn reference(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    #[test]
    fn stub_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("stub");
        let header = StubHeader::new(
            "abc123".to_string(),
            vec![6 * 1024 * 1024, 5 * 1024 * 1024, 1024],
            "deadbeef-3".to_string(),
        );
        write_stub(&path, &header).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), header.total);
        let read_back = read_stub_header(&path).unwrap().unwrap();
        assert_eq!(read_back, header);
    }

    #[test]
    fn stub_rejects_total_smaller_than_header() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("stub");
        let header = StubHeader::new("x".to_string(), vec![10], "e-1".to_string());
        assert!(write_stub(&path, &header).is_err());
    }

    #[test]
    fn non_stub_files_return_none() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("plain");
        std::fs::write(&path, b"hello world, definitely not a stub").unwrap();
        assert!(read_stub_header(&path).unwrap().is_none());
        let short = tmp.path().join("short");
        std::fs::write(&short, b"hi").unwrap();
        assert!(read_stub_header(&short).unwrap().is_none());
        let empty = tmp.path().join("empty");
        std::fs::write(&empty, b"").unwrap();
        assert!(read_stub_header(&empty).unwrap().is_none());
    }

    #[test]
    fn large_sparse_stub_creates_quickly() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("big");
        let header = StubHeader::new(
            "big".to_string(),
            vec![512 * 1024 * 1024, 512 * 1024 * 1024],
            "e-2".to_string(),
        );
        let started = std::time::Instant::now();
        write_stub(&path, &header).unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 1024 * 1024 * 1024);
    }

    #[test]
    fn chain_read_matches_reference_across_windows() {
        let tmp = tempfile::tempdir().unwrap();
        let parts: Vec<Vec<u8>> = vec![
            (0..200u32).map(|i| (i % 251) as u8).collect(),
            (0..77u32).map(|i| (i % 13) as u8).collect(),
            vec![],
            (0..350u32).map(|i| (i % 97) as u8).collect(),
        ];
        let part_refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        let set = build_segments(&tmp.path().join("segs"), &part_refs);
        let full = reference(&part_refs);
        let total = full.len() as u64;

        let boundaries = [0u64, 1, 199, 200, 201, 276, 277, 278, total - 1, total];
        for &start in &boundaries {
            for &end in &boundaries {
                if end <= start {
                    continue;
                }
                let len = end - start;
                let mut reader = SegmentChainRead::new(set.clone(), start, len);
                let mut out = Vec::new();
                reader.read_to_end(&mut out).unwrap();
                assert_eq!(
                    out,
                    &full[start as usize..end as usize],
                    "window {}..{}",
                    start,
                    end
                );
            }
        }

        let mut reader = SegmentChainRead::full(set);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, full);
    }

    #[test]
    fn chain_read_detects_truncated_segment() {
        let tmp = tempfile::tempdir().unwrap();
        let part_refs: Vec<&[u8]> = vec![b"0123456789"];
        let mut set = build_segments(&tmp.path().join("segs"), &part_refs);
        set.sizes[0] = 20;
        let mut reader = SegmentChainRead::full(set);
        let mut out = Vec::new();
        let err = reader.read_to_end(&mut out).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn async_range_reader_matches_reference() {
        use tokio::io::AsyncReadExt;
        let tmp = tempfile::tempdir().unwrap();
        let parts: Vec<Vec<u8>> = vec![
            (0..1000u32).map(|i| (i % 251) as u8).collect(),
            (0..500u32).map(|i| (i % 13) as u8).collect(),
            (0..750u32).map(|i| (i % 97) as u8).collect(),
        ];
        let part_refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        let set = build_segments(&tmp.path().join("segs"), &part_refs);
        let full = reference(&part_refs);
        let total = full.len() as u64;

        for (start, len) in [
            (0, total),
            (0, 1),
            (999, 2),
            (1000, 500),
            (1499, 2),
            (total - 1, 1),
            (250, 1500),
        ] {
            let mut reader = SegmentRangeReader::open(&set, start, len).await.unwrap();
            let mut out = Vec::new();
            reader.read_to_end(&mut out).await.unwrap();
            assert_eq!(
                out,
                &full[start as usize..(start + len) as usize],
                "window {}+{}",
                start,
                len
            );
        }

        let files = {
            let mut v = Vec::new();
            for (i, size) in set.sizes.iter().enumerate() {
                v.push((tokio::fs::File::open(set.seg_path(i)).await.unwrap(), *size));
            }
            v
        };
        let mut reader = SegmentRangeReader::from_files(files, 999, 502)
            .await
            .unwrap();
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, &full[999..1501]);
    }
}
