use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::ops::Bound;
use std::path::{Path, PathBuf};

const SNAPSHOT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListingRecord {
    pub(crate) key: String,
    pub(crate) size: u64,
    #[serde(with = "f64_bits")]
    pub(crate) mtime: f64,
    pub(crate) etag: Option<String>,
    pub(crate) version_id: Option<String>,
    pub(crate) owner: Option<String>,
}

impl ListingRecord {
    pub(crate) fn new(
        key: String,
        size: u64,
        mtime: f64,
        etag: Option<String>,
        version_id: Option<String>,
        owner: Option<String>,
    ) -> Self {
        Self {
            key,
            size,
            mtime,
            etag,
            version_id,
            owner,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    checksum: String,
    entries: Vec<ListingRecord>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
enum JournalOp {
    Put { key: String, rec: ListingRecord },
    Del { key: String },
}

pub(crate) struct BucketListingIndex {
    map: BTreeMap<String, ListingRecord>,
    journal: Option<File>,
    ops_since_snapshot: usize,
    listing_dir: PathBuf,
    compact_min_ops: usize,
    compact_pending: bool,
    valid: bool,
}

impl BucketListingIndex {
    pub(crate) fn from_records(
        listing_dir: PathBuf,
        records: Vec<ListingRecord>,
        compact_min_ops: usize,
    ) -> Self {
        let map = records
            .into_iter()
            .map(|record| (record.key.clone(), record))
            .collect();
        Self {
            map,
            journal: None,
            ops_since_snapshot: 0,
            listing_dir,
            compact_min_ops,
            compact_pending: false,
            valid: true,
        }
    }

    pub(crate) fn load(listing_dir: PathBuf, compact_min_ops: usize) -> std::io::Result<Self> {
        let snapshot_path = listing_dir.join("snapshot.json");
        let snapshot_bytes = std::fs::read(&snapshot_path)?;
        let snapshot: Snapshot = serde_json::from_slice(&snapshot_bytes).map_err(invalid_data)?;
        if snapshot.version != SNAPSHOT_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported listing snapshot version {}", snapshot.version),
            ));
        }
        let payload = serde_json::to_vec(&snapshot.entries).map_err(invalid_data)?;
        let checksum = hex::encode(Sha256::digest(&payload));
        if !checksum.eq_ignore_ascii_case(&snapshot.checksum) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "listing snapshot checksum mismatch",
            ));
        }
        if snapshot
            .entries
            .windows(2)
            .any(|pair| pair[0].key >= pair[1].key)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "listing snapshot entries are not strictly ordered",
            ));
        }

        let mut map = snapshot
            .entries
            .into_iter()
            .map(|record| (record.key.clone(), record))
            .collect::<BTreeMap<_, _>>();
        let journal_path = listing_dir.join("journal.jsonl");
        let (ops_since_snapshot, compact_pending) = replay_journal(&journal_path, &mut map)?;
        let journal = open_journal(&journal_path)?;
        Ok(Self {
            map,
            journal: Some(journal),
            ops_since_snapshot,
            listing_dir,
            compact_min_ops,
            compact_pending,
            valid: true,
        })
    }

    pub(crate) fn persist_rebuilt(&mut self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.listing_dir)?;
        self.write_snapshot()?;
        let journal_path = self.listing_dir.join("journal.jsonl");
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&journal_path)?;
        self.journal = Some(open_journal(&journal_path)?);
        self.ops_since_snapshot = 0;
        self.compact_pending = false;
        Ok(())
    }

    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    pub(crate) fn is_valid(&self) -> bool {
        self.valid
    }

    pub(crate) fn invalidate(&mut self) {
        self.valid = false;
    }

    pub(crate) fn apply_put(&mut self, record: ListingRecord) -> std::io::Result<()> {
        let key = record.key.clone();
        self.append(&JournalOp::Put {
            key: key.clone(),
            rec: record.clone(),
        })?;
        self.map.insert(key, record);
        self.ops_since_snapshot = self.ops_since_snapshot.saturating_add(1);
        Ok(())
    }

    pub(crate) fn apply_del(&mut self, key: &str) -> std::io::Result<()> {
        self.append(&JournalOp::Del {
            key: key.to_string(),
        })?;
        self.map.remove(key);
        self.ops_since_snapshot = self.ops_since_snapshot.saturating_add(1);
        Ok(())
    }

    pub(crate) fn should_compact(&self) -> bool {
        self.compact_pending
            || self.ops_since_snapshot > std::cmp::max(self.compact_min_ops, self.map.len() / 4)
    }

    pub(crate) fn compact(&mut self) -> std::io::Result<()> {
        self.write_snapshot()?;
        if self.journal.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "listing journal is unavailable",
            ));
        }
        drop(self.journal.take());
        let journal_path = self.listing_dir.join("journal.jsonl");
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&journal_path)?;
        self.journal = Some(open_journal(&journal_path).map_err(|err| {
            std::io::Error::new(
                err.kind(),
                format!("failed to reopen listing journal: {}", err),
            )
        })?);
        self.ops_since_snapshot = 0;
        self.compact_pending = false;
        Ok(())
    }

    pub(crate) fn page(
        &self,
        prefix: &str,
        marker: Option<&str>,
        max_keys: usize,
    ) -> (Vec<ListingRecord>, bool, Option<String>) {
        let start = match marker {
            Some(marker) if marker >= prefix => Bound::Excluded(marker.to_string()),
            _ => Bound::Included(prefix.to_string()),
        };
        let mut records = Vec::with_capacity(max_keys.saturating_add(1).min(self.map.len() + 1));
        for (key, record) in self.map.range((start, Bound::Unbounded)) {
            if !prefix.is_empty() && !key.starts_with(prefix) {
                break;
            }
            records.push(record.clone());
            if records.len() > max_keys {
                break;
            }
        }
        let is_truncated = records.len() > max_keys;
        if is_truncated {
            records.pop();
        }
        let next_token = if is_truncated {
            records.last().map(|record| record.key.clone())
        } else {
            None
        };
        (records, is_truncated, next_token)
    }

    fn append(&mut self, op: &JournalOp) -> std::io::Result<()> {
        let journal = self.journal.as_mut().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "listing journal is unavailable")
        })?;
        let mut line = serde_json::to_vec(op).map_err(invalid_data)?;
        line.push(b'\n');
        journal.write_all(&line)
    }

    fn write_snapshot(&self) -> std::io::Result<()> {
        let entries = self.map.values().cloned().collect::<Vec<_>>();
        let payload = serde_json::to_vec(&entries).map_err(invalid_data)?;
        let snapshot = Snapshot {
            version: SNAPSHOT_VERSION,
            checksum: hex::encode(Sha256::digest(&payload)),
            entries,
        };
        let bytes = serde_json::to_vec(&snapshot).map_err(invalid_data)?;
        atomic_write(&self.listing_dir.join("snapshot.json"), &bytes)
    }
}

pub(crate) fn discard(listing_dir: &Path) -> std::io::Result<()> {
    let snapshot_path = listing_dir.join("snapshot.json");
    let snapshot_result = match std::fs::remove_file(snapshot_path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    };
    match std::fs::remove_dir_all(listing_dir) {
        Ok(()) => snapshot_result,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => snapshot_result,
        Err(err) => Err(err),
    }
}

fn replay_journal(
    path: &Path,
    map: &mut BTreeMap<String, ListingRecord>,
) -> std::io::Result<(usize, bool)> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok((0, false)),
        Err(err) => return Err(err),
    };
    let lines = bytes.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    let last_nonempty = lines
        .iter()
        .rposition(|line| !line.strip_suffix(b"\r").unwrap_or(line).is_empty());
    let mut applied = 0usize;
    for (index, raw_line) in lines.iter().enumerate() {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            if last_nonempty.is_some_and(|last| index < last) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "empty line in listing journal",
                ));
            }
            continue;
        }
        let op = match serde_json::from_slice::<JournalOp>(line) {
            Ok(op) => op,
            Err(err) if Some(index) == last_nonempty => return Ok((applied, true)),
            Err(err) => return Err(invalid_data(err)),
        };
        match op {
            JournalOp::Put { key, rec } => {
                if key != rec.key {
                    if Some(index) == last_nonempty {
                        return Ok((applied, true));
                    }
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "listing journal put key does not match record key",
                    ));
                }
                map.insert(key, rec);
            }
            JournalOp::Del { key } => {
                map.remove(&key);
            }
        }
        applied = applied.saturating_add(1);
    }
    Ok((applied, false))
}

fn open_journal(path: &Path) -> std::io::Result<File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .append(true)
        .open(path)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("json.tmp");
    let result = (|| {
        let file = File::create(&tmp_path)?;
        let mut writer = std::io::BufWriter::new(file);
        writer.write_all(bytes)?;
        let file = writer.into_inner()?;
        file.sync_all()?;
        drop(file);
        replace_path(&tmp_path, path)?;
        sync_dir(path.parent())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

fn replace_path(tmp_path: &Path, path: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;

        #[link(name = "Kernel32")]
        extern "system" {
            fn MoveFileExW(
                existing_file_name: *const u16,
                new_file_name: *const u16,
                flags: u32,
            ) -> i32;
        }

        let existing = tmp_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let new = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let result = unsafe { MoveFileExW(existing.as_ptr(), new.as_ptr(), 0x1 | 0x8) };
        if result == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(tmp_path, path)
    }
}

fn sync_dir(dir: Option<&Path>) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        if let Some(dir) = dir {
            File::open(dir)?.sync_all()?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

fn invalid_data(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}

mod f64_bits {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S>(value: &f64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(value.to_bits())
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<f64, D::Error>
    where
        D: Deserializer<'de>,
    {
        u64::deserialize(deserializer).map(f64::from_bits)
    }
}
