use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

const FORMAT_VERSION: u32 = 1;
const DEFAULT_MAX_ENTRIES: usize = 1_000_000;
const DEFAULT_COMPACTION_ACKS: u64 = 1024;
const MAX_JOURNAL_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum ReplicationOpKind {
    Put,
    Delete,
    DeleteMarker,
}

impl ReplicationOpKind {
    pub(super) fn action(self) -> &'static str {
        match self {
            Self::Put => "write",
            Self::Delete | Self::DeleteMarker => "delete",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(super) struct LedgerKey {
    pub(super) rule_id: String,
    pub(super) key: String,
    pub(super) generation: String,
    pub(super) kind: ReplicationOpKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct LedgerEntry {
    pub(super) identity: LedgerKey,
    pub(super) sequence: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct LedgerSnapshot {
    format_version: u32,
    next_sequence: u64,
    entries: Vec<LedgerEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum JournalRecord {
    Upsert { entry: LedgerEntry },
    Ack { identity: LedgerKey },
}

#[derive(Default)]
struct BucketState {
    loaded: bool,
    initialized: bool,
    next_sequence: u64,
    entries: HashMap<LedgerKey, LedgerEntry>,
    acked_since_compaction: u64,
}

pub(super) enum LoadResult {
    Missing,
    Loaded(Vec<LedgerEntry>),
}

pub(super) struct ReplicationLedger {
    storage_root: PathBuf,
    states: Mutex<HashMap<String, Arc<Mutex<BucketState>>>>,
    max_entries: usize,
    compaction_acks: u64,
}

impl ReplicationLedger {
    pub(super) fn new(storage_root: PathBuf) -> Self {
        Self {
            storage_root,
            states: Mutex::new(HashMap::new()),
            max_entries: DEFAULT_MAX_ENTRIES,
            compaction_acks: DEFAULT_COMPACTION_ACKS,
        }
    }

    #[cfg(test)]
    fn with_limits(storage_root: PathBuf, max_entries: usize, compaction_acks: u64) -> Self {
        Self {
            storage_root,
            states: Mutex::new(HashMap::new()),
            max_entries,
            compaction_acks,
        }
    }

    fn state_for(&self, bucket: &str) -> Arc<Mutex<BucketState>> {
        self.states
            .lock()
            .entry(bucket.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(BucketState::default())))
            .clone()
    }

    fn replication_dir(&self, bucket: &str) -> PathBuf {
        self.storage_root
            .join(".myfsio.sys")
            .join("buckets")
            .join(bucket)
            .join("replication")
    }

    fn snapshot_path(&self, bucket: &str) -> PathBuf {
        self.replication_dir(bucket).join("pending.snapshot.json")
    }

    pub(super) fn journal_path(&self, bucket: &str) -> PathBuf {
        self.replication_dir(bucket).join("pending.journal.jsonl")
    }

    fn ensure_loaded(&self, bucket: &str, state: &mut BucketState) -> Result<(), String> {
        if state.loaded {
            return Ok(());
        }
        let snapshot_path = self.snapshot_path(bucket);
        let journal_path = self.journal_path(bucket);
        state.initialized = snapshot_path.exists() || journal_path.exists();
        if snapshot_path.exists() {
            let bytes = std::fs::read(&snapshot_path).map_err(|error| error.to_string())?;
            let snapshot: LedgerSnapshot =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            if snapshot.format_version != FORMAT_VERSION {
                return Err(format!(
                    "unsupported replication ledger snapshot format {}",
                    snapshot.format_version
                ));
            }
            state.next_sequence = snapshot.next_sequence;
            for entry in snapshot.entries {
                state.next_sequence = state.next_sequence.max(entry.sequence.saturating_add(1));
                state.entries.insert(entry.identity.clone(), entry);
            }
        }
        if journal_path.exists() {
            let journal_len = std::fs::metadata(&journal_path)
                .map_err(|error| error.to_string())?
                .len();
            if journal_len > MAX_JOURNAL_BYTES {
                return Err(format!(
                    "replication ledger journal exceeds {} bytes",
                    MAX_JOURNAL_BYTES
                ));
            }
            let file = File::open(&journal_path).map_err(|error| error.to_string())?;
            for line in BufReader::new(file).lines() {
                let line = line.map_err(|error| error.to_string())?;
                if line.trim().is_empty() {
                    continue;
                }
                let record: JournalRecord =
                    serde_json::from_str(&line).map_err(|error| error.to_string())?;
                match record {
                    JournalRecord::Upsert { entry } => {
                        state.next_sequence =
                            state.next_sequence.max(entry.sequence.saturating_add(1));
                        state.entries.insert(entry.identity.clone(), entry);
                    }
                    JournalRecord::Ack { identity } => {
                        state.entries.remove(&identity);
                    }
                }
                if state.entries.len() > self.max_entries {
                    return Err(format!(
                        "replication ledger exceeds {} entries",
                        self.max_entries
                    ));
                }
            }
        }
        state.loaded = true;
        Ok(())
    }

    pub(super) fn load(
        &self,
        bucket: &str,
        active_rule_id: Option<&str>,
    ) -> Result<LoadResult, String> {
        let state_handle = self.state_for(bucket);
        let mut state = state_handle.lock();
        self.ensure_loaded(bucket, &mut state)?;
        if !state.initialized {
            return Ok(LoadResult::Missing);
        }
        let before = state.entries.len();
        state.entries.retain(|identity, _| {
            active_rule_id.is_some_and(|rule_id| identity.rule_id == rule_id)
        });
        if state.entries.len() != before {
            self.compact_locked(bucket, &mut state)?;
        }
        let mut entries: Vec<_> = state.entries.values().cloned().collect();
        entries.sort_by_key(|entry| entry.sequence);
        Ok(LoadResult::Loaded(entries))
    }

    pub(super) fn append(
        &self,
        bucket: &str,
        mut identity: LedgerKey,
    ) -> Result<LedgerEntry, String> {
        let state_handle = self.state_for(bucket);
        let mut state = state_handle.lock();
        self.ensure_loaded(bucket, &mut state)?;
        if let Some(existing) = state.entries.get(&identity) {
            return Ok(existing.clone());
        }
        if state.entries.len() >= self.max_entries {
            return Err(format!(
                "replication ledger exceeds {} entries",
                self.max_entries
            ));
        }
        identity.generation.shrink_to_fit();
        let entry = LedgerEntry {
            identity,
            sequence: state.next_sequence,
        };
        let record = JournalRecord::Upsert {
            entry: entry.clone(),
        };
        self.append_record(bucket, &record)?;
        state.next_sequence = state.next_sequence.saturating_add(1);
        state.initialized = true;
        state.entries.insert(entry.identity.clone(), entry.clone());
        Ok(entry)
    }

    pub(super) fn ack(&self, bucket: &str, identity: &LedgerKey) -> Result<bool, String> {
        let state_handle = self.state_for(bucket);
        let mut state = state_handle.lock();
        self.ensure_loaded(bucket, &mut state)?;
        if !state.entries.contains_key(identity) {
            return Ok(false);
        }
        self.append_record(
            bucket,
            &JournalRecord::Ack {
                identity: identity.clone(),
            },
        )?;
        state.entries.remove(identity);
        state.acked_since_compaction = state.acked_since_compaction.saturating_add(1);
        if state.acked_since_compaction >= self.compaction_acks {
            self.compact_locked(bucket, &mut state)?;
        }
        Ok(true)
    }

    pub(super) fn replace(
        &self,
        bucket: &str,
        identities: Vec<LedgerKey>,
    ) -> Result<Vec<LedgerEntry>, String> {
        if identities.len() > self.max_entries {
            return Err(format!(
                "replication ledger recovery found {} entries, above cap {}",
                identities.len(),
                self.max_entries
            ));
        }
        let state_handle = self.state_for(bucket);
        let mut state = state_handle.lock();
        let mut entries = HashMap::with_capacity(identities.len());
        let mut next_sequence = 0u64;
        for identity in identities {
            if entries.contains_key(&identity) {
                continue;
            }
            let entry = LedgerEntry {
                identity: identity.clone(),
                sequence: next_sequence,
            };
            entries.insert(identity, entry);
            next_sequence = next_sequence.saturating_add(1);
        }
        let snapshot = LedgerSnapshot {
            format_version: FORMAT_VERSION,
            next_sequence,
            entries: sorted_entries(&entries),
        };
        self.write_snapshot(bucket, &snapshot)?;
        self.truncate_journal(bucket)?;
        state.loaded = true;
        state.initialized = true;
        state.next_sequence = next_sequence;
        state.entries = entries;
        state.acked_since_compaction = 0;
        Ok(sorted_entries(&state.entries))
    }

    pub(super) fn reset(&self, bucket: &str) -> Result<(), String> {
        self.replace(bucket, Vec::new()).map(|_| ())
    }

    pub(super) fn buckets_with_state(&self) -> Vec<String> {
        let buckets_root = self.storage_root.join(".myfsio.sys").join("buckets");
        let Ok(entries) = std::fs::read_dir(buckets_root) else {
            return Vec::new();
        };
        let mut buckets = Vec::new();
        for entry in entries.flatten() {
            let replication = entry.path().join("replication");
            if !replication.is_dir() {
                continue;
            }
            let snapshot = replication.join("pending.snapshot.json");
            let journal = replication.join("pending.journal.jsonl");
            if snapshot.exists() || journal.exists() {
                if let Some(bucket) = entry.file_name().to_str() {
                    buckets.push(bucket.to_string());
                }
            }
        }
        buckets
    }

    fn append_record(&self, bucket: &str, record: &JournalRecord) -> Result<(), String> {
        let path = self.journal_path(bucket);
        let existed = path.exists();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| error.to_string())?;
        let mut bytes = serde_json::to_vec(record).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        file.write_all(&bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        if !existed {
            sync_dir(path.parent()).map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    fn compact_locked(&self, bucket: &str, state: &mut BucketState) -> Result<(), String> {
        let snapshot = LedgerSnapshot {
            format_version: FORMAT_VERSION,
            next_sequence: state.next_sequence,
            entries: sorted_entries(&state.entries),
        };
        self.write_snapshot(bucket, &snapshot)?;
        self.truncate_journal(bucket)?;
        state.initialized = true;
        state.acked_since_compaction = 0;
        Ok(())
    }

    fn write_snapshot(&self, bucket: &str, snapshot: &LedgerSnapshot) -> Result<(), String> {
        let path = self.snapshot_path(bucket);
        let bytes = serde_json::to_vec(snapshot).map_err(|error| error.to_string())?;
        atomic_write(&path, &bytes).map_err(|error| error.to_string())
    }

    fn truncate_journal(&self, bucket: &str) -> Result<(), String> {
        let path = self.journal_path(bucket);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let existed = path.exists();
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        if !existed {
            sync_dir(path.parent()).map_err(|error| error.to_string())?;
        }
        Ok(())
    }
}

fn sorted_entries(entries: &HashMap<LedgerKey, LedgerEntry>) -> Vec<LedgerEntry> {
    let mut result: Vec<_> = entries.values().cloned().collect();
    result.sort_by_key(|entry| entry.sequence);
    result
}

fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("json.tmp");
    let result = (|| {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key(generation: &str, kind: ReplicationOpKind) -> LedgerKey {
        LedgerKey {
            rule_id: "rule".to_string(),
            key: "key".to_string(),
            generation: generation.to_string(),
            kind,
        }
    }

    #[test]
    fn pending_entry_survives_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = ReplicationLedger::new(tmp.path().to_path_buf());
        ledger
            .append("bucket", key("generation-1", ReplicationOpKind::Put))
            .unwrap();
        drop(ledger);

        let ledger = ReplicationLedger::new(tmp.path().to_path_buf());
        let LoadResult::Loaded(entries) = ledger.load("bucket", Some("rule")).unwrap() else {
            panic!("ledger missing");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].identity.generation, "generation-1");
    }

    #[test]
    fn crash_after_remote_success_before_ack_replays_and_acks() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = ReplicationLedger::new(tmp.path().to_path_buf());
        let entry = ledger
            .append("bucket", key("generation-1", ReplicationOpKind::Put))
            .unwrap();
        drop(ledger);

        let ledger = ReplicationLedger::new(tmp.path().to_path_buf());
        let LoadResult::Loaded(entries) = ledger.load("bucket", Some("rule")).unwrap() else {
            panic!("ledger missing");
        };
        assert_eq!(entries, vec![entry.clone()]);
        assert!(ledger.ack("bucket", &entry.identity).unwrap());
        drop(ledger);

        let ledger = ReplicationLedger::new(tmp.path().to_path_buf());
        let LoadResult::Loaded(entries) = ledger.load("bucket", Some("rule")).unwrap() else {
            panic!("ledger missing");
        };
        assert!(entries.is_empty());
    }

    #[test]
    fn versioned_delete_and_delete_marker_survive_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = ReplicationLedger::new(tmp.path().to_path_buf());
        ledger
            .append("bucket", key("version-1", ReplicationOpKind::Delete))
            .unwrap();
        ledger
            .append(
                "bucket",
                key("marker-version-2", ReplicationOpKind::DeleteMarker),
            )
            .unwrap();
        drop(ledger);

        let ledger = ReplicationLedger::new(tmp.path().to_path_buf());
        let LoadResult::Loaded(entries) = ledger.load("bucket", Some("rule")).unwrap() else {
            panic!("ledger missing");
        };
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].identity.kind, ReplicationOpKind::Delete);
        assert_eq!(entries[1].identity.kind, ReplicationOpKind::DeleteMarker);
        assert!(entries
            .iter()
            .all(|entry| entry.identity.kind.action() == "delete"));
    }

    #[test]
    fn removed_rule_is_pruned_at_load() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = ReplicationLedger::new(tmp.path().to_path_buf());
        ledger
            .append("bucket", key("generation-1", ReplicationOpKind::Put))
            .unwrap();
        drop(ledger);

        let ledger = ReplicationLedger::new(tmp.path().to_path_buf());
        let LoadResult::Loaded(entries) = ledger.load("bucket", None).unwrap() else {
            panic!("ledger missing");
        };
        assert!(entries.is_empty());
        drop(ledger);

        let ledger = ReplicationLedger::new(tmp.path().to_path_buf());
        let LoadResult::Loaded(entries) = ledger.load("bucket", Some("rule")).unwrap() else {
            panic!("ledger missing");
        };
        assert!(entries.is_empty());
    }

    #[test]
    fn compaction_snapshot_is_replay_safe_before_journal_truncate() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = ReplicationLedger::with_limits(tmp.path().to_path_buf(), 100, 10);
        let first = ledger
            .append("bucket", key("generation-1", ReplicationOpKind::Put))
            .unwrap();
        ledger.ack("bucket", &first.identity).unwrap();
        let second = ledger
            .append("bucket", key("generation-2", ReplicationOpKind::Put))
            .unwrap();
        {
            let state_handle = ledger.state_for("bucket");
            let state = state_handle.lock();
            let snapshot = LedgerSnapshot {
                format_version: FORMAT_VERSION,
                next_sequence: state.next_sequence,
                entries: sorted_entries(&state.entries),
            };
            ledger.write_snapshot("bucket", &snapshot).unwrap();
        }
        drop(ledger);

        let ledger = ReplicationLedger::new(tmp.path().to_path_buf());
        let LoadResult::Loaded(entries) = ledger.load("bucket", Some("rule")).unwrap() else {
            panic!("ledger missing");
        };
        assert_eq!(entries, vec![second]);
    }

    #[test]
    fn corrupt_journal_is_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = ReplicationLedger::new(tmp.path().to_path_buf());
        ledger
            .append("bucket", key("generation-1", ReplicationOpKind::Put))
            .unwrap();
        std::fs::write(ledger.journal_path("bucket"), b"{not-json}\n").unwrap();
        drop(ledger);

        let ledger = ReplicationLedger::new(tmp.path().to_path_buf());
        assert!(ledger.load("bucket", Some("rule")).is_err());
    }
}
