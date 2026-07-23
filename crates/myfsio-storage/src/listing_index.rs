use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const SNAPSHOT_VERSION: u32 = 3;
static NEXT_INDEX_IDENTITY: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListingCounters {
    pub(crate) live_objects: u64,
    pub(crate) live_logical_bytes: u64,
    pub(crate) version_count: u64,
    pub(crate) version_logical_bytes: u64,
    pub(crate) delete_marker_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum VersionMutationKind {
    Archive,
    Purge,
    DeleteMarkerCreate,
    DeleteMarkerRemove,
    Restore,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VersionMutation {
    pub(crate) version_id: String,
    pub(crate) kind: VersionMutationKind,
    pub(crate) logical_size: u64,
    pub(crate) delete_marker: bool,
}

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
    high_water_generation: u64,
    counters: ListingCounters,
    entries: Vec<ListingRecord>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
enum JournalOp {
    Put {
        key: String,
        rec: ListingRecord,
    },
    Del {
        key: String,
    },
    Version {
        generation: u64,
        version_id: String,
        kind: VersionMutationKind,
        logical_size: u64,
        delete_marker: bool,
    },
}

#[derive(Clone)]
pub(crate) struct SealedListingCompaction {
    pub(crate) listing_dir: PathBuf,
    pub(crate) identity: u64,
    pub(crate) base_high_water_generation: u64,
    pub(crate) cutoff_generation: u64,
}

pub(crate) struct BucketListingIndex {
    map: BTreeMap<String, ListingRecord>,
    counters: ListingCounters,
    journal: Option<File>,
    current_generation: u64,
    snapshot_high_water_generation: u64,
    ops_since_snapshot: usize,
    listing_dir: PathBuf,
    compact_min_ops: usize,
    compact_pending: bool,
    compaction_installing: bool,
    identity: u64,
    valid: bool,
}

impl BucketListingIndex {
    #[cfg(test)]
    pub(crate) fn from_records(
        listing_dir: PathBuf,
        records: Vec<ListingRecord>,
        compact_min_ops: usize,
    ) -> Self {
        Self::from_records_with_counters(
            listing_dir,
            records,
            ListingCounters::default(),
            compact_min_ops,
        )
    }

    pub(crate) fn from_records_with_counters(
        listing_dir: PathBuf,
        records: Vec<ListingRecord>,
        mut counters: ListingCounters,
        compact_min_ops: usize,
    ) -> Self {
        let map = records
            .into_iter()
            .map(|record| (record.key.clone(), record))
            .collect::<BTreeMap<_, _>>();
        counters.live_objects = map.len() as u64;
        counters.live_logical_bytes = map
            .values()
            .fold(0u64, |total, record| total.saturating_add(record.size));
        Self {
            map,
            counters,
            journal: None,
            current_generation: 1,
            snapshot_high_water_generation: 0,
            ops_since_snapshot: 0,
            listing_dir,
            compact_min_ops,
            compact_pending: false,
            compaction_installing: false,
            identity: next_identity(),
            valid: true,
        }
    }

    pub(crate) fn load(listing_dir: PathBuf, compact_min_ops: usize) -> std::io::Result<Self> {
        let snapshot = load_snapshot(&listing_dir.join("snapshot.json"))?;
        let high_water_generation = snapshot.high_water_generation;
        let mut counters = snapshot.counters;
        let mut map = snapshot
            .entries
            .into_iter()
            .map(|record| (record.key.clone(), record))
            .collect::<BTreeMap<_, _>>();
        let generations = journal_generations(&listing_dir)?;
        let newer = generations
            .iter()
            .copied()
            .filter(|generation| *generation > high_water_generation)
            .collect::<Vec<_>>();
        validate_generation_chain(high_water_generation, &newer)?;

        let mut ops_since_snapshot = 0usize;
        let mut partial_tail = false;
        for generation in &newer {
            let replay = replay_journal(
                &journal_path(&listing_dir, *generation),
                *generation,
                &mut map,
                &mut counters,
            )?;
            ops_since_snapshot = ops_since_snapshot.saturating_add(replay.applied);
            partial_tail |= replay.partial_tail;
        }

        let last_generation = newer.last().copied().unwrap_or_else(|| {
            high_water_generation
                .checked_add(1)
                .unwrap_or(high_water_generation)
        });
        let current_generation = if partial_tail {
            last_generation.checked_add(1).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "listing journal generation overflow",
                )
            })?
        } else {
            last_generation
        };
        let journal = open_journal_synced(&journal_path(&listing_dir, current_generation))?;

        Ok(Self {
            map,
            counters,
            journal: Some(journal),
            current_generation,
            snapshot_high_water_generation: high_water_generation,
            ops_since_snapshot,
            listing_dir,
            compact_min_ops,
            compact_pending: partial_tail,
            compaction_installing: false,
            identity: next_identity(),
            valid: true,
        })
    }

    pub(crate) fn persist_rebuilt(&mut self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.listing_dir)?;
        self.snapshot_high_water_generation = 0;
        self.current_generation = 1;
        self.write_snapshot()?;
        let journal_path = journal_path(&self.listing_dir, self.current_generation);
        let journal = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&journal_path)?;
        journal.sync_all()?;
        sync_dir(Some(&self.listing_dir))?;
        self.journal = Some(open_journal(&journal_path)?);
        self.ops_since_snapshot = 0;
        self.compact_pending = false;
        Ok(())
    }

    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    pub(crate) fn counters(&self) -> ListingCounters {
        self.counters
    }

    pub(crate) fn is_valid(&self) -> bool {
        self.valid
    }

    pub(crate) fn invalidate(&mut self) {
        self.valid = false;
    }

    pub(crate) fn apply_put(&mut self, record: ListingRecord) -> std::io::Result<()> {
        let key = record.key.clone();
        let mut counters = self.counters;
        match self.map.get(&key) {
            Some(previous) => {
                counters.live_logical_bytes = counters
                    .live_logical_bytes
                    .checked_sub(previous.size)
                    .and_then(|value| value.checked_add(record.size))
                    .ok_or_else(|| invalid_data("listing live byte counter overflow"))?;
            }
            None => {
                counters.live_objects = counters
                    .live_objects
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("listing live object counter overflow"))?;
                counters.live_logical_bytes = counters
                    .live_logical_bytes
                    .checked_add(record.size)
                    .ok_or_else(|| invalid_data("listing live byte counter overflow"))?;
            }
        }
        self.append(&JournalOp::Put {
            key: key.clone(),
            rec: record.clone(),
        })?;
        self.map.insert(key, record);
        self.counters = counters;
        self.ops_since_snapshot = self.ops_since_snapshot.saturating_add(1);
        Ok(())
    }

    pub(crate) fn apply_del(&mut self, key: &str) -> std::io::Result<()> {
        let mut counters = self.counters;
        if let Some(previous) = self.map.get(key) {
            counters.live_objects = counters
                .live_objects
                .checked_sub(1)
                .ok_or_else(|| invalid_data("listing live object counter underflow"))?;
            counters.live_logical_bytes = counters
                .live_logical_bytes
                .checked_sub(previous.size)
                .ok_or_else(|| invalid_data("listing live byte counter underflow"))?;
        }
        self.append(&JournalOp::Del {
            key: key.to_string(),
        })?;
        self.map.remove(key);
        self.counters = counters;
        self.ops_since_snapshot = self.ops_since_snapshot.saturating_add(1);
        Ok(())
    }

    pub(crate) fn apply_version_mutation(
        &mut self,
        mutation: &VersionMutation,
    ) -> std::io::Result<()> {
        let mut counters = self.counters;
        apply_version_mutation_to_counters(&mut counters, mutation)?;
        self.append(&JournalOp::Version {
            generation: self.current_generation,
            version_id: mutation.version_id.clone(),
            kind: mutation.kind,
            logical_size: mutation.logical_size,
            delete_marker: mutation.delete_marker,
        })?;
        self.counters = counters;
        self.ops_since_snapshot = self.ops_since_snapshot.saturating_add(1);
        Ok(())
    }

    pub(crate) fn mark_compact_pending_if_needed(&mut self) -> bool {
        if self.valid
            && (self.compact_pending
                || self.ops_since_snapshot
                    > std::cmp::max(self.compact_min_ops, self.map.len() / 4))
        {
            self.compact_pending = true;
            true
        } else {
            false
        }
    }

    pub(crate) fn request_compaction_retry(&mut self) {
        if self.valid {
            self.compact_pending = true;
        }
    }

    pub(crate) fn seal_for_compaction(
        &mut self,
    ) -> std::io::Result<Option<SealedListingCompaction>> {
        if !self.valid || !self.compact_pending {
            return Ok(None);
        }
        let journal = self
            .journal
            .as_mut()
            .ok_or_else(|| std::io::Error::other("listing journal is unavailable"))?;
        journal.sync_all()?;
        let cutoff_generation = self.current_generation;
        let next_generation = cutoff_generation.checked_add(1).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "listing journal generation overflow",
            )
        })?;
        let next_path = journal_path(&self.listing_dir, next_generation);
        let next = OpenOptions::new()
            .create_new(true)
            .read(true)
            .append(true)
            .open(&next_path)?;
        next.sync_all()?;
        sync_dir(Some(&self.listing_dir))?;
        self.journal = Some(next);
        self.current_generation = next_generation;
        self.ops_since_snapshot = 0;
        self.compact_pending = false;
        Ok(Some(SealedListingCompaction {
            listing_dir: self.listing_dir.clone(),
            identity: self.identity,
            base_high_water_generation: self.snapshot_high_water_generation,
            cutoff_generation,
        }))
    }

    fn can_install(&self, sealed: &SealedListingCompaction) -> bool {
        self.valid
            && self.identity == sealed.identity
            && self.listing_dir == sealed.listing_dir
            && self.snapshot_high_water_generation == sealed.base_high_water_generation
            && self.current_generation > sealed.cutoff_generation
    }

    pub(crate) fn begin_compaction_install(&mut self, sealed: &SealedListingCompaction) -> bool {
        if self.compaction_installing || !self.can_install(sealed) {
            return false;
        }
        self.compaction_installing = true;
        true
    }

    pub(crate) fn complete_compaction_install(
        &mut self,
        sealed: &SealedListingCompaction,
        installed: bool,
    ) {
        if self.compaction_installing {
            if installed && self.can_install(sealed) {
                self.snapshot_high_water_generation = sealed.cutoff_generation;
            }
            self.compaction_installing = false;
        }
    }

    pub(crate) fn is_compaction_installing(&self) -> bool {
        self.compaction_installing
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
        let journal = self
            .journal
            .as_mut()
            .ok_or_else(|| std::io::Error::other("listing journal is unavailable"))?;
        let mut line = serde_json::to_vec(op).map_err(invalid_data)?;
        line.push(b'\n');
        journal.write_all(&line)
    }

    fn write_snapshot(&self) -> std::io::Result<()> {
        let entries = self.map.values().cloned().collect::<Vec<_>>();
        let snapshot = make_snapshot(self.snapshot_high_water_generation, self.counters, entries)?;
        let bytes = serde_json::to_vec(&snapshot).map_err(invalid_data)?;
        atomic_write(&self.listing_dir.join("snapshot.json"), &bytes)
    }
}

pub(crate) fn prepare_compaction_snapshot(
    sealed: &SealedListingCompaction,
) -> std::io::Result<Vec<u8>> {
    let snapshot = load_snapshot(&sealed.listing_dir.join("snapshot.json"))?;
    if snapshot.high_water_generation < sealed.base_high_water_generation
        || snapshot.high_water_generation > sealed.cutoff_generation
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "listing snapshot generation changed during compaction",
        ));
    }
    let durable_high_water_generation = snapshot.high_water_generation;
    let mut counters = snapshot.counters;
    let mut map = snapshot
        .entries
        .into_iter()
        .map(|record| (record.key.clone(), record))
        .collect::<BTreeMap<_, _>>();
    let generations = journal_generations(&sealed.listing_dir)?
        .into_iter()
        .filter(|generation| {
            *generation > durable_high_water_generation && *generation <= sealed.cutoff_generation
        })
        .collect::<Vec<_>>();
    validate_generation_range(
        durable_high_water_generation,
        sealed.cutoff_generation,
        &generations,
    )?;
    for generation in generations {
        replay_journal(
            &journal_path(&sealed.listing_dir, generation),
            generation,
            &mut map,
            &mut counters,
        )?;
    }
    let snapshot = make_snapshot(
        sealed.cutoff_generation,
        counters,
        map.into_values().collect::<Vec<_>>(),
    )?;
    serde_json::to_vec(&snapshot).map_err(invalid_data)
}

pub(crate) fn write_snapshot_temp(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = File::create(path)?;
    let mut writer = std::io::BufWriter::new(file);
    writer.write_all(bytes)?;
    let file = writer.into_inner()?;
    file.sync_all()
}

pub(crate) fn install_snapshot_temp(temp_path: &Path, listing_dir: &Path) -> std::io::Result<()> {
    replace_path(temp_path, &listing_dir.join("snapshot.json"))?;
    sync_dir(Some(listing_dir))
}

pub(crate) fn confirm_compaction_snapshot(sealed: &SealedListingCompaction) -> std::io::Result<()> {
    let snapshot = load_snapshot(&sealed.listing_dir.join("snapshot.json"))?;
    if snapshot.high_water_generation != sealed.cutoff_generation {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "listing compaction snapshot was not installed",
        ));
    }
    sync_dir(Some(&sealed.listing_dir))
}

pub(crate) fn delete_covered_journals(
    listing_dir: &Path,
    cutoff_generation: u64,
) -> std::io::Result<()> {
    let mut removed = false;
    for generation in journal_generations(listing_dir)? {
        if generation > cutoff_generation {
            continue;
        }
        match std::fs::remove_file(journal_path(listing_dir, generation)) {
            Ok(()) => removed = true,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    if removed {
        sync_dir(Some(listing_dir))?;
    }
    Ok(())
}

pub(crate) fn discard(listing_dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_dir_all(listing_dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn load_snapshot(path: &Path) -> std::io::Result<Snapshot> {
    let snapshot_bytes = std::fs::read(path)?;
    let snapshot: Snapshot = serde_json::from_slice(&snapshot_bytes).map_err(invalid_data)?;
    if snapshot.version != SNAPSHOT_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unsupported listing snapshot version {}", snapshot.version),
        ));
    }
    let checksum = snapshot_checksum(
        snapshot.high_water_generation,
        snapshot.counters,
        &snapshot.entries,
    )?;
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
    let live_objects = snapshot.entries.len() as u64;
    let live_logical_bytes = snapshot.entries.iter().try_fold(0u64, |total, record| {
        total
            .checked_add(record.size)
            .ok_or_else(|| invalid_data("listing snapshot live byte counter overflow"))
    })?;
    if snapshot.counters.live_objects != live_objects
        || snapshot.counters.live_logical_bytes != live_logical_bytes
    {
        return Err(invalid_data(
            "listing snapshot live counters do not match entries",
        ));
    }
    Ok(snapshot)
}

fn make_snapshot(
    high_water_generation: u64,
    counters: ListingCounters,
    entries: Vec<ListingRecord>,
) -> std::io::Result<Snapshot> {
    Ok(Snapshot {
        version: SNAPSHOT_VERSION,
        checksum: snapshot_checksum(high_water_generation, counters, &entries)?,
        high_water_generation,
        counters,
        entries,
    })
}

fn snapshot_checksum(
    high_water_generation: u64,
    counters: ListingCounters,
    entries: &[ListingRecord],
) -> std::io::Result<String> {
    let payload =
        serde_json::to_vec(&(high_water_generation, counters, entries)).map_err(invalid_data)?;
    Ok(hex::encode(Sha256::digest(&payload)))
}

struct JournalReplay {
    applied: usize,
    partial_tail: bool,
}

fn replay_journal(
    path: &Path,
    generation: u64,
    map: &mut BTreeMap<String, ListingRecord>,
    counters: &mut ListingCounters,
) -> std::io::Result<JournalReplay> {
    let bytes = std::fs::read(path)?;
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
            Err(_) if Some(index) == last_nonempty => {
                return Ok(JournalReplay {
                    applied,
                    partial_tail: true,
                });
            }
            Err(err) => return Err(invalid_data(err)),
        };
        match op {
            JournalOp::Put { key, rec } => {
                if key != rec.key {
                    if Some(index) == last_nonempty {
                        return Ok(JournalReplay {
                            applied,
                            partial_tail: true,
                        });
                    }
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "listing journal put key does not match record key",
                    ));
                }
                match map.insert(key, rec.clone()) {
                    Some(previous) => {
                        counters.live_logical_bytes = counters
                            .live_logical_bytes
                            .checked_sub(previous.size)
                            .and_then(|value| value.checked_add(rec.size))
                            .ok_or_else(|| {
                                invalid_data("listing live byte counter overflow during replay")
                            })?;
                    }
                    None => {
                        counters.live_objects =
                            counters.live_objects.checked_add(1).ok_or_else(|| {
                                invalid_data("listing live object counter overflow during replay")
                            })?;
                        counters.live_logical_bytes = counters
                            .live_logical_bytes
                            .checked_add(rec.size)
                            .ok_or_else(|| {
                                invalid_data("listing live byte counter overflow during replay")
                            })?;
                    }
                }
            }
            JournalOp::Del { key } => {
                if let Some(previous) = map.remove(&key) {
                    counters.live_objects =
                        counters.live_objects.checked_sub(1).ok_or_else(|| {
                            invalid_data("listing live object counter underflow during replay")
                        })?;
                    counters.live_logical_bytes = counters
                        .live_logical_bytes
                        .checked_sub(previous.size)
                        .ok_or_else(|| {
                            invalid_data("listing live byte counter underflow during replay")
                        })?;
                }
            }
            JournalOp::Version {
                generation: op_generation,
                version_id,
                kind,
                logical_size,
                delete_marker,
            } => {
                if op_generation != generation {
                    return Err(invalid_data(
                        "listing version counter operation generation mismatch",
                    ));
                }
                apply_version_mutation_to_counters(
                    counters,
                    &VersionMutation {
                        version_id,
                        kind,
                        logical_size,
                        delete_marker,
                    },
                )?;
            }
        }
        applied = applied.saturating_add(1);
    }
    Ok(JournalReplay {
        applied,
        partial_tail: false,
    })
}

fn apply_version_mutation_to_counters(
    counters: &mut ListingCounters,
    mutation: &VersionMutation,
) -> std::io::Result<()> {
    if mutation.version_id.is_empty() {
        return Err(invalid_data(
            "listing version counter mutation has no identity",
        ));
    }
    match mutation.kind {
        VersionMutationKind::Archive if !mutation.delete_marker => {
            counters.version_count = counters
                .version_count
                .checked_add(1)
                .ok_or_else(|| invalid_data("listing version counter overflow"))?;
            counters.version_logical_bytes = counters
                .version_logical_bytes
                .checked_add(mutation.logical_size)
                .ok_or_else(|| invalid_data("listing version byte counter overflow"))?;
        }
        VersionMutationKind::Purge | VersionMutationKind::Restore if !mutation.delete_marker => {
            counters.version_count = counters
                .version_count
                .checked_sub(1)
                .ok_or_else(|| invalid_data("listing version counter underflow"))?;
            counters.version_logical_bytes = counters
                .version_logical_bytes
                .checked_sub(mutation.logical_size)
                .ok_or_else(|| invalid_data("listing version byte counter underflow"))?;
        }
        VersionMutationKind::DeleteMarkerCreate
            if mutation.delete_marker && mutation.logical_size == 0 =>
        {
            counters.delete_marker_count = counters
                .delete_marker_count
                .checked_add(1)
                .ok_or_else(|| invalid_data("listing delete marker counter overflow"))?;
        }
        VersionMutationKind::DeleteMarkerRemove
            if mutation.delete_marker && mutation.logical_size == 0 =>
        {
            counters.delete_marker_count = counters
                .delete_marker_count
                .checked_sub(1)
                .ok_or_else(|| invalid_data("listing delete marker counter underflow"))?;
        }
        _ => {
            return Err(invalid_data(
                "listing version counter mutation kind does not match state",
            ));
        }
    }
    Ok(())
}

fn journal_generations(listing_dir: &Path) -> std::io::Result<Vec<u64>> {
    let entries = match std::fs::read_dir(listing_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let mut generations = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(raw) = name
            .strip_prefix("journal.")
            .and_then(|name| name.strip_suffix(".jsonl"))
        else {
            continue;
        };
        if let Ok(generation) = raw.parse::<u64>() {
            generations.push(generation);
        }
    }
    generations.sort_unstable();
    generations.dedup();
    Ok(generations)
}

fn validate_generation_chain(high_water_generation: u64, newer: &[u64]) -> std::io::Result<()> {
    if newer.is_empty() {
        return Ok(());
    }
    let expected_first = high_water_generation.checked_add(1).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "listing journal generation overflow",
        )
    })?;
    if newer[0] != expected_first
        || newer
            .windows(2)
            .any(|pair| pair[1] != pair[0].saturating_add(1))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "listing journal generation chain has a gap",
        ));
    }
    Ok(())
}

fn validate_generation_range(
    base_generation: u64,
    cutoff_generation: u64,
    generations: &[u64],
) -> std::io::Result<()> {
    if base_generation == cutoff_generation && generations.is_empty() {
        return Ok(());
    }
    validate_generation_chain(base_generation, generations)?;
    if generations.last().copied() != Some(cutoff_generation) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "sealed listing journal generation is missing",
        ));
    }
    Ok(())
}

fn journal_path(listing_dir: &Path, generation: u64) -> PathBuf {
    listing_dir.join(format!("journal.{}.jsonl", generation))
}

fn open_journal_synced(path: &Path) -> std::io::Result<File> {
    let existed = path.exists();
    let journal = open_journal(path)?;
    if !existed {
        journal.sync_all()?;
        sync_dir(path.parent())?;
    }
    Ok(journal)
}

fn open_journal(path: &Path) -> std::io::Result<File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("json.tmp");
    let result = (|| {
        write_snapshot_temp(&tmp_path, bytes)?;
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

fn next_identity() -> u64 {
    NEXT_INDEX_IDENTITY.fetch_add(1, Ordering::Relaxed)
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
