use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceRecordOutcome {
    Recorded,
    Replay,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedNonces {
    version: u32,
    nonces: BTreeMap<String, i64>,
}

struct PeerNonceState {
    nonces: BTreeMap<String, i64>,
    load_error: Option<String>,
}

pub struct PeerNonceStore {
    path: PathBuf,
    tolerance_seconds: i64,
    state: Mutex<PeerNonceState>,
    #[cfg(feature = "failpoints")]
    storage_root: PathBuf,
}

impl PeerNonceStore {
    pub fn new(storage_root: &Path, tolerance_secs: u64) -> Self {
        let path = storage_root
            .join(".myfsio.sys")
            .join("config")
            .join("peer_request_nonces.json");
        let tolerance_seconds = i64::try_from(tolerance_secs).unwrap_or(i64::MAX);
        let (mut nonces, load_error, existed) = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<PersistedNonces>(&bytes) {
                Ok(persisted) if persisted.version == FORMAT_VERSION => {
                    (persisted.nonces, None, true)
                }
                Ok(persisted) => (
                    BTreeMap::new(),
                    Some(format!(
                        "unsupported peer nonce format version {}",
                        persisted.version
                    )),
                    true,
                ),
                Err(error) => (
                    BTreeMap::new(),
                    Some(format!("invalid peer nonce store: {error}")),
                    true,
                ),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                (BTreeMap::new(), None, false)
            }
            Err(error) => (
                BTreeMap::new(),
                Some(format!("failed to read peer nonce store: {error}")),
                true,
            ),
        };
        let original_len = nonces.len();
        prune_nonces(
            &mut nonces,
            chrono::Utc::now().timestamp(),
            tolerance_seconds,
        );
        let store = Self {
            path,
            tolerance_seconds,
            state: Mutex::new(PeerNonceState { nonces, load_error }),
            #[cfg(feature = "failpoints")]
            storage_root: storage_root.to_path_buf(),
        };
        if existed && original_len != store.state.lock().nonces.len() {
            let mut state = store.state.lock();
            if state.load_error.is_none() {
                if let Err(error) = store.persist(&state.nonces) {
                    state.load_error = Some(error);
                }
            }
        }
        store
    }

    pub fn record(&self, nonce: &str) -> Result<NonceRecordOutcome, String> {
        self.record_at(nonce, chrono::Utc::now().timestamp())
    }

    fn record_at(&self, nonce: &str, now: i64) -> Result<NonceRecordOutcome, String> {
        let mut state = self.state.lock();
        if let Some(error) = &state.load_error {
            return Err(error.clone());
        }
        let mut next = state.nonces.clone();
        prune_nonces(&mut next, now, self.tolerance_seconds);
        let outcome = if next.contains_key(nonce) {
            NonceRecordOutcome::Replay
        } else {
            next.insert(nonce.to_string(), now);
            NonceRecordOutcome::Recorded
        };
        if next != state.nonces {
            self.persist(&next)?;
            state.nonces = next;
        }
        Ok(outcome)
    }

    fn persist(&self, nonces: &BTreeMap<String, i64>) -> Result<(), String> {
        #[cfg(feature = "failpoints")]
        myfsio_storage::failpoints::hit(&self.storage_root, "peer-nonce:snapshot-write")
            .map_err(|error| error.to_string())?;
        let persisted = PersistedNonces {
            version: FORMAT_VERSION,
            nonces: nonces.clone(),
        };
        let mut bytes = serde_json::to_vec_pretty(&persisted).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        myfsio_common::fs_util::atomic_write_file(&self.path, &bytes)
            .map_err(|error| error.to_string())
    }
}

fn prune_nonces(nonces: &mut BTreeMap<String, i64>, now: i64, tolerance_seconds: i64) {
    let cutoff = now.saturating_sub(tolerance_seconds);
    nonces.retain(|_, seen_at| *seen_at >= cutoff && *seen_at <= now);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonces_survive_restart_and_expired_entries_are_pruned() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PeerNonceStore::new(tmp.path(), 60);
        let now = chrono::Utc::now().timestamp();
        assert_eq!(
            store.record_at("old", now - 61).unwrap(),
            NonceRecordOutcome::Recorded
        );
        assert_eq!(
            store.record_at("live", now).unwrap(),
            NonceRecordOutcome::Recorded
        );
        drop(store);

        let store = PeerNonceStore::new(tmp.path(), 60);
        assert_eq!(
            store.record_at("live", now).unwrap(),
            NonceRecordOutcome::Replay
        );
        assert_eq!(
            store.record_at("old", now + 1).unwrap(),
            NonceRecordOutcome::Recorded
        );
        let persisted: PersistedNonces = serde_json::from_slice(
            &std::fs::read(
                tmp.path()
                    .join(".myfsio.sys/config/peer_request_nonces.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(persisted.nonces.len(), 2);
        assert_eq!(persisted.nonces.get("old"), Some(&(now + 1)));
    }

    #[cfg(feature = "failpoints")]
    #[test]
    fn failed_persistence_does_not_record_nonce() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PeerNonceStore::new(tmp.path(), 60);
        myfsio_storage::failpoints::set(
            tmp.path(),
            "peer-nonce:snapshot-write",
            myfsio_storage::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
        );
        assert!(store.record_at("nonce", 1_000).is_err());
        myfsio_storage::failpoints::clear(tmp.path(), "peer-nonce:snapshot-write");
        assert_eq!(
            store.record_at("nonce", 1_000).unwrap(),
            NonceRecordOutcome::Recorded
        );
    }
}
