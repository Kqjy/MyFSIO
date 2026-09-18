use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use parking_lot::RwLock;
use rand::RngCore;
use serde::{Deserialize, Serialize};

pub const SESSION_COOKIE_NAME: &str = "myfsio_session";
pub const CSRF_FIELD_NAME: &str = "csrf_token";
pub const CSRF_HEADER_NAME: &str = "x-csrf-token";

const SESSION_ID_BYTES: usize = 32;
const CSRF_TOKEN_BYTES: usize = 32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlashMessage {
    pub category: String,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct SessionData {
    pub user_id: Option<String>,
    pub display_name: Option<String>,
    pub csrf_token: String,
    pub flash: Vec<FlashMessage>,
    pub extra: HashMap<String, String>,
    last_accessed: Instant,
    revision: u64,
}

impl SessionData {
    pub fn new() -> Self {
        Self {
            user_id: None,
            display_name: None,
            csrf_token: generate_token(CSRF_TOKEN_BYTES),
            flash: Vec::new(),
            extra: HashMap::new(),
            last_accessed: Instant::now(),
            revision: 0,
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.user_id.is_some()
    }

    pub fn push_flash(&mut self, category: impl Into<String>, message: impl Into<String>) {
        self.flash.push(FlashMessage {
            category: category.into(),
            message: message.into(),
        });
    }

    pub fn take_flash(&mut self) -> Vec<FlashMessage> {
        std::mem::take(&mut self.flash)
    }

    pub fn rotate_csrf(&mut self) {
        self.csrf_token = generate_token(CSRF_TOKEN_BYTES);
    }
}

impl Default for SessionData {
    fn default() -> Self {
        Self::new()
    }
}

const DEFAULT_SESSION_STORE_CAPACITY: usize = 10_000;

pub struct SessionStore {
    sessions: RwLock<HashMap<String, SessionData>>,
    ttl: Duration,
    capacity: usize,
}

impl SessionStore {
    pub fn new(ttl: Duration) -> Self {
        Self::with_capacity(ttl, DEFAULT_SESSION_STORE_CAPACITY)
    }

    pub fn with_capacity(ttl: Duration, capacity: usize) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            ttl,
            capacity: capacity.max(1),
        }
    }

    fn enforce_capacity(&self, guard: &mut HashMap<String, SessionData>) {
        if guard.len() < self.capacity {
            return;
        }
        let ttl = self.ttl;
        guard.retain(|_, data| data.last_accessed.elapsed() <= ttl);
        while guard.len() >= self.capacity {
            let victim = guard
                .iter()
                .filter(|(_, v)| !v.is_authenticated())
                .min_by_key(|(_, v)| v.last_accessed)
                .map(|(k, _)| k.clone())
                .or_else(|| {
                    guard
                        .iter()
                        .min_by_key(|(_, v)| v.last_accessed)
                        .map(|(k, _)| k.clone())
                });
            let Some(victim) = victim else {
                break;
            };
            guard.remove(&victim);
        }
    }

    pub fn ephemeral(&self) -> (String, SessionData) {
        (generate_token(SESSION_ID_BYTES), SessionData::new())
    }

    pub fn create(&self) -> (String, SessionData) {
        let id = generate_token(SESSION_ID_BYTES);
        let data = SessionData::new();
        let mut guard = self.sessions.write();
        self.enforce_capacity(&mut guard);
        guard.insert(id.clone(), data.clone());
        (id, data)
    }

    pub fn get(&self, id: &str) -> Option<SessionData> {
        let mut guard = self.sessions.write();
        let entry = guard.get_mut(id)?;
        if entry.last_accessed.elapsed() > self.ttl {
            guard.remove(id);
            return None;
        }
        entry.last_accessed = Instant::now();
        Some(entry.clone())
    }

    pub fn save(&self, id: &str, data: SessionData) -> bool {
        let mut guard = self.sessions.write();
        let current_revision = match guard.get(id) {
            Some(existing) => {
                if existing.revision > data.revision {
                    return false;
                }
                existing.revision
            }
            None => {
                self.enforce_capacity(&mut guard);
                data.revision
            }
        };
        let mut updated = data;
        updated.last_accessed = Instant::now();
        updated.revision = current_revision.saturating_add(1);
        guard.insert(id.to_string(), updated);
        true
    }

    pub fn save_authoritative(&self, id: &str, data: SessionData) {
        let mut guard = self.sessions.write();
        let current_revision = match guard.get(id) {
            Some(existing) => existing.revision.max(data.revision),
            None => {
                self.enforce_capacity(&mut guard);
                data.revision
            }
        };
        let mut updated = data;
        updated.last_accessed = Instant::now();
        updated.revision = current_revision.saturating_add(1);
        guard.insert(id.to_string(), updated);
    }

    pub fn destroy(&self, id: &str) {
        self.sessions.write().remove(id);
    }

    pub fn sweep(&self) {
        let ttl = self.ttl;
        let mut guard = self.sessions.write();
        guard.retain(|_, data| data.last_accessed.elapsed() <= ttl);
    }

    pub fn len(&self) -> usize {
        self.sessions.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.read().is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn spawn_sweeper(self: Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                self.sweep();
            }
        })
    }
}

pub type SharedSessionStore = Arc<SessionStore>;

pub fn generate_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(&buf)
}

pub fn csrf_tokens_match(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    subtle::ConstantTimeEq::ct_eq(a.as_bytes(), b.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(capacity: usize) -> SessionStore {
        SessionStore::with_capacity(Duration::from_secs(3600), capacity)
    }

    #[test]
    fn ephemeral_sessions_are_not_stored_until_saved() {
        let store = store(16);
        let (id, data) = store.ephemeral();
        assert!(store.is_empty());
        assert!(store.get(&id).is_none());

        store.save(&id, data);
        assert_eq!(store.len(), 1);
        assert!(store.get(&id).is_some());
    }

    #[test]
    fn a_stale_snapshot_cannot_overwrite_a_newer_save() {
        let store = store(16);
        let mut signed_in = SessionData::new();
        signed_in.user_id = Some("AKIAADMIN".to_string());
        store.save("sid", signed_in);

        let stale = store.get("sid").expect("loaded");

        let mut logged_out = store.get("sid").expect("loaded");
        logged_out.user_id = None;
        store.save_authoritative("sid", logged_out);

        assert!(!store.save("sid", stale), "a stale write must be refused");
        assert!(
            store.get("sid").expect("present").user_id.is_none(),
            "a concurrent request must not resurrect a logged-out session"
        );
    }

    #[test]
    fn an_authoritative_save_wins_over_a_concurrent_newer_write() {
        let store = store(16);
        let mut signed_in = SessionData::new();
        signed_in.user_id = Some("AKIAADMIN".to_string());
        store.save("sid", signed_in);

        let logout_snapshot = store.get("sid").expect("loaded");

        let mut concurrent = store.get("sid").expect("loaded");
        concurrent.push_flash("info", "still working");
        assert!(store.save("sid", concurrent));

        let mut logged_out = logout_snapshot;
        logged_out.user_id = None;
        store.save_authoritative("sid", logged_out);

        assert!(store.get("sid").expect("present").user_id.is_none());
    }

    #[test]
    fn capacity_eviction_prefers_unauthenticated_sessions() {
        let store = store(4);

        let mut signed_in = SessionData::new();
        signed_in.user_id = Some("AKIAADMIN".to_string());
        store.save("signed-in", signed_in);

        for i in 0..8 {
            store.save(&format!("anon-{}", i), SessionData::new());
        }

        assert!(store.len() <= store.capacity());
        assert!(
            store.get("signed-in").is_some(),
            "an authenticated session must outlive anonymous ones under capacity pressure"
        );
    }

    #[test]
    fn authenticated_sessions_are_evicted_only_as_a_last_resort() {
        let store = store(3);

        for i in 0..6 {
            let mut data = SessionData::new();
            data.user_id = Some(format!("AKIAUSER{}", i));
            store.save(&format!("user-{}", i), data);
        }

        assert!(store.len() <= store.capacity());
        assert!(
            store.get("user-5").is_some(),
            "the newest authenticated session must survive"
        );
    }
}
