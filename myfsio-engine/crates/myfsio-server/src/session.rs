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
    created_at: Instant,
    last_accessed: Instant,
}

impl SessionData {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            user_id: None,
            display_name: None,
            csrf_token: generate_token(CSRF_TOKEN_BYTES),
            flash: Vec::new(),
            extra: HashMap::new(),
            created_at: now,
            last_accessed: now,
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

pub struct SessionStore {
    sessions: RwLock<HashMap<String, SessionData>>,
    ttl: Duration,
}

impl SessionStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    pub fn create(&self) -> (String, SessionData) {
        let id = generate_token(SESSION_ID_BYTES);
        let data = SessionData::new();
        self.sessions.write().insert(id.clone(), data.clone());
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

    pub fn save(&self, id: &str, data: SessionData) {
        let mut guard = self.sessions.write();
        let mut updated = data;
        updated.last_accessed = Instant::now();
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
