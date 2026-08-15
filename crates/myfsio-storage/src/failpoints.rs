use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailAction {
    Error(std::io::ErrorKind),
    Panic,
}

type Registry = Mutex<HashMap<(PathBuf, &'static str), FailAction>>;

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn set(root: &Path, name: &'static str, action: FailAction) {
    registry().lock().insert((root.to_path_buf(), name), action);
}

pub fn clear(root: &Path, name: &str) {
    registry()
        .lock()
        .retain(|(r, n), _| !(r == root && *n == name));
}

pub fn clear_all() {
    registry().lock().clear();
}

pub fn hit(root: &Path, name: &str) -> std::io::Result<()> {
    let action = {
        let map = registry().lock();
        if map.is_empty() {
            return Ok(());
        }
        map.iter()
            .find(|((r, n), _)| r == root && *n == name)
            .map(|(_, action)| *action)
    };
    match action {
        None => Ok(()),
        Some(FailAction::Error(kind)) => Err(std::io::Error::new(
            kind,
            format!("failpoint '{name}' injected an error"),
        )),
        Some(FailAction::Panic) => panic!("failpoint '{name}' simulated a process crash"),
    }
}
