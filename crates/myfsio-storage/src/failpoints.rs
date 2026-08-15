use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailAction {
    Error(std::io::ErrorKind),
    Panic,
    Abort,
}

type Registry = Mutex<HashMap<(PathBuf, String), FailAction>>;

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn set(root: &Path, name: &str, action: FailAction) {
    registry()
        .lock()
        .insert((root.to_path_buf(), name.to_string()), action);
}

pub fn set_global(name: &str, action: FailAction) {
    registry()
        .lock()
        .insert((PathBuf::new(), name.to_string()), action);
}

pub fn clear(root: &Path, name: &str) {
    registry()
        .lock()
        .retain(|(r, n), _| !(r == root && n == name));
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
        map.get(&(root.to_path_buf(), name.to_string()))
            .or_else(|| map.get(&(PathBuf::new(), name.to_string())))
            .copied()
    };
    match action {
        None => Ok(()),
        Some(FailAction::Error(kind)) => Err(std::io::Error::new(
            kind,
            format!("failpoint '{name}' injected an error"),
        )),
        Some(FailAction::Panic) => panic!("failpoint '{name}' simulated a process crash"),
        Some(FailAction::Abort) => {
            eprintln!("failpoint '{name}' aborting the process to simulate a crash");
            std::process::abort();
        }
    }
}

pub fn arm_from_spec(spec: &str) {
    for entry in spec.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((name, action)) = entry.split_once('=') else {
            continue;
        };
        let action = match action.trim() {
            "abort" => FailAction::Abort,
            "panic" => FailAction::Panic,
            _ => FailAction::Error(std::io::ErrorKind::Other),
        };
        set_global(name.trim(), action);
    }
}
