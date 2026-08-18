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
        let action = parse_action(action.trim());
        set_global(name.trim(), action);
    }
}

fn parse_action(action: &str) -> FailAction {
    match action {
        "abort" => FailAction::Abort,
        "panic" => FailAction::Panic,
        "error:storage_full" => FailAction::Error(std::io::ErrorKind::StorageFull),
        "error:not_found" => FailAction::Error(std::io::ErrorKind::NotFound),
        "error:permission_denied" => FailAction::Error(std::io::ErrorKind::PermissionDenied),
        "error:already_exists" => FailAction::Error(std::io::ErrorKind::AlreadyExists),
        "error:invalid_input" => FailAction::Error(std::io::ErrorKind::InvalidInput),
        "error:invalid_data" => FailAction::Error(std::io::ErrorKind::InvalidData),
        "error:timed_out" => FailAction::Error(std::io::ErrorKind::TimedOut),
        "error:write_zero" => FailAction::Error(std::io::ErrorKind::WriteZero),
        "error:interrupted" => FailAction::Error(std::io::ErrorKind::Interrupted),
        "error:unexpected_eof" => FailAction::Error(std::io::ErrorKind::UnexpectedEof),
        "error:out_of_memory" => FailAction::Error(std::io::ErrorKind::OutOfMemory),
        "error:other" | "error" => FailAction::Error(std::io::ErrorKind::Other),
        _ => FailAction::Error(std::io::ErrorKind::Other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_storage_full_and_legacy_actions() {
        assert_eq!(
            parse_action("error:storage_full"),
            FailAction::Error(std::io::ErrorKind::StorageFull)
        );
        assert_eq!(
            parse_action("error"),
            FailAction::Error(std::io::ErrorKind::Other)
        );
        assert_eq!(parse_action("panic"), FailAction::Panic);
        assert_eq!(parse_action("abort"), FailAction::Abort);
        assert_eq!(
            parse_action("legacy-bare-error"),
            FailAction::Error(std::io::ErrorKind::Other)
        );
    }

    #[test]
    fn parses_existing_io_error_kinds() {
        for (action, expected) in [
            ("error:not_found", std::io::ErrorKind::NotFound),
            (
                "error:permission_denied",
                std::io::ErrorKind::PermissionDenied,
            ),
            ("error:already_exists", std::io::ErrorKind::AlreadyExists),
            ("error:invalid_input", std::io::ErrorKind::InvalidInput),
            ("error:invalid_data", std::io::ErrorKind::InvalidData),
            ("error:timed_out", std::io::ErrorKind::TimedOut),
            ("error:write_zero", std::io::ErrorKind::WriteZero),
            ("error:interrupted", std::io::ErrorKind::Interrupted),
            ("error:unexpected_eof", std::io::ErrorKind::UnexpectedEof),
            ("error:out_of_memory", std::io::ErrorKind::OutOfMemory),
            ("error:other", std::io::ErrorKind::Other),
        ] {
            assert_eq!(parse_action(action), FailAction::Error(expected));
        }
    }
}
