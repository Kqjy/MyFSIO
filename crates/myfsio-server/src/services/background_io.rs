use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackgroundIoPriority {
    Normal,
    #[default]
    Low,
    Idle,
}

impl BackgroundIoPriority {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Low => "low",
            Self::Idle => "idle",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "normal" => Some(Self::Normal),
            "low" => Some(Self::Low),
            "idle" => Some(Self::Idle),
            _ => None,
        }
    }
}

static PRIORITY: OnceLock<BackgroundIoPriority> = OnceLock::new();

pub fn configure(priority: BackgroundIoPriority) {
    let _ = PRIORITY.set(priority);
}

pub fn configured() -> BackgroundIoPriority {
    PRIORITY.get().copied().unwrap_or_default()
}

pub async fn run<F, R>(name: &str, work: F) -> Result<R, String>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    let priority = configured();
    std::thread::Builder::new()
        .name(format!("myfsio-bg-{name}"))
        .spawn(move || {
            apply_to_current_thread(priority);
            let _ = tx.send(work());
        })
        .map_err(|error| format!("could not start background {name} worker: {error}"))?;
    rx.await
        .map_err(|_| format!("background {name} worker exited without a result"))
}

fn apply_to_current_thread(priority: BackgroundIoPriority) {
    if priority == BackgroundIoPriority::Normal {
        return;
    }
    if let Err(error) = platform::lower_current_thread(priority) {
        tracing::debug!(
            priority = priority.as_str(),
            "could not lower background worker I/O priority: {}",
            error
        );
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::BackgroundIoPriority;

    const IOPRIO_WHO_PROCESS: libc::c_int = 1;
    const IOPRIO_CLASS_SHIFT: libc::c_int = 13;
    const IOPRIO_CLASS_BE: libc::c_int = 2;
    const IOPRIO_CLASS_IDLE: libc::c_int = 3;

    pub(super) fn ioprio_value(priority: BackgroundIoPriority) -> Option<libc::c_int> {
        match priority {
            BackgroundIoPriority::Normal => None,
            BackgroundIoPriority::Low => Some((IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | 7),
            BackgroundIoPriority::Idle => Some(IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT),
        }
    }

    pub(super) fn lower_current_thread(priority: BackgroundIoPriority) -> std::io::Result<()> {
        let Some(value) = ioprio_value(priority) else {
            return Ok(());
        };
        let rc = unsafe { libc::syscall(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0, value) };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(test)]
    pub(super) fn current_thread_ioprio() -> std::io::Result<libc::c_int> {
        let rc = unsafe { libc::syscall(libc::SYS_ioprio_get, IOPRIO_WHO_PROCESS, 0) };
        if rc < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(rc as libc::c_int)
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::BackgroundIoPriority;

    const THREAD_MODE_BACKGROUND_BEGIN: i32 = 0x0001_0000;

    #[link(name = "Kernel32")]
    extern "system" {
        fn GetCurrentThread() -> *mut std::ffi::c_void;
        fn SetThreadPriority(thread: *mut std::ffi::c_void, priority: i32) -> i32;
    }

    pub(super) fn lower_current_thread(priority: BackgroundIoPriority) -> std::io::Result<()> {
        if priority == BackgroundIoPriority::Normal {
            return Ok(());
        }
        let ok = unsafe { SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN) };
        if ok == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use super::BackgroundIoPriority;

    pub(super) fn lower_current_thread(_priority: BackgroundIoPriority) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_priorities() {
        assert_eq!(
            BackgroundIoPriority::parse(" IDLE "),
            Some(BackgroundIoPriority::Idle)
        );
        assert_eq!(
            BackgroundIoPriority::parse("low"),
            Some(BackgroundIoPriority::Low)
        );
        assert_eq!(
            BackgroundIoPriority::parse("normal"),
            Some(BackgroundIoPriority::Normal)
        );
        assert_eq!(BackgroundIoPriority::parse("realtime"), None);
        assert_eq!(BackgroundIoPriority::default(), BackgroundIoPriority::Low);
    }

    #[tokio::test]
    async fn runs_work_on_a_dedicated_named_thread() {
        let caller = std::thread::current().id();
        let (name, id) = run("probe", || {
            let current = std::thread::current();
            (current.name().map(str::to_string), current.id())
        })
        .await
        .unwrap();
        assert_eq!(name.as_deref(), Some("myfsio-bg-probe"));
        assert_ne!(id, caller);
    }

    #[tokio::test]
    async fn panicking_work_reports_an_error() {
        let result = run("panics", || -> u32 { panic!("boom") }).await;
        assert!(result.unwrap_err().contains("panics"));
    }

    #[tokio::test]
    async fn priority_does_not_leak_to_the_caller_thread() {
        #[cfg(target_os = "linux")]
        let before = platform::current_thread_ioprio().unwrap();
        run("leak-check", || {
            apply_to_current_thread(BackgroundIoPriority::Idle)
        })
        .await
        .unwrap();
        #[cfg(target_os = "linux")]
        assert_eq!(platform::current_thread_ioprio().unwrap(), before);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lowers_linux_thread_io_priority() {
        for priority in [BackgroundIoPriority::Low, BackgroundIoPriority::Idle] {
            let observed = std::thread::spawn(move || {
                platform::lower_current_thread(priority).unwrap();
                platform::current_thread_ioprio().unwrap()
            })
            .join()
            .unwrap();
            assert_eq!(Some(observed), platform::ioprio_value(priority));
        }
    }
}
