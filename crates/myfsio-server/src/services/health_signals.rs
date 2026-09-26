use serde::Serialize;

pub const SERVER_ERROR_WINDOW_SECONDS: u64 = 900;
const SERVER_ERROR_MIN_REQUESTS: u64 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Ok,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthIssue {
    pub key: &'static str,
    pub severity: Severity,
    pub label: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthAssessment {
    pub status: Severity,
    pub issues: Vec<HealthIssue>,
    pub checks: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ServerErrorSignal {
    pub requests: u64,
    pub server_errors: u64,
    pub window_seconds: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DiskQueueSignal {
    pub timeouts: u64,
    pub wait_ms_avg: u64,
    pub window_seconds: u64,
    pub queue_timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ReplicationSignal {
    pub queue_depth: u64,
    pub queue_capacity: u64,
    pub failed_objects: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct HealthInputs {
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub disk_percent: f64,
    pub server_errors: Option<ServerErrorSignal>,
    pub disk_queue: Option<DiskQueueSignal>,
    pub replication: Option<ReplicationSignal>,
}

fn minutes(seconds: u64) -> String {
    let minutes = seconds.div_ceil(60).max(1);
    if minutes == 1 {
        "1 min".to_string()
    } else {
        format!("{minutes} min")
    }
}

fn threshold(value: f64, warning: f64, critical: f64) -> Severity {
    if value > critical {
        Severity::Critical
    } else if value > warning {
        Severity::Warning
    } else {
        Severity::Ok
    }
}

pub fn assess(inputs: &HealthInputs) -> HealthAssessment {
    let mut issues = Vec::new();
    let mut checks = vec!["cpu", "memory", "disk"];
    let mut push = |key, label, severity, detail: String| {
        if severity != Severity::Ok {
            issues.push(HealthIssue {
                key,
                severity,
                label,
                detail,
            });
        }
    };

    push(
        "cpu",
        "CPU",
        threshold(inputs.cpu_percent, 80.0, 95.0),
        format!("{:.1}% busy", inputs.cpu_percent),
    );
    push(
        "memory",
        "Memory",
        threshold(inputs.memory_percent, 85.0, 95.0),
        format!("{:.1}% used", inputs.memory_percent),
    );
    push(
        "disk",
        "Disk space",
        threshold(inputs.disk_percent, 90.0, 95.0),
        format!("{:.1}% full", inputs.disk_percent),
    );

    if let Some(signal) = inputs.server_errors {
        checks.push("server_errors");
        let rate = if signal.requests > 0 {
            signal.server_errors as f64 / signal.requests as f64
        } else {
            0.0
        };
        let severity = if signal.server_errors == 0 {
            Severity::Ok
        } else if signal.server_errors >= 5 && rate >= 0.05 {
            Severity::Critical
        } else if rate >= 0.01 || signal.server_errors >= 10 {
            if signal.requests >= SERVER_ERROR_MIN_REQUESTS || signal.server_errors >= 3 {
                Severity::Warning
            } else {
                Severity::Ok
            }
        } else {
            Severity::Ok
        };
        push(
            "server_errors",
            "S3 5xx errors",
            severity,
            format!(
                "{} of {} requests in the last {} ({:.1}%)",
                signal.server_errors,
                signal.requests,
                minutes(signal.window_seconds),
                rate * 100.0
            ),
        );
    }

    if let Some(signal) = inputs.disk_queue {
        checks.push("disk_queue");
        let severity = if signal.timeouts >= 10 {
            Severity::Critical
        } else if signal.timeouts > 0
            || (signal.queue_timeout_ms > 0 && signal.wait_ms_avg * 2 >= signal.queue_timeout_ms)
        {
            Severity::Warning
        } else {
            Severity::Ok
        };
        let detail = if signal.timeouts > 0 {
            format!(
                "{} requests got 503 SlowDown waiting for a disk permit in the last {}",
                signal.timeouts,
                minutes(signal.window_seconds)
            )
        } else {
            format!(
                "Average disk permit wait {} ms in the last {}",
                signal.wait_ms_avg,
                minutes(signal.window_seconds)
            )
        };
        push("disk_queue", "Disk queue", severity, detail);
    }

    if let Some(signal) = inputs.replication {
        checks.push("replication");
        if signal.queue_capacity > 0 {
            let fill = signal.queue_depth as f64 / signal.queue_capacity as f64;
            let severity = if fill >= 0.9 {
                Severity::Critical
            } else if fill >= 0.5 {
                Severity::Warning
            } else {
                Severity::Ok
            };
            push(
                "replication_queue",
                "Replication backlog",
                severity,
                format!(
                    "{} of {} queue slots in use",
                    signal.queue_depth, signal.queue_capacity
                ),
            );
        }
        push(
            "replication_failures",
            "Replication failures",
            if signal.failed_objects > 0 {
                Severity::Warning
            } else {
                Severity::Ok
            },
            format!(
                "{} object{} waiting for a replication retry",
                signal.failed_objects,
                if signal.failed_objects == 1 { "" } else { "s" }
            ),
        );
    }

    issues.sort_by(|a, b| b.severity.cmp(&a.severity));
    let status = issues
        .iter()
        .map(|issue| issue.severity)
        .max()
        .unwrap_or(Severity::Ok);
    HealthAssessment {
        status,
        issues,
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn calm() -> HealthInputs {
        HealthInputs {
            cpu_percent: 10.0,
            memory_percent: 40.0,
            disk_percent: 50.0,
            server_errors: Some(ServerErrorSignal {
                requests: 1000,
                server_errors: 0,
                window_seconds: 900,
            }),
            disk_queue: Some(DiskQueueSignal {
                timeouts: 0,
                wait_ms_avg: 3,
                window_seconds: 300,
                queue_timeout_ms: 15_000,
            }),
            replication: Some(ReplicationSignal {
                queue_depth: 0,
                queue_capacity: 10_000,
                failed_objects: 0,
            }),
        }
    }

    #[test]
    fn calm_system_is_ok_and_lists_every_check() {
        let result = assess(&calm());
        assert_eq!(result.status, Severity::Ok);
        assert!(result.issues.is_empty());
        assert_eq!(
            result.checks,
            vec![
                "cpu",
                "memory",
                "disk",
                "server_errors",
                "disk_queue",
                "replication"
            ]
        );
    }

    #[test]
    fn resource_thresholds_escalate() {
        let mut inputs = calm();
        inputs.cpu_percent = 85.0;
        inputs.disk_percent = 97.0;
        let result = assess(&inputs);
        assert_eq!(result.status, Severity::Critical);
        assert_eq!(result.issues[0].key, "disk");
        assert_eq!(result.issues[1].key, "cpu");
        assert_eq!(result.issues[1].severity, Severity::Warning);
    }

    #[test]
    fn server_error_rate_needs_volume_before_warning() {
        let mut inputs = calm();
        inputs.server_errors = Some(ServerErrorSignal {
            requests: 4,
            server_errors: 1,
            window_seconds: 900,
        });
        assert_eq!(assess(&inputs).status, Severity::Ok);

        inputs.server_errors = Some(ServerErrorSignal {
            requests: 200,
            server_errors: 3,
            window_seconds: 900,
        });
        let result = assess(&inputs);
        assert_eq!(result.status, Severity::Warning);
        assert_eq!(result.issues[0].key, "server_errors");
        assert!(result.issues[0].detail.contains("3 of 200"));

        inputs.server_errors = Some(ServerErrorSignal {
            requests: 100,
            server_errors: 10,
            window_seconds: 900,
        });
        assert_eq!(assess(&inputs).status, Severity::Critical);
    }

    #[test]
    fn disk_queue_timeouts_and_slow_waits_warn() {
        let mut inputs = calm();
        inputs.disk_queue = Some(DiskQueueSignal {
            timeouts: 2,
            wait_ms_avg: 100,
            window_seconds: 300,
            queue_timeout_ms: 15_000,
        });
        let result = assess(&inputs);
        assert_eq!(result.status, Severity::Warning);
        assert!(result.issues[0].detail.contains("503 SlowDown"));

        inputs.disk_queue = Some(DiskQueueSignal {
            timeouts: 0,
            wait_ms_avg: 8_000,
            window_seconds: 300,
            queue_timeout_ms: 15_000,
        });
        assert_eq!(assess(&inputs).status, Severity::Warning);

        inputs.disk_queue = Some(DiskQueueSignal {
            timeouts: 12,
            ..inputs.disk_queue.unwrap()
        });
        assert_eq!(assess(&inputs).status, Severity::Critical);
    }

    #[test]
    fn replication_backlog_and_failures() {
        let mut inputs = calm();
        inputs.replication = Some(ReplicationSignal {
            queue_depth: 6_000,
            queue_capacity: 10_000,
            failed_objects: 1,
        });
        let result = assess(&inputs);
        assert_eq!(result.status, Severity::Warning);
        assert_eq!(result.issues.len(), 2);
        assert!(result
            .issues
            .iter()
            .any(|issue| issue.detail == "1 object waiting for a replication retry"));

        inputs.replication = Some(ReplicationSignal {
            queue_depth: 9_500,
            queue_capacity: 10_000,
            failed_objects: 0,
        });
        assert_eq!(assess(&inputs).status, Severity::Critical);
    }

    #[test]
    fn missing_signals_are_skipped() {
        let inputs = HealthInputs {
            cpu_percent: 10.0,
            memory_percent: 10.0,
            disk_percent: 10.0,
            ..Default::default()
        };
        let result = assess(&inputs);
        assert_eq!(result.checks, vec!["cpu", "memory", "disk"]);
        assert_eq!(result.status, Severity::Ok);
    }
}
