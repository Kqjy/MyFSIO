use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use myfsio_storage::fs_backend::{MetadataLayout, MultipartLayout};

pub const FORMAT_VERSION: u32 = 1;
pub const LISTING_INDEX_VERSION: u32 = 1;

const METADATA_LAYOUT_RANK: [&str; 2] = ["index", "sidecar"];
const MULTIPART_LAYOUT_RANK: [&str; 2] = ["concat", "segments"];

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
struct FormatFeatures {
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    multipart: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    listing_index: Option<u32>,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct FormatMarker {
    format_version: u32,
    #[serde(default)]
    features: FormatFeatures,
    #[serde(skip_serializing_if = "Option::is_none")]
    written_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

pub fn format_marker_path(storage_root: &Path) -> PathBuf {
    storage_root
        .join(".myfsio.sys")
        .join("config")
        .join("format.json")
}

fn layout_rank(rank: &[&str], value: &str) -> Option<usize> {
    rank.iter().position(|candidate| *candidate == value)
}

fn merge_layout(rank: &[&str], recorded: Option<&str>, active: &str) -> Result<String, String> {
    let active_rank = layout_rank(rank, active)
        .ok_or_else(|| format!("this binary produced an unknown layout name '{active}'"))?;
    match recorded {
        None => Ok(active.to_string()),
        Some(value) => {
            let recorded_rank = layout_rank(rank, value).ok_or_else(|| {
                format!(
                    "the data directory records layout '{value}', which this myfsio-server \
                     binary does not understand; it was written by a newer version. Upgrade \
                     the binary, or restore the data directory from a backup taken before \
                     the upgrade (downgrading in place is not supported)"
                )
            })?;
            if recorded_rank >= active_rank {
                Ok(value.to_string())
            } else {
                Ok(active.to_string())
            }
        }
    }
}

pub struct ActiveFormat {
    pub metadata_layout: MetadataLayout,
    pub multipart_layout: MultipartLayout,
    pub listing_index_enabled: bool,
}

pub fn enforce_format_marker(storage_root: &Path, active: &ActiveFormat) -> Result<(), String> {
    let path = format_marker_path(storage_root);
    let existing: Option<FormatMarker> = match std::fs::read_to_string(&path) {
        Ok(text) => Some(serde_json::from_str(&text).map_err(|err| {
            format!(
                "the on-disk format marker {} is unreadable ({err}); refusing to start. \
                 Repair or remove the file only if you are certain every past writer of \
                 this data directory was the same or an older myfsio-server version",
                path.display()
            )
        })?),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(format!(
                "failed to read the on-disk format marker {}: {err}",
                path.display()
            ))
        }
    };

    if let Some(marker) = &existing {
        if marker.format_version > FORMAT_VERSION {
            return Err(format!(
                "the data directory at {} uses on-disk format version {} but this \
                 myfsio-server binary supports up to version {}; it was written by a newer \
                 version. Upgrade the binary, or restore the data directory from a backup \
                 taken before the upgrade (downgrading in place is not supported)",
                storage_root.display(),
                marker.format_version,
                FORMAT_VERSION
            ));
        }
        for key in marker.features.extra.keys() {
            tracing::warn!(
                "the on-disk format marker {} records an unknown feature '{}'; it will be \
                 preserved untouched",
                path.display(),
                key
            );
        }
        if let Some(recorded) = marker.features.listing_index {
            if recorded > LISTING_INDEX_VERSION {
                tracing::warn!(
                    "the data directory records listing index version {} but this binary \
                     supports version {}; listing indexes are derived data and will be \
                     rebuilt from object metadata where they cannot be read",
                    recorded,
                    LISTING_INDEX_VERSION
                );
            }
        }
    }

    let active_metadata = match active.metadata_layout {
        MetadataLayout::Sidecar => "sidecar",
        MetadataLayout::Index => "index",
    };
    let active_multipart = match active.multipart_layout {
        MultipartLayout::Segments => "segments",
        MultipartLayout::Concat => "concat",
    };

    let recorded_features = existing
        .as_ref()
        .map(|marker| marker.features.clone())
        .unwrap_or_default();

    let metadata = merge_layout(
        &METADATA_LAYOUT_RANK,
        recorded_features.metadata.as_deref(),
        active_metadata,
    )?;
    let multipart = merge_layout(
        &MULTIPART_LAYOUT_RANK,
        recorded_features.multipart.as_deref(),
        active_multipart,
    )?;
    let listing_index = match (
        recorded_features.listing_index,
        active.listing_index_enabled,
    ) {
        (Some(recorded), true) => Some(recorded.max(LISTING_INDEX_VERSION)),
        (Some(recorded), false) => Some(recorded),
        (None, true) => Some(LISTING_INDEX_VERSION),
        (None, false) => None,
    };

    let updated = FormatMarker {
        format_version: existing
            .as_ref()
            .map(|marker| marker.format_version.max(FORMAT_VERSION))
            .unwrap_or(FORMAT_VERSION),
        features: FormatFeatures {
            metadata: Some(metadata),
            multipart: Some(multipart),
            listing_index,
            extra: recorded_features.extra,
        },
        written_by: Some(env!("CARGO_PKG_VERSION").to_string()),
        updated_at: Some(chrono::Utc::now().to_rfc3339()),
        extra: existing
            .as_ref()
            .map(|marker| marker.extra.clone())
            .unwrap_or_default(),
    };

    let unchanged = existing.as_ref().is_some_and(|marker| {
        marker.format_version == updated.format_version
            && marker.features == updated.features
            && marker.extra == updated.extra
    });
    if unchanged {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create the config directory for the format marker {}: {err}",
                path.display()
            )
        })?;
    }
    let tmp_path = path.with_extension("json.tmp");
    let payload = serde_json::to_vec_pretty(&updated)
        .map_err(|err| format!("failed to serialize the format marker: {err}"))?;
    std::fs::write(&tmp_path, payload)
        .and_then(|()| std::fs::rename(&tmp_path, &path))
        .map_err(|err| {
            let _ = std::fs::remove_file(&tmp_path);
            format!(
                "failed to write the on-disk format marker {}: {err}",
                path.display()
            )
        })?;
    tracing::info!(
        "On-disk format marker updated: format version {}, metadata layout '{}', multipart \
         layout '{}'",
        updated.format_version,
        updated.features.metadata.as_deref().unwrap_or("?"),
        updated.features.multipart.as_deref().unwrap_or("?")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn active_default() -> ActiveFormat {
        ActiveFormat {
            metadata_layout: MetadataLayout::Sidecar,
            multipart_layout: MultipartLayout::Segments,
            listing_index_enabled: true,
        }
    }

    #[test]
    fn writes_marker_on_first_start() {
        let dir = tempfile::tempdir().unwrap();
        enforce_format_marker(dir.path(), &active_default()).unwrap();
        let text = std::fs::read_to_string(format_marker_path(dir.path())).unwrap();
        let marker: FormatMarker = serde_json::from_str(&text).unwrap();
        assert_eq!(marker.format_version, FORMAT_VERSION);
        assert_eq!(marker.features.metadata.as_deref(), Some("sidecar"));
        assert_eq!(marker.features.multipart.as_deref(), Some("segments"));
        assert_eq!(marker.features.listing_index, Some(LISTING_INDEX_VERSION));
    }

    #[test]
    fn refuses_newer_format_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = format_marker_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, r#"{"format_version": 999}"#).unwrap();
        let err = enforce_format_marker(dir.path(), &active_default()).unwrap_err();
        assert!(err.contains("999"), "unexpected error: {err}");
        assert!(err.contains("restore"), "unexpected error: {err}");
    }

    #[test]
    fn refuses_unknown_authoritative_layout() {
        let dir = tempfile::tempdir().unwrap();
        let path = format_marker_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{"format_version": 1, "features": {"metadata": "sidecar-v2"}}"#,
        )
        .unwrap();
        let err = enforce_format_marker(dir.path(), &active_default()).unwrap_err();
        assert!(err.contains("sidecar-v2"), "unexpected error: {err}");
    }

    #[test]
    fn never_downgrades_a_recorded_layout() {
        let dir = tempfile::tempdir().unwrap();
        enforce_format_marker(dir.path(), &active_default()).unwrap();
        let legacy = ActiveFormat {
            metadata_layout: MetadataLayout::Index,
            multipart_layout: MultipartLayout::Concat,
            listing_index_enabled: false,
        };
        enforce_format_marker(dir.path(), &legacy).unwrap();
        let text = std::fs::read_to_string(format_marker_path(dir.path())).unwrap();
        let marker: FormatMarker = serde_json::from_str(&text).unwrap();
        assert_eq!(marker.features.metadata.as_deref(), Some("sidecar"));
        assert_eq!(marker.features.multipart.as_deref(), Some("segments"));
        assert_eq!(marker.features.listing_index, Some(LISTING_INDEX_VERSION));
    }

    #[test]
    fn preserves_unknown_fields_and_features() {
        let dir = tempfile::tempdir().unwrap();
        let path = format_marker_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{"format_version": 1, "features": {"metadata": "index", "future_feature": 7}, "custom": true}"#,
        )
        .unwrap();
        enforce_format_marker(dir.path(), &active_default()).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let marker: FormatMarker = serde_json::from_str(&text).unwrap();
        assert_eq!(marker.features.metadata.as_deref(), Some("sidecar"));
        assert_eq!(
            marker.features.extra.get("future_feature"),
            Some(&serde_json::Value::from(7))
        );
        assert_eq!(
            marker.extra.get("custom"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn idempotent_when_nothing_changed() {
        let dir = tempfile::tempdir().unwrap();
        enforce_format_marker(dir.path(), &active_default()).unwrap();
        let path = format_marker_path(dir.path());
        let first = std::fs::read_to_string(&path).unwrap();
        enforce_format_marker(dir.path(), &active_default()).unwrap();
        let second = std::fs::read_to_string(&path).unwrap();
        assert_eq!(first, second);
    }
}
