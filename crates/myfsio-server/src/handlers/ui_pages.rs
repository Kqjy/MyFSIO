use std::collections::HashMap;

use axum::body::Body;
use axum::extract::{Extension, Form, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tera::Context;

use crate::handlers::ui::{base_context, inject_flash, render};
use crate::middleware::session::SessionHandle;
use crate::state::AppState;
use crate::templates::TemplateEngine;
use myfsio_storage::traits::StorageEngine;

pub fn register_ui_endpoints(engine: &TemplateEngine) {
    engine.register_endpoints(&[
        ("ui.login", "/login"),
        ("ui.logout", "/logout"),
        ("ui.buckets_overview", "/ui/buckets"),
        ("ui.bucket_detail", "/ui/buckets/{bucket_name}"),
        ("ui.create_bucket", "/ui/buckets/create"),
        ("ui.delete_bucket", "/ui/buckets/{bucket_name}/delete"),
        (
            "ui.update_bucket_versioning",
            "/ui/buckets/{bucket_name}/versioning",
        ),
        ("ui.update_bucket_quota", "/ui/buckets/{bucket_name}/quota"),
        (
            "ui.update_bucket_encryption",
            "/ui/buckets/{bucket_name}/encryption",
        ),
        (
            "ui.update_bucket_policy",
            "/ui/buckets/{bucket_name}/policy",
        ),
        (
            "ui.update_bucket_replication",
            "/ui/buckets/{bucket_name}/replication",
        ),
        (
            "ui.update_bucket_website",
            "/ui/buckets/{bucket_name}/website",
        ),
        ("ui.upload_object", "/ui/buckets/{bucket_name}/upload"),
        (
            "ui.bulk_delete_objects",
            "/ui/buckets/{bucket_name}/bulk-delete",
        ),
        (
            "ui.bulk_download_objects",
            "/ui/buckets/{bucket_name}/bulk-download",
        ),
        ("ui.archived_objects", "/ui/buckets/{bucket_name}/archived"),
        (
            "ui.initiate_multipart_upload",
            "/ui/buckets/{bucket_name}/multipart/initiate",
        ),
        (
            "ui.upload_multipart_part",
            "/ui/buckets/{bucket_name}/multipart/{upload_id}/part",
        ),
        (
            "ui.complete_multipart_upload",
            "/ui/buckets/{bucket_name}/multipart/{upload_id}/complete",
        ),
        (
            "ui.abort_multipart_upload",
            "/ui/buckets/{bucket_name}/multipart/{upload_id}/abort",
        ),
        (
            "ui.get_lifecycle_history",
            "/ui/buckets/{bucket_name}/lifecycle/history",
        ),
        (
            "ui.get_replication_status",
            "/ui/buckets/{bucket_name}/replication/status",
        ),
        (
            "ui.get_replication_failures",
            "/ui/buckets/{bucket_name}/replication/failures",
        ),
        (
            "ui.clear_replication_failures",
            "/ui/buckets/{bucket_name}/replication/failures/clear",
        ),
        (
            "ui.retry_all_replication_failures",
            "/ui/buckets/{bucket_name}/replication/failures/retry-all",
        ),
        (
            "ui.retry_replication_failure",
            "/ui/buckets/{bucket_name}/replication/failures/retry",
        ),
        (
            "ui.dismiss_replication_failure",
            "/ui/buckets/{bucket_name}/replication/failures/dismiss",
        ),
        ("ui.replication_wizard", "/ui/replication/new"),
        (
            "ui.create_peer_replication_rules",
            "/ui/sites/peers/{site_id}/replication-rules",
        ),
        ("ui.iam_dashboard", "/ui/iam"),
        ("ui.create_iam_user", "/ui/iam/users"),
        ("ui.update_iam_user", "/ui/iam/users/{user_id}"),
        ("ui.delete_iam_user", "/ui/iam/users/{user_id}/delete"),
        ("ui.update_iam_policies", "/ui/iam/users/{user_id}/policies"),
        ("ui.update_iam_expiry", "/ui/iam/users/{user_id}/expiry"),
        (
            "ui.rotate_iam_secret",
            "/ui/iam/users/{user_id}/rotate-secret",
        ),
        ("ui.connections_dashboard", "/ui/connections"),
        ("ui.create_connection", "/ui/connections/create"),
        ("ui.update_connection", "/ui/connections/{connection_id}"),
        (
            "ui.delete_connection",
            "/ui/connections/{connection_id}/delete",
        ),
        ("ui.test_connection", "/ui/connections/test"),
        ("ui.sites_dashboard", "/ui/sites"),
        ("ui.update_local_site", "/ui/sites/local"),
        ("ui.add_peer_site", "/ui/sites/peers"),
        ("ui.cluster_dashboard", "/ui/cluster"),
        ("ui.metrics_dashboard", "/ui/metrics"),
        ("ui.system_dashboard", "/ui/system"),
        ("ui.system_gc_status", "/ui/system/gc/status"),
        ("ui.system_gc_run", "/ui/system/gc/run"),
        ("ui.system_gc_history", "/ui/system/gc/history"),
        ("ui.system_integrity_status", "/ui/system/integrity/status"),
        ("ui.system_integrity_run", "/ui/system/integrity/run"),
        (
            "ui.system_integrity_history",
            "/ui/system/integrity/history",
        ),
        ("ui.website_domains_dashboard", "/ui/website-domains"),
        ("ui.create_website_domain", "/ui/website-domains/create"),
        ("ui.update_website_domain", "/ui/website-domains/{domain}"),
        (
            "ui.delete_website_domain",
            "/ui/website-domains/{domain}/delete",
        ),
        ("ui.docs_page", "/ui/docs"),
    ]);
}

fn page_context(state: &AppState, session: &SessionHandle, endpoint: &str) -> Context {
    let mut ctx = base_context(session, Some(endpoint));
    let principal = session.read(|s| {
        s.user_id.as_ref().map(|uid| {
            json!({
                "access_key": uid,
                "user_id": uid,
                "display_name": s
                    .display_name
                    .clone()
                    .unwrap_or_else(|| uid.clone()),
                "is_admin": true,
            })
        })
    });
    match principal {
        Some(p) => ctx.insert("principal", &p),
        None => ctx.insert("principal", &Value::Null),
    }
    ctx.insert("can_manage_iam", &true);
    ctx.insert("can_manage_replication", &true);
    ctx.insert("can_manage_sites", &true);
    ctx.insert("can_manage_encryption", &state.config.encryption_enabled);
    ctx.insert("website_hosting_nav", &state.config.website_hosting_enabled);
    ctx.insert("encryption_enabled", &state.config.encryption_enabled);
    ctx.insert("kms_enabled", &state.config.kms_enabled);

    let flashed = session.write(|s| s.take_flash());
    inject_flash(&mut ctx, flashed);
    ctx
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut size = bytes as f64;
    let mut idx = 0usize;
    while size >= 1024.0 && idx < UNITS.len() - 1 {
        size /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{} {}", bytes, UNITS[idx])
    } else {
        format!("{:.1} {}", size, UNITS[idx])
    }
}

fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get("x-requested-with")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("xmlhttprequest"))
        .unwrap_or(false)
        || headers
            .get(header::ACCEPT)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.contains("application/json"))
            .unwrap_or(false)
}

async fn parse_form_any(
    headers: &HeaderMap,
    body: Body,
) -> Result<HashMap<String, String>, String> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let is_multipart = content_type
        .to_ascii_lowercase()
        .starts_with("multipart/form-data");

    let bytes = body
        .collect()
        .await
        .map_err(|e| format!("Failed to read request body: {}", e))?
        .to_bytes();

    if is_multipart {
        let boundary = multer::parse_boundary(&content_type)
            .map_err(|_| "Missing multipart boundary".to_string())?;
        let stream = futures::stream::once(async move { Ok::<_, std::io::Error>(bytes) });
        let mut multipart = multer::Multipart::new(stream, boundary);
        let mut out = HashMap::new();
        while let Some(field) = multipart
            .next_field()
            .await
            .map_err(|e| format!("Malformed multipart body: {}", e))?
        {
            let name = match field.name() {
                Some(name) => name.to_string(),
                None => continue,
            };
            if field.file_name().is_some() {
                continue;
            }
            let value = field
                .text()
                .await
                .map_err(|e| format!("Invalid multipart field '{}': {}", name, e))?;
            out.insert(name, value);
        }
        Ok(out)
    } else {
        let parsed: Vec<(String, String)> = serde_urlencoded::from_bytes(&bytes)
            .map_err(|e| format!("Invalid form body: {}", e))?;
        Ok(parsed.into_iter().collect())
    }
}

fn bucket_tab_redirect(bucket_name: &str, tab: &str) -> Response {
    Redirect::to(&format!("/ui/buckets/{}?tab={}", bucket_name, tab)).into_response()
}

fn default_public_policy(bucket_name: &str) -> String {
    serde_json::to_string_pretty(&json!({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowList",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:ListBucket"],
                "Resource": [format!("arn:aws:s3:::{}", bucket_name)],
            },
            {
                "Sid": "AllowRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject"],
                "Resource": [format!("arn:aws:s3:::{}/*", bucket_name)],
            }
        ]
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

fn parse_api_base(state: &AppState) -> (String, String) {
    let api_base = state.config.api_base_url.trim_end_matches('/').to_string();
    let api_host = api_base
        .split("://")
        .nth(1)
        .unwrap_or(&api_base)
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();
    (api_base, api_host)
}

fn config_encryption_to_ui(value: Option<&Value>) -> Value {
    match value {
        Some(Value::Object(map)) => Value::Object(map.clone()),
        Some(Value::String(s)) => {
            serde_json::from_str(s).unwrap_or_else(|_| json!({ "Rules": [] }))
        }
        _ => json!({ "Rules": [] }),
    }
}

fn config_website_to_ui(value: Option<&Value>) -> Value {
    let parsed = match value {
        Some(Value::Object(map)) => Value::Object(map.clone()),
        Some(Value::String(s)) => serde_json::from_str(s).unwrap_or(Value::Null),
        _ => Value::Null,
    };

    let Some(map) = parsed.as_object() else {
        return Value::Null;
    };

    json!({
        "index_document": map
            .get("index_document")
            .and_then(Value::as_str)
            .unwrap_or("index.html"),
        "error_document": map.get("error_document").and_then(Value::as_str),
    })
}

fn bucket_access_descriptor(
    policy: Option<&Value>,
    bucket_name: &str,
) -> (&'static str, &'static str) {
    let Some(policy) = policy else {
        return ("Private", "bg-secondary-subtle text-secondary-emphasis");
    };

    let default_policy = default_public_policy(bucket_name);
    let default_policy_value: Value = serde_json::from_str(&default_policy).unwrap_or(Value::Null);
    if *policy == default_policy_value {
        return ("Public Read", "bg-warning-subtle text-warning-emphasis");
    }

    ("Custom policy", "bg-info-subtle text-info-emphasis")
}

pub async fn buckets_overview(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
) -> Response {
    let mut ctx = page_context(&state, &session, "ui.buckets_overview");

    let buckets = match state.storage.list_buckets().await {
        Ok(list) => list,
        Err(e) => {
            tracing::error!("list_buckets failed: {}", e);
            Vec::new()
        }
    };

    let mut items: Vec<Value> = Vec::with_capacity(buckets.len());
    for b in &buckets {
        let stats = state.storage.bucket_stats(&b.name).await.ok();
        let total_bytes = stats.as_ref().map(|s| s.total_bytes()).unwrap_or(0);
        let total_objects = stats.as_ref().map(|s| s.total_objects()).unwrap_or(0);
        let policy = state
            .storage
            .get_bucket_config(&b.name)
            .await
            .ok()
            .and_then(|cfg| cfg.policy);
        let (access_label, access_badge) = bucket_access_descriptor(policy.as_ref(), &b.name);

        items.push(json!({
            "meta": {
                "name": b.name,
                "creation_date": b.creation_date.to_rfc3339(),
            },
            "summary": {
                "human_size": human_size(total_bytes),
                "objects": total_objects,
            },
            "detail_url": format!("/ui/buckets/{}", b.name),
            "access_badge": access_badge,
            "access_label": access_label,
        }));
    }

    ctx.insert("buckets", &items);
    render(&state, "buckets.html", &ctx)
}

pub async fn bucket_detail(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
    Query(request_args): Query<HashMap<String, String>>,
) -> Response {
    if !matches!(state.storage.bucket_exists(&bucket_name).await, Ok(true)) {
        session.write(|s| {
            s.push_flash(
                "danger",
                format!("Bucket '{}' does not exist.", bucket_name),
            )
        });
        return Redirect::to("/ui/buckets").into_response();
    }

    let mut ctx = page_context(&state, &session, "ui.bucket_detail");
    ctx.insert("request_args", &request_args);
    let bucket_meta = state
        .storage
        .list_buckets()
        .await
        .ok()
        .and_then(|list| list.into_iter().find(|b| b.name == bucket_name));
    let bucket_config = state
        .storage
        .get_bucket_config(&bucket_name)
        .await
        .unwrap_or_default();
    let bucket_stats = state
        .storage
        .bucket_stats(&bucket_name)
        .await
        .unwrap_or_default();
    let replication_rule = state.replication.get_rule(&bucket_name);
    let target_conn = replication_rule
        .as_ref()
        .and_then(|rule| state.connections.get(&rule.target_connection_id));
    let versioning_status_enum = state
        .storage
        .get_versioning_status(&bucket_name)
        .await
        .unwrap_or(myfsio_common::types::VersioningStatus::Disabled);
    let versioning_enabled = matches!(
        versioning_status_enum,
        myfsio_common::types::VersioningStatus::Enabled
    );
    let versioning_suspended = matches!(
        versioning_status_enum,
        myfsio_common::types::VersioningStatus::Suspended
    );
    let encryption_config = config_encryption_to_ui(bucket_config.encryption.as_ref());
    let website_config = config_website_to_ui(bucket_config.website.as_ref());
    let quota = bucket_config.quota.clone();
    let max_bytes = quota.as_ref().and_then(|q| q.max_bytes);
    let max_objects = quota.as_ref().and_then(|q| q.max_objects);
    let bucket_policy = bucket_config.policy.clone().unwrap_or(Value::Null);
    let bucket_policy_text = if bucket_policy.is_null() {
        String::new()
    } else {
        serde_json::to_string_pretty(&bucket_policy).unwrap_or_else(|_| bucket_policy.to_string())
    };
    let default_policy = default_public_policy(&bucket_name);
    let default_policy_value: Value = serde_json::from_str(&default_policy).unwrap_or(Value::Null);
    let preset_choice = if bucket_policy.is_null() {
        "private"
    } else if bucket_policy == default_policy_value {
        "public"
    } else {
        "custom"
    };
    ctx.insert("bucket_name", &bucket_name);
    ctx.insert(
        "bucket",
        &json!({
            "name": bucket_name,
            "creation_date": bucket_meta
                .as_ref()
                .map(|b| b.creation_date.to_rfc3339())
                .unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
        }),
    );
    ctx.insert("objects", &Vec::<Value>::new());
    ctx.insert("prefixes", &Vec::<Value>::new());
    ctx.insert("total_objects", &bucket_stats.total_objects());
    ctx.insert("total_bytes", &bucket_stats.total_bytes());
    ctx.insert("current_objects", &bucket_stats.objects);
    ctx.insert("current_bytes", &bucket_stats.bytes);
    ctx.insert("version_count", &bucket_stats.version_count);
    ctx.insert("version_bytes", &bucket_stats.version_bytes);
    ctx.insert("max_objects", &max_objects);
    ctx.insert("max_bytes", &max_bytes);
    ctx.insert("has_max_objects", &max_objects.is_some());
    ctx.insert("has_max_bytes", &max_bytes.is_some());
    ctx.insert(
        "obj_pct",
        &max_objects
            .map(|m| {
                ((bucket_stats.total_objects() as f64 / m.max(1) as f64) * 100.0).round() as u64
            })
            .unwrap_or(0),
    );
    ctx.insert(
        "bytes_pct",
        &max_bytes
            .map(|m| ((bucket_stats.total_bytes() as f64 / m.max(1) as f64) * 100.0).round() as u64)
            .unwrap_or(0),
    );
    ctx.insert("has_quota", &quota.is_some());
    ctx.insert("versioning_enabled", &versioning_enabled);
    ctx.insert("versioning_suspended", &versioning_suspended);
    ctx.insert(
        "versioning_status",
        &(match versioning_status_enum {
            myfsio_common::types::VersioningStatus::Enabled => "Enabled",
            myfsio_common::types::VersioningStatus::Suspended => "Suspended",
            myfsio_common::types::VersioningStatus::Disabled => "Disabled",
        }),
    );
    ctx.insert("encryption_config", &encryption_config);
    ctx.insert("enc_rules", &Vec::<Value>::new());
    ctx.insert("enc_algorithm", &"");
    ctx.insert("enc_kms_key", &"");
    let replication_rules = replication_rule
        .clone()
        .and_then(|rule| serde_json::to_value(rule).ok())
        .map(|rule| vec![rule])
        .unwrap_or_default();
    ctx.insert("replication_rules", &replication_rules);
    ctx.insert(
        "replication_rule",
        &replication_rule
            .clone()
            .and_then(|rule| serde_json::to_value(rule).ok())
            .unwrap_or(Value::Null),
    );
    ctx.insert("website_config", &website_config);
    ctx.insert("bucket_policy", &bucket_policy);
    ctx.insert("bucket_policy_text", &bucket_policy_text);
    ctx.insert("preset_choice", &preset_choice);
    let conns: Vec<Value> = state
        .connections
        .list()
        .into_iter()
        .map(|c| {
            json!({
                "id": c.id,
                "name": c.name,
                "endpoint_url": c.endpoint_url,
                "region": c.region,
                "access_key": c.access_key,
            })
        })
        .collect();
    ctx.insert("connections", &conns);
    ctx.insert("current_prefix", &"");
    ctx.insert("parent_prefix", &"");
    ctx.insert("has_more", &false);
    ctx.insert("next_token", &"");
    ctx.insert(
        "active_tab",
        &request_args
            .get("tab")
            .cloned()
            .unwrap_or_else(|| "objects".to_string()),
    );
    let multipart_uploads: Vec<Value> = state
        .storage
        .list_multipart_uploads(&bucket_name)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|u| {
            json!({
                "upload_id": u.upload_id,
                "key": u.key,
                "initiated": u.initiated.to_rfc3339(),
            })
        })
        .collect();
    ctx.insert("multipart_uploads", &multipart_uploads);
    ctx.insert(
        "target_conn",
        &target_conn
            .as_ref()
            .and_then(|conn| serde_json::to_value(conn).ok())
            .unwrap_or(Value::Null),
    );
    ctx.insert(
        "target_conn_name",
        &target_conn
            .as_ref()
            .map(|conn| conn.name.clone())
            .unwrap_or_default(),
    );
    ctx.insert("default_policy", &default_policy);
    ctx.insert("can_manage_cors", &true);
    ctx.insert("can_manage_lifecycle", &true);
    ctx.insert("can_manage_quota", &true);
    ctx.insert("can_manage_versioning", &true);
    ctx.insert("can_manage_website", &true);
    ctx.insert("can_edit_policy", &true);
    ctx.insert("is_replication_admin", &true);
    ctx.insert("lifecycle_enabled", &state.config.lifecycle_enabled);
    ctx.insert("site_sync_enabled", &state.config.site_sync_enabled);
    ctx.insert(
        "website_hosting_enabled",
        &state.config.website_hosting_enabled,
    );
    let website_domains: Vec<String> = state
        .website_domains
        .as_ref()
        .map(|store| {
            store
                .list_all()
                .into_iter()
                .filter_map(|entry| {
                    if entry.get("bucket").and_then(|v| v.as_str()) == Some(bucket_name.as_str()) {
                        entry
                            .get("domain")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    ctx.insert("website_domains", &website_domains);
    let kms_keys: Vec<Value> = if let Some(kms) = &state.kms {
        kms.list_keys()
            .await
            .into_iter()
            .map(|key| {
                json!({
                    "key_id": key.key_id,
                    "description": key.description,
                })
            })
            .collect()
    } else {
        Vec::new()
    };
    ctx.insert("kms_keys", &kms_keys);
    ctx.insert(
        "bucket_stats",
        &json!({
            "bytes": bucket_stats.bytes,
            "objects": bucket_stats.objects,
            "total_bytes": bucket_stats.total_bytes(),
            "total_objects": bucket_stats.total_objects(),
            "version_bytes": bucket_stats.version_bytes,
            "version_count": bucket_stats.version_count
        }),
    );
    ctx.insert(
        "bucket_quota",
        &json!({ "max_bytes": max_bytes, "max_objects": max_objects }),
    );
    ctx.insert(
        "buckets_for_copy_url",
        &format!("/ui/buckets/{}/copy-targets", bucket_name),
    );
    ctx.insert("acl_url", &format!("/ui/buckets/{}/acl", bucket_name));
    ctx.insert("cors_url", &format!("/ui/buckets/{}/cors", bucket_name));
    ctx.insert(
        "folders_url",
        &format!("/ui/buckets/{}/folders", bucket_name),
    );
    ctx.insert(
        "lifecycle_url",
        &format!("/ui/buckets/{}/lifecycle", bucket_name),
    );
    ctx.insert(
        "objects_api_url",
        &format!("/ui/buckets/{}/objects", bucket_name),
    );
    ctx.insert(
        "objects_stream_url",
        &format!("/ui/buckets/{}/objects/stream", bucket_name),
    );
    render(&state, "bucket_detail.html", &ctx)
}

pub async fn iam_dashboard(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
) -> Response {
    let mut ctx = page_context(&state, &session, "ui.iam_dashboard");
    let now = chrono::Utc::now();
    let soon = now + chrono::Duration::days(7);
    let raw_users = state.iam.list_users().await;
    let mut users: Vec<Value> = Vec::with_capacity(raw_users.len());
    for u in raw_users.iter() {
        let user_id = u
            .get("user_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let display_name = u
            .get("display_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let enabled = u.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
        let access_key = u
            .get("access_keys")
            .and_then(|v| v.as_array())
            .and_then(|arr| {
                arr.iter().find_map(|k| {
                    k.get("access_key")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string())
                })
            })
            .unwrap_or_default();

        let detail = state.iam.get_user(&user_id).await;
        let policies = detail
            .as_ref()
            .and_then(|d| d.get("policies").cloned())
            .unwrap_or(Value::Array(Vec::new()));
        let expires_at = detail
            .as_ref()
            .and_then(|d| d.get("expires_at").cloned())
            .unwrap_or(Value::Null);
        let is_admin = policies
            .as_array()
            .map(|items| {
                items.iter().any(|policy| {
                    policy
                        .get("actions")
                        .and_then(|value| value.as_array())
                        .map(|actions| {
                            actions
                                .iter()
                                .any(|action| matches!(action.as_str(), Some("*") | Some("iam:*")))
                        })
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
        let expires_dt = expires_at.as_str().and_then(|value| {
            chrono::DateTime::parse_from_rfc3339(value)
                .ok()
                .map(|dt| dt.with_timezone(&chrono::Utc))
        });
        let is_expired = expires_dt.map(|dt| dt <= now).unwrap_or(false);
        let is_expiring_soon = expires_dt.map(|dt| dt > now && dt <= soon).unwrap_or(false);
        let access_keys = u
            .get("access_keys")
            .cloned()
            .unwrap_or(Value::Array(Vec::new()));

        users.push(json!({
            "user_id": user_id,
            "access_key": access_key,
            "display_name": display_name,
            "enabled": enabled,
            "is_enabled": enabled,
            "expires_at": expires_at,
            "is_admin": is_admin,
            "is_expired": is_expired,
            "is_expiring_soon": is_expiring_soon,
            "access_keys": access_keys,
            "policies": policies,
            "policy_count": u.get("policy_count").cloned().unwrap_or(Value::from(0)),
        }));
    }
    let all_buckets: Vec<String> = state
        .storage
        .list_buckets()
        .await
        .map(|list| list.into_iter().map(|b| b.name).collect())
        .unwrap_or_default();
    ctx.insert("users", &users);
    ctx.insert("iam_locked", &false);
    ctx.insert("locked_reason", &"");
    ctx.insert("iam_disabled", &false);
    ctx.insert("all_buckets", &all_buckets);
    ctx.insert("disclosed_secret", &Value::Null);
    let config_doc =
        serde_json::to_string_pretty(&state.iam.export_config(true)).unwrap_or_default();
    ctx.insert("config_document", &config_doc);
    ctx.insert("config_summary", &json!({ "user_count": users.len() }));
    render(&state, "iam.html", &ctx)
}

#[derive(serde::Deserialize)]
pub struct CreateIamUserForm {
    pub display_name: Option<String>,
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
    pub policies: Option<String>,
    pub expires_at: Option<String>,
    #[serde(default)]
    pub csrf_token: String,
}

fn parse_policies(raw: &str) -> Result<Vec<myfsio_auth::iam::IamPolicy>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(vec![]);
    }
    serde_json::from_str::<Vec<myfsio_auth::iam::IamPolicy>>(trimmed)
        .map_err(|e| format!("Invalid policies JSON: {}", e))
}

fn normalize_expires_at(raw: Option<String>) -> Result<Option<String>, String> {
    let Some(value) = raw else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        return Ok(Some(dt.with_timezone(&chrono::Utc).to_rfc3339()));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M") {
        return Ok(Some(naive.and_utc().to_rfc3339()));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S") {
        return Ok(Some(naive.and_utc().to_rfc3339()));
    }
    Err("Invalid expiry date format".to_string())
}

pub async fn create_iam_user(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    headers: HeaderMap,
    axum::extract::Form(form): axum::extract::Form<CreateIamUserForm>,
) -> Response {
    let wants_json = wants_json(&headers);
    let display_name = form
        .display_name
        .as_deref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Unnamed".to_string());

    if display_name.len() > 64 {
        let message = "Display name must be 64 characters or fewer".to_string();
        if wants_json {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({ "error": message })),
            )
                .into_response();
        }
        session.write(|s| s.push_flash("danger", message));
        return Redirect::to("/ui/iam").into_response();
    }

    let policies = match form.policies.as_deref().map(parse_policies) {
        Some(Ok(p)) if !p.is_empty() => Some(p),
        Some(Ok(_)) | None => None,
        Some(Err(e)) => {
            if wants_json {
                return (StatusCode::BAD_REQUEST, axum::Json(json!({ "error": e })))
                    .into_response();
            }
            session.write(|s| s.push_flash("danger", e));
            return Redirect::to("/ui/iam").into_response();
        }
    };

    let expires_at = match normalize_expires_at(form.expires_at) {
        Ok(v) => v,
        Err(e) => {
            if wants_json {
                return (StatusCode::BAD_REQUEST, axum::Json(json!({ "error": e })))
                    .into_response();
            }
            session.write(|s| s.push_flash("danger", e));
            return Redirect::to("/ui/iam").into_response();
        }
    };

    let custom_access_key = form
        .access_key
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let custom_secret_key = form
        .secret_key
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    match state.iam.create_user(
        &display_name,
        policies.clone(),
        custom_access_key,
        custom_secret_key,
        expires_at,
    ) {
        Ok(created) => {
            let user_id = created
                .get("user_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let access_key = created
                .get("access_key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let secret_key = created
                .get("secret_key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let message = format!("Created user {}", access_key);
            if wants_json {
                return axum::Json(json!({
                    "success": true,
                    "message": message,
                    "user_id": user_id,
                    "access_key": access_key,
                    "secret_key": secret_key,
                    "display_name": display_name,
                    "expires_at": created.get("expires_at").cloned().unwrap_or(Value::Null),
                    "policies": policies.unwrap_or_default(),
                }))
                .into_response();
            }
            session
                .write(|s| s.push_flash("success", format!("{}. Copy the secret now.", message)));
            Redirect::to("/ui/iam").into_response()
        }
        Err(e) => {
            if wants_json {
                return (StatusCode::BAD_REQUEST, axum::Json(json!({ "error": e })))
                    .into_response();
            }
            session.write(|s| s.push_flash("danger", e));
            Redirect::to("/ui/iam").into_response()
        }
    }
}

#[derive(serde::Deserialize)]
pub struct UpdateIamUserForm {
    pub display_name: Option<String>,
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn update_iam_user(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    axum::extract::Form(form): axum::extract::Form<UpdateIamUserForm>,
) -> Response {
    let wants_json = wants_json(&headers);
    let display_name = form
        .display_name
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    match state.iam.update_user(&user_id, display_name, None) {
        Ok(()) => {
            if wants_json {
                let display_name = state
                    .iam
                    .get_user(&user_id)
                    .await
                    .and_then(|user| {
                        user.get("display_name")
                            .and_then(|value| value.as_str())
                            .map(ToString::to_string)
                    })
                    .unwrap_or_default();
                return axum::Json(json!({
                    "success": true,
                    "user_id": user_id,
                    "display_name": display_name,
                }))
                .into_response();
            }
            session.write(|s| s.push_flash("success", "User updated."));
            Redirect::to("/ui/iam").into_response()
        }
        Err(e) => {
            if wants_json {
                return (StatusCode::BAD_REQUEST, axum::Json(json!({ "error": e })))
                    .into_response();
            }
            session.write(|s| s.push_flash("danger", e));
            Redirect::to("/ui/iam").into_response()
        }
    }
}

pub async fn delete_iam_user(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let wants_json = wants_json(&headers);
    match state.iam.delete_user(&user_id) {
        Ok(()) => {
            if wants_json {
                return axum::Json(json!({ "success": true })).into_response();
            }
            session.write(|s| s.push_flash("success", "User deleted."));
            Redirect::to("/ui/iam").into_response()
        }
        Err(e) => {
            if wants_json {
                return (StatusCode::BAD_REQUEST, axum::Json(json!({ "error": e })))
                    .into_response();
            }
            session.write(|s| s.push_flash("danger", e));
            Redirect::to("/ui/iam").into_response()
        }
    }
}

#[derive(serde::Deserialize)]
pub struct UpdateIamPoliciesForm {
    pub policies: String,
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn update_iam_policies(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    axum::extract::Form(form): axum::extract::Form<UpdateIamPoliciesForm>,
) -> Response {
    let wants_json = wants_json(&headers);
    let policies = match parse_policies(&form.policies) {
        Ok(p) => p,
        Err(e) => {
            if wants_json {
                return (StatusCode::BAD_REQUEST, axum::Json(json!({ "error": e })))
                    .into_response();
            }
            session.write(|s| s.push_flash("danger", e));
            return Redirect::to("/ui/iam").into_response();
        }
    };

    match state.iam.update_user_policies(&user_id, policies) {
        Ok(()) => {
            if wants_json {
                let policies = state
                    .iam
                    .get_user(&user_id)
                    .await
                    .and_then(|user| user.get("policies").cloned())
                    .unwrap_or_else(|| Value::Array(Vec::new()));
                return axum::Json(json!({
                    "success": true,
                    "user_id": user_id,
                    "policies": policies,
                }))
                .into_response();
            }
            session.write(|s| s.push_flash("success", "Policies updated."));
            Redirect::to("/ui/iam").into_response()
        }
        Err(e) => {
            if wants_json {
                return (StatusCode::BAD_REQUEST, axum::Json(json!({ "error": e })))
                    .into_response();
            }
            session.write(|s| s.push_flash("danger", e));
            Redirect::to("/ui/iam").into_response()
        }
    }
}

#[derive(serde::Deserialize)]
pub struct UpdateIamExpiryForm {
    pub expires_at: Option<String>,
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn update_iam_expiry(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    axum::extract::Form(form): axum::extract::Form<UpdateIamExpiryForm>,
) -> Response {
    let wants_json = wants_json(&headers);
    let expires_at = match normalize_expires_at(form.expires_at) {
        Ok(v) => v,
        Err(e) => {
            if wants_json {
                return (StatusCode::BAD_REQUEST, axum::Json(json!({ "error": e })))
                    .into_response();
            }
            session.write(|s| s.push_flash("danger", e));
            return Redirect::to("/ui/iam").into_response();
        }
    };

    match state.iam.update_user(&user_id, None, Some(expires_at)) {
        Ok(()) => {
            if wants_json {
                return axum::Json(json!({ "success": true })).into_response();
            }
            session.write(|s| s.push_flash("success", "Expiry updated."));
            Redirect::to("/ui/iam").into_response()
        }
        Err(e) => {
            if wants_json {
                return (StatusCode::BAD_REQUEST, axum::Json(json!({ "error": e })))
                    .into_response();
            }
            session.write(|s| s.push_flash("danger", e));
            Redirect::to("/ui/iam").into_response()
        }
    }
}

pub async fn rotate_iam_secret(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let wants_json = wants_json(&headers);
    match state.iam.rotate_secret(&user_id) {
        Ok(result) => {
            let access_key = result
                .get("access_key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let secret_key = result
                .get("secret_key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if wants_json {
                return axum::Json(json!({
                    "success": true,
                    "access_key": access_key,
                    "secret_key": secret_key,
                }))
                .into_response();
            }
            session
                .write(|s| s.push_flash("success", format!("Secret rotated for {}.", access_key)));
            Redirect::to("/ui/iam").into_response()
        }
        Err(e) => {
            if wants_json {
                return (StatusCode::BAD_REQUEST, axum::Json(json!({ "error": e })))
                    .into_response();
            }
            session.write(|s| s.push_flash("danger", e));
            Redirect::to("/ui/iam").into_response()
        }
    }
}

pub async fn sites_dashboard(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
) -> Response {
    let mut ctx = page_context(&state, &session, "ui.sites_dashboard");

    let local_site = state
        .site_registry
        .as_ref()
        .and_then(|reg| reg.get_local_site())
        .map(|s| {
            json!({
                "site_id": s.site_id,
                "display_name": s.display_name,
                "endpoint": s.endpoint,
                "region": s.region,
                "priority": s.priority,
            })
        })
        .unwrap_or(Value::Null);

    let peers: Vec<Value> = state
        .site_registry
        .as_ref()
        .map(|reg| {
            reg.list_peers()
                .into_iter()
                .map(|p| {
                    json!({
                        "site_id": p.site_id,
                        "display_name": p.display_name,
                        "endpoint": p.endpoint,
                        "region": p.region,
                        "priority": p.priority,
                        "connection_id": p.connection_id,
                        "peer_inbound_access_key": p.peer_inbound_access_key,
                        "is_healthy": p.is_healthy,
                        "last_health_check": p.last_health_check,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let rules = state.replication.rules_snapshot();
    let sync_snapshot = state
        .site_sync
        .as_ref()
        .map(|w| w.snapshot_stats())
        .unwrap_or_default();

    let peers_with_stats: Vec<Value> = peers
        .iter()
        .cloned()
        .map(|peer| {
            let connection_id = peer
                .get("connection_id")
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty())
                .map(|value| value.to_string());
            let has_connection = connection_id.is_some();

            let mut buckets_syncing: u64 = 0;
            let mut has_bidirectional = false;
            let mut last_sync_at: Option<f64> = None;
            let mut total_pulled: u64 = 0;
            let mut total_errors: u64 = 0;

            if let Some(ref conn_id) = connection_id {
                for (bucket, rule) in &rules {
                    if &rule.target_connection_id != conn_id || !rule.enabled {
                        continue;
                    }
                    if rule.mode == crate::services::replication::MODE_BIDIRECTIONAL {
                        has_bidirectional = true;
                        buckets_syncing += 1;
                        if let Some(stats) = sync_snapshot.get(bucket) {
                            total_pulled += stats.objects_pulled;
                            total_errors += stats.errors;
                            if let Some(ts) = stats.last_sync_at {
                                last_sync_at = match last_sync_at {
                                    Some(prev) if prev > ts => Some(prev),
                                    _ => Some(ts),
                                };
                            }
                        }
                    }
                }
            }

            json!({
                "peer": peer,
                "has_connection": has_connection,
                "buckets_syncing": buckets_syncing,
                "has_bidirectional": has_bidirectional,
                "last_sync_at": last_sync_at,
                "objects_pulled": total_pulled,
                "errors": total_errors,
            })
        })
        .collect();

    let conns: Vec<Value> = state
        .connections
        .list()
        .into_iter()
        .map(|c| {
            json!({
                "id": c.id,
                "name": c.name,
                "endpoint_url": c.endpoint_url,
                "region": c.region,
                "access_key": c.access_key,
            })
        })
        .collect();

    ctx.insert("local_site", &local_site);
    ctx.insert("peers", &peers);
    ctx.insert("peers_with_stats", &peers_with_stats);
    ctx.insert("connections", &conns);
    ctx.insert(
        "config_site_id",
        &state.config.site_id.clone().unwrap_or_default(),
    );
    ctx.insert(
        "config_site_endpoint",
        &state.config.site_endpoint.clone().unwrap_or_default(),
    );
    ctx.insert("config_site_region", &state.config.site_region);
    ctx.insert("topology", &json!({"sites": [], "connections": []}));
    render(&state, "sites.html", &ctx)
}

pub async fn cluster_data_json(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let force = params
        .get("force")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if force {
        *state.cluster_aggregate_cache.lock() = None;
        *state.cluster_overview_cache.lock() = None;
    }
    let sites = build_cluster_sites(&state).await;
    let totals = cluster_totals(&sites);
    let body = json!({ "sites": sites, "totals": totals });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn cluster_totals(sites: &[Value]) -> Value {
    let total_buckets: u64 = sites
        .iter()
        .filter_map(|s| s.get("buckets").and_then(|v| v.as_u64()))
        .sum();
    let total_objects: u64 = sites
        .iter()
        .filter_map(|s| s.get("objects").and_then(|v| v.as_u64()))
        .sum();
    let total_size_bytes: u64 = sites
        .iter()
        .filter_map(|s| s.get("size_bytes").and_then(|v| v.as_u64()))
        .sum();
    let online = sites
        .iter()
        .filter(|s| s.get("online").and_then(|v| v.as_bool()).unwrap_or(false))
        .count();
    json!({
        "buckets": total_buckets,
        "objects": total_objects,
        "size_bytes": total_size_bytes,
        "online_count": online,
        "total_count": sites.len(),
    })
}

pub async fn cluster_dashboard(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
) -> Response {
    let mut ctx = page_context(&state, &session, "ui.cluster_dashboard");

    let sites = build_cluster_sites(&state).await;

    let total_buckets: u64 = sites
        .iter()
        .filter_map(|s| s.get("buckets").and_then(|v| v.as_u64()))
        .sum();
    let total_objects: u64 = sites
        .iter()
        .filter_map(|s| s.get("objects").and_then(|v| v.as_u64()))
        .sum();
    let total_size_bytes: u64 = sites
        .iter()
        .filter_map(|s| s.get("size_bytes").and_then(|v| v.as_u64()))
        .sum();
    let online_count = sites
        .iter()
        .filter(|s| s.get("online").and_then(|v| v.as_bool()).unwrap_or(false))
        .count();

    ctx.insert("cluster_sites", &sites);
    ctx.insert("cluster_total_buckets", &total_buckets);
    ctx.insert("cluster_total_objects", &total_objects);
    ctx.insert("cluster_total_size_bytes", &total_size_bytes);
    ctx.insert("cluster_online_count", &online_count);
    ctx.insert("cluster_total_count", &sites.len());
    render(&state, "cluster.html", &ctx)
}

async fn build_cluster_sites(state: &AppState) -> Vec<Value> {
    {
        let guard = state.cluster_aggregate_cache.lock();
        if let Some((at, ref value)) = *guard {
            if at.elapsed() < std::time::Duration::from_secs(10) {
                if let Some(arr) = value.as_array() {
                    return arr.clone();
                }
            }
        }
    }

    let mut sites: Vec<Value> = Vec::new();

    let local = crate::handlers::admin::build_cluster_overview_public(state).await;
    let mut local_card = decorate_site(local, true, false, None);
    if local_card.get("site_id").and_then(|v| v.as_str()).is_none() {
        local_card["site_id"] = json!(state
            .config
            .site_id
            .clone()
            .unwrap_or_else(|| "local".to_string()));
    }
    local_card["is_local"] = json!(true);
    sites.push(local_card);

    let peers = state
        .site_registry
        .as_ref()
        .map(|r| r.list_peers())
        .unwrap_or_default();

    let connect_to = std::time::Duration::from_secs(2);
    let read_to = std::time::Duration::from_secs(3);
    let client = crate::services::peer_admin::PeerAdminClient::new(connect_to, read_to);

    let mut peer_futures = Vec::new();
    for peer in peers {
        let conn = peer
            .connection_id
            .as_deref()
            .and_then(|id| state.connections.get(id));
        let endpoint = peer.endpoint.clone();
        let conn_clone = conn.clone();
        let client_ref = &client;
        peer_futures.push(async move {
            let value = match conn_clone {
                Some(c) => client_ref.fetch_cluster_overview(&endpoint, &c).await,
                None => Err("no connection configured".to_string()),
            };
            (peer, value)
        });
    }

    let results = futures::future::join_all(peer_futures).await;
    for (peer, result) in results {
        let (overview, online, error) = match result {
            Ok(value) => (value, true, None),
            Err(err) => (json!({}), false, Some(err)),
        };
        let mut card = decorate_site(overview, online, !online, error);
        if card.get("site_id").and_then(|v| v.as_str()).is_none() {
            card["site_id"] = json!(peer.site_id.clone());
        }
        if card.get("display_name").and_then(|v| v.as_str()).is_none() {
            card["display_name"] = json!(peer.display_name.clone());
        }
        if card.get("endpoint").and_then(|v| v.as_str()).is_none() {
            card["endpoint"] = json!(peer.endpoint.clone());
        }
        card["is_local"] = json!(false);
        card["registered_priority"] = json!(peer.priority);
        card["registered_region"] = json!(peer.region);
        sites.push(card);
    }

    *state.cluster_aggregate_cache.lock() =
        Some((std::time::Instant::now(), Value::Array(sites.clone())));
    sites
}

fn decorate_site(mut value: Value, online: bool, stale: bool, error: Option<String>) -> Value {
    if !value.is_object() {
        value = json!({});
    }
    value["online"] = json!(online);
    value["stale"] = json!(stale);
    value["error"] = match error {
        Some(e) => json!(e),
        None => Value::Null,
    };
    value
}

#[derive(serde::Deserialize)]
pub struct LocalSiteForm {
    pub site_id: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default = "default_site_region")]
    pub region: String,
    #[serde(default = "default_site_priority")]
    pub priority: i32,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub csrf_token: String,
}

#[derive(serde::Deserialize)]
pub struct PeerSiteForm {
    pub site_id: String,
    pub endpoint: String,
    #[serde(default = "default_site_region")]
    pub region: String,
    #[serde(default = "default_site_priority")]
    pub priority: i32,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub connection_id: String,
    #[serde(default)]
    pub peer_inbound_access_key: String,
    #[serde(default)]
    pub csrf_token: String,
}

#[derive(serde::Deserialize, Default)]
pub struct DeletePeerSiteForm {
    #[serde(default)]
    pub csrf_token: String,
}

fn default_site_region() -> String {
    "us-east-1".to_string()
}

fn default_site_priority() -> i32 {
    100
}

pub async fn update_local_site(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    headers: HeaderMap,
    Form(form): Form<LocalSiteForm>,
) -> Response {
    let wants_json = wants_json(&headers);
    let site_id = form.site_id.trim().to_string();
    if site_id.is_empty() {
        let message = "Site ID is required.".to_string();
        if wants_json {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({ "error": message })),
            )
                .into_response();
        }
        session.write(|s| s.push_flash("danger", message));
        return Redirect::to("/ui/sites").into_response();
    }

    let Some(registry) = &state.site_registry else {
        let message = "Site registry is not available.".to_string();
        if wants_json {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({ "error": message })),
            )
                .into_response();
        }
        session.write(|s| s.push_flash("danger", message));
        return Redirect::to("/ui/sites").into_response();
    };

    let existing = registry.get_local_site();
    let site = crate::services::site_registry::SiteInfo {
        site_id: site_id.clone(),
        endpoint: form.endpoint.trim().to_string(),
        region: form.region.trim().to_string(),
        priority: form.priority,
        display_name: {
            let display_name = form.display_name.trim();
            if display_name.is_empty() {
                site_id.clone()
            } else {
                display_name.to_string()
            }
        },
        created_at: existing.and_then(|site| site.created_at),
    };
    registry.set_local_site(site);

    let message = "Local site configuration updated".to_string();
    if wants_json {
        return axum::Json(json!({ "ok": true, "message": message })).into_response();
    }
    session.write(|s| s.push_flash("success", message));
    Redirect::to("/ui/sites").into_response()
}

pub async fn add_peer_site(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    headers: HeaderMap,
    Form(form): Form<PeerSiteForm>,
) -> Response {
    let wants_json = wants_json(&headers);
    let site_id = form.site_id.trim().to_string();
    let endpoint = form.endpoint.trim().to_string();
    if site_id.is_empty() {
        let message = "Site ID is required.".to_string();
        if wants_json {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({ "error": message })),
            )
                .into_response();
        }
        session.write(|s| s.push_flash("danger", message));
        return Redirect::to("/ui/sites").into_response();
    }
    if endpoint.is_empty() {
        let message = "Endpoint is required.".to_string();
        if wants_json {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({ "error": message })),
            )
                .into_response();
        }
        session.write(|s| s.push_flash("danger", message));
        return Redirect::to("/ui/sites").into_response();
    }

    let Some(registry) = &state.site_registry else {
        let message = "Site registry is not available.".to_string();
        if wants_json {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({ "error": message })),
            )
                .into_response();
        }
        session.write(|s| s.push_flash("danger", message));
        return Redirect::to("/ui/sites").into_response();
    };

    if registry.get_peer(&site_id).is_some() {
        let message = format!("Peer site '{}' already exists.", site_id);
        if wants_json {
            return (
                StatusCode::CONFLICT,
                axum::Json(json!({ "error": message })),
            )
                .into_response();
        }
        session.write(|s| s.push_flash("danger", message));
        return Redirect::to("/ui/sites").into_response();
    }

    let connection_id = {
        let value = form.connection_id.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    };
    if let Some(connection_id) = connection_id.as_deref() {
        if state.connections.get(connection_id).is_none() {
            let message = format!("Connection '{}' not found.", connection_id);
            if wants_json {
                return (
                    StatusCode::NOT_FOUND,
                    axum::Json(json!({ "error": message })),
                )
                    .into_response();
            }
            session.write(|s| s.push_flash("danger", message));
            return Redirect::to("/ui/sites").into_response();
        }
    }

    let has_connection = connection_id.is_some();
    let peer_inbound_access_key = {
        let value = form.peer_inbound_access_key.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    };
    let peer = crate::services::site_registry::PeerSite {
        site_id: site_id.clone(),
        endpoint,
        region: form.region.trim().to_string(),
        priority: form.priority,
        display_name: {
            let display_name = form.display_name.trim();
            if display_name.is_empty() {
                site_id.clone()
            } else {
                display_name.to_string()
            }
        },
        connection_id: connection_id.clone(),
        peer_inbound_access_key,
        created_at: None,
        is_healthy: false,
        last_health_check: None,
    };
    registry.add_peer(peer);

    let message = format!("Peer site '{}' added.", site_id);
    if wants_json {
        let redirect = if has_connection {
            Some(format!("/ui/replication/new?site_id={}", site_id))
        } else {
            None
        };
        return axum::Json(json!({
            "ok": true,
            "message": message,
            "redirect": redirect,
        }))
        .into_response();
    }
    session.write(|s| s.push_flash("success", message));
    if has_connection {
        return Redirect::to(&format!("/ui/replication/new?site_id={}", site_id)).into_response();
    }
    Redirect::to("/ui/sites").into_response()
}

pub async fn update_peer_site(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<PeerSiteForm>,
) -> Response {
    let wants_json = wants_json(&headers);
    let Some(registry) = &state.site_registry else {
        let message = "Site registry is not available.".to_string();
        if wants_json {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({ "error": message })),
            )
                .into_response();
        }
        session.write(|s| s.push_flash("danger", message));
        return Redirect::to("/ui/sites").into_response();
    };

    let Some(existing) = registry.get_peer(&site_id) else {
        let message = format!("Peer site '{}' not found.", site_id);
        if wants_json {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({ "error": message })),
            )
                .into_response();
        }
        session.write(|s| s.push_flash("danger", message));
        return Redirect::to("/ui/sites").into_response();
    };

    let connection_id = {
        let value = form.connection_id.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    };
    if let Some(connection_id) = connection_id.as_deref() {
        if state.connections.get(connection_id).is_none() {
            let message = format!("Connection '{}' not found.", connection_id);
            if wants_json {
                return (
                    StatusCode::NOT_FOUND,
                    axum::Json(json!({ "error": message })),
                )
                    .into_response();
            }
            session.write(|s| s.push_flash("danger", message));
            return Redirect::to("/ui/sites").into_response();
        }
    }

    let peer_inbound_access_key = {
        let value = form.peer_inbound_access_key.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    };
    let peer = crate::services::site_registry::PeerSite {
        site_id: site_id.clone(),
        endpoint: form.endpoint.trim().to_string(),
        region: form.region.trim().to_string(),
        priority: form.priority,
        display_name: {
            let display_name = form.display_name.trim();
            if display_name.is_empty() {
                site_id.clone()
            } else {
                display_name.to_string()
            }
        },
        connection_id,
        peer_inbound_access_key,
        created_at: existing.created_at,
        is_healthy: existing.is_healthy,
        last_health_check: existing.last_health_check,
    };
    registry.update_peer(peer);

    let message = format!("Peer site '{}' updated.", site_id);
    if wants_json {
        return axum::Json(json!({ "ok": true, "message": message })).into_response();
    }
    session.write(|s| s.push_flash("success", message));
    Redirect::to("/ui/sites").into_response()
}

pub async fn delete_peer_site(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
    Form(_form): Form<DeletePeerSiteForm>,
) -> Response {
    let wants_json = wants_json(&headers);
    let Some(registry) = &state.site_registry else {
        let message = "Site registry is not available.".to_string();
        if wants_json {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({ "error": message })),
            )
                .into_response();
        }
        session.write(|s| s.push_flash("danger", message));
        return Redirect::to("/ui/sites").into_response();
    };

    if registry.delete_peer(&site_id) {
        let message = format!("Peer site '{}' deleted.", site_id);
        if wants_json {
            return axum::Json(json!({ "ok": true, "message": message })).into_response();
        }
        session.write(|s| s.push_flash("success", message));
    } else {
        let message = format!("Peer site '{}' not found.", site_id);
        if wants_json {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({ "error": message })),
            )
                .into_response();
        }
        session.write(|s| s.push_flash("danger", message));
    }

    Redirect::to("/ui/sites").into_response()
}

pub async fn connections_dashboard(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
) -> Response {
    let mut ctx = page_context(&state, &session, "ui.connections_dashboard");
    let conns = state.connections.list();
    let items: Vec<Value> = conns
        .into_iter()
        .map(|c| {
            json!({
                "id": c.id,
                "name": c.name,
                "endpoint_url": c.endpoint_url,
                "region": c.region,
                "access_key": c.access_key,
            })
        })
        .collect();
    ctx.insert("connections", &items);
    render(&state, "connections.html", &ctx)
}

pub async fn metrics_dashboard(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
) -> Response {
    let mut ctx = page_context(&state, &session, "ui.metrics_dashboard");
    ctx.insert(
        "metrics_enabled",
        &(state.config.metrics_enabled || state.config.metrics_history_enabled),
    );
    ctx.insert(
        "metrics_history_enabled",
        &state.config.metrics_history_enabled,
    );
    ctx.insert("operation_metrics_enabled", &state.config.metrics_enabled);
    ctx.insert("history", &Vec::<Value>::new());
    ctx.insert("operation_metrics", &Vec::<Value>::new());

    let metrics = crate::handlers::ui_api::collect_metrics(&state).await;
    let cpu_percent = metrics
        .get("cpu_percent")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let memory = metrics
        .get("memory")
        .cloned()
        .unwrap_or_else(|| json!({ "percent": 0, "total": "0 B", "used": "0 B" }));
    let disk = metrics
        .get("disk")
        .cloned()
        .unwrap_or_else(|| json!({ "percent": 0, "free": "0 B", "total": "0 B" }));
    let app = metrics.get("app").cloned().unwrap_or_else(|| {
        json!({
            "buckets": 0, "objects": 0, "storage_used": "0 B",
            "uptime_days": 0, "versions": 0,
        })
    });
    let mem_pct = memory
        .get("percent")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let disk_pct = disk.get("percent").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let has_issues = cpu_percent > 80.0 || mem_pct > 85.0 || disk_pct > 90.0;

    ctx.insert("cpu_percent", &cpu_percent);
    ctx.insert("memory", &memory);
    ctx.insert("disk", &disk);
    ctx.insert("app", &app);
    ctx.insert("has_issues", &has_issues);
    ctx.insert(
        "summary",
        &json!({
            "app": app,
            "cpu_percent": cpu_percent,
            "disk": disk,
            "memory": memory,
            "has_issues": has_issues,
        }),
    );
    render(&state, "metrics.html", &ctx)
}

fn format_history_timestamp(timestamp: Option<f64>) -> String {
    let Some(timestamp) = timestamp else {
        return "-".to_string();
    };
    let millis = (timestamp * 1000.0).round() as i64;
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(millis)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn format_byte_count(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn decorate_gc_history(executions: &[Value]) -> Vec<Value> {
    executions
        .iter()
        .cloned()
        .map(|mut execution| {
            let timestamp = execution.get("timestamp").and_then(|value| value.as_f64());
            let bytes_freed = execution
                .get("result")
                .and_then(|value| value.get("temp_bytes_freed"))
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            if let Some(obj) = execution.as_object_mut() {
                obj.insert(
                    "timestamp_display".to_string(),
                    Value::String(format_history_timestamp(timestamp)),
                );
                obj.insert(
                    "bytes_freed_display".to_string(),
                    Value::String(format_byte_count(bytes_freed)),
                );
            }
            execution
        })
        .collect()
}

fn decorate_integrity_history(executions: &[Value]) -> Vec<Value> {
    executions
        .iter()
        .cloned()
        .map(|mut execution| {
            let timestamp = execution.get("timestamp").and_then(|value| value.as_f64());
            if let Some(obj) = execution.as_object_mut() {
                obj.insert(
                    "timestamp_display".to_string(),
                    Value::String(format_history_timestamp(timestamp)),
                );
            }
            execution
        })
        .collect()
}

pub async fn system_dashboard(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
) -> Response {
    let mut ctx = page_context(&state, &session, "ui.system_dashboard");

    let gc_status = match &state.gc {
        Some(gc) => gc.status().await,
        None => json!({
            "dry_run": false,
            "enabled": false,
            "interval_hours": 6,
            "lock_file_max_age_hours": 1,
            "multipart_max_age_days": 7,
            "running": false,
            "scanning": false,
            "scan_elapsed_seconds": Value::Null,
            "temp_file_max_age_hours": 24,
        }),
    };
    let gc_history = match &state.gc {
        Some(gc) => gc
            .history()
            .await
            .get("executions")
            .and_then(|value| value.as_array())
            .map(|values| decorate_gc_history(values))
            .unwrap_or_default(),
        None => Vec::new(),
    };

    let integrity_status = match &state.integrity {
        Some(checker) => checker.status().await,
        None => json!({
            "auto_heal": false,
            "batch_size": 100,
            "dry_run": false,
            "enabled": false,
            "interval_hours": 24,
            "running": false,
            "scanning": false,
            "scan_elapsed_seconds": Value::Null,
        }),
    };
    let integrity_history = match &state.integrity {
        Some(checker) => checker
            .history()
            .await
            .get("executions")
            .and_then(|value| value.as_array())
            .map(|values| decorate_integrity_history(values))
            .unwrap_or_default(),
        None => Vec::new(),
    };

    ctx.insert("gc_enabled", &state.config.gc_enabled);
    ctx.insert("integrity_enabled", &state.config.integrity_enabled);
    ctx.insert("gc_history", &gc_history);
    ctx.insert("integrity_history", &integrity_history);
    ctx.insert("gc_status", &gc_status);
    ctx.insert("integrity_status", &integrity_status);
    ctx.insert("app_version", &env!("CARGO_PKG_VERSION"));
    ctx.insert("display_timezone", &"UTC");
    ctx.insert("platform", &std::env::consts::OS);
    ctx.insert(
        "storage_root",
        &state.config.storage_root.display().to_string(),
    );
    ctx.insert("total_issues", &0);
    let features = vec![
        json!({"label": "Encryption (SSE-S3)", "enabled": state.config.encryption_enabled}),
        json!({"label": "KMS", "enabled": state.config.kms_enabled}),
        json!({"label": "Versioning Lifecycle", "enabled": state.config.lifecycle_enabled}),
        json!({"label": "Metrics History", "enabled": state.config.metrics_history_enabled}),
        json!({"label": "Operation Metrics", "enabled": state.config.metrics_enabled}),
        json!({"label": "Site Sync", "enabled": state.config.site_sync_enabled}),
        json!({"label": "Website Hosting", "enabled": state.config.website_hosting_enabled}),
        json!({"label": "Garbage Collection", "enabled": state.config.gc_enabled}),
        json!({"label": "Integrity Scanner", "enabled": state.config.integrity_enabled}),
    ];
    ctx.insert("features", &features);
    render(&state, "system.html", &ctx)
}

pub async fn website_domains_dashboard(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
) -> Response {
    let mut ctx = page_context(&state, &session, "ui.website_domains_dashboard");
    let buckets: Vec<String> = state
        .storage
        .list_buckets()
        .await
        .map(|list| list.into_iter().map(|b| b.name).collect())
        .unwrap_or_default();
    let mappings = state
        .website_domains
        .as_ref()
        .map(|store| {
            let mut mappings = store.list_all();
            mappings.sort_by(|a, b| {
                let a_domain = a
                    .get("domain")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                let b_domain = b
                    .get("domain")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                a_domain.cmp(b_domain)
            });
            mappings
        })
        .unwrap_or_default();
    ctx.insert("domains", &mappings);
    ctx.insert("mappings", &mappings);
    ctx.insert("buckets", &buckets);
    render(&state, "website_domains.html", &ctx)
}

pub async fn replication_wizard(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let mut ctx = page_context(&state, &session, "ui.replication_wizard");

    let site_id = q.get("site_id").cloned().unwrap_or_default();
    let peer_record = state
        .site_registry
        .as_ref()
        .and_then(|reg| {
            if site_id.is_empty() {
                reg.list_peers().into_iter().next()
            } else {
                reg.get_peer(&site_id)
            }
        })
        .map(|p| {
            json!({
                "site_id": p.site_id,
                "display_name": p.display_name,
                "endpoint": p.endpoint,
                "region": p.region,
                "connection_id": p.connection_id,
            })
        })
        .unwrap_or_else(|| {
            json!({
                "site_id": site_id,
                "display_name": "",
                "endpoint": "",
                "region": "us-east-1",
            })
        });
    let peer_connection_id = peer_record
        .get("connection_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let local_site = state
        .site_registry
        .as_ref()
        .and_then(|reg| reg.get_local_site())
        .map(|s| {
            json!({
                "site_id": s.site_id,
                "display_name": s.display_name,
                "endpoint": s.endpoint,
                "region": s.region,
            })
        })
        .unwrap_or(Value::Null);

    let peers: Vec<Value> = state
        .site_registry
        .as_ref()
        .map(|reg| {
            reg.list_peers()
                .into_iter()
                .map(|p| {
                    json!({
                        "site_id": p.site_id,
                        "display_name": p.display_name,
                        "endpoint": p.endpoint,
                        "region": p.region,
                        "connection_id": p.connection_id,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let all_rules = state.replication.list_rules();
    let bucket_names: Vec<String> = state
        .storage
        .list_buckets()
        .await
        .map(|list| list.into_iter().map(|b| b.name).collect())
        .unwrap_or_default();
    let buckets: Vec<Value> = bucket_names
        .into_iter()
        .map(|bucket_name| {
            let existing_rule = all_rules
                .iter()
                .find(|rule| rule.bucket_name == bucket_name);
            let has_rule_for_peer = existing_rule
                .map(|rule| rule.target_connection_id == peer_connection_id)
                .unwrap_or(false);
            json!({
                "name": bucket_name,
                "has_rule": has_rule_for_peer,
                "existing_mode": if has_rule_for_peer {
                    existing_rule.map(|rule| rule.mode.clone())
                } else {
                    None::<String>
                },
                "existing_target": if has_rule_for_peer {
                    existing_rule.map(|rule| rule.target_bucket.clone())
                } else {
                    None::<String>
                },
            })
        })
        .collect();

    let conns: Vec<Value> = state
        .connections
        .list()
        .into_iter()
        .map(|c| {
            json!({
                "id": c.id,
                "name": c.name,
                "endpoint_url": c.endpoint_url,
                "region": c.region,
                "access_key": c.access_key,
            })
        })
        .collect();

    let connection = conns
        .iter()
        .find(|conn| {
            conn.get("id")
                .and_then(|value| value.as_str())
                .map(|id| id == peer_connection_id)
                .unwrap_or(false)
        })
        .cloned()
        .or_else(|| conns.first().cloned())
        .unwrap_or_else(
            || json!({ "id": "", "name": "", "endpoint_url": "", "region": "", "access_key": "" }),
        );

    ctx.insert("peer", &peer_record);
    ctx.insert("peers", &peers);
    ctx.insert("local_site", &local_site);
    ctx.insert("connections", &conns);
    ctx.insert("connection", &connection);
    ctx.insert("buckets", &buckets);
    render(&state, "replication_wizard.html", &ctx)
}

#[derive(serde::Deserialize)]
pub struct CreatePeerReplicationRulesForm {
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub buckets: Vec<String>,
    #[serde(default)]
    pub csrf_token: String,
    #[serde(flatten)]
    pub extras: HashMap<String, String>,
}

pub async fn create_peer_replication_rules(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Path(site_id): Path<String>,
    Form(form): Form<CreatePeerReplicationRulesForm>,
) -> Response {
    create_peer_replication_rules_impl(state, session, site_id, form).await
}

pub async fn create_peer_replication_rules_from_query(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Query(q): Query<HashMap<String, String>>,
    Form(form): Form<CreatePeerReplicationRulesForm>,
) -> Response {
    let site_id = q.get("site_id").cloned().unwrap_or_default();
    create_peer_replication_rules_impl(state, session, site_id, form).await
}

async fn create_peer_replication_rules_impl(
    state: AppState,
    session: SessionHandle,
    site_id: String,
    form: CreatePeerReplicationRulesForm,
) -> Response {
    let Some(registry) = &state.site_registry else {
        session.write(|s| s.push_flash("danger", "Site registry is not available."));
        return Redirect::to("/ui/sites").into_response();
    };
    let Some(peer) = registry.get_peer(&site_id) else {
        session.write(|s| s.push_flash("danger", format!("Peer site '{}' not found.", site_id)));
        return Redirect::to("/ui/sites").into_response();
    };
    let Some(connection_id) = peer.connection_id.clone() else {
        session.write(|s| {
            s.push_flash(
                "danger",
                "This peer has no connection configured. Add a connection first.",
            )
        });
        return Redirect::to("/ui/sites").into_response();
    };
    if state.connections.get(&connection_id).is_none() {
        session.write(|s| {
            s.push_flash(
                "danger",
                format!("Connection '{}' was not found.", connection_id),
            )
        });
        return Redirect::to("/ui/sites").into_response();
    }

    let mode = match form.mode.trim() {
        crate::services::replication::MODE_ALL => crate::services::replication::MODE_ALL,
        crate::services::replication::MODE_BIDIRECTIONAL => {
            crate::services::replication::MODE_BIDIRECTIONAL
        }
        _ => crate::services::replication::MODE_NEW_ONLY,
    }
    .to_string();

    if form.buckets.is_empty() {
        session.write(|s| s.push_flash("warning", "No buckets selected."));
        return Redirect::to("/ui/sites").into_response();
    }

    let mut created = 0usize;
    let mut created_existing = Vec::new();

    for bucket_name in form.buckets {
        let target_key = format!("target_{}", bucket_name);
        let target_bucket = form
            .extras
            .get(&target_key)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .unwrap_or(bucket_name.as_str())
            .to_string();

        let rule = crate::services::replication::ReplicationRule {
            bucket_name: bucket_name.clone(),
            target_connection_id: connection_id.clone(),
            target_bucket,
            enabled: true,
            mode: mode.clone(),
            created_at: Some(chrono::Utc::now().timestamp_millis() as f64 / 1000.0),
            stats: Default::default(),
            sync_deletions: true,
            last_pull_at: None,
            filter_prefix: None,
        };

        state.replication.set_rule(rule);
        created += 1;
        if mode == crate::services::replication::MODE_ALL {
            created_existing.push(bucket_name);
        }
    }

    for bucket_name in created_existing {
        state
            .replication
            .clone()
            .schedule_existing_objects_sync(bucket_name);
    }

    if created > 0 {
        session.write(|s| {
            s.push_flash(
                "success",
                format!(
                    "Created {} replication rule(s) for {}.",
                    created,
                    if peer.display_name.is_empty() {
                        peer.site_id.as_str()
                    } else {
                        peer.display_name.as_str()
                    }
                ),
            )
        });
    }
    Redirect::to("/ui/sites").into_response()
}

pub async fn docs_page(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
) -> Response {
    let mut ctx = page_context(&state, &session, "ui.docs_page");
    let (api_base, api_host) = parse_api_base(&state);
    ctx.insert("api_base", &api_base);
    ctx.insert("api_host", &api_host);
    render(&state, "docs.html", &ctx)
}

#[derive(serde::Deserialize)]
pub struct CreateBucketForm {
    pub bucket_name: String,
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn create_bucket(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let wants_json = wants_json(&headers);
    let form = match parse_form_any(&headers, body).await {
        Ok(fields) => CreateBucketForm {
            bucket_name: fields.get("bucket_name").cloned().unwrap_or_default(),
            csrf_token: fields.get("csrf_token").cloned().unwrap_or_default(),
        },
        Err(message) => {
            if wants_json {
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({ "error": message })),
                )
                    .into_response();
            }
            session.write(|s| s.push_flash("danger", message));
            return Redirect::to("/ui/buckets").into_response();
        }
    };
    let bucket_name = form.bucket_name.trim().to_string();

    if bucket_name.is_empty() {
        let message = "Bucket name is required".to_string();
        if wants_json {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({ "error": message })),
            )
                .into_response();
        }
        session.write(|s| s.push_flash("danger", message));
        return Redirect::to("/ui/buckets").into_response();
    }

    match state.storage.create_bucket(&bucket_name).await {
        Ok(()) => {
            let message = format!("Bucket '{}' created.", bucket_name);
            if wants_json {
                return axum::Json(json!({
                    "success": true,
                    "message": message,
                    "bucket_name": bucket_name,
                }))
                .into_response();
            }
            session.write(|s| s.push_flash("success", message));
        }
        Err(e) => {
            let message = format!("Failed to create bucket: {}", e);
            if wants_json {
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({ "error": message })),
                )
                    .into_response();
            }
            session.write(|s| s.push_flash("danger", message));
        }
    }
    Redirect::to("/ui/buckets").into_response()
}

#[derive(serde::Deserialize)]
pub struct UpdateBucketVersioningForm {
    pub state: String,
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn delete_bucket(
    State(state): State<AppState>,
    Path(bucket_name): Path<String>,
) -> Response {
    match state.storage.delete_bucket(&bucket_name).await {
        Ok(()) => axum::Json(json!({
            "ok": true,
            "message": format!("Bucket '{}' deleted.", bucket_name),
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn update_bucket_versioning(
    State(state): State<AppState>,
    Path(bucket_name): Path<String>,
    axum::extract::Form(form): axum::extract::Form<UpdateBucketVersioningForm>,
) -> Response {
    let enabled = form.state.eq_ignore_ascii_case("enable");
    match state.storage.set_versioning(&bucket_name, enabled).await {
        Ok(()) => axum::Json(json!({
            "ok": true,
            "enabled": enabled,
            "message": if enabled { "Versioning enabled." } else { "Versioning suspended." },
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

fn empty_string_as_none<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    use serde::Deserialize;
    let opt = Option::<String>::deserialize(deserializer)?;
    match opt.as_deref() {
        None | Some("") => Ok(None),
        Some(s) => s.parse::<T>().map(Some).map_err(serde::de::Error::custom),
    }
}

#[derive(serde::Deserialize)]
pub struct UpdateBucketQuotaForm {
    pub action: String,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub max_mb: Option<u64>,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub max_objects: Option<u64>,
    #[serde(default)]
    pub csrf_token: String,
}

#[derive(serde::Deserialize)]
pub struct UpdateBucketReplicationForm {
    pub action: String,
    #[serde(default)]
    pub target_connection_id: String,
    #[serde(default)]
    pub target_bucket: String,
    #[serde(default)]
    pub replication_mode: String,
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn update_bucket_replication(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
    headers: HeaderMap,
    Form(form): Form<UpdateBucketReplicationForm>,
) -> Response {
    let wants_json = wants_json(&headers);

    let respond = |ok: bool, status: StatusCode, message: String, extra: Value| -> Response {
        if wants_json {
            let mut payload = json!({
                "ok": ok,
                "message": message,
            });
            if let Some(obj) = payload.as_object_mut() {
                if let Some(extra_obj) = extra.as_object() {
                    for (key, value) in extra_obj {
                        obj.insert(key.clone(), value.clone());
                    }
                }
            }
            return (status, axum::Json(payload)).into_response();
        }

        session.write(|s| s.push_flash(if ok { "success" } else { "danger" }, message));
        bucket_tab_redirect(&bucket_name, "replication")
    };

    match form.action.as_str() {
        "delete" => {
            state.replication.delete_rule(&bucket_name);
            respond(
                true,
                StatusCode::OK,
                "Replication configuration removed.".to_string(),
                json!({ "action": "delete", "enabled": false }),
            )
        }
        "pause" => {
            let Some(mut rule) = state.replication.get_rule(&bucket_name) else {
                return respond(
                    true,
                    StatusCode::OK,
                    "No replication configuration to pause.".to_string(),
                    json!({ "action": "pause", "enabled": false, "no_op": true }),
                );
            };
            rule.enabled = false;
            state.replication.set_rule(rule);
            respond(
                true,
                StatusCode::OK,
                "Replication paused.".to_string(),
                json!({ "action": "pause", "enabled": false }),
            )
        }
        "resume" => {
            let Some(mut rule) = state.replication.get_rule(&bucket_name) else {
                return respond(
                    true,
                    StatusCode::OK,
                    "No replication configuration to resume.".to_string(),
                    json!({ "action": "resume", "enabled": false, "no_op": true }),
                );
            };
            rule.enabled = true;
            let mode = rule.mode.clone();
            state.replication.set_rule(rule);

            let message = if mode == crate::services::replication::MODE_ALL {
                state
                    .replication
                    .clone()
                    .schedule_existing_objects_sync(bucket_name.clone());
                "Replication resumed. Existing object sync will continue in the background."
                    .to_string()
            } else {
                "Replication resumed.".to_string()
            };

            respond(
                true,
                StatusCode::OK,
                message,
                json!({ "action": "resume", "enabled": true, "mode": mode }),
            )
        }
        "create" => {
            let target_connection_id = form.target_connection_id.trim();
            let target_bucket = form.target_bucket.trim();
            if target_connection_id.is_empty() || target_bucket.is_empty() {
                return respond(
                    false,
                    StatusCode::BAD_REQUEST,
                    "Target connection and bucket are required.".to_string(),
                    json!({ "error": "Target connection and bucket are required" }),
                );
            }
            if state.connections.get(target_connection_id).is_none() {
                return respond(
                    false,
                    StatusCode::BAD_REQUEST,
                    "Target connection was not found.".to_string(),
                    json!({ "error": "Target connection was not found" }),
                );
            }

            let mode = match form.replication_mode.trim() {
                crate::services::replication::MODE_ALL => crate::services::replication::MODE_ALL,
                crate::services::replication::MODE_BIDIRECTIONAL => {
                    crate::services::replication::MODE_BIDIRECTIONAL
                }
                _ => crate::services::replication::MODE_NEW_ONLY,
            };

            state
                .replication
                .set_rule(crate::services::replication::ReplicationRule {
                    bucket_name: bucket_name.clone(),
                    target_connection_id: target_connection_id.to_string(),
                    target_bucket: target_bucket.to_string(),
                    enabled: true,
                    mode: mode.to_string(),
                    created_at: Some(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs_f64())
                            .unwrap_or(0.0),
                    ),
                    stats: crate::services::replication::ReplicationStats::default(),
                    sync_deletions: true,
                    last_pull_at: None,
                    filter_prefix: None,
                });

            let message = if mode == crate::services::replication::MODE_ALL {
                state
                    .replication
                    .clone()
                    .schedule_existing_objects_sync(bucket_name.clone());
                "Replication configured. Existing object sync will continue in the background."
                    .to_string()
            } else {
                "Replication configured. New uploads will be replicated.".to_string()
            };

            respond(
                true,
                StatusCode::OK,
                message,
                json!({
                    "action": "create",
                    "enabled": true,
                    "mode": mode,
                    "target_connection_id": target_connection_id,
                    "target_bucket": target_bucket,
                }),
            )
        }
        _ => respond(
            false,
            StatusCode::BAD_REQUEST,
            "Invalid replication action.".to_string(),
            json!({ "error": "Invalid action" }),
        ),
    }
}

#[derive(serde::Deserialize)]
pub struct ConnectionForm {
    pub name: String,
    pub endpoint_url: String,
    pub access_key: String,
    #[serde(default)]
    pub secret_key: String,
    #[serde(default = "default_connection_region")]
    pub region: String,
    #[serde(default)]
    pub csrf_token: String,
}

fn default_connection_region() -> String {
    "us-east-1".to_string()
}

pub async fn create_connection(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    headers: HeaderMap,
    Form(form): Form<ConnectionForm>,
) -> Response {
    let wants_json = wants_json(&headers);
    let name = form.name.trim();
    let endpoint = form.endpoint_url.trim();
    let access_key = form.access_key.trim();
    let secret_key = form.secret_key.trim();
    let region = form.region.trim();

    if name.is_empty() || endpoint.is_empty() || access_key.is_empty() || secret_key.is_empty() {
        let message = "All connection fields are required.".to_string();
        if wants_json {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({ "error": message })),
            )
                .into_response();
        }
        session.write(|s| s.push_flash("danger", message));
        return Redirect::to("/ui/connections").into_response();
    }

    let connection = crate::stores::connections::RemoteConnection {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_string(),
        endpoint_url: endpoint.to_string(),
        access_key: access_key.to_string(),
        secret_key: secret_key.to_string(),
        region: if region.is_empty() {
            default_connection_region()
        } else {
            region.to_string()
        },
    };

    match state.connections.add(connection.clone()) {
        Ok(()) => {
            let message = format!("Connection '{}' created.", connection.name);
            if wants_json {
                axum::Json(json!({
                    "ok": true,
                    "message": message,
                    "connection": {
                        "id": connection.id,
                        "name": connection.name,
                        "endpoint_url": connection.endpoint_url,
                        "access_key": connection.access_key,
                        "region": connection.region,
                    }
                }))
                .into_response()
            } else {
                session.write(|s| s.push_flash("success", message));
                Redirect::to("/ui/connections").into_response()
            }
        }
        Err(err) => {
            let message = format!("Failed to create connection: {}", err);
            if wants_json {
                (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({ "error": message })),
                )
                    .into_response()
            } else {
                session.write(|s| s.push_flash("danger", message));
                Redirect::to("/ui/connections").into_response()
            }
        }
    }
}

pub async fn update_connection(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Path(connection_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<ConnectionForm>,
) -> Response {
    let wants_json = wants_json(&headers);
    let Some(mut connection) = state.connections.get(&connection_id) else {
        let message = "Connection not found.".to_string();
        if wants_json {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({ "error": message })),
            )
                .into_response();
        }
        session.write(|s| s.push_flash("danger", message));
        return Redirect::to("/ui/connections").into_response();
    };

    let name = form.name.trim();
    let endpoint = form.endpoint_url.trim();
    let access_key = form.access_key.trim();
    let secret_key = form.secret_key.trim();
    let region = form.region.trim();

    if name.is_empty() || endpoint.is_empty() || access_key.is_empty() {
        let message = "Name, endpoint, and access key are required.".to_string();
        if wants_json {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({ "error": message })),
            )
                .into_response();
        }
        session.write(|s| s.push_flash("danger", message));
        return Redirect::to("/ui/connections").into_response();
    }

    connection.name = name.to_string();
    connection.endpoint_url = endpoint.to_string();
    connection.access_key = access_key.to_string();
    if !secret_key.is_empty() {
        connection.secret_key = secret_key.to_string();
    }
    connection.region = if region.is_empty() {
        default_connection_region()
    } else {
        region.to_string()
    };

    match state.connections.add(connection.clone()) {
        Ok(()) => {
            let message = format!("Connection '{}' updated.", connection.name);
            if wants_json {
                axum::Json(json!({
                    "ok": true,
                    "message": message,
                    "connection": {
                        "id": connection.id,
                        "name": connection.name,
                        "endpoint_url": connection.endpoint_url,
                        "access_key": connection.access_key,
                        "region": connection.region,
                    }
                }))
                .into_response()
            } else {
                session.write(|s| s.push_flash("success", message));
                Redirect::to("/ui/connections").into_response()
            }
        }
        Err(err) => {
            let message = format!("Failed to update connection: {}", err);
            if wants_json {
                (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({ "error": message })),
                )
                    .into_response()
            } else {
                session.write(|s| s.push_flash("danger", message));
                Redirect::to("/ui/connections").into_response()
            }
        }
    }
}

#[derive(serde::Deserialize, Default)]
pub struct DeleteConnectionForm {
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn delete_connection(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Path(connection_id): Path<String>,
    headers: HeaderMap,
    Form(_form): Form<DeleteConnectionForm>,
) -> Response {
    let wants_json = wants_json(&headers);
    match state.connections.delete(&connection_id) {
        Ok(true) => {
            let message = "Connection deleted.".to_string();
            if wants_json {
                axum::Json(json!({ "ok": true, "message": message })).into_response()
            } else {
                session.write(|s| s.push_flash("success", message));
                Redirect::to("/ui/connections").into_response()
            }
        }
        Ok(false) => {
            let message = "Connection not found.".to_string();
            if wants_json {
                (
                    StatusCode::NOT_FOUND,
                    axum::Json(json!({ "error": message })),
                )
                    .into_response()
            } else {
                session.write(|s| s.push_flash("danger", message));
                Redirect::to("/ui/connections").into_response()
            }
        }
        Err(err) => {
            let message = format!("Failed to delete connection: {}", err);
            if wants_json {
                (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({ "error": message })),
                )
                    .into_response()
            } else {
                session.write(|s| s.push_flash("danger", message));
                Redirect::to("/ui/connections").into_response()
            }
        }
    }
}

#[derive(serde::Deserialize)]
pub struct WebsiteDomainForm {
    pub bucket: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub csrf_token: String,
}

#[derive(serde::Deserialize, Default)]
pub struct WebsiteDomainDeleteForm {
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn create_website_domain(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Form(form): Form<WebsiteDomainForm>,
) -> Response {
    let Some(store) = &state.website_domains else {
        session.write(|s| s.push_flash("danger", "Website hosting is not enabled."));
        return Redirect::to("/ui/website-domains").into_response();
    };

    let domain = crate::services::website_domains::normalize_domain(&form.domain);
    let bucket = form.bucket.trim().to_string();
    if !crate::services::website_domains::is_valid_domain(&domain) {
        session.write(|s| s.push_flash("danger", "Enter a valid domain name."));
        return Redirect::to("/ui/website-domains").into_response();
    }
    match state.storage.bucket_exists(&bucket).await {
        Ok(true) => {}
        _ => {
            session
                .write(|s| s.push_flash("danger", format!("Bucket '{}' does not exist.", bucket)));
            return Redirect::to("/ui/website-domains").into_response();
        }
    }
    store.set_mapping(&domain, &bucket);
    session.write(|s| {
        s.push_flash(
            "success",
            format!("Domain '{}' mapped to '{}'.", domain, bucket),
        )
    });
    Redirect::to("/ui/website-domains").into_response()
}

pub async fn update_website_domain(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Path(domain): Path<String>,
    Form(form): Form<WebsiteDomainForm>,
) -> Response {
    let Some(store) = &state.website_domains else {
        session.write(|s| s.push_flash("danger", "Website hosting is not enabled."));
        return Redirect::to("/ui/website-domains").into_response();
    };

    let domain = crate::services::website_domains::normalize_domain(&domain);
    let bucket = form.bucket.trim().to_string();
    match state.storage.bucket_exists(&bucket).await {
        Ok(true) => {}
        _ => {
            session
                .write(|s| s.push_flash("danger", format!("Bucket '{}' does not exist.", bucket)));
            return Redirect::to("/ui/website-domains").into_response();
        }
    }
    if store.get_bucket(&domain).is_none() {
        session.write(|s| s.push_flash("danger", format!("Domain '{}' was not found.", domain)));
        return Redirect::to("/ui/website-domains").into_response();
    }
    store.set_mapping(&domain, &bucket);
    session.write(|s| s.push_flash("success", format!("Domain '{}' updated.", domain)));
    Redirect::to("/ui/website-domains").into_response()
}

pub async fn delete_website_domain(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Path(domain): Path<String>,
    Form(_form): Form<WebsiteDomainDeleteForm>,
) -> Response {
    let Some(store) = &state.website_domains else {
        session.write(|s| s.push_flash("danger", "Website hosting is not enabled."));
        return Redirect::to("/ui/website-domains").into_response();
    };

    let domain = crate::services::website_domains::normalize_domain(&domain);
    if store.delete_mapping(&domain) {
        session.write(|s| s.push_flash("success", format!("Domain '{}' removed.", domain)));
    } else {
        session.write(|s| s.push_flash("danger", format!("Domain '{}' was not found.", domain)));
    }
    Redirect::to("/ui/website-domains").into_response()
}

pub async fn update_bucket_quota(
    State(state): State<AppState>,
    Path(bucket_name): Path<String>,
    axum::extract::Form(form): axum::extract::Form<UpdateBucketQuotaForm>,
) -> Response {
    let mut config = match state.storage.get_bucket_config(&bucket_name).await {
        Ok(cfg) => cfg,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    if form.action.eq_ignore_ascii_case("remove") {
        config.quota = None;
    } else {
        config.quota = Some(myfsio_common::types::QuotaConfig {
            max_bytes: form.max_mb.map(|mb| mb.saturating_mul(1024 * 1024)),
            max_objects: form.max_objects,
        });
    }

    match state.storage.set_bucket_config(&bucket_name, &config).await {
        Ok(()) => axum::Json(json!({
            "ok": true,
            "has_quota": config.quota.is_some(),
            "max_bytes": config.quota.as_ref().and_then(|q| q.max_bytes),
            "max_objects": config.quota.as_ref().and_then(|q| q.max_objects),
            "message": if config.quota.is_some() { "Quota settings saved." } else { "Quota removed." },
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct UpdateBucketEncryptionForm {
    pub action: String,
    #[serde(default)]
    pub algorithm: String,
    #[serde(default)]
    pub kms_key_id: String,
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn update_bucket_encryption(
    State(state): State<AppState>,
    Path(bucket_name): Path<String>,
    axum::extract::Form(form): axum::extract::Form<UpdateBucketEncryptionForm>,
) -> Response {
    let mut config = match state.storage.get_bucket_config(&bucket_name).await {
        Ok(cfg) => cfg,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    if form.action.eq_ignore_ascii_case("disable") {
        config.encryption = None;
    } else {
        let mut inner = json!({
            "SSEAlgorithm": if form.algorithm == "aws:kms" { "aws:kms" } else { "AES256" }
        });
        if form.algorithm == "aws:kms" && !form.kms_key_id.trim().is_empty() {
            inner["KMSMasterKeyID"] = Value::String(form.kms_key_id.trim().to_string());
        }
        config.encryption = Some(json!({
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": inner
            }]
        }));
    }

    match state.storage.set_bucket_config(&bucket_name, &config).await {
        Ok(()) => {
            let algorithm = config
                .encryption
                .as_ref()
                .and_then(|value| value.get("Rules"))
                .and_then(|rules| rules.as_array())
                .and_then(|rules| rules.first())
                .and_then(|rule| rule.get("ApplyServerSideEncryptionByDefault"))
                .and_then(|inner| inner.get("SSEAlgorithm"))
                .and_then(|v| v.as_str())
                .unwrap_or("AES256");
            axum::Json(json!({
                "ok": true,
                "enabled": config.encryption.is_some(),
                "algorithm": algorithm,
                "message": if config.encryption.is_some() { "Encryption settings saved." } else { "Encryption disabled." },
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct UpdateBucketPolicyForm {
    pub mode: String,
    #[serde(default)]
    pub policy_document: String,
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn update_bucket_policy(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
    headers: HeaderMap,
    axum::extract::Form(form): axum::extract::Form<UpdateBucketPolicyForm>,
) -> Response {
    let wants_json = wants_json(&headers);
    let redirect_url = format!("/ui/buckets/{}?tab=permissions", bucket_name);
    let mut config = match state.storage.get_bucket_config(&bucket_name).await {
        Ok(cfg) => cfg,
        Err(e) => {
            let message = e.to_string();
            if wants_json {
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({ "error": message })),
                )
                    .into_response();
            }
            session.write(|s| s.push_flash("danger", message));
            return Redirect::to(&redirect_url).into_response();
        }
    };

    if form.mode.eq_ignore_ascii_case("delete") {
        config.policy = None;
    } else {
        let policy: Value = match serde_json::from_str(&form.policy_document) {
            Ok(value) => value,
            Err(e) => {
                let message = format!("Invalid policy JSON: {}", e);
                if wants_json {
                    return (
                        StatusCode::BAD_REQUEST,
                        axum::Json(json!({ "error": message })),
                    )
                        .into_response();
                }
                session.write(|s| s.push_flash("danger", message));
                return Redirect::to(&redirect_url).into_response();
            }
        };
        config.policy = Some(policy);
    }

    match state.storage.set_bucket_config(&bucket_name, &config).await {
        Ok(()) => {
            let message = if config.policy.is_some() {
                "Bucket policy saved."
            } else {
                "Bucket policy deleted."
            };
            if wants_json {
                axum::Json(json!({
                    "ok": true,
                    "message": message,
                }))
                .into_response()
            } else {
                session.write(|s| s.push_flash("success", message));
                Redirect::to(&redirect_url).into_response()
            }
        }
        Err(e) => {
            let message = e.to_string();
            if wants_json {
                (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({ "error": message })),
                )
                    .into_response()
            } else {
                session.write(|s| s.push_flash("danger", message));
                Redirect::to(&redirect_url).into_response()
            }
        }
    }
}

#[derive(serde::Deserialize)]
pub struct UpdateBucketWebsiteForm {
    pub action: String,
    #[serde(default)]
    pub index_document: String,
    #[serde(default)]
    pub error_document: String,
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn update_bucket_website(
    State(state): State<AppState>,
    Path(bucket_name): Path<String>,
    axum::extract::Form(form): axum::extract::Form<UpdateBucketWebsiteForm>,
) -> Response {
    let mut config = match state.storage.get_bucket_config(&bucket_name).await {
        Ok(cfg) => cfg,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    if form.action.eq_ignore_ascii_case("disable") {
        config.website = None;
    } else {
        let index_document = if form.index_document.trim().is_empty() {
            "index.html".to_string()
        } else {
            form.index_document.trim().to_string()
        };
        let error_document = form.error_document.trim().to_string();
        config.website = Some(json!({
            "index_document": index_document,
            "error_document": if error_document.is_empty() { Value::Null } else { Value::String(error_document) }
        }));
    }

    match state.storage.set_bucket_config(&bucket_name, &config).await {
        Ok(()) => {
            let website = config.website.clone().unwrap_or(Value::Null);
            axum::Json(json!({
                "ok": true,
                "enabled": !website.is_null(),
                "index_document": website.get("index_document").and_then(|v| v.as_str()).unwrap_or("index.html"),
                "error_document": website.get("error_document").and_then(|v| v.as_str()).unwrap_or(""),
                "message": if website.is_null() { "Website hosting disabled." } else { "Website settings saved." },
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}
