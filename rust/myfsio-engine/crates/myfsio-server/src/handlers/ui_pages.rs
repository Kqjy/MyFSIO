use std::collections::HashMap;

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
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
        ("ui.update_bucket_versioning", "/ui/buckets/{bucket_name}/versioning"),
        ("ui.update_bucket_quota", "/ui/buckets/{bucket_name}/quota"),
        ("ui.update_bucket_encryption", "/ui/buckets/{bucket_name}/encryption"),
        ("ui.update_bucket_policy", "/ui/buckets/{bucket_name}/policy"),
        ("ui.update_bucket_replication", "/ui/buckets/{bucket_name}/replication"),
        ("ui.update_bucket_website", "/ui/buckets/{bucket_name}/website"),
        ("ui.upload_object", "/ui/buckets/{bucket_name}/upload"),
        ("ui.bulk_delete_objects", "/ui/buckets/{bucket_name}/bulk-delete"),
        ("ui.bulk_download_objects", "/ui/buckets/{bucket_name}/bulk-download"),
        ("ui.archived_objects", "/ui/buckets/{bucket_name}/archived"),
        ("ui.initiate_multipart_upload", "/ui/buckets/{bucket_name}/multipart/initiate"),
        ("ui.upload_multipart_part", "/ui/buckets/{bucket_name}/multipart/{upload_id}/part/{part_number}"),
        ("ui.complete_multipart_upload", "/ui/buckets/{bucket_name}/multipart/{upload_id}/complete"),
        ("ui.abort_multipart_upload", "/ui/buckets/{bucket_name}/multipart/{upload_id}/abort"),
        ("ui.get_lifecycle_history", "/ui/buckets/{bucket_name}/lifecycle/history"),
        ("ui.get_replication_status", "/ui/buckets/{bucket_name}/replication/status"),
        ("ui.get_replication_failures", "/ui/buckets/{bucket_name}/replication/failures"),
        ("ui.clear_replication_failures", "/ui/buckets/{bucket_name}/replication/failures/clear"),
        ("ui.retry_all_replication_failures", "/ui/buckets/{bucket_name}/replication/failures/retry-all"),
        ("ui.retry_replication_failure", "/ui/buckets/{bucket_name}/replication/failures/retry"),
        ("ui.dismiss_replication_failure", "/ui/buckets/{bucket_name}/replication/failures/dismiss"),
        ("ui.replication_wizard", "/ui/replication/new"),
        ("ui.create_peer_replication_rules", "/ui/replication/create"),
        ("ui.iam_dashboard", "/ui/iam"),
        ("ui.create_iam_user", "/ui/iam/users"),
        ("ui.update_iam_user", "/ui/iam/users/{user_id}"),
        ("ui.delete_iam_user", "/ui/iam/users/{user_id}/delete"),
        ("ui.update_iam_policies", "/ui/iam/users/{user_id}/policies"),
        ("ui.update_iam_expiry", "/ui/iam/users/{user_id}/expiry"),
        ("ui.rotate_iam_secret", "/ui/iam/users/{user_id}/rotate-secret"),
        ("ui.connections_dashboard", "/ui/connections"),
        ("ui.create_connection", "/ui/connections/create"),
        ("ui.update_connection", "/ui/connections/{connection_id}"),
        ("ui.delete_connection", "/ui/connections/{connection_id}/delete"),
        ("ui.test_connection", "/ui/connections/{connection_id}/test"),
        ("ui.sites_dashboard", "/ui/sites"),
        ("ui.update_local_site", "/ui/sites/local"),
        ("ui.add_peer_site", "/ui/sites/peers"),
        ("ui.metrics_dashboard", "/ui/metrics"),
        ("ui.system_dashboard", "/ui/system"),
        ("ui.system_gc_status", "/ui/system/gc/status"),
        ("ui.system_gc_run", "/ui/system/gc/run"),
        ("ui.system_gc_history", "/ui/system/gc/history"),
        ("ui.system_integrity_status", "/ui/system/integrity/status"),
        ("ui.system_integrity_run", "/ui/system/integrity/run"),
        ("ui.system_integrity_history", "/ui/system/integrity/history"),
        ("ui.website_domains_dashboard", "/ui/website-domains"),
        ("ui.create_website_domain", "/ui/website-domains/create"),
        ("ui.update_website_domain", "/ui/website-domains/{domain}"),
        ("ui.delete_website_domain", "/ui/website-domains/{domain}/delete"),
        ("ui.docs_page", "/ui/docs"),
    ]);
}

fn page_context(
    state: &AppState,
    session: &SessionHandle,
    endpoint: &str,
) -> Context {
    let mut ctx = base_context(session, Some(endpoint));
    ctx.insert("principal", &session.read(|s| s.user_id.clone()));
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

    let items: Vec<Value> = buckets
        .iter()
        .map(|b| {
            json!({
                "meta": {
                    "name": b.name,
                    "creation_date": b.creation_date.to_rfc3339(),
                },
                "summary": {
                    "human_size": "0 B",
                    "objects": 0,
                },
                "detail_url": format!("/ui/buckets/{}", b.name),
                "access_badge": "bg-secondary bg-opacity-10 text-secondary",
                "access_label": "Private",
            })
        })
        .collect();

    ctx.insert("buckets", &items);
    render(&state, "buckets.html", &ctx)
}

pub async fn bucket_detail(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
) -> Response {
    if !matches!(state.storage.bucket_exists(&bucket_name).await, Ok(true)) {
        return (StatusCode::NOT_FOUND, "Bucket not found").into_response();
    }

    let mut ctx = page_context(&state, &session, "ui.bucket_detail");
    ctx.insert("bucket_name", &bucket_name);
    ctx.insert("bucket", &json!({ "name": bucket_name }));
    ctx.insert("objects", &Vec::<Value>::new());
    ctx.insert("prefixes", &Vec::<Value>::new());
    ctx.insert("total_objects", &0);
    ctx.insert("total_bytes", &0);
    ctx.insert("max_objects", &Value::Null);
    ctx.insert("max_bytes", &Value::Null);
    ctx.insert("versioning_status", &"Disabled");
    ctx.insert("encryption_config", &json!({ "Rules": [] }));
    ctx.insert("replication_rules", &Vec::<Value>::new());
    ctx.insert("website_config", &Value::Null);
    ctx.insert("bucket_policy", &"");
    ctx.insert("connections", &Vec::<Value>::new());
    ctx.insert("current_prefix", &"");
    ctx.insert("parent_prefix", &"");
    ctx.insert("has_more", &false);
    ctx.insert("next_token", &"");
    ctx.insert("active_tab", &"objects");
    ctx.insert("multipart_uploads", &Vec::<Value>::new());
    render(&state, "bucket_detail.html", &ctx)
}

pub async fn iam_dashboard(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
) -> Response {
    let mut ctx = page_context(&state, &session, "ui.iam_dashboard");
    let users: Vec<Value> = state
        .iam
        .list_users()
        .await
        .into_iter()
        .map(|u| {
            let mut map = u.as_object().cloned().unwrap_or_default();
            map.entry("policies".to_string()).or_insert(Value::Array(Vec::new()));
            map.entry("expires_at".to_string()).or_insert(Value::Null);
            map.entry("is_enabled".to_string()).or_insert(Value::Bool(true));
            map.entry("display_name".to_string())
                .or_insert_with(|| Value::String(String::new()));
            Value::Object(map)
        })
        .collect();
    ctx.insert("users", &users);
    ctx.insert("iam_locked", &false);
    ctx.insert("now_iso", &chrono::Utc::now().to_rfc3339());
    ctx.insert(
        "soon_iso",
        &(chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339(),
    );
    ctx.insert("all_buckets", &Vec::<String>::new());
    render(&state, "iam.html", &ctx)
}

pub async fn sites_dashboard(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
) -> Response {
    let mut ctx = page_context(&state, &session, "ui.sites_dashboard");
    ctx.insert("local_site", &Value::Null);
    ctx.insert("peers", &Vec::<Value>::new());
    ctx.insert("topology", &json!({"sites": [], "connections": []}));
    render(&state, "sites.html", &ctx)
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
    ctx.insert("metrics_enabled", &state.config.metrics_enabled);
    ctx.insert("history", &Vec::<Value>::new());
    ctx.insert("operation_metrics", &Vec::<Value>::new());
    ctx.insert("summary", &json!({}));
    render(&state, "metrics.html", &ctx)
}

pub async fn system_dashboard(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
) -> Response {
    let mut ctx = page_context(&state, &session, "ui.system_dashboard");
    ctx.insert("gc_enabled", &state.config.gc_enabled);
    ctx.insert("integrity_enabled", &state.config.integrity_enabled);
    ctx.insert("gc_history", &Vec::<Value>::new());
    ctx.insert("integrity_history", &Vec::<Value>::new());
    ctx.insert("gc_status", &json!({"running": false}));
    ctx.insert("integrity_status", &json!({"running": false}));
    render(&state, "system.html", &ctx)
}

pub async fn website_domains_dashboard(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
) -> Response {
    let mut ctx = page_context(&state, &session, "ui.website_domains_dashboard");
    ctx.insert("domains", &Vec::<Value>::new());
    render(&state, "website_domains.html", &ctx)
}

pub async fn replication_wizard(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
) -> Response {
    let mut ctx = page_context(&state, &session, "ui.replication_wizard");
    ctx.insert("connections", &Vec::<Value>::new());
    ctx.insert("local_site", &Value::Null);
    ctx.insert("peers", &Vec::<Value>::new());
    render(&state, "replication_wizard.html", &ctx)
}

pub async fn docs_page(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
) -> Response {
    let ctx = page_context(&state, &session, "ui.docs_page");
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
    axum::extract::Form(form): axum::extract::Form<CreateBucketForm>,
) -> Response {
    match state.storage.create_bucket(form.bucket_name.trim()).await {
        Ok(()) => {
            session.write(|s| s.push_flash("success", format!("Bucket '{}' created.", form.bucket_name)));
        }
        Err(e) => {
            session.write(|s| s.push_flash("danger", format!("Failed to create bucket: {}", e)));
        }
    }
    Redirect::to("/ui/buckets").into_response()
}

pub async fn stub_post(
    Extension(session): Extension<SessionHandle>,
) -> Response {
    session.write(|s| s.push_flash("info", "This action is not yet implemented in the Rust UI."));
    Redirect::to("/ui/buckets").into_response()
}

#[derive(serde::Deserialize)]
pub struct QueryArgs(#[serde(default)] pub HashMap<String, String>);

pub async fn json_stub(Query(_q): Query<QueryArgs>) -> Response {
    axum::Json(json!({"status": "not_implemented", "items": []})).into_response()
}
