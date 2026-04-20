use std::error::Error as StdError;
use std::path::PathBuf;

use myfsio_server::templates::TemplateEngine;
use serde_json::{json, Value};
use tera::Context;

fn engine() -> TemplateEngine {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("templates");
    path.push("*.html");
    let glob = path.to_string_lossy().replace('\\', "/");
    let engine = TemplateEngine::new(&glob).expect("template parse");
    myfsio_server::handlers::ui_pages::register_ui_endpoints(&engine);
    engine
}

fn base_ctx() -> Context {
    let mut ctx = Context::new();
    ctx.insert("csrf_token_value", &"test-csrf");
    ctx.insert("is_authenticated", &true);
    ctx.insert("current_user", &"test");
    ctx.insert("current_user_display_name", &"Test User");
    ctx.insert("current_endpoint", &"");
    ctx.insert("request_args", &serde_json::json!({}));
    ctx.insert(
        "principal",
        &json!({
            "access_key": "AKIATESTTEST",
            "user_id": "u-test",
            "display_name": "Test Admin",
            "is_admin": true
        }),
    );
    ctx.insert("can_manage_iam", &true);
    ctx.insert("can_manage_replication", &true);
    ctx.insert("can_manage_sites", &true);
    ctx.insert("can_manage_encryption", &false);
    ctx.insert("website_hosting_nav", &false);
    ctx.insert("encryption_enabled", &false);
    ctx.insert("kms_enabled", &false);
    ctx.insert("flashed_messages", &Vec::<Value>::new());
    ctx.insert("null", &Value::Null);
    ctx.insert("none", &Value::Null);
    ctx
}

fn format_err(e: tera::Error) -> String {
    let mut out = format!("{}", e);
    let mut src = StdError::source(&e);
    while let Some(s) = src {
        out.push_str("\n  caused by: ");
        out.push_str(&s.to_string());
        src = s.source();
    }
    out
}

fn render_or_panic(tmpl: &str, ctx: &Context) {
    let e = engine();
    match e.render(tmpl, ctx) {
        Ok(_) => {}
        Err(err) => panic!("{} failed:\n{}", tmpl, format_err(err)),
    }
}

fn render_to_string_or_panic(tmpl: &str, ctx: &Context) -> String {
    let e = engine();
    match e.render(tmpl, ctx) {
        Ok(rendered) => rendered,
        Err(err) => panic!("{} failed:\n{}", tmpl, format_err(err)),
    }
}

#[test]
fn render_buckets() {
    let mut ctx = base_ctx();
    ctx.insert(
        "buckets",
        &json!([{
            "meta": {"name": "b1", "creation_date": "2024-01-01T00:00:00Z"},
            "summary": {"human_size": "0 B", "objects": 0},
            "detail_url": "/ui/buckets/b1",
            "access_badge": "bg-secondary",
            "access_label": "Private"
        }]),
    );
    render_or_panic("buckets.html", &ctx);
}

#[test]
fn render_connections() {
    let mut ctx = base_ctx();
    ctx.insert(
        "connections",
        &json!([{
            "id": "c1",
            "name": "Prod",
            "endpoint_url": "https://s3.example.com",
            "region": "us-east-1",
            "access_key": "AKIAEXAMPLEKEY12345"
        }]),
    );
    render_or_panic("connections.html", &ctx);
}

#[test]
fn render_iam() {
    let mut ctx = base_ctx();
    ctx.insert(
        "users",
        &json!([{
            "user_id": "u-1",
            "access_key": "AKIA1",
            "display_name": "Alice",
            "enabled": true,
            "is_enabled": true,
            "expires_at": "2026-04-21T00:00:00Z",
            "is_admin": true,
            "is_expired": false,
            "is_expiring_soon": true,
            "access_keys": [{"access_key": "AKIA1", "status": "active", "created_at": "2024-01-01"}],
            "policy_count": 1,
            "policies": [{"bucket": "*", "actions": ["*"], "prefix": "*"}]
        }]),
    );
    ctx.insert("iam_locked", &false);
    ctx.insert("locked_reason", &"");
    ctx.insert("iam_disabled", &false);
    ctx.insert("all_buckets", &Vec::<String>::new());
    ctx.insert("disclosed_secret", &Value::Null);
    ctx.insert("config_document", &"");
    ctx.insert("config_summary", &json!({"user_count": 1}));
    let rendered = render_to_string_or_panic("iam.html", &ctx);
    assert!(rendered.contains("data-user-id=\"u-1\""));
    assert!(rendered.contains("data-access-key=\"AKIA1\""));
    assert!(rendered.contains("Expiring soon"));
}

#[test]
fn render_metrics() {
    let mut ctx = base_ctx();
    ctx.insert("metrics_enabled", &false);
    ctx.insert("metrics_history_enabled", &false);
    ctx.insert("operation_metrics_enabled", &false);
    ctx.insert("history", &Vec::<Value>::new());
    ctx.insert("operation_metrics", &Vec::<Value>::new());
    ctx.insert("cpu_percent", &0);
    ctx.insert(
        "memory",
        &json!({ "percent": 0, "total": "0 B", "used": "0 B" }),
    );
    ctx.insert(
        "disk",
        &json!({ "percent": 0, "free": "0 B", "total": "0 B" }),
    );
    ctx.insert(
        "app",
        &json!({
            "buckets": 0, "objects": 0, "storage_used": "0 B",
            "uptime_days": 0, "versions": 0
        }),
    );
    ctx.insert("has_issues", &false);
    ctx.insert(
        "summary",
        &json!({
            "app": {"buckets": 0, "objects": 0, "storage_used": "0 B", "uptime_days": 0, "versions": 0},
            "cpu_percent": 0,
            "disk": {"free": 0, "percent": 0, "total": 0},
            "memory": {"percent": 0, "total": 0, "used": 0},
            "has_issues": false
        }),
    );
    render_or_panic("metrics.html", &ctx);
}

#[test]
fn render_system() {
    let mut ctx = base_ctx();
    ctx.insert("app_version", &"0.1.0");
    ctx.insert("display_timezone", &"UTC");
    ctx.insert("platform", &"linux");
    ctx.insert("python_version", &"n/a");
    ctx.insert("storage_root", &"/tmp/data");
    ctx.insert("has_rust", &true);
    ctx.insert("total_issues", &0);
    ctx.insert("features", &Vec::<Value>::new());
    ctx.insert("gc_history", &Vec::<Value>::new());
    ctx.insert("integrity_history", &Vec::<Value>::new());
    ctx.insert(
        "gc_status",
        &json!({
            "dry_run": false, "enabled": false, "interval_hours": 6,
            "lock_file_max_age_hours": 1, "multipart_max_age_days": 7,
            "scanning": false, "temp_file_max_age_hours": 24
        }),
    );
    ctx.insert(
        "integrity_status",
        &json!({
            "auto_heal": false, "batch_size": 100, "dry_run": false,
            "enabled": false, "interval_hours": 24, "scanning": false
        }),
    );
    render_or_panic("system.html", &ctx);
}

#[test]
fn render_sites() {
    let mut ctx = base_ctx();
    ctx.insert("local_site", &Value::Null);
    ctx.insert("peers", &Vec::<Value>::new());
    ctx.insert("peers_with_stats", &Vec::<Value>::new());
    ctx.insert("connections", &Vec::<Value>::new());
    ctx.insert("config_site_id", &"");
    ctx.insert("config_site_endpoint", &"");
    ctx.insert("config_site_region", &"us-east-1");
    render_or_panic("sites.html", &ctx);
}

#[test]
fn render_website_domains() {
    let mut ctx = base_ctx();
    ctx.insert("mappings", &Vec::<Value>::new());
    ctx.insert("buckets", &Vec::<String>::new());
    render_or_panic("website_domains.html", &ctx);
}

#[test]
fn render_replication_wizard() {
    let mut ctx = base_ctx();
    ctx.insert("connections", &Vec::<Value>::new());
    ctx.insert("local_site", &Value::Null);
    ctx.insert("peers", &Vec::<Value>::new());
    ctx.insert("buckets", &Vec::<Value>::new());
    ctx.insert(
        "peer",
        &json!({
            "site_id": "peer-1",
            "display_name": "Peer One",
            "endpoint": "https://peer.example.com",
            "region": "us-east-1"
        }),
    );
    ctx.insert(
        "connection",
        &json!({
            "id": "c1", "name": "Prod",
            "endpoint_url": "https://s3.example.com",
            "region": "us-east-1",
            "access_key": "AKIA"
        }),
    );
    render_or_panic("replication_wizard.html", &ctx);
}

#[test]
fn render_docs() {
    let mut ctx = base_ctx();
    ctx.insert("api_base", &"http://127.0.0.1:9000");
    ctx.insert("api_host", &"127.0.0.1:9000");
    render_or_panic("docs.html", &ctx);
}

#[test]
fn render_bucket_detail() {
    let mut ctx = base_ctx();
    ctx.insert("bucket_name", &"my-bucket");
    ctx.insert(
        "bucket",
        &json!({
            "name": "my-bucket",
            "creation_date": "2024-01-01T00:00:00Z"
        }),
    );
    ctx.insert("objects", &Vec::<Value>::new());
    ctx.insert("prefixes", &Vec::<Value>::new());
    ctx.insert("total_objects", &0);
    ctx.insert("total_bytes", &0);
    ctx.insert("current_objects", &0);
    ctx.insert("current_bytes", &0);
    ctx.insert("version_count", &0);
    ctx.insert("version_bytes", &0);
    ctx.insert("max_objects", &Value::Null);
    ctx.insert("max_bytes", &Value::Null);
    ctx.insert("obj_pct", &0);
    ctx.insert("bytes_pct", &0);
    ctx.insert("has_quota", &false);
    ctx.insert("versioning_enabled", &false);
    ctx.insert("versioning_status", &"Disabled");
    ctx.insert("encryption_config", &json!({"Rules": []}));
    ctx.insert("enc_rules", &Vec::<Value>::new());
    ctx.insert("enc_algorithm", &"");
    ctx.insert("enc_kms_key", &"");
    ctx.insert("replication_rules", &Vec::<Value>::new());
    ctx.insert("replication_rule", &Value::Null);
    ctx.insert("website_config", &Value::Null);
    ctx.insert("bucket_policy", &"");
    ctx.insert("bucket_policy_text", &"");
    ctx.insert("connections", &Vec::<Value>::new());
    ctx.insert("current_prefix", &"");
    ctx.insert("parent_prefix", &"");
    ctx.insert("has_more", &false);
    ctx.insert("next_token", &"");
    ctx.insert("active_tab", &"objects");
    ctx.insert("multipart_uploads", &Vec::<Value>::new());
    ctx.insert("target_conn", &Value::Null);
    ctx.insert("target_conn_name", &"");
    ctx.insert("preset_choice", &"");
    ctx.insert("default_policy", &"");
    ctx.insert("can_manage_cors", &true);
    ctx.insert("can_manage_lifecycle", &true);
    ctx.insert("can_manage_quota", &true);
    ctx.insert("can_manage_versioning", &true);
    ctx.insert("can_manage_website", &true);
    ctx.insert("can_edit_policy", &true);
    ctx.insert("is_replication_admin", &true);
    ctx.insert("lifecycle_enabled", &false);
    ctx.insert("site_sync_enabled", &false);
    ctx.insert("website_hosting_enabled", &false);
    ctx.insert("website_domains", &Vec::<Value>::new());
    ctx.insert("kms_keys", &Vec::<Value>::new());
    ctx.insert(
        "bucket_stats",
        &json!({
            "bytes": 0, "objects": 0, "total_bytes": 0, "total_objects": 0,
            "version_bytes": 0, "version_count": 0
        }),
    );
    ctx.insert(
        "bucket_quota",
        &json!({ "max_bytes": null, "max_objects": null }),
    );
    ctx.insert("buckets_for_copy_url", &"");
    ctx.insert("acl_url", &"");
    ctx.insert("cors_url", &"");
    ctx.insert("folders_url", &"");
    ctx.insert("lifecycle_url", &"");
    ctx.insert("objects_api_url", &"");
    ctx.insert("objects_stream_url", &"");
    render_or_panic("bucket_detail.html", &ctx);
}

#[test]
fn render_bucket_detail_without_error_document() {
    let mut ctx = base_ctx();
    ctx.insert("bucket_name", &"site-bucket");
    ctx.insert(
        "bucket",
        &json!({
            "name": "site-bucket",
            "creation_date": "2025-01-01T00:00:00Z",
        }),
    );
    ctx.insert("objects", &Vec::<Value>::new());
    ctx.insert("prefixes", &Vec::<Value>::new());
    ctx.insert("total_objects", &0u64);
    ctx.insert("total_bytes", &0u64);
    ctx.insert("current_objects", &0u64);
    ctx.insert("current_bytes", &0u64);
    ctx.insert("version_count", &0u64);
    ctx.insert("version_bytes", &0u64);
    ctx.insert("max_objects", &Value::Null);
    ctx.insert("max_bytes", &Value::Null);
    ctx.insert("has_max_objects", &false);
    ctx.insert("has_max_bytes", &false);
    ctx.insert("obj_pct", &0);
    ctx.insert("bytes_pct", &0);
    ctx.insert("has_quota", &false);
    ctx.insert("versioning_enabled", &false);
    ctx.insert("versioning_status", &"Disabled");
    ctx.insert("encryption_config", &json!({"Rules": []}));
    ctx.insert("enc_rules", &Vec::<Value>::new());
    ctx.insert("enc_algorithm", &"");
    ctx.insert("enc_kms_key", &"");
    ctx.insert("replication_rules", &Vec::<Value>::new());
    ctx.insert("replication_rule", &Value::Null);
    ctx.insert("website_config", &json!({"index_document": "index.html"}));
    ctx.insert("bucket_policy", &"");
    ctx.insert("bucket_policy_text", &"");
    ctx.insert("connections", &Vec::<Value>::new());
    ctx.insert("current_prefix", &"");
    ctx.insert("parent_prefix", &"");
    ctx.insert("has_more", &false);
    ctx.insert("next_token", &"");
    ctx.insert("active_tab", &"objects");
    ctx.insert("multipart_uploads", &Vec::<Value>::new());
    ctx.insert("target_conn", &Value::Null);
    ctx.insert("target_conn_name", &"");
    ctx.insert("preset_choice", &"");
    ctx.insert("default_policy", &"");
    ctx.insert("can_manage_cors", &true);
    ctx.insert("can_manage_lifecycle", &true);
    ctx.insert("can_manage_quota", &true);
    ctx.insert("can_manage_versioning", &true);
    ctx.insert("can_manage_website", &true);
    ctx.insert("can_edit_policy", &true);
    ctx.insert("is_replication_admin", &true);
    ctx.insert("lifecycle_enabled", &false);
    ctx.insert("site_sync_enabled", &false);
    ctx.insert("website_hosting_enabled", &true);
    ctx.insert("website_domains", &Vec::<Value>::new());
    ctx.insert("kms_keys", &Vec::<Value>::new());
    ctx.insert(
        "bucket_stats",
        &json!({
            "bytes": 0, "objects": 0, "total_bytes": 0, "total_objects": 0,
            "version_bytes": 0, "version_count": 0
        }),
    );
    ctx.insert(
        "bucket_quota",
        &json!({ "max_bytes": null, "max_objects": null }),
    );
    ctx.insert("buckets_for_copy_url", &"");
    ctx.insert("acl_url", &"");
    ctx.insert("cors_url", &"");
    ctx.insert("folders_url", &"");
    ctx.insert("lifecycle_url", &"");
    ctx.insert("objects_api_url", &"");
    ctx.insert("objects_stream_url", &"");
    render_or_panic("bucket_detail.html", &ctx);
}
