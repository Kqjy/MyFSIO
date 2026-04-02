use axum::body::Body;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::json;

use crate::state::AppState;

fn json_ok(value: serde_json::Value) -> Response {
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        value.to_string(),
    )
        .into_response()
}

fn json_err(status: StatusCode, msg: &str) -> Response {
    (
        status,
        [("content-type", "application/json")],
        json!({"error": msg}).to_string(),
    )
        .into_response()
}

pub async fn list_keys(State(state): State<AppState>) -> Response {
    let kms = match &state.kms {
        Some(k) => k,
        None => return json_err(StatusCode::SERVICE_UNAVAILABLE, "KMS not enabled"),
    };

    let keys = kms.list_keys().await;
    let keys_json: Vec<serde_json::Value> = keys
        .iter()
        .map(|k| {
            json!({
                "KeyId": k.key_id,
                "Arn": k.arn,
                "Description": k.description,
                "CreationDate": k.creation_date.to_rfc3339(),
                "Enabled": k.enabled,
                "KeyState": k.key_state,
                "KeyUsage": k.key_usage,
                "KeySpec": k.key_spec,
            })
        })
        .collect();

    json_ok(json!({"keys": keys_json}))
}

pub async fn create_key(State(state): State<AppState>, body: Body) -> Response {
    let kms = match &state.kms {
        Some(k) => k,
        None => return json_err(StatusCode::SERVICE_UNAVAILABLE, "KMS not enabled"),
    };

    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(c) => c.to_bytes(),
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "Invalid request body"),
    };

    let description = if body_bytes.is_empty() {
        String::new()
    } else {
        match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            Ok(v) => v
                .get("Description")
                .or_else(|| v.get("description"))
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string(),
            Err(_) => String::new(),
        }
    };

    match kms.create_key(&description).await {
        Ok(key) => json_ok(json!({
            "KeyId": key.key_id,
            "Arn": key.arn,
            "Description": key.description,
            "CreationDate": key.creation_date.to_rfc3339(),
            "Enabled": key.enabled,
            "KeyState": key.key_state,
        })),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

pub async fn get_key(
    State(state): State<AppState>,
    axum::extract::Path(key_id): axum::extract::Path<String>,
) -> Response {
    let kms = match &state.kms {
        Some(k) => k,
        None => return json_err(StatusCode::SERVICE_UNAVAILABLE, "KMS not enabled"),
    };

    match kms.get_key(&key_id).await {
        Some(key) => json_ok(json!({
            "KeyId": key.key_id,
            "Arn": key.arn,
            "Description": key.description,
            "CreationDate": key.creation_date.to_rfc3339(),
            "Enabled": key.enabled,
            "KeyState": key.key_state,
            "KeyUsage": key.key_usage,
            "KeySpec": key.key_spec,
        })),
        None => json_err(StatusCode::NOT_FOUND, "Key not found"),
    }
}

pub async fn delete_key(
    State(state): State<AppState>,
    axum::extract::Path(key_id): axum::extract::Path<String>,
) -> Response {
    let kms = match &state.kms {
        Some(k) => k,
        None => return json_err(StatusCode::SERVICE_UNAVAILABLE, "KMS not enabled"),
    };

    match kms.delete_key(&key_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => json_err(StatusCode::NOT_FOUND, "Key not found"),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

pub async fn enable_key(
    State(state): State<AppState>,
    axum::extract::Path(key_id): axum::extract::Path<String>,
) -> Response {
    let kms = match &state.kms {
        Some(k) => k,
        None => return json_err(StatusCode::SERVICE_UNAVAILABLE, "KMS not enabled"),
    };

    match kms.enable_key(&key_id).await {
        Ok(true) => json_ok(json!({"status": "enabled"})),
        Ok(false) => json_err(StatusCode::NOT_FOUND, "Key not found"),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

pub async fn disable_key(
    State(state): State<AppState>,
    axum::extract::Path(key_id): axum::extract::Path<String>,
) -> Response {
    let kms = match &state.kms {
        Some(k) => k,
        None => return json_err(StatusCode::SERVICE_UNAVAILABLE, "KMS not enabled"),
    };

    match kms.disable_key(&key_id).await {
        Ok(true) => json_ok(json!({"status": "disabled"})),
        Ok(false) => json_err(StatusCode::NOT_FOUND, "Key not found"),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

pub async fn encrypt(State(state): State<AppState>, body: Body) -> Response {
    let kms = match &state.kms {
        Some(k) => k,
        None => return json_err(StatusCode::SERVICE_UNAVAILABLE, "KMS not enabled"),
    };

    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(c) => c.to_bytes(),
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "Invalid request body"),
    };

    let req: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "Invalid JSON"),
    };

    let key_id = match req.get("KeyId").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => return json_err(StatusCode::BAD_REQUEST, "Missing KeyId"),
    };
    let plaintext_b64 = match req.get("Plaintext").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return json_err(StatusCode::BAD_REQUEST, "Missing Plaintext"),
    };
    let plaintext = match B64.decode(plaintext_b64) {
        Ok(p) => p,
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "Invalid base64 Plaintext"),
    };

    match kms.encrypt_data(key_id, &plaintext).await {
        Ok(ct) => json_ok(json!({
            "KeyId": key_id,
            "CiphertextBlob": B64.encode(&ct),
        })),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

pub async fn decrypt(State(state): State<AppState>, body: Body) -> Response {
    let kms = match &state.kms {
        Some(k) => k,
        None => return json_err(StatusCode::SERVICE_UNAVAILABLE, "KMS not enabled"),
    };

    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(c) => c.to_bytes(),
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "Invalid request body"),
    };

    let req: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "Invalid JSON"),
    };

    let key_id = match req.get("KeyId").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => return json_err(StatusCode::BAD_REQUEST, "Missing KeyId"),
    };
    let ct_b64 = match req.get("CiphertextBlob").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => return json_err(StatusCode::BAD_REQUEST, "Missing CiphertextBlob"),
    };
    let ciphertext = match B64.decode(ct_b64) {
        Ok(c) => c,
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "Invalid base64"),
    };

    match kms.decrypt_data(key_id, &ciphertext).await {
        Ok(pt) => json_ok(json!({
            "KeyId": key_id,
            "Plaintext": B64.encode(&pt),
        })),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

pub async fn generate_data_key(State(state): State<AppState>, body: Body) -> Response {
    let kms = match &state.kms {
        Some(k) => k,
        None => return json_err(StatusCode::SERVICE_UNAVAILABLE, "KMS not enabled"),
    };

    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(c) => c.to_bytes(),
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "Invalid request body"),
    };

    let req: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "Invalid JSON"),
    };

    let key_id = match req.get("KeyId").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => return json_err(StatusCode::BAD_REQUEST, "Missing KeyId"),
    };
    let num_bytes = req
        .get("NumberOfBytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(32) as usize;

    if num_bytes < 1 || num_bytes > 1024 {
        return json_err(StatusCode::BAD_REQUEST, "NumberOfBytes must be 1-1024");
    }

    match kms.generate_data_key(key_id, num_bytes).await {
        Ok((plaintext, wrapped)) => json_ok(json!({
            "KeyId": key_id,
            "Plaintext": B64.encode(&plaintext),
            "CiphertextBlob": B64.encode(&wrapped),
        })),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}
