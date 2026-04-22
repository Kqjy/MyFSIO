use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use axum::body::Body;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;
use serde_json::{json, Value};

use crate::state::AppState;

fn json_ok(value: Value) -> Response {
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

async fn read_json(body: Body) -> Result<Value, Response> {
    let body_bytes = http_body_util::BodyExt::collect(body)
        .await
        .map_err(|_| json_err(StatusCode::BAD_REQUEST, "Invalid request body"))?
        .to_bytes();
    if body_bytes.is_empty() {
        Ok(json!({}))
    } else {
        serde_json::from_slice(&body_bytes)
            .map_err(|_| json_err(StatusCode::BAD_REQUEST, "Invalid JSON"))
    }
}

fn require_kms(
    state: &AppState,
) -> Result<&std::sync::Arc<myfsio_crypto::kms::KmsService>, Response> {
    state
        .kms
        .as_ref()
        .ok_or_else(|| json_err(StatusCode::SERVICE_UNAVAILABLE, "KMS not enabled"))
}

fn decode_b64(value: &str, field: &str) -> Result<Vec<u8>, Response> {
    B64.decode(value).map_err(|_| {
        json_err(
            StatusCode::BAD_REQUEST,
            &format!("Invalid base64 {}", field),
        )
    })
}

fn require_str<'a>(value: &'a Value, names: &[&str], message: &str) -> Result<&'a str, Response> {
    for name in names {
        if let Some(found) = value.get(*name).and_then(|v| v.as_str()) {
            return Ok(found);
        }
    }
    Err(json_err(StatusCode::BAD_REQUEST, message))
}

pub async fn list_keys(State(state): State<AppState>) -> Response {
    let kms = match require_kms(&state) {
        Ok(kms) => kms,
        Err(response) => return response,
    };

    let keys = kms.list_keys().await;
    let keys_json: Vec<Value> = keys
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
    let kms = match require_kms(&state) {
        Ok(kms) => kms,
        Err(response) => return response,
    };
    let req = match read_json(body).await {
        Ok(req) => req,
        Err(response) => return response,
    };

    let description = req
        .get("Description")
        .or_else(|| req.get("description"))
        .and_then(|d| d.as_str())
        .unwrap_or("");

    match kms.create_key(description).await {
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
    let kms = match require_kms(&state) {
        Ok(kms) => kms,
        Err(response) => return response,
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
    let kms = match require_kms(&state) {
        Ok(kms) => kms,
        Err(response) => return response,
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
    let kms = match require_kms(&state) {
        Ok(kms) => kms,
        Err(response) => return response,
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
    let kms = match require_kms(&state) {
        Ok(kms) => kms,
        Err(response) => return response,
    };

    match kms.disable_key(&key_id).await {
        Ok(true) => json_ok(json!({"status": "disabled"})),
        Ok(false) => json_err(StatusCode::NOT_FOUND, "Key not found"),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

pub async fn encrypt(State(state): State<AppState>, body: Body) -> Response {
    let kms = match require_kms(&state) {
        Ok(kms) => kms,
        Err(response) => return response,
    };
    let req = match read_json(body).await {
        Ok(req) => req,
        Err(response) => return response,
    };

    let key_id = match require_str(&req, &["KeyId", "key_id"], "Missing KeyId") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let plaintext_b64 = match require_str(&req, &["Plaintext", "plaintext"], "Missing Plaintext") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let plaintext = match decode_b64(plaintext_b64, "Plaintext") {
        Ok(value) => value,
        Err(response) => return response,
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
    let kms = match require_kms(&state) {
        Ok(kms) => kms,
        Err(response) => return response,
    };
    let req = match read_json(body).await {
        Ok(req) => req,
        Err(response) => return response,
    };

    let key_id = match require_str(&req, &["KeyId", "key_id"], "Missing KeyId") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let ciphertext_b64 = match require_str(
        &req,
        &["CiphertextBlob", "ciphertext_blob"],
        "Missing CiphertextBlob",
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let ciphertext = match decode_b64(ciphertext_b64, "CiphertextBlob") {
        Ok(value) => value,
        Err(response) => return response,
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
    generate_data_key_inner(state, body, true).await
}

pub async fn generate_data_key_without_plaintext(
    State(state): State<AppState>,
    body: Body,
) -> Response {
    generate_data_key_inner(state, body, false).await
}

async fn generate_data_key_inner(state: AppState, body: Body, include_plaintext: bool) -> Response {
    let kms = match require_kms(&state) {
        Ok(kms) => kms,
        Err(response) => return response,
    };
    let req = match read_json(body).await {
        Ok(req) => req,
        Err(response) => return response,
    };

    let key_id = match require_str(&req, &["KeyId", "key_id"], "Missing KeyId") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let num_bytes = req
        .get("NumberOfBytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(32) as usize;

    if num_bytes < state.config.kms_generate_data_key_min_bytes
        || num_bytes > state.config.kms_generate_data_key_max_bytes
    {
        return json_err(
            StatusCode::BAD_REQUEST,
            &format!(
                "NumberOfBytes must be {}-{}",
                state.config.kms_generate_data_key_min_bytes,
                state.config.kms_generate_data_key_max_bytes
            ),
        );
    }

    match kms.generate_data_key(key_id, num_bytes).await {
        Ok((plaintext, wrapped)) => {
            let mut value = json!({
                "KeyId": key_id,
                "CiphertextBlob": B64.encode(&wrapped),
            });
            if include_plaintext {
                value["Plaintext"] = json!(B64.encode(&plaintext));
            }
            json_ok(value)
        }
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

pub async fn re_encrypt(State(state): State<AppState>, body: Body) -> Response {
    let kms = match require_kms(&state) {
        Ok(kms) => kms,
        Err(response) => return response,
    };
    let req = match read_json(body).await {
        Ok(req) => req,
        Err(response) => return response,
    };

    let ciphertext_b64 = match require_str(
        &req,
        &["CiphertextBlob", "ciphertext_blob"],
        "CiphertextBlob is required",
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let destination_key_id = match require_str(
        &req,
        &["DestinationKeyId", "destination_key_id"],
        "DestinationKeyId is required",
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let ciphertext = match decode_b64(ciphertext_b64, "CiphertextBlob") {
        Ok(value) => value,
        Err(response) => return response,
    };

    let keys = kms.list_keys().await;
    let mut source_key_id: Option<String> = None;
    let mut plaintext: Option<Vec<u8>> = None;
    for key in keys {
        if !key.enabled {
            continue;
        }
        if let Ok(value) = kms.decrypt_data(&key.key_id, &ciphertext).await {
            source_key_id = Some(key.key_id);
            plaintext = Some(value);
            break;
        }
    }

    let Some(source_key_id) = source_key_id else {
        return json_err(
            StatusCode::BAD_REQUEST,
            "Could not determine source key for CiphertextBlob",
        );
    };
    let plaintext = plaintext.unwrap_or_default();

    match kms.encrypt_data(destination_key_id, &plaintext).await {
        Ok(new_ciphertext) => json_ok(json!({
            "CiphertextBlob": B64.encode(&new_ciphertext),
            "SourceKeyId": source_key_id,
            "KeyId": destination_key_id,
        })),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

pub async fn generate_random(State(state): State<AppState>, body: Body) -> Response {
    if let Err(response) = require_kms(&state) {
        return response;
    }
    let req = match read_json(body).await {
        Ok(req) => req,
        Err(response) => return response,
    };
    let num_bytes = req
        .get("NumberOfBytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(32) as usize;

    if num_bytes < state.config.kms_generate_data_key_min_bytes
        || num_bytes > state.config.kms_generate_data_key_max_bytes
    {
        return json_err(
            StatusCode::BAD_REQUEST,
            &format!(
                "NumberOfBytes must be {}-{}",
                state.config.kms_generate_data_key_min_bytes,
                state.config.kms_generate_data_key_max_bytes
            ),
        );
    }

    let mut bytes = vec![0u8; num_bytes];
    rand::thread_rng().fill_bytes(&mut bytes);
    json_ok(json!({
        "Plaintext": B64.encode(bytes),
    }))
}

pub async fn client_generate_key(State(state): State<AppState>) -> Response {
    let _ = state;

    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    json_ok(json!({
        "Key": B64.encode(key),
        "Algorithm": "AES-256-GCM",
        "KeySize": 32,
    }))
}

pub async fn client_encrypt(State(state): State<AppState>, body: Body) -> Response {
    let _ = state;
    let req = match read_json(body).await {
        Ok(req) => req,
        Err(response) => return response,
    };
    let plaintext_b64 =
        match require_str(&req, &["Plaintext", "plaintext"], "Plaintext is required") {
            Ok(value) => value,
            Err(response) => return response,
        };
    let key_b64 = match require_str(&req, &["Key", "key"], "Key is required") {
        Ok(value) => value,
        Err(response) => return response,
    };

    let plaintext = match decode_b64(plaintext_b64, "Plaintext") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let key_bytes = match decode_b64(key_b64, "Key") {
        Ok(value) => value,
        Err(response) => return response,
    };
    if key_bytes.len() != 32 {
        return json_err(StatusCode::BAD_REQUEST, "Key must decode to 32 bytes");
    }

    let cipher = match Aes256Gcm::new_from_slice(&key_bytes) {
        Ok(cipher) => cipher,
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "Invalid encryption key"),
    };
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    match cipher.encrypt(nonce, plaintext.as_ref()) {
        Ok(ciphertext) => json_ok(json!({
            "Ciphertext": B64.encode(ciphertext),
            "Nonce": B64.encode(nonce_bytes),
            "Algorithm": "AES-256-GCM",
        })),
        Err(e) => json_err(StatusCode::BAD_REQUEST, &e.to_string()),
    }
}

pub async fn client_decrypt(State(state): State<AppState>, body: Body) -> Response {
    let _ = state;
    let req = match read_json(body).await {
        Ok(req) => req,
        Err(response) => return response,
    };
    let ciphertext_b64 = match require_str(
        &req,
        &["Ciphertext", "ciphertext"],
        "Ciphertext is required",
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let nonce_b64 = match require_str(&req, &["Nonce", "nonce"], "Nonce is required") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let key_b64 = match require_str(&req, &["Key", "key"], "Key is required") {
        Ok(value) => value,
        Err(response) => return response,
    };

    let ciphertext = match decode_b64(ciphertext_b64, "Ciphertext") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let nonce_bytes = match decode_b64(nonce_b64, "Nonce") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let key_bytes = match decode_b64(key_b64, "Key") {
        Ok(value) => value,
        Err(response) => return response,
    };
    if key_bytes.len() != 32 {
        return json_err(StatusCode::BAD_REQUEST, "Key must decode to 32 bytes");
    }
    if nonce_bytes.len() != 12 {
        return json_err(StatusCode::BAD_REQUEST, "Nonce must decode to 12 bytes");
    }

    let cipher = match Aes256Gcm::new_from_slice(&key_bytes) {
        Ok(cipher) => cipher,
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "Invalid encryption key"),
    };
    let nonce = Nonce::from_slice(&nonce_bytes);

    match cipher.decrypt(nonce, ciphertext.as_ref()) {
        Ok(plaintext) => json_ok(json!({
            "Plaintext": B64.encode(plaintext),
        })),
        Err(e) => json_err(StatusCode::BAD_REQUEST, &e.to_string()),
    }
}

pub async fn materials(
    State(state): State<AppState>,
    axum::extract::Path(key_id): axum::extract::Path<String>,
    body: Body,
) -> Response {
    let kms = match require_kms(&state) {
        Ok(kms) => kms,
        Err(response) => return response,
    };
    let _ = match read_json(body).await {
        Ok(req) => req,
        Err(response) => return response,
    };

    match kms.generate_data_key(&key_id, 32).await {
        Ok((plaintext, wrapped)) => json_ok(json!({
            "PlaintextKey": B64.encode(plaintext),
            "EncryptedKey": B64.encode(wrapped),
            "KeyId": key_id,
            "Algorithm": "AES-256-GCM",
            "KeyWrapAlgorithm": "kms",
        })),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}
