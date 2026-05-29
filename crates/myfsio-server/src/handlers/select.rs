use std::collections::HashMap;
use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use bytes::Bytes;
use crc32fast::Hasher;
use duckdb::types::ValueRef;
use duckdb::Connection;
use futures::stream;
use http_body_util::BodyExt;
use myfsio_common::error::{S3Error, S3ErrorCode};
use myfsio_storage::traits::StorageEngine;

use crate::state::AppState;

#[cfg(target_os = "windows")]
#[link(name = "Rstrtmgr")]
extern "system" {}

const CHUNK_SIZE: usize = 65_536;

pub async fn post_select_object_content(
    state: &AppState,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
    body: Body,
) -> Response {
    if let Some(resp) = require_xml_content_type(headers) {
        return resp;
    }

    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return s3_error_response(S3Error::new(
                S3ErrorCode::MalformedXML,
                "Unable to parse XML document",
            ));
        }
    };

    let request = match parse_select_request(&body_bytes) {
        Ok(r) => r,
        Err(err) => return s3_error_response(err),
    };

    let object_path = match state.storage.get_object_path(bucket, key).await {
        Ok(path) => path,
        Err(_) => {
            return s3_error_response(S3Error::new(S3ErrorCode::NoSuchKey, "Object not found"));
        }
    };

    let join_res =
        tokio::task::spawn_blocking(move || execute_select_query(object_path, request)).await;
    let chunks = match join_res {
        Ok(Ok(chunks)) => chunks,
        Ok(Err(message)) => {
            return s3_error_response(S3Error::new(S3ErrorCode::InvalidRequest, message));
        }
        Err(_) => {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InternalError,
                "SelectObjectContent execution failed",
            ));
        }
    };

    let bytes_returned: usize = chunks.iter().map(|c| c.len()).sum();
    let mut events: Vec<Bytes> = Vec::with_capacity(chunks.len() + 2);
    for chunk in chunks {
        events.push(Bytes::from(encode_select_event("Records", &chunk)));
    }

    let stats_payload = build_stats_xml(0, bytes_returned);
    events.push(Bytes::from(encode_select_event(
        "Stats",
        stats_payload.as_bytes(),
    )));
    events.push(Bytes::from(encode_select_event("End", b"")));

    let stream = stream::iter(events.into_iter().map(Ok::<Bytes, std::io::Error>));
    let body = Body::from_stream(stream);

    let mut response = (StatusCode::OK, body).into_response();
    response.headers_mut().insert(
        HeaderName::from_static("content-type"),
        "application/octet-stream".parse().unwrap(),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-amz-request-charged"),
        "requester".parse().unwrap(),
    );
    response
}

#[derive(Clone)]
struct SelectRequest {
    expression: String,
    input_format: InputFormat,
    output_format: OutputFormat,
}

#[derive(Clone)]
enum InputFormat {
    Csv(CsvInputConfig),
    Json(JsonInputConfig),
    Parquet,
}

#[derive(Clone)]
struct CsvInputConfig {
    file_header_info: String,
    field_delimiter: String,
    quote_character: String,
}

#[derive(Clone)]
struct JsonInputConfig {
    json_type: String,
}

#[derive(Clone)]
enum OutputFormat {
    Csv(CsvOutputConfig),
    Json(JsonOutputConfig),
}

#[derive(Clone)]
struct CsvOutputConfig {
    field_delimiter: String,
    record_delimiter: String,
    quote_character: String,
}

#[derive(Clone)]
struct JsonOutputConfig {
    record_delimiter: String,
}

fn parse_select_request(payload: &[u8]) -> Result<SelectRequest, S3Error> {
    let xml = String::from_utf8_lossy(payload);
    let doc = roxmltree::Document::parse(&xml)
        .map_err(|_| S3Error::new(S3ErrorCode::MalformedXML, "Unable to parse XML document"))?;

    let root = doc.root_element();
    if root.tag_name().name() != "SelectObjectContentRequest" {
        return Err(S3Error::new(
            S3ErrorCode::MalformedXML,
            "Root element must be SelectObjectContentRequest",
        ));
    }

    let expression = child_text(&root, "Expression")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| S3Error::new(S3ErrorCode::InvalidRequest, "Expression is required"))?;

    let expression_type = child_text(&root, "ExpressionType").unwrap_or_else(|| "SQL".to_string());
    if !expression_type.eq_ignore_ascii_case("SQL") {
        return Err(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "Only SQL expression type is supported",
        ));
    }

    let input_node = child(&root, "InputSerialization").ok_or_else(|| {
        S3Error::new(
            S3ErrorCode::InvalidRequest,
            "InputSerialization is required",
        )
    })?;
    let output_node = child(&root, "OutputSerialization").ok_or_else(|| {
        S3Error::new(
            S3ErrorCode::InvalidRequest,
            "OutputSerialization is required",
        )
    })?;

    let input_format = parse_input_format(&input_node)?;
    let output_format = parse_output_format(&output_node)?;

    Ok(SelectRequest {
        expression,
        input_format,
        output_format,
    })
}

fn parse_input_format(node: &roxmltree::Node<'_, '_>) -> Result<InputFormat, S3Error> {
    if let Some(csv_node) = child(node, "CSV") {
        return Ok(InputFormat::Csv(CsvInputConfig {
            file_header_info: child_text(&csv_node, "FileHeaderInfo")
                .unwrap_or_else(|| "NONE".to_string())
                .to_ascii_uppercase(),
            field_delimiter: child_text(&csv_node, "FieldDelimiter")
                .unwrap_or_else(|| ",".to_string()),
            quote_character: child_text(&csv_node, "QuoteCharacter")
                .unwrap_or_else(|| "\"".to_string()),
        }));
    }

    if let Some(json_node) = child(node, "JSON") {
        return Ok(InputFormat::Json(JsonInputConfig {
            json_type: child_text(&json_node, "Type")
                .unwrap_or_else(|| "DOCUMENT".to_string())
                .to_ascii_uppercase(),
        }));
    }

    if child(node, "Parquet").is_some() {
        return Ok(InputFormat::Parquet);
    }

    Err(S3Error::new(
        S3ErrorCode::InvalidRequest,
        "InputSerialization must specify CSV, JSON, or Parquet",
    ))
}

fn parse_output_format(node: &roxmltree::Node<'_, '_>) -> Result<OutputFormat, S3Error> {
    if let Some(csv_node) = child(node, "CSV") {
        return Ok(OutputFormat::Csv(CsvOutputConfig {
            field_delimiter: child_text(&csv_node, "FieldDelimiter")
                .unwrap_or_else(|| ",".to_string()),
            record_delimiter: child_text(&csv_node, "RecordDelimiter")
                .unwrap_or_else(|| "\n".to_string()),
            quote_character: child_text(&csv_node, "QuoteCharacter")
                .unwrap_or_else(|| "\"".to_string()),
        }));
    }

    if let Some(json_node) = child(node, "JSON") {
        return Ok(OutputFormat::Json(JsonOutputConfig {
            record_delimiter: child_text(&json_node, "RecordDelimiter")
                .unwrap_or_else(|| "\n".to_string()),
        }));
    }

    Err(S3Error::new(
        S3ErrorCode::InvalidRequest,
        "OutputSerialization must specify CSV or JSON",
    ))
}

fn child<'a, 'input>(
    node: &'a roxmltree::Node<'a, 'input>,
    name: &str,
) -> Option<roxmltree::Node<'a, 'input>> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == name)
}

fn child_text(node: &roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    child(node, name)
        .and_then(|n| n.text())
        .map(|s| s.to_string())
}

fn execute_select_query(path: PathBuf, request: SelectRequest) -> Result<Vec<Vec<u8>>, String> {
    if let Some(token) = find_disallowed_token(&request.expression) {
        return Err(format!(
            "Disallowed function or statement in expression: {}",
            token
        ));
    }

    let conn =
        Connection::open_in_memory().map_err(|e| format!("DuckDB connection error: {}", e))?;

    conn.execute_batch(
        "SET autoinstall_known_extensions=false; \
         SET autoload_known_extensions=false;",
    )
    .map_err(|e| format!("DuckDB lockdown failed: {}", e))?;

    load_input_table(&conn, &path, &request.input_format)?;

    conn.execute_batch(
        "SET memory_limit='256MB'; \
         SET max_memory='256MB'; \
         SET enable_external_access=false; \
         SET lock_configuration=true;",
    )
    .map_err(|e| format!("DuckDB lockdown failed: {}", e))?;

    let expression = request
        .expression
        .replace("s3object", "data")
        .replace("S3Object", "data");

    let mut stmt = conn
        .prepare(&expression)
        .map_err(|e| format!("SQL execution error: {}", e))?;
    let mut rows = stmt
        .query([])
        .map_err(|e| format!("SQL execution error: {}", e))?;
    let stmt_ref = rows
        .as_ref()
        .ok_or_else(|| "SQL execution error: statement metadata unavailable".to_string())?;
    let col_count = stmt_ref.column_count();
    let mut columns: Vec<String> = Vec::with_capacity(col_count);
    for i in 0..col_count {
        let name = stmt_ref
            .column_name(i)
            .map(|s| s.to_string())
            .unwrap_or_else(|_| format!("_{}", i));
        columns.push(name);
    }

    match request.output_format {
        OutputFormat::Csv(cfg) => collect_csv_chunks(&mut rows, col_count, cfg),
        OutputFormat::Json(cfg) => collect_json_chunks(&mut rows, col_count, &columns, cfg),
    }
}

fn load_input_table(conn: &Connection, path: &Path, input: &InputFormat) -> Result<(), String> {
    let path_str = path.to_string_lossy().replace('\\', "/");
    match input {
        InputFormat::Csv(cfg) => {
            let header = cfg.file_header_info == "USE" || cfg.file_header_info == "IGNORE";
            let delimiter = normalize_single_char(&cfg.field_delimiter, ',');
            let quote = normalize_single_char(&cfg.quote_character, '"');

            let sql = format!(
                "CREATE TABLE data AS SELECT * FROM read_csv('{}', header={}, delim='{}', quote='{}')",
                sql_escape(&path_str),
                if header { "true" } else { "false" },
                sql_escape(&delimiter),
                sql_escape(&quote)
            );
            conn.execute_batch(&sql)
                .map_err(|e| format!("Failed loading CSV data: {}", e))?;
        }
        InputFormat::Json(cfg) => {
            conn.execute_batch("LOAD json;")
                .map_err(|e| format!("Failed loading JSON extension: {}", e))?;
            let format = if cfg.json_type == "LINES" {
                "newline_delimited"
            } else {
                "array"
            };
            let sql = format!(
                "CREATE TABLE data AS SELECT * FROM read_json_auto('{}', format='{}')",
                sql_escape(&path_str),
                format
            );
            conn.execute_batch(&sql)
                .map_err(|e| format!("Failed loading JSON data: {}", e))?;
        }
        InputFormat::Parquet => {
            let sql = format!(
                "CREATE TABLE data AS SELECT * FROM read_parquet('{}')",
                sql_escape(&path_str)
            );
            conn.execute_batch(&sql)
                .map_err(|e| format!("Failed loading Parquet data: {}", e))?;
        }
    }
    Ok(())
}

fn sql_escape(value: &str) -> String {
    value.replace('\'', "''")
}

fn find_disallowed_token(expression: &str) -> Option<&'static str> {
    const BANNED_FUNCTIONS: &[&str] = &[
        "read_csv",
        "read_csv_auto",
        "read_json",
        "read_json_auto",
        "read_json_objects",
        "read_ndjson",
        "read_ndjson_auto",
        "read_ndjson_objects",
        "read_parquet",
        "parquet_scan",
        "read_blob",
        "read_text",
        "sniff_csv",
        "parquet_schema",
        "parquet_metadata",
        "parquet_file_metadata",
        "parquet_kv_metadata",
        "from_substrait",
        "from_substrait_json",
        "copy_from_database",
        "copy_to_database",
        "duckdb_extensions",
        "load_extension",
        "install_extension",
        "load_aws_credentials",
    ];
    const BANNED_LEADING_KEYWORDS: &[&str] = &[
        "copy", "attach", "detach", "install", "load", "pragma", "set", "export", "import",
    ];

    #[derive(Clone)]
    struct Tok {
        pos: usize,
        end: usize,
        text: String,
        followed_by_paren: bool,
    }

    let mut tokens: Vec<Tok> = Vec::new();
    let mut buf = String::new();
    let mut start = 0usize;
    let bytes = expression.as_bytes();
    let mut i = 0usize;

    let push_token = |tokens: &mut Vec<Tok>, buf: &mut String, start: usize, end: usize| {
        if buf.is_empty() {
            return;
        }
        tokens.push(Tok {
            pos: start,
            end,
            text: std::mem::take(buf),
            followed_by_paren: false,
        });
    };

    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '\'' {
            push_token(&mut tokens, &mut buf, start, i);
            i += 1;
            while i < bytes.len() {
                if bytes[i] as char == '\'' {
                    if i + 1 < bytes.len() && bytes[i + 1] as char == '\'' {
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if c == '"' {
            push_token(&mut tokens, &mut buf, start, i);
            i += 1;
            while i < bytes.len() {
                if bytes[i] as char == '"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if c == '-' && i + 1 < bytes.len() && bytes[i + 1] as char == '-' {
            push_token(&mut tokens, &mut buf, start, i);
            while i < bytes.len() && bytes[i] as char != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && i + 1 < bytes.len() && bytes[i + 1] as char == '*' {
            push_token(&mut tokens, &mut buf, start, i);
            i += 2;
            while i + 1 < bytes.len() {
                if bytes[i] as char == '*' && bytes[i + 1] as char == '/' {
                    i += 2;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if c.is_ascii_alphanumeric() || c == '_' {
            if buf.is_empty() {
                start = i;
            }
            buf.push(c.to_ascii_lowercase());
        } else if !buf.is_empty() {
            push_token(&mut tokens, &mut buf, start, i);
        }
        i += 1;
    }
    if !buf.is_empty() {
        let end = bytes.len();
        push_token(&mut tokens, &mut buf, start, end);
    }

    for tok in tokens.iter_mut() {
        let mut j = tok.end;
        while j < bytes.len() {
            let c = bytes[j] as char;
            if c.is_whitespace() {
                j += 1;
                continue;
            }
            if c == '-' && j + 1 < bytes.len() && bytes[j + 1] as char == '-' {
                while j < bytes.len() && bytes[j] as char != '\n' {
                    j += 1;
                }
                continue;
            }
            if c == '/' && j + 1 < bytes.len() && bytes[j + 1] as char == '*' {
                j += 2;
                while j + 1 < bytes.len() {
                    if bytes[j] as char == '*' && bytes[j + 1] as char == '/' {
                        j += 2;
                        break;
                    }
                    j += 1;
                }
                continue;
            }
            tok.followed_by_paren = c == '(';
            break;
        }
    }

    for tok in &tokens {
        if !tok.followed_by_paren {
            continue;
        }
        for banned in BANNED_FUNCTIONS {
            if tok.text == *banned {
                return Some(banned);
            }
        }
    }

    let mut at_statement_start = true;
    let mut last_end = 0usize;
    for tok in &tokens {
        let between = &expression[last_end..tok.pos];
        if between.contains(';') {
            at_statement_start = true;
        }
        if at_statement_start {
            if !tok.followed_by_paren {
                for kw in BANNED_LEADING_KEYWORDS {
                    if tok.text == *kw {
                        return Some(match *kw {
                            "copy" => "COPY",
                            "attach" => "ATTACH",
                            "detach" => "DETACH",
                            "install" => "INSTALL",
                            "load" => "LOAD",
                            "pragma" => "PRAGMA",
                            "set" => "SET",
                            "export" => "EXPORT",
                            "import" => "IMPORT",
                            _ => unreachable!(),
                        });
                    }
                }
            }
            at_statement_start = false;
        }
        last_end = tok.end;
    }

    None
}

fn normalize_single_char(value: &str, default_char: char) -> String {
    value.chars().next().unwrap_or(default_char).to_string()
}

fn floor_char_boundary(s: &str, mut idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn collect_csv_chunks(
    rows: &mut duckdb::Rows<'_>,
    col_count: usize,
    cfg: CsvOutputConfig,
) -> Result<Vec<Vec<u8>>, String> {
    let delimiter = cfg.field_delimiter;
    let record_delimiter = cfg.record_delimiter;
    let quote = cfg.quote_character;

    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut buffer = String::new();

    while let Some(row) = rows
        .next()
        .map_err(|e| format!("SQL execution error: {}", e))?
    {
        let mut fields: Vec<String> = Vec::with_capacity(col_count);
        for i in 0..col_count {
            let value = row
                .get_ref(i)
                .map_err(|e| format!("SQL execution error: {}", e))?;
            if matches!(value, ValueRef::Null) {
                fields.push(String::new());
                continue;
            }

            let mut text = value_ref_to_string(value);
            if text.contains(&delimiter)
                || text.contains(&quote)
                || text.contains(&record_delimiter)
            {
                text = text.replace(&quote, &(quote.clone() + &quote));
                text = format!("{}{}{}", quote, text, quote);
            }
            fields.push(text);
        }
        buffer.push_str(&fields.join(&delimiter));
        buffer.push_str(&record_delimiter);

        while buffer.len() >= CHUNK_SIZE {
            let split_at = floor_char_boundary(&buffer, CHUNK_SIZE);
            let rest = buffer.split_off(split_at);
            chunks.push(buffer.into_bytes());
            buffer = rest;
        }
    }

    if !buffer.is_empty() {
        chunks.push(buffer.into_bytes());
    }
    Ok(chunks)
}

fn collect_json_chunks(
    rows: &mut duckdb::Rows<'_>,
    col_count: usize,
    columns: &[String],
    cfg: JsonOutputConfig,
) -> Result<Vec<Vec<u8>>, String> {
    let record_delimiter = cfg.record_delimiter;
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut buffer = String::new();

    while let Some(row) = rows
        .next()
        .map_err(|e| format!("SQL execution error: {}", e))?
    {
        let mut record: HashMap<String, serde_json::Value> = HashMap::with_capacity(col_count);
        for i in 0..col_count {
            let value = row
                .get_ref(i)
                .map_err(|e| format!("SQL execution error: {}", e))?;
            let key = columns.get(i).cloned().unwrap_or_else(|| format!("_{}", i));
            record.insert(key, value_ref_to_json(value));
        }
        let line = serde_json::to_string(&record)
            .map_err(|e| format!("JSON output encoding failed: {}", e))?;
        buffer.push_str(&line);
        buffer.push_str(&record_delimiter);

        while buffer.len() >= CHUNK_SIZE {
            let split_at = floor_char_boundary(&buffer, CHUNK_SIZE);
            let rest = buffer.split_off(split_at);
            chunks.push(buffer.into_bytes());
            buffer = rest;
        }
    }

    if !buffer.is_empty() {
        chunks.push(buffer.into_bytes());
    }
    Ok(chunks)
}

fn value_ref_to_string(value: ValueRef<'_>) -> String {
    match value {
        ValueRef::Null => String::new(),
        ValueRef::Boolean(v) => v.to_string(),
        ValueRef::TinyInt(v) => v.to_string(),
        ValueRef::SmallInt(v) => v.to_string(),
        ValueRef::Int(v) => v.to_string(),
        ValueRef::BigInt(v) => v.to_string(),
        ValueRef::UTinyInt(v) => v.to_string(),
        ValueRef::USmallInt(v) => v.to_string(),
        ValueRef::UInt(v) => v.to_string(),
        ValueRef::UBigInt(v) => v.to_string(),
        ValueRef::Float(v) => v.to_string(),
        ValueRef::Double(v) => v.to_string(),
        ValueRef::Decimal(v) => v.to_string(),
        ValueRef::Text(v) => String::from_utf8_lossy(v).into_owned(),
        ValueRef::Blob(v) => base64::engine::general_purpose::STANDARD.encode(v),
        _ => format!("{:?}", value),
    }
}

fn value_ref_to_json(value: ValueRef<'_>) -> serde_json::Value {
    match value {
        ValueRef::Null => serde_json::Value::Null,
        ValueRef::Boolean(v) => serde_json::Value::Bool(v),
        ValueRef::TinyInt(v) => serde_json::json!(v),
        ValueRef::SmallInt(v) => serde_json::json!(v),
        ValueRef::Int(v) => serde_json::json!(v),
        ValueRef::BigInt(v) => serde_json::json!(v),
        ValueRef::UTinyInt(v) => serde_json::json!(v),
        ValueRef::USmallInt(v) => serde_json::json!(v),
        ValueRef::UInt(v) => serde_json::json!(v),
        ValueRef::UBigInt(v) => serde_json::json!(v),
        ValueRef::Float(v) => serde_json::json!(v),
        ValueRef::Double(v) => serde_json::json!(v),
        ValueRef::Decimal(v) => serde_json::Value::String(v.to_string()),
        ValueRef::Text(v) => serde_json::Value::String(String::from_utf8_lossy(v).into_owned()),
        ValueRef::Blob(v) => {
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(v))
        }
        _ => serde_json::Value::String(format!("{:?}", value)),
    }
}

fn require_xml_content_type(headers: &HeaderMap) -> Option<Response> {
    let value = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    if value.is_empty() {
        return None;
    }
    let lowered = value.to_ascii_lowercase();
    if lowered.starts_with("application/xml") || lowered.starts_with("text/xml") {
        return None;
    }
    Some(s3_error_response(S3Error::new(
        S3ErrorCode::InvalidRequest,
        "Content-Type must be application/xml or text/xml",
    )))
}

fn s3_error_response(err: S3Error) -> Response {
    crate::s3_response::s3_error_response(err)
}

fn build_stats_xml(bytes_scanned: usize, bytes_returned: usize) -> String {
    format!(
        "<Stats><BytesScanned>{}</BytesScanned><BytesProcessed>{}</BytesProcessed><BytesReturned>{}</BytesReturned></Stats>",
        bytes_scanned,
        bytes_scanned,
        bytes_returned
    )
}

fn encode_select_event(event_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut headers = Vec::new();
    headers.extend(encode_select_header(":event-type", event_type));
    if event_type == "Records" {
        headers.extend(encode_select_header(
            ":content-type",
            "application/octet-stream",
        ));
    } else if event_type == "Stats" {
        headers.extend(encode_select_header(":content-type", "text/xml"));
    }
    headers.extend(encode_select_header(":message-type", "event"));

    let headers_len = headers.len() as u32;
    let total_len = 4 + 4 + 4 + headers.len() + payload.len() + 4;

    let mut message = Vec::with_capacity(total_len);
    let mut prelude = Vec::with_capacity(8);
    prelude.extend((total_len as u32).to_be_bytes());
    prelude.extend(headers_len.to_be_bytes());

    let prelude_crc = crc32(&prelude);
    message.extend(prelude);
    message.extend(prelude_crc.to_be_bytes());
    message.extend(headers);
    message.extend(payload);

    let msg_crc = crc32(&message);
    message.extend(msg_crc.to_be_bytes());
    message
}

fn encode_select_header(name: &str, value: &str) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let value_bytes = value.as_bytes();
    let mut header = Vec::with_capacity(1 + name_bytes.len() + 1 + 2 + value_bytes.len());
    header.push(name_bytes.len() as u8);
    header.extend(name_bytes);
    header.push(7);
    header.extend((value_bytes.len() as u16).to_be_bytes());
    header.extend(value_bytes);
    header
}

fn crc32(data: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod select_denylist_tests {
    use super::find_disallowed_token;

    #[test]
    fn allows_plain_select() {
        assert!(find_disallowed_token("SELECT * FROM s3object").is_none());
        assert!(find_disallowed_token("SELECT a, b FROM data WHERE c > 1").is_none());
        assert!(find_disallowed_token("SELECT load FROM data").is_none());
        assert!(find_disallowed_token("SELECT copy_count FROM data").is_none());
    }

    #[test]
    fn allows_columns_named_like_banned_functions() {
        assert!(find_disallowed_token("SELECT read_csv FROM s3object").is_none());
        assert!(find_disallowed_token("SELECT read_parquet, read_json FROM data").is_none());
        assert!(find_disallowed_token("SELECT s.read_blob FROM data s").is_none());
        assert!(find_disallowed_token("SELECT read_csv AS x FROM data").is_none());
    }

    #[test]
    fn allows_keywords_used_as_columns() {
        assert!(find_disallowed_token("SELECT copy, attach FROM data").is_none());
        assert!(find_disallowed_token("SELECT load AS l FROM data").is_none());
    }

    #[test]
    fn rejects_file_functions() {
        assert!(find_disallowed_token("SELECT * FROM read_csv_auto('/etc/passwd')").is_some());
        assert!(find_disallowed_token("select * from read_parquet('x')").is_some());
        assert!(find_disallowed_token("SELECT read_blob('/etc/hosts')").is_some());
        assert!(find_disallowed_token("SELECT read_csv ('x')").is_some());
        assert!(find_disallowed_token("SELECT read_csv\n('x')").is_some());
    }

    #[test]
    fn rejects_leading_statements() {
        assert!(find_disallowed_token("ATTACH 'x.db'").is_some());
        assert!(find_disallowed_token("INSTALL httpfs").is_some());
        assert!(find_disallowed_token("LOAD httpfs").is_some());
        assert!(find_disallowed_token("COPY data TO 'x'").is_some());
    }

    #[test]
    fn rejects_chained_statements() {
        assert!(find_disallowed_token("SELECT 1; ATTACH 'x.db'").is_some());
        assert!(find_disallowed_token("SELECT 1;\nLOAD httpfs").is_some());
    }

    #[test]
    fn ignores_string_literals() {
        assert!(find_disallowed_token("SELECT 'read_csv' FROM data").is_none());
        assert!(find_disallowed_token("SELECT 'ATTACH abc' AS x FROM data").is_none());
    }

    #[test]
    fn ignores_comments() {
        assert!(find_disallowed_token("SELECT * FROM data -- read_csv").is_none());
        assert!(find_disallowed_token("SELECT * /* read_parquet */ FROM data").is_none());
    }
}
