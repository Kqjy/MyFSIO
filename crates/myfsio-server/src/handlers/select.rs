use std::sync::atomic::Ordering;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use crc32fast::Hasher;
use futures::{StreamExt, TryStreamExt};
use myfsio_common::error::{S3Error, S3ErrorCode};
use myfsio_crypto::encryption::EncryptionMetadata;
use myfsio_storage::traits::StorageEngine;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::{StreamReader, SyncIoBridge};

use crate::select_engine::input::{
    CountingReader, CsvHeaderMode, CsvSource, JsonSource, ParquetSource, RecordSource,
};
use crate::select_engine::plan::SelectPlan;
use crate::select_engine::{plan_query, run_select, OutputFormatCfg};
use crate::state::AppState;

use super::object_read::{serve_object_data, snapshot_object_for_read, ObjectReadError};

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

    let body_bytes = match super::collect_body_limited(body, super::CONFIG_BODY_LIMIT).await {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };

    let request = match parse_select_request(&body_bytes) {
        Ok(r) => r,
        Err(err) => return s3_error_response(err),
    };

    let plan = match plan_query(&request.expression) {
        Ok(plan) => plan,
        Err(message) => {
            return s3_error_response(S3Error::new(S3ErrorCode::InvalidRequest, message));
        }
    };

    let output_cfg = match &request.output_format {
        OutputFormat::Csv(cfg) => OutputFormatCfg::Csv {
            field_delimiter: cfg.field_delimiter.clone(),
            record_delimiter: cfg.record_delimiter.clone(),
            quote: cfg.quote_character.clone(),
            quote_always: cfg.quote_always,
        },
        OutputFormat::Json(cfg) => OutputFormatCfg::Json {
            record_delimiter: cfg.record_delimiter.clone(),
        },
    };

    match &request.input_format {
        InputFormat::Parquet => run_parquet_select(state, bucket, key, plan, output_cfg).await,
        InputFormat::Csv(_) | InputFormat::Json(_) => {
            run_streaming_select(state, bucket, key, headers, request, plan, output_cfg).await
        }
    }
}

async fn run_streaming_select(
    state: &AppState,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
    request: SelectRequest,
    plan: SelectPlan,
    output_cfg: OutputFormatCfg,
) -> Response {
    let snapshot = match snapshot_object_for_read(state, bucket, key, None, None).await {
        Ok(snapshot) => snapshot,
        Err(_) => {
            return s3_error_response(S3Error::new(S3ErrorCode::NoSuchKey, "Object not found"));
        }
    };

    let served = match serve_object_data(state, snapshot, None, headers).await {
        Ok(served) => served,
        Err(ObjectReadError::Rejected(response)) => return response,
        Err(ObjectReadError::Storage(_)) => {
            return s3_error_response(S3Error::new(S3ErrorCode::NoSuchKey, "Object not found"));
        }
        Err(ObjectReadError::RangeNotSatisfiable(_)) | Err(ObjectReadError::Internal(_)) => {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InternalError,
                "SelectObjectContent execution failed",
            ));
        }
    };

    let data_stream = served
        .body
        .into_data_stream()
        .map_err(std::io::Error::other);
    let reader = SyncIoBridge::new(StreamReader::new(data_stream));

    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(16);
    tokio::task::spawn_blocking(move || {
        let outcome = (|| -> Result<(u64, u64), String> {
            let (counting, counter) = CountingReader::new(reader);
            let input: Box<dyn std::io::Read + Send> = Box::new(counting);
            let mut source: Box<dyn RecordSource> = match &request.input_format {
                InputFormat::Csv(cfg) => Box::new(CsvSource::new(
                    input,
                    cfg.field_delimiter,
                    cfg.quote_character,
                    cfg.comment_character,
                    CsvHeaderMode::from_file_header_info(&cfg.file_header_info),
                )?),
                InputFormat::Json(cfg) => {
                    Box::new(JsonSource::new(input, cfg.json_type != "LINES"))
                }
                InputFormat::Parquet => unreachable!(),
            };
            let returned = run_and_emit(source.as_mut(), &plan, &output_cfg, &tx)?;
            Ok((counter.load(Ordering::Relaxed), returned))
        })();
        finish_stream(&tx, outcome);
    });

    select_stream_response(rx)
}

async fn run_parquet_select(
    state: &AppState,
    bucket: &str,
    key: &str,
    plan: SelectPlan,
    output_cfg: OutputFormatCfg,
) -> Response {
    let meta = match state.storage.head_object(bucket, key).await {
        Ok(meta) => meta,
        Err(_) => {
            return s3_error_response(S3Error::new(S3ErrorCode::NoSuchKey, "Object not found"));
        }
    };
    if EncryptionMetadata::from_metadata(&meta.internal_metadata).is_some()
        || super::mpu_is_sse_c(&meta.internal_metadata)
    {
        return s3_error_response(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "SelectObjectContent with Parquet input is not supported on encrypted objects",
        ));
    }

    let segmented = meta
        .internal_metadata
        .contains_key(myfsio_storage::segments::META_KEY_SEGMENTS);
    let (object_path, cleanup) = if segmented {
        match state.storage.materialize_object_to_tmp(bucket, key).await {
            Ok(path) => (path.clone(), Some(path)),
            Err(_) => {
                return s3_error_response(S3Error::new(S3ErrorCode::NoSuchKey, "Object not found"));
            }
        }
    } else {
        match state.storage.get_object_path(bucket, key).await {
            Ok(path) => (path, None),
            Err(_) => {
                return s3_error_response(S3Error::new(S3ErrorCode::NoSuchKey, "Object not found"));
            }
        }
    };

    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(16);
    tokio::task::spawn_blocking(move || {
        let outcome = (|| -> Result<(u64, u64), String> {
            let file = std::fs::File::open(&object_path)
                .map_err(|e| format!("Failed opening object: {}", e))?;
            let scanned = file.metadata().map(|m| m.len()).unwrap_or(0);
            let mut source = ParquetSource::new(file)?;
            let returned = run_and_emit(&mut source, &plan, &output_cfg, &tx)?;
            Ok((scanned, returned))
        })();
        if let Some(path) = cleanup {
            let _ = std::fs::remove_file(&path);
        }
        finish_stream(&tx, outcome);
    });

    select_stream_response(rx)
}

fn run_and_emit(
    source: &mut dyn RecordSource,
    plan: &SelectPlan,
    output_cfg: &OutputFormatCfg,
    tx: &tokio::sync::mpsc::Sender<Bytes>,
) -> Result<u64, String> {
    let mut emit = |chunk: Vec<u8>| -> Result<(), String> {
        tx.blocking_send(Bytes::from(encode_select_event("Records", &chunk)))
            .map_err(|_| "client disconnected".to_string())
    };
    run_select(source, plan, output_cfg, &mut emit, &|| tx.is_closed())
}

fn finish_stream(tx: &tokio::sync::mpsc::Sender<Bytes>, outcome: Result<(u64, u64), String>) {
    match outcome {
        Ok((scanned, returned)) => {
            let stats = build_stats_xml(scanned as usize, returned as usize);
            let _ = tx.blocking_send(Bytes::from(encode_select_event("Stats", stats.as_bytes())));
            let _ = tx.blocking_send(Bytes::from(encode_select_event("End", b"")));
        }
        Err(message) => {
            let _ = tx.blocking_send(Bytes::from(encode_select_error_event(
                "InvalidRequest",
                &message,
            )));
        }
    }
}

fn select_stream_response(rx: tokio::sync::mpsc::Receiver<Bytes>) -> Response {
    let stream = ReceiverStream::new(rx).map(Ok::<Bytes, std::convert::Infallible>);
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
    field_delimiter: u8,
    quote_character: u8,
    comment_character: Option<u8>,
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
    quote_always: bool,
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

fn invalid_request(message: String) -> S3Error {
    S3Error::new(S3ErrorCode::InvalidRequest, message)
}

fn single_ascii_char(
    node: &roxmltree::Node<'_, '_>,
    name: &str,
    default_byte: u8,
) -> Result<u8, S3Error> {
    match child_text(node, name) {
        None => Ok(default_byte),
        Some(value) => {
            let mut chars = value.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) if c.is_ascii() => Ok(c as u8),
                _ => Err(invalid_request(format!(
                    "{} must be a single ASCII character",
                    name
                ))),
            }
        }
    }
}

fn require_no_compression(node: &roxmltree::Node<'_, '_>) -> Result<(), S3Error> {
    match child_text(node, "CompressionType") {
        None => Ok(()),
        Some(value) if value.eq_ignore_ascii_case("NONE") => Ok(()),
        Some(value) => Err(invalid_request(format!(
            "CompressionType {} is not supported",
            value
        ))),
    }
}

fn parse_input_format(node: &roxmltree::Node<'_, '_>) -> Result<InputFormat, S3Error> {
    require_no_compression(node)?;

    if let Some(csv_node) = child(node, "CSV") {
        let file_header_info = child_text(&csv_node, "FileHeaderInfo")
            .unwrap_or_else(|| "NONE".to_string())
            .to_ascii_uppercase();
        if !matches!(file_header_info.as_str(), "USE" | "IGNORE" | "NONE") {
            return Err(invalid_request(
                "FileHeaderInfo must be USE, IGNORE, or NONE".to_string(),
            ));
        }
        let field_delimiter = single_ascii_char(&csv_node, "FieldDelimiter", b',')?;
        let quote_character = single_ascii_char(&csv_node, "QuoteCharacter", b'"')?;
        let comment_character = match child_text(&csv_node, "Comments") {
            None => None,
            Some(_) => Some(single_ascii_char(&csv_node, "Comments", b'#')?),
        };
        if let Some(value) = child_text(&csv_node, "RecordDelimiter") {
            if value != "\n" && value != "\r\n" {
                return Err(invalid_request(
                    "Input CSV RecordDelimiter must be \\n or \\r\\n".to_string(),
                ));
            }
        }
        if let Some(value) = child_text(&csv_node, "QuoteEscapeCharacter") {
            if value.len() != 1 || value.as_bytes()[0] != quote_character {
                return Err(invalid_request(
                    "QuoteEscapeCharacter other than the quote character is not supported"
                        .to_string(),
                ));
            }
        }
        if let Some(value) = child_text(&csv_node, "AllowQuotedRecordDelimiter") {
            if !value.eq_ignore_ascii_case("true") && !value.eq_ignore_ascii_case("false") {
                return Err(invalid_request(
                    "AllowQuotedRecordDelimiter must be TRUE or FALSE".to_string(),
                ));
            }
        }
        return Ok(InputFormat::Csv(CsvInputConfig {
            file_header_info,
            field_delimiter,
            quote_character,
            comment_character,
        }));
    }

    if let Some(json_node) = child(node, "JSON") {
        let json_type = child_text(&json_node, "Type")
            .unwrap_or_else(|| "DOCUMENT".to_string())
            .to_ascii_uppercase();
        if !matches!(json_type.as_str(), "DOCUMENT" | "LINES") {
            return Err(invalid_request(
                "JSON Type must be DOCUMENT or LINES".to_string(),
            ));
        }
        return Ok(InputFormat::Json(JsonInputConfig { json_type }));
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
        let field_delimiter = single_ascii_char(&csv_node, "FieldDelimiter", b',')?;
        let quote_character = single_ascii_char(&csv_node, "QuoteCharacter", b'"')?;
        if let Some(value) = child_text(&csv_node, "QuoteEscapeCharacter") {
            if value.len() != 1 || value.as_bytes()[0] != quote_character {
                return Err(invalid_request(
                    "QuoteEscapeCharacter other than the quote character is not supported"
                        .to_string(),
                ));
            }
        }
        let quote_always = match child_text(&csv_node, "QuoteFields") {
            None => false,
            Some(value) if value.eq_ignore_ascii_case("ASNEEDED") => false,
            Some(value) if value.eq_ignore_ascii_case("ALWAYS") => true,
            Some(_) => {
                return Err(invalid_request(
                    "QuoteFields must be ALWAYS or ASNEEDED".to_string(),
                ));
            }
        };
        return Ok(OutputFormat::Csv(CsvOutputConfig {
            field_delimiter: (field_delimiter as char).to_string(),
            record_delimiter: child_text(&csv_node, "RecordDelimiter")
                .unwrap_or_else(|| "\n".to_string()),
            quote_character: (quote_character as char).to_string(),
            quote_always,
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
    encode_event_message(headers, payload)
}

fn encode_select_error_event(code: &str, message: &str) -> Vec<u8> {
    let mut headers = Vec::new();
    headers.extend(encode_select_header(":error-code", code));
    headers.extend(encode_select_header(
        ":error-message",
        truncate_header_value(message),
    ));
    headers.extend(encode_select_header(":message-type", "error"));
    encode_event_message(headers, b"")
}

fn truncate_header_value(value: &str) -> &str {
    const MAX: usize = 512;
    if value.len() <= MAX {
        return value;
    }
    let mut end = MAX;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn encode_event_message(headers: Vec<u8>, payload: &[u8]) -> Vec<u8> {
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
    let mut boundary = value.len().min(usize::from(u16::MAX));
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    let value_bytes = &value.as_bytes()[..boundary];
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
mod event_frame_tests {
    use super::{encode_select_error_event, encode_select_event};

    fn assert_frame_consistent(frame: &[u8]) {
        let total = u32::from_be_bytes(frame[0..4].try_into().unwrap()) as usize;
        let header_len = u32::from_be_bytes(frame[4..8].try_into().unwrap()) as usize;
        assert_eq!(total, frame.len(), "declared total length must match");
        let mut i = 12;
        let end = 12 + header_len;
        while i < end {
            let name_len = frame[i] as usize;
            i += 1 + name_len;
            assert_eq!(frame[i], 7, "header value type must be string");
            i += 1;
            let value_len = u16::from_be_bytes(frame[i..i + 2].try_into().unwrap()) as usize;
            i += 2 + value_len;
        }
        assert_eq!(i, end, "headers must end exactly at declared length");
    }

    #[test]
    fn huge_error_message_still_encodes_a_valid_frame() {
        let message = "x".repeat(5 * 1024 * 1024);
        let frame = encode_select_error_event("InvalidRequest", &message);
        assert_frame_consistent(&frame);
        assert!(frame.len() < 2048, "error frame should be small");
    }

    #[test]
    fn multibyte_error_message_truncates_on_char_boundary() {
        let message = "é".repeat(100_000);
        let frame = encode_select_error_event("InvalidRequest", &message);
        assert_frame_consistent(&frame);
    }

    #[test]
    fn records_and_control_frames_are_consistent() {
        assert_frame_consistent(&encode_select_event("Records", b"hello,world\n"));
        assert_frame_consistent(&encode_select_event("Stats", b"<Stats></Stats>"));
        assert_frame_consistent(&encode_select_event("End", b""));
    }
}
