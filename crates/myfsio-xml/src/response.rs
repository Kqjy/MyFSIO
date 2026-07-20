use chrono::{DateTime, Utc};
use myfsio_common::types::{BucketMeta, ObjectMeta};
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use std::io::Cursor;

pub fn format_s3_datetime(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

pub fn rate_limit_exceeded_xml(resource: &str, request_id: &str) -> String {
    let host_id = derive_host_id(request_id);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<Error><Code>SlowDown</Code><Message>Please reduce your request rate</Message><Resource>{}</Resource><RequestId>{}</RequestId><HostId>{}</HostId></Error>",
        xml_escape(resource),
        xml_escape(request_id),
        xml_escape(&host_id),
    )
}

fn derive_host_id(request_id: &str) -> String {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    if request_id.is_empty() {
        return String::new();
    }
    let mut hasher = Sha256::new();
    hasher.update(b"myfsio-host-id\0");
    hasher.update(request_id.as_bytes());
    B64.encode(hasher.finalize())
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub fn list_buckets_xml(
    owner_id: &str,
    owner_name: &str,
    buckets: &[BucketMeta],
    region: &str,
) -> String {
    let mut writer = Writer::new(Cursor::new(Vec::new()));

    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .unwrap();

    let start = BytesStart::new("ListAllMyBucketsResult")
        .with_attributes([("xmlns", "http://s3.amazonaws.com/doc/2006-03-01/")]);
    writer.write_event(Event::Start(start)).unwrap();

    writer
        .write_event(Event::Start(BytesStart::new("Owner")))
        .unwrap();
    write_text_element(&mut writer, "ID", owner_id);
    write_text_element(&mut writer, "DisplayName", owner_name);
    writer
        .write_event(Event::End(BytesEnd::new("Owner")))
        .unwrap();

    writer
        .write_event(Event::Start(BytesStart::new("Buckets")))
        .unwrap();
    for bucket in buckets {
        writer
            .write_event(Event::Start(BytesStart::new("Bucket")))
            .unwrap();
        write_text_element(&mut writer, "Name", &bucket.name);
        write_text_element(
            &mut writer,
            "CreationDate",
            &format_s3_datetime(&bucket.creation_date),
        );
        write_text_element(&mut writer, "BucketRegion", region);
        writer
            .write_event(Event::End(BytesEnd::new("Bucket")))
            .unwrap();
    }
    writer
        .write_event(Event::End(BytesEnd::new("Buckets")))
        .unwrap();

    writer
        .write_event(Event::End(BytesEnd::new("ListAllMyBucketsResult")))
        .unwrap();

    String::from_utf8(writer.into_inner().into_inner()).unwrap()
}

fn maybe_url_encode(value: &str, encoding_type: Option<&str>) -> String {
    if matches!(encoding_type, Some(v) if v.eq_ignore_ascii_case("url")) {
        percent_encoding::utf8_percent_encode(value, KEY_ENCODE_SET).to_string()
    } else {
        value.to_string()
    }
}

const KEY_ENCODE_SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'/');

pub fn list_objects_v2_xml(
    bucket_name: &str,
    prefix: &str,
    delimiter: &str,
    max_keys: usize,
    objects: &[ObjectMeta],
    common_prefixes: &[String],
    is_truncated: bool,
    continuation_token: Option<&str>,
    next_continuation_token: Option<&str>,
    key_count: usize,
) -> String {
    list_objects_v2_xml_with_encoding(
        bucket_name,
        prefix,
        delimiter,
        max_keys,
        objects,
        common_prefixes,
        is_truncated,
        continuation_token,
        next_continuation_token,
        key_count,
        None,
        false,
        None,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn list_objects_v2_xml_with_encoding(
    bucket_name: &str,
    prefix: &str,
    delimiter: &str,
    max_keys: usize,
    objects: &[ObjectMeta],
    common_prefixes: &[String],
    is_truncated: bool,
    continuation_token: Option<&str>,
    next_continuation_token: Option<&str>,
    key_count: usize,
    encoding_type: Option<&str>,
    fetch_owner: bool,
    start_after: Option<&str>,
    owner_id: Option<&str>,
    owner_display_name: Option<&str>,
) -> String {
    list_objects_v2_xml_full(
        bucket_name,
        prefix,
        delimiter,
        max_keys,
        objects,
        common_prefixes,
        is_truncated,
        continuation_token,
        next_continuation_token,
        key_count,
        encoding_type,
        fetch_owner,
        start_after,
        owner_id,
        owner_display_name,
        &std::collections::HashMap::new(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn list_objects_v2_xml_full(
    bucket_name: &str,
    prefix: &str,
    delimiter: &str,
    max_keys: usize,
    objects: &[ObjectMeta],
    common_prefixes: &[String],
    is_truncated: bool,
    continuation_token: Option<&str>,
    next_continuation_token: Option<&str>,
    key_count: usize,
    encoding_type: Option<&str>,
    fetch_owner: bool,
    start_after: Option<&str>,
    owner_id: Option<&str>,
    owner_display_name: Option<&str>,
    owner_display_map: &std::collections::HashMap<String, String>,
) -> String {
    let mut writer = Writer::new(Cursor::new(Vec::new()));

    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .unwrap();

    let start = BytesStart::new("ListBucketResult")
        .with_attributes([("xmlns", "http://s3.amazonaws.com/doc/2006-03-01/")]);
    writer.write_event(Event::Start(start)).unwrap();

    write_text_element(&mut writer, "Name", bucket_name);
    write_text_element(
        &mut writer,
        "Prefix",
        &maybe_url_encode(prefix, encoding_type),
    );
    if !delimiter.is_empty() {
        write_text_element(
            &mut writer,
            "Delimiter",
            &maybe_url_encode(delimiter, encoding_type),
        );
    }
    write_text_element(&mut writer, "MaxKeys", &max_keys.to_string());
    write_text_element(&mut writer, "KeyCount", &key_count.to_string());
    write_text_element(&mut writer, "IsTruncated", &is_truncated.to_string());
    if let Some(encoding) = encoding_type {
        if !encoding.is_empty() {
            write_text_element(&mut writer, "EncodingType", encoding);
        }
    }

    if let Some(token) = continuation_token {
        write_text_element(&mut writer, "ContinuationToken", token);
    }
    if let Some(token) = next_continuation_token {
        write_text_element(&mut writer, "NextContinuationToken", token);
    }
    if let Some(sa) = start_after {
        if !sa.is_empty() {
            write_text_element(
                &mut writer,
                "StartAfter",
                &maybe_url_encode(sa, encoding_type),
            );
        }
    }

    let default_owner_id = owner_id.unwrap_or("myfsio");
    let default_owner_display = owner_display_name.unwrap_or(default_owner_id);

    for obj in objects {
        writer
            .write_event(Event::Start(BytesStart::new("Contents")))
            .unwrap();
        write_text_element(
            &mut writer,
            "Key",
            &maybe_url_encode(&obj.key, encoding_type),
        );
        write_text_element(
            &mut writer,
            "LastModified",
            &format_s3_datetime(&obj.last_modified),
        );
        if let Some(ref etag) = obj.etag {
            write_text_element(&mut writer, "ETag", &format!("\"{}\"", etag));
        }
        write_text_element(&mut writer, "Size", &obj.size.to_string());
        write_text_element(
            &mut writer,
            "StorageClass",
            obj.storage_class.as_deref().unwrap_or("STANDARD"),
        );
        if fetch_owner {
            let obj_owner_id = obj.owner.as_deref().unwrap_or(default_owner_id);
            let obj_owner_display = owner_display_map
                .get(obj_owner_id)
                .map(String::as_str)
                .unwrap_or_else(|| {
                    if obj.owner.is_none() {
                        default_owner_display
                    } else {
                        obj_owner_id
                    }
                });
            writer
                .write_event(Event::Start(BytesStart::new("Owner")))
                .unwrap();
            write_text_element(&mut writer, "ID", obj_owner_id);
            write_text_element(&mut writer, "DisplayName", obj_owner_display);
            writer
                .write_event(Event::End(BytesEnd::new("Owner")))
                .unwrap();
        }
        writer
            .write_event(Event::End(BytesEnd::new("Contents")))
            .unwrap();
    }

    for prefix in common_prefixes {
        writer
            .write_event(Event::Start(BytesStart::new("CommonPrefixes")))
            .unwrap();
        write_text_element(
            &mut writer,
            "Prefix",
            &maybe_url_encode(prefix, encoding_type),
        );
        writer
            .write_event(Event::End(BytesEnd::new("CommonPrefixes")))
            .unwrap();
    }

    writer
        .write_event(Event::End(BytesEnd::new("ListBucketResult")))
        .unwrap();

    String::from_utf8(writer.into_inner().into_inner()).unwrap()
}

pub fn list_objects_v1_xml(
    bucket_name: &str,
    prefix: &str,
    marker: &str,
    delimiter: &str,
    max_keys: usize,
    objects: &[ObjectMeta],
    common_prefixes: &[String],
    is_truncated: bool,
    next_marker: Option<&str>,
) -> String {
    list_objects_v1_xml_with_encoding(
        bucket_name,
        prefix,
        marker,
        delimiter,
        max_keys,
        objects,
        common_prefixes,
        is_truncated,
        next_marker,
        None,
    )
}

pub fn list_objects_v1_xml_with_encoding(
    bucket_name: &str,
    prefix: &str,
    marker: &str,
    delimiter: &str,
    max_keys: usize,
    objects: &[ObjectMeta],
    common_prefixes: &[String],
    is_truncated: bool,
    next_marker: Option<&str>,
    encoding_type: Option<&str>,
) -> String {
    list_objects_v1_xml_with_owner(
        bucket_name,
        prefix,
        marker,
        delimiter,
        max_keys,
        objects,
        common_prefixes,
        is_truncated,
        next_marker,
        encoding_type,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn list_objects_v1_xml_with_owner(
    bucket_name: &str,
    prefix: &str,
    marker: &str,
    delimiter: &str,
    max_keys: usize,
    objects: &[ObjectMeta],
    common_prefixes: &[String],
    is_truncated: bool,
    next_marker: Option<&str>,
    encoding_type: Option<&str>,
    owner_id: Option<&str>,
    owner_display_name: Option<&str>,
) -> String {
    list_objects_v1_xml_full(
        bucket_name,
        prefix,
        marker,
        delimiter,
        max_keys,
        objects,
        common_prefixes,
        is_truncated,
        next_marker,
        encoding_type,
        owner_id,
        owner_display_name,
        &std::collections::HashMap::new(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn list_objects_v1_xml_full(
    bucket_name: &str,
    prefix: &str,
    marker: &str,
    delimiter: &str,
    max_keys: usize,
    objects: &[ObjectMeta],
    common_prefixes: &[String],
    is_truncated: bool,
    next_marker: Option<&str>,
    encoding_type: Option<&str>,
    owner_id: Option<&str>,
    owner_display_name: Option<&str>,
    owner_display_map: &std::collections::HashMap<String, String>,
) -> String {
    let mut writer = Writer::new(Cursor::new(Vec::new()));

    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .unwrap();

    let start = BytesStart::new("ListBucketResult")
        .with_attributes([("xmlns", "http://s3.amazonaws.com/doc/2006-03-01/")]);
    writer.write_event(Event::Start(start)).unwrap();

    write_text_element(&mut writer, "Name", bucket_name);
    write_text_element(
        &mut writer,
        "Prefix",
        &maybe_url_encode(prefix, encoding_type),
    );
    write_text_element(
        &mut writer,
        "Marker",
        &maybe_url_encode(marker, encoding_type),
    );
    write_text_element(&mut writer, "MaxKeys", &max_keys.to_string());
    write_text_element(&mut writer, "IsTruncated", &is_truncated.to_string());

    if !delimiter.is_empty() {
        write_text_element(
            &mut writer,
            "Delimiter",
            &maybe_url_encode(delimiter, encoding_type),
        );
    }
    if is_truncated {
        let fallback = next_marker
            .filter(|nm| !nm.is_empty())
            .map(|nm| nm.to_string())
            .or_else(|| {
                if !delimiter.is_empty() {
                    common_prefixes.last().cloned()
                } else {
                    objects.last().map(|o| o.key.clone())
                }
            });
        if let Some(nm) = fallback {
            if !nm.is_empty() {
                write_text_element(
                    &mut writer,
                    "NextMarker",
                    &maybe_url_encode(&nm, encoding_type),
                );
            }
        }
    }
    if let Some(encoding) = encoding_type {
        if !encoding.is_empty() {
            write_text_element(&mut writer, "EncodingType", encoding);
        }
    }

    let default_owner_id = owner_id.unwrap_or("myfsio");
    let default_owner_display = owner_display_name.unwrap_or(default_owner_id);

    for obj in objects {
        writer
            .write_event(Event::Start(BytesStart::new("Contents")))
            .unwrap();
        write_text_element(
            &mut writer,
            "Key",
            &maybe_url_encode(&obj.key, encoding_type),
        );
        write_text_element(
            &mut writer,
            "LastModified",
            &format_s3_datetime(&obj.last_modified),
        );
        if let Some(ref etag) = obj.etag {
            write_text_element(&mut writer, "ETag", &format!("\"{}\"", etag));
        }
        write_text_element(&mut writer, "Size", &obj.size.to_string());
        let obj_owner_id = obj.owner.as_deref().unwrap_or(default_owner_id);
        let obj_owner_display = owner_display_map
            .get(obj_owner_id)
            .map(String::as_str)
            .unwrap_or_else(|| {
                if obj.owner.is_none() {
                    default_owner_display
                } else {
                    obj_owner_id
                }
            });
        writer
            .write_event(Event::Start(BytesStart::new("Owner")))
            .unwrap();
        write_text_element(&mut writer, "ID", obj_owner_id);
        write_text_element(&mut writer, "DisplayName", obj_owner_display);
        writer
            .write_event(Event::End(BytesEnd::new("Owner")))
            .unwrap();
        write_text_element(
            &mut writer,
            "StorageClass",
            obj.storage_class.as_deref().unwrap_or("STANDARD"),
        );
        writer
            .write_event(Event::End(BytesEnd::new("Contents")))
            .unwrap();
    }

    for cp in common_prefixes {
        writer
            .write_event(Event::Start(BytesStart::new("CommonPrefixes")))
            .unwrap();
        write_text_element(&mut writer, "Prefix", &maybe_url_encode(cp, encoding_type));
        writer
            .write_event(Event::End(BytesEnd::new("CommonPrefixes")))
            .unwrap();
    }

    writer
        .write_event(Event::End(BytesEnd::new("ListBucketResult")))
        .unwrap();

    String::from_utf8(writer.into_inner().into_inner()).unwrap()
}

fn write_text_element(writer: &mut Writer<Cursor<Vec<u8>>>, tag: &str, text: &str) {
    writer
        .write_event(Event::Start(BytesStart::new(tag)))
        .unwrap();
    writer
        .write_event(Event::Text(BytesText::new(text)))
        .unwrap();
    writer.write_event(Event::End(BytesEnd::new(tag))).unwrap();
}

pub fn initiate_multipart_upload_xml(bucket: &str, key: &str, upload_id: &str) -> String {
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .unwrap();

    let start = BytesStart::new("InitiateMultipartUploadResult")
        .with_attributes([("xmlns", "http://s3.amazonaws.com/doc/2006-03-01/")]);
    writer.write_event(Event::Start(start)).unwrap();
    write_text_element(&mut writer, "Bucket", bucket);
    write_text_element(&mut writer, "Key", key);
    write_text_element(&mut writer, "UploadId", upload_id);
    writer
        .write_event(Event::End(BytesEnd::new("InitiateMultipartUploadResult")))
        .unwrap();

    String::from_utf8(writer.into_inner().into_inner()).unwrap()
}

pub fn complete_multipart_upload_xml(
    bucket: &str,
    key: &str,
    etag: &str,
    location: &str,
) -> String {
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .unwrap();

    let start = BytesStart::new("CompleteMultipartUploadResult")
        .with_attributes([("xmlns", "http://s3.amazonaws.com/doc/2006-03-01/")]);
    writer.write_event(Event::Start(start)).unwrap();
    write_text_element(&mut writer, "Location", location);
    write_text_element(&mut writer, "Bucket", bucket);
    write_text_element(&mut writer, "Key", key);
    write_text_element(&mut writer, "ETag", &format!("\"{}\"", etag));
    writer
        .write_event(Event::End(BytesEnd::new("CompleteMultipartUploadResult")))
        .unwrap();

    String::from_utf8(writer.into_inner().into_inner()).unwrap()
}

pub fn copy_part_result_xml(etag: &str, last_modified: &str) -> String {
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .unwrap();

    let start = BytesStart::new("CopyPartResult")
        .with_attributes([("xmlns", "http://s3.amazonaws.com/doc/2006-03-01/")]);
    writer.write_event(Event::Start(start)).unwrap();
    write_text_element(&mut writer, "LastModified", last_modified);
    write_text_element(&mut writer, "ETag", &format!("\"{}\"", etag));
    writer
        .write_event(Event::End(BytesEnd::new("CopyPartResult")))
        .unwrap();

    String::from_utf8(writer.into_inner().into_inner()).unwrap()
}

pub fn post_object_result_xml(location: &str, bucket: &str, key: &str, etag: &str) -> String {
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .unwrap();

    let start = BytesStart::new("PostResponse")
        .with_attributes([("xmlns", "http://s3.amazonaws.com/doc/2006-03-01/")]);
    writer.write_event(Event::Start(start)).unwrap();
    write_text_element(&mut writer, "Location", location);
    write_text_element(&mut writer, "Bucket", bucket);
    write_text_element(&mut writer, "Key", key);
    write_text_element(&mut writer, "ETag", &format!("\"{}\"", etag));
    writer
        .write_event(Event::End(BytesEnd::new("PostResponse")))
        .unwrap();

    String::from_utf8(writer.into_inner().into_inner()).unwrap()
}

pub fn copy_object_result_xml(etag: &str, last_modified: &str) -> String {
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .unwrap();

    let start = BytesStart::new("CopyObjectResult")
        .with_attributes([("xmlns", "http://s3.amazonaws.com/doc/2006-03-01/")]);
    writer.write_event(Event::Start(start)).unwrap();
    write_text_element(&mut writer, "ETag", &format!("\"{}\"", etag));
    write_text_element(&mut writer, "LastModified", last_modified);
    writer
        .write_event(Event::End(BytesEnd::new("CopyObjectResult")))
        .unwrap();

    String::from_utf8(writer.into_inner().into_inner()).unwrap()
}

pub struct DeletedEntry {
    pub key: String,
    pub version_id: Option<String>,
    pub delete_marker: bool,
    pub delete_marker_version_id: Option<String>,
}

pub fn delete_result_xml(
    deleted: &[DeletedEntry],
    errors: &[(String, String, String)],
    quiet: bool,
) -> String {
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .unwrap();

    let start = BytesStart::new("DeleteResult")
        .with_attributes([("xmlns", "http://s3.amazonaws.com/doc/2006-03-01/")]);
    writer.write_event(Event::Start(start)).unwrap();

    if !quiet {
        for entry in deleted {
            writer
                .write_event(Event::Start(BytesStart::new("Deleted")))
                .unwrap();
            write_text_element(&mut writer, "Key", &entry.key);
            if let Some(ref vid) = entry.version_id {
                write_text_element(&mut writer, "VersionId", vid);
            }
            if entry.delete_marker {
                write_text_element(&mut writer, "DeleteMarker", "true");
                if let Some(ref dm_vid) = entry.delete_marker_version_id {
                    write_text_element(&mut writer, "DeleteMarkerVersionId", dm_vid);
                }
            }
            writer
                .write_event(Event::End(BytesEnd::new("Deleted")))
                .unwrap();
        }
    }

    for (key, code, message) in errors {
        writer
            .write_event(Event::Start(BytesStart::new("Error")))
            .unwrap();
        write_text_element(&mut writer, "Key", key);
        write_text_element(&mut writer, "Code", code);
        write_text_element(&mut writer, "Message", message);
        writer
            .write_event(Event::End(BytesEnd::new("Error")))
            .unwrap();
    }

    writer
        .write_event(Event::End(BytesEnd::new("DeleteResult")))
        .unwrap();

    String::from_utf8(writer.into_inner().into_inner()).unwrap()
}

pub struct ListMultipartUploadsParams<'a> {
    pub bucket: &'a str,
    pub key_marker: &'a str,
    pub upload_id_marker: &'a str,
    pub next_key_marker: &'a str,
    pub next_upload_id_marker: &'a str,
    pub max_uploads: usize,
    pub is_truncated: bool,
    pub uploads: &'a [myfsio_common::types::MultipartUploadInfo],
}

pub fn list_multipart_uploads_xml(
    bucket: &str,
    uploads: &[myfsio_common::types::MultipartUploadInfo],
) -> String {
    list_multipart_uploads_xml_paged(&ListMultipartUploadsParams {
        bucket,
        key_marker: "",
        upload_id_marker: "",
        next_key_marker: "",
        next_upload_id_marker: "",
        max_uploads: 1000,
        is_truncated: false,
        uploads,
    })
}

pub fn list_multipart_uploads_xml_paged(p: &ListMultipartUploadsParams<'_>) -> String {
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .unwrap();

    let start = BytesStart::new("ListMultipartUploadsResult")
        .with_attributes([("xmlns", "http://s3.amazonaws.com/doc/2006-03-01/")]);
    writer.write_event(Event::Start(start)).unwrap();
    write_text_element(&mut writer, "Bucket", p.bucket);
    write_text_element(&mut writer, "KeyMarker", p.key_marker);
    write_text_element(&mut writer, "UploadIdMarker", p.upload_id_marker);
    if p.is_truncated {
        write_text_element(&mut writer, "NextKeyMarker", p.next_key_marker);
        write_text_element(&mut writer, "NextUploadIdMarker", p.next_upload_id_marker);
    }
    write_text_element(&mut writer, "MaxUploads", &p.max_uploads.to_string());
    write_text_element(&mut writer, "IsTruncated", &p.is_truncated.to_string());

    for upload in p.uploads {
        writer
            .write_event(Event::Start(BytesStart::new("Upload")))
            .unwrap();
        write_text_element(&mut writer, "Key", &upload.key);
        write_text_element(&mut writer, "UploadId", &upload.upload_id);
        write_text_element(
            &mut writer,
            "Initiated",
            &format_s3_datetime(&upload.initiated),
        );
        writer
            .write_event(Event::End(BytesEnd::new("Upload")))
            .unwrap();
    }

    writer
        .write_event(Event::End(BytesEnd::new("ListMultipartUploadsResult")))
        .unwrap();

    String::from_utf8(writer.into_inner().into_inner()).unwrap()
}

pub struct ListPartsParams<'a> {
    pub bucket: &'a str,
    pub key: &'a str,
    pub upload_id: &'a str,
    pub part_number_marker: u32,
    pub next_part_number_marker: u32,
    pub max_parts: usize,
    pub is_truncated: bool,
    pub parts: &'a [myfsio_common::types::PartMeta],
}

pub fn list_parts_xml(
    bucket: &str,
    key: &str,
    upload_id: &str,
    parts: &[myfsio_common::types::PartMeta],
) -> String {
    list_parts_xml_paged(&ListPartsParams {
        bucket,
        key,
        upload_id,
        part_number_marker: 0,
        next_part_number_marker: parts.last().map(|p| p.part_number).unwrap_or(0),
        max_parts: 1000,
        is_truncated: false,
        parts,
    })
}

pub fn list_parts_xml_paged(p: &ListPartsParams<'_>) -> String {
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .unwrap();

    let start = BytesStart::new("ListPartsResult")
        .with_attributes([("xmlns", "http://s3.amazonaws.com/doc/2006-03-01/")]);
    writer.write_event(Event::Start(start)).unwrap();
    write_text_element(&mut writer, "Bucket", p.bucket);
    write_text_element(&mut writer, "Key", p.key);
    write_text_element(&mut writer, "UploadId", p.upload_id);
    write_text_element(
        &mut writer,
        "PartNumberMarker",
        &p.part_number_marker.to_string(),
    );
    write_text_element(
        &mut writer,
        "NextPartNumberMarker",
        &p.next_part_number_marker.to_string(),
    );
    write_text_element(&mut writer, "MaxParts", &p.max_parts.to_string());
    write_text_element(&mut writer, "IsTruncated", &p.is_truncated.to_string());

    for part in p.parts {
        writer
            .write_event(Event::Start(BytesStart::new("Part")))
            .unwrap();
        write_text_element(&mut writer, "PartNumber", &part.part_number.to_string());
        write_text_element(&mut writer, "ETag", &format!("\"{}\"", part.etag));
        write_text_element(&mut writer, "Size", &part.size.to_string());
        if let Some(ref lm) = part.last_modified {
            write_text_element(&mut writer, "LastModified", &format_s3_datetime(lm));
        }
        writer
            .write_event(Event::End(BytesEnd::new("Part")))
            .unwrap();
    }

    writer
        .write_event(Event::End(BytesEnd::new("ListPartsResult")))
        .unwrap();

    String::from_utf8(writer.into_inner().into_inner()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_list_buckets_xml() {
        let buckets = vec![BucketMeta {
            name: "test-bucket".to_string(),
            creation_date: Utc::now(),
        }];
        let xml = list_buckets_xml("owner-id", "owner-name", &buckets, "us-east-1");
        assert!(xml.contains("<Name>test-bucket</Name>"));
        assert!(xml.contains("<ID>owner-id</ID>"));
        assert!(xml.contains("<BucketRegion>us-east-1</BucketRegion>"));
        assert!(xml.contains("ListAllMyBucketsResult"));
    }

    #[test]
    fn test_list_objects_v2_xml() {
        let objects = vec![ObjectMeta::new("file.txt".to_string(), 1024, Utc::now())];
        let xml = list_objects_v2_xml(
            "my-bucket",
            "",
            "/",
            1000,
            &objects,
            &[],
            false,
            None,
            None,
            1,
        );
        assert!(xml.contains("<Key>file.txt</Key>"));
        assert!(xml.contains("<Size>1024</Size>"));
        assert!(xml.contains("<IsTruncated>false</IsTruncated>"));
    }

    #[test]
    fn test_list_objects_v1_xml() {
        let objects = vec![ObjectMeta::new("file.txt".to_string(), 1024, Utc::now())];
        let xml = list_objects_v1_xml("my-bucket", "", "", "/", 1000, &objects, &[], false, None);
        assert!(xml.contains("<Key>file.txt</Key>"));
        assert!(xml.contains("<Size>1024</Size>"));
        assert!(xml.contains("<Marker></Marker>"));
    }

    #[test]
    fn test_list_v1_uses_per_object_owner_with_canonical_fallback() {
        let mut explicit = ObjectMeta::new("explicit.txt".to_string(), 1, Utc::now());
        explicit.owner = Some("alice".to_string());
        let legacy = ObjectMeta::new("legacy.txt".to_string(), 1, Utc::now());

        let mut display_map = std::collections::HashMap::new();
        display_map.insert("alice".to_string(), "Alice A.".to_string());

        let xml = list_objects_v1_xml_full(
            "my-bucket",
            "",
            "",
            "",
            1000,
            &[explicit, legacy],
            &[],
            false,
            None,
            None,
            Some("myfsio"),
            Some("MyFSIO Service"),
            &display_map,
        );
        assert!(xml.contains("<ID>alice</ID>"));
        assert!(xml.contains("<DisplayName>Alice A.</DisplayName>"));
        assert!(xml.contains("<ID>myfsio</ID>"));
        assert!(xml.contains("<DisplayName>MyFSIO Service</DisplayName>"));
    }

    #[test]
    fn test_list_v2_uses_per_object_owner_with_canonical_fallback() {
        let mut explicit = ObjectMeta::new("explicit.txt".to_string(), 1, Utc::now());
        explicit.owner = Some("alice".to_string());
        let legacy = ObjectMeta::new("legacy.txt".to_string(), 1, Utc::now());

        let mut display_map = std::collections::HashMap::new();
        display_map.insert("alice".to_string(), "Alice A.".to_string());

        let xml = list_objects_v2_xml_full(
            "my-bucket",
            "",
            "",
            1000,
            &[explicit, legacy],
            &[],
            false,
            None,
            None,
            2,
            None,
            true,
            None,
            Some("myfsio"),
            Some("MyFSIO Service"),
            &display_map,
        );
        assert!(xml.contains("<ID>alice</ID>"));
        assert!(xml.contains("<DisplayName>Alice A.</DisplayName>"));
        assert!(xml.contains("<ID>myfsio</ID>"));
        assert!(xml.contains("<DisplayName>MyFSIO Service</DisplayName>"));
    }
}
