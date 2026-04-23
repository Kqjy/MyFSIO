use chrono::{DateTime, Utc};
use myfsio_common::types::{BucketMeta, ObjectMeta};
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use std::io::Cursor;

pub fn format_s3_datetime(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

pub fn rate_limit_exceeded_xml() -> String {
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<Error><Code>SlowDown</Code><Message>Rate limit exceeded</Message><Resource></Resource><RequestId></RequestId></Error>"
        .to_string()
}

pub fn list_buckets_xml(owner_id: &str, owner_name: &str, buckets: &[BucketMeta]) -> String {
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
    )
}

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
) -> String {
    let mut writer = Writer::new(Cursor::new(Vec::new()));

    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .unwrap();

    let start = BytesStart::new("ListBucketResult")
        .with_attributes([("xmlns", "http://s3.amazonaws.com/doc/2006-03-01/")]);
    writer.write_event(Event::Start(start)).unwrap();

    write_text_element(&mut writer, "Name", bucket_name);
    write_text_element(&mut writer, "Prefix", &maybe_url_encode(prefix, encoding_type));
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

    for obj in objects {
        writer
            .write_event(Event::Start(BytesStart::new("Contents")))
            .unwrap();
        write_text_element(&mut writer, "Key", &maybe_url_encode(&obj.key, encoding_type));
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
        writer
            .write_event(Event::End(BytesEnd::new("Contents")))
            .unwrap();
    }

    for prefix in common_prefixes {
        writer
            .write_event(Event::Start(BytesStart::new("CommonPrefixes")))
            .unwrap();
        write_text_element(&mut writer, "Prefix", &maybe_url_encode(prefix, encoding_type));
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
    let mut writer = Writer::new(Cursor::new(Vec::new()));

    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .unwrap();

    let start = BytesStart::new("ListBucketResult")
        .with_attributes([("xmlns", "http://s3.amazonaws.com/doc/2006-03-01/")]);
    writer.write_event(Event::Start(start)).unwrap();

    write_text_element(&mut writer, "Name", bucket_name);
    write_text_element(&mut writer, "Prefix", &maybe_url_encode(prefix, encoding_type));
    write_text_element(&mut writer, "Marker", &maybe_url_encode(marker, encoding_type));
    write_text_element(&mut writer, "MaxKeys", &max_keys.to_string());
    write_text_element(&mut writer, "IsTruncated", &is_truncated.to_string());

    if !delimiter.is_empty() {
        write_text_element(
            &mut writer,
            "Delimiter",
            &maybe_url_encode(delimiter, encoding_type),
        );
    }
    if !delimiter.is_empty() && is_truncated {
        if let Some(nm) = next_marker {
            if !nm.is_empty() {
                write_text_element(&mut writer, "NextMarker", &maybe_url_encode(nm, encoding_type));
            }
        }
    }
    if let Some(encoding) = encoding_type {
        if !encoding.is_empty() {
            write_text_element(&mut writer, "EncodingType", encoding);
        }
    }

    for obj in objects {
        writer
            .write_event(Event::Start(BytesStart::new("Contents")))
            .unwrap();
        write_text_element(&mut writer, "Key", &maybe_url_encode(&obj.key, encoding_type));
        write_text_element(
            &mut writer,
            "LastModified",
            &format_s3_datetime(&obj.last_modified),
        );
        if let Some(ref etag) = obj.etag {
            write_text_element(&mut writer, "ETag", &format!("\"{}\"", etag));
        }
        write_text_element(&mut writer, "Size", &obj.size.to_string());
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

pub fn list_multipart_uploads_xml(
    bucket: &str,
    uploads: &[myfsio_common::types::MultipartUploadInfo],
) -> String {
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .unwrap();

    let start = BytesStart::new("ListMultipartUploadsResult")
        .with_attributes([("xmlns", "http://s3.amazonaws.com/doc/2006-03-01/")]);
    writer.write_event(Event::Start(start)).unwrap();
    write_text_element(&mut writer, "Bucket", bucket);

    for upload in uploads {
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

pub fn list_parts_xml(
    bucket: &str,
    key: &str,
    upload_id: &str,
    parts: &[myfsio_common::types::PartMeta],
) -> String {
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .unwrap();

    let start = BytesStart::new("ListPartsResult")
        .with_attributes([("xmlns", "http://s3.amazonaws.com/doc/2006-03-01/")]);
    writer.write_event(Event::Start(start)).unwrap();
    write_text_element(&mut writer, "Bucket", bucket);
    write_text_element(&mut writer, "Key", key);
    write_text_element(&mut writer, "UploadId", upload_id);

    for part in parts {
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
        let xml = list_buckets_xml("owner-id", "owner-name", &buckets);
        assert!(xml.contains("<Name>test-bucket</Name>"));
        assert!(xml.contains("<ID>owner-id</ID>"));
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
}
