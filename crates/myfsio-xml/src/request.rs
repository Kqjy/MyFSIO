use quick_xml::events::Event;
use quick_xml::Reader;

#[derive(Debug, Default, Clone)]
pub struct DeleteObjectsRequest {
    pub objects: Vec<ObjectIdentifier>,
    pub quiet: bool,
}

#[derive(Debug, Clone)]
pub struct ObjectIdentifier {
    pub key: String,
    pub version_id: Option<String>,
}

#[derive(Debug, Default)]
pub struct CompleteMultipartUpload {
    pub parts: Vec<CompletedPart>,
}

#[derive(Debug)]
pub struct CompletedPart {
    pub part_number: u32,
    pub etag: String,
}

pub fn parse_complete_multipart_upload(xml: &str) -> Result<CompleteMultipartUpload, String> {
    let mut reader = Reader::from_str(xml);
    let mut result = CompleteMultipartUpload::default();
    let mut buf = Vec::new();
    let mut current_tag = String::new();
    let mut part_number: Option<u32> = None;
    let mut etag: Option<String> = None;
    let mut in_part = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                current_tag = name.clone();
                if name == "Part" {
                    in_part = true;
                    part_number = None;
                    etag = None;
                }
            }
            Ok(Event::Text(ref e)) => {
                if in_part {
                    let text = e.unescape().map_err(|e| e.to_string())?.to_string();
                    match current_tag.as_str() {
                        "PartNumber" => {
                            part_number = Some(
                                text.trim()
                                    .parse()
                                    .map_err(|e: std::num::ParseIntError| e.to_string())?,
                            );
                        }
                        "ETag" => {
                            etag = Some(text.trim().trim_matches('"').to_string());
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name == "Part" && in_part {
                    if let (Some(pn), Some(et)) = (part_number.take(), etag.take()) {
                        result.parts.push(CompletedPart {
                            part_number: pn,
                            etag: et,
                        });
                    }
                    in_part = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {}", e)),
            _ => {}
        }
        buf.clear();
    }

    result.parts.sort_by_key(|p| p.part_number);
    Ok(result)
}

pub fn parse_delete_objects(xml: &str) -> Result<DeleteObjectsRequest, String> {
    let trimmed = xml.trim();
    if trimmed.is_empty() {
        return Err("Request body is empty".to_string());
    }

    let mut reader = Reader::from_str(xml);
    let mut result = DeleteObjectsRequest::default();
    let mut buf = Vec::new();
    let mut current_tag = String::new();
    let mut current_key: Option<String> = None;
    let mut current_version_id: Option<String> = None;
    let mut in_object = false;
    let mut saw_delete_root = false;
    let mut first_element_seen = false;

    loop {
        let event = reader.read_event_into(&mut buf);
        match event {
            Ok(Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                current_tag = name.clone();
                if !first_element_seen {
                    first_element_seen = true;
                    if name != "Delete" {
                        return Err(format!(
                            "Expected <Delete> root element, found <{}>",
                            name
                        ));
                    }
                    saw_delete_root = true;
                } else if name == "Object" {
                    in_object = true;
                    current_key = None;
                    current_version_id = None;
                }
            }
            Ok(Event::Empty(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if !first_element_seen {
                    first_element_seen = true;
                    if name != "Delete" {
                        return Err(format!(
                            "Expected <Delete> root element, found <{}>",
                            name
                        ));
                    }
                    saw_delete_root = true;
                }
            }
            Ok(Event::Text(ref e)) => {
                let text = e.unescape().map_err(|e| e.to_string())?.to_string();
                match current_tag.as_str() {
                    "Key" if in_object => {
                        current_key = Some(text.trim().to_string());
                    }
                    "VersionId" if in_object => {
                        current_version_id = Some(text.trim().to_string());
                    }
                    "Quiet" => {
                        result.quiet = text.trim() == "true";
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name == "Object" && in_object {
                    if let Some(key) = current_key.take() {
                        result.objects.push(ObjectIdentifier {
                            key,
                            version_id: current_version_id.take(),
                        });
                    }
                    in_object = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {}", e)),
            _ => {}
        }
        buf.clear();
    }

    if !saw_delete_root {
        return Err("Expected <Delete> root element".to_string());
    }
    if result.objects.is_empty() {
        return Err("Delete request must contain at least one <Object>".to_string());
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_complete_multipart() {
        let xml = r#"<CompleteMultipartUpload>
            <Part><PartNumber>2</PartNumber><ETag>"etag2"</ETag></Part>
            <Part><PartNumber>1</PartNumber><ETag>"etag1"</ETag></Part>
        </CompleteMultipartUpload>"#;

        let result = parse_complete_multipart_upload(xml).unwrap();
        assert_eq!(result.parts.len(), 2);
        assert_eq!(result.parts[0].part_number, 1);
        assert_eq!(result.parts[0].etag, "etag1");
        assert_eq!(result.parts[1].part_number, 2);
        assert_eq!(result.parts[1].etag, "etag2");
    }
}
