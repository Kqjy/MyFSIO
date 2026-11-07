pub mod request;
pub mod response;

use quick_xml::events::BytesRef;
use quick_xml::Writer;
use std::io::Cursor;

pub fn resolve_general_ref(reference: &BytesRef) -> Result<String, String> {
    if let Some(ch) = reference.resolve_char_ref().map_err(|e| e.to_string())? {
        return Ok(ch.to_string());
    }
    let name = reference.xml10_content();
    quick_xml::escape::resolve_predefined_entity(&name)
        .map(str::to_string)
        .ok_or_else(|| format!("Unrecognized entity reference: &{};", name))
}

pub fn write_xml_element(tag: &str, text: &str) -> String {
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    writer
        .create_element(tag)
        .write_text_content(quick_xml::events::BytesText::new(text))
        .unwrap();
    String::from_utf8(writer.into_inner().into_inner()).unwrap()
}
