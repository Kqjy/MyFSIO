pub mod request;
pub mod response;

use quick_xml::Writer;
use std::io::Cursor;

pub fn write_xml_element(tag: &str, text: &str) -> String {
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    writer
        .create_element(tag)
        .write_text_content(quick_xml::events::BytesText::new(text))
        .unwrap();
    String::from_utf8(writer.into_inner().into_inner()).unwrap()
}
