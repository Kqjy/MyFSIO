use rust_embed::{EmbeddedFile, RustEmbed};

#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/templates"]
#[include = "*.html"]
pub struct EmbeddedTemplates;

#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/static"]
pub struct EmbeddedStatic;

pub fn template_names() -> Vec<String> {
    EmbeddedTemplates::iter()
        .map(|c: std::borrow::Cow<'static, str>| c.into_owned())
        .collect()
}

pub fn template_contents(name: &str) -> Option<String> {
    let file = EmbeddedTemplates::get(name)?;
    String::from_utf8(file.data.into_owned()).ok()
}

pub fn static_file(path: &str) -> Option<EmbeddedFile> {
    EmbeddedStatic::get(path)
}
