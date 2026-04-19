use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde_json::Value;
use tera::{Context, Error as TeraError, Tera};

pub type EndpointResolver = Arc<dyn Fn(&str, &HashMap<String, Value>) -> Option<String> + Send + Sync>;

#[derive(Clone)]
pub struct TemplateEngine {
    tera: Arc<RwLock<Tera>>,
    endpoints: Arc<RwLock<HashMap<String, String>>>,
}

impl TemplateEngine {
    pub fn new(template_glob: &str) -> Result<Self, TeraError> {
        let mut tera = Tera::new(template_glob)?;
        register_filters(&mut tera);

        let endpoints: Arc<RwLock<HashMap<String, String>>> =
            Arc::new(RwLock::new(HashMap::new()));

        register_functions(&mut tera, endpoints.clone());

        Ok(Self {
            tera: Arc::new(RwLock::new(tera)),
            endpoints,
        })
    }

    pub fn register_endpoint(&self, name: &str, path_template: &str) {
        self.endpoints
            .write()
            .insert(name.to_string(), path_template.to_string());
    }

    pub fn register_endpoints(&self, pairs: &[(&str, &str)]) {
        let mut guard = self.endpoints.write();
        for (n, p) in pairs {
            guard.insert((*n).to_string(), (*p).to_string());
        }
    }

    pub fn render(&self, name: &str, context: &Context) -> Result<String, TeraError> {
        self.tera.read().render(name, context)
    }

    pub fn reload(&self) -> Result<(), TeraError> {
        self.tera.write().full_reload()
    }
}

fn register_filters(tera: &mut Tera) {
    tera.register_filter("format_datetime", format_datetime_filter);
    tera.register_filter("filesizeformat", filesizeformat_filter);
}

fn register_functions(tera: &mut Tera, endpoints: Arc<RwLock<HashMap<String, String>>>) {
    let endpoints_for_url = endpoints.clone();
    tera.register_function(
        "url_for",
        move |args: &HashMap<String, Value>| -> tera::Result<Value> {
            let endpoint = args
                .get("endpoint")
                .and_then(|v| v.as_str())
                .ok_or_else(|| tera::Error::msg("url_for requires endpoint"))?;
            if endpoint == "static" {
                let filename = args
                    .get("filename")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                return Ok(Value::String(format!("/static/{}", filename)));
            }
            let path = match endpoints_for_url.read().get(endpoint) {
                Some(p) => p.clone(),
                None => {
                    return Ok(Value::String(format!("/__missing__/{}", endpoint)));
                }
            };
            Ok(Value::String(substitute_path_params(&path, args)))
        },
    );

    tera.register_function(
        "csrf_token",
        |args: &HashMap<String, Value>| -> tera::Result<Value> {
            if let Some(token) = args.get("token").and_then(|v| v.as_str()) {
                return Ok(Value::String(token.to_string()));
            }
            Ok(Value::String(String::new()))
        },
    );
}

fn substitute_path_params(template: &str, args: &HashMap<String, Value>) -> String {
    let mut path = template.to_string();
    let mut query: Vec<(String, String)> = Vec::new();
    for (k, v) in args {
        if k == "endpoint" || k == "filename" {
            continue;
        }
        let value_str = value_to_string(v);
        let placeholder = format!("{{{}}}", k);
        if path.contains(&placeholder) {
            let encoded = urlencode_path(&value_str);
            path = path.replace(&placeholder, &encoded);
        } else {
            query.push((k.clone(), value_str));
        }
    }
    if !query.is_empty() {
        let qs: Vec<String> = query
            .into_iter()
            .map(|(k, v)| format!("{}={}", urlencode_query(&k), urlencode_query(&v)))
            .collect();
        path.push('?');
        path.push_str(&qs.join("&"));
    }
    path
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

const UNRESERVED: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

fn urlencode_path(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, UNRESERVED).to_string()
}

fn urlencode_query(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, UNRESERVED).to_string()
}

fn format_datetime_filter(value: &Value, args: &HashMap<String, Value>) -> tera::Result<Value> {
    let format = args
        .get("format")
        .and_then(|v| v.as_str())
        .unwrap_or("%Y-%m-%d %H:%M:%S UTC");

    let dt: Option<DateTime<Utc>> = match value {
        Value::String(s) => DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|d| d.with_timezone(&Utc))
            .or_else(|| DateTime::parse_from_rfc2822(s).ok().map(|d| d.with_timezone(&Utc))),
        Value::Number(n) => n.as_f64().and_then(|f| {
            let secs = f as i64;
            let nanos = ((f - secs as f64) * 1_000_000_000.0) as u32;
            DateTime::<Utc>::from_timestamp(secs, nanos)
        }),
        _ => None,
    };

    match dt {
        Some(d) => Ok(Value::String(d.format(format).to_string())),
        None => Ok(value.clone()),
    }
}

fn filesizeformat_filter(value: &Value, _args: &HashMap<String, Value>) -> tera::Result<Value> {
    let bytes = match value {
        Value::Number(n) => n.as_f64().unwrap_or(0.0),
        Value::String(s) => s.parse::<f64>().unwrap_or(0.0),
        _ => 0.0,
    };

    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut size = bytes;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    let formatted = if unit == 0 {
        format!("{} {}", size as u64, UNITS[unit])
    } else {
        format!("{:.1} {}", size, UNITS[unit])
    };
    Ok(Value::String(formatted))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> TemplateEngine {
        let tmp = tempfile::TempDir::new().unwrap();
        let tpl = tmp.path().join("t.html");
        std::fs::write(&tpl, "").unwrap();
        let glob = format!("{}/*.html", tmp.path().display());
        let engine = TemplateEngine::new(&glob).unwrap();
        engine.register_endpoints(&[
            ("ui.buckets_overview", "/ui/buckets"),
            ("ui.bucket_detail", "/ui/buckets/{bucket_name}"),
            ("ui.abort_multipart_upload", "/ui/buckets/{bucket_name}/multipart/{upload_id}/abort"),
        ]);
        engine
    }

    fn render_inline(engine: &TemplateEngine, tpl: &str) -> String {
        let mut tera = engine.tera.write();
        tera.add_raw_template("__inline__", tpl).unwrap();
        drop(tera);
        engine.render("__inline__", &Context::new()).unwrap()
    }

    #[test]
    fn static_url() {
        let e = test_engine();
        let out = render_inline(&e, "{{ url_for(endpoint='static', filename='css/main.css') }}");
        assert_eq!(out, "/static/css/main.css");
    }

    #[test]
    fn path_param_substitution() {
        let e = test_engine();
        let out = render_inline(
            &e,
            "{{ url_for(endpoint='ui.bucket_detail', bucket_name='my-bucket') }}",
        );
        assert_eq!(out, "/ui/buckets/my-bucket");
    }

    #[test]
    fn extra_args_become_query() {
        let e = test_engine();
        let out = render_inline(
            &e,
            "{{ url_for(endpoint='ui.bucket_detail', bucket_name='b', tab='replication') }}",
        );
        assert_eq!(out, "/ui/buckets/b?tab=replication");
    }

    #[test]
    fn filesizeformat_basic() {
        let v = filesizeformat_filter(&Value::Number(1024.into()), &HashMap::new()).unwrap();
        assert_eq!(v, Value::String("1.0 KB".into()));
        let v = filesizeformat_filter(&Value::Number(1_048_576.into()), &HashMap::new()).unwrap();
        assert_eq!(v, Value::String("1.0 MB".into()));
        let v = filesizeformat_filter(&Value::Number(500.into()), &HashMap::new()).unwrap();
        assert_eq!(v, Value::String("500 B".into()));
    }

    #[test]
    fn project_templates_parse() {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("templates");
        path.push("*.html");
        let glob = path.to_string_lossy().replace('\\', "/");
        let engine = TemplateEngine::new(&glob).expect("Tera parse failed");
        let names: Vec<String> = engine
            .tera
            .read()
            .get_template_names()
            .map(|s| s.to_string())
            .collect();
        assert!(names.len() >= 10, "expected 10+ templates, got {}", names.len());
    }

    #[test]
    fn format_datetime_rfc3339() {
        let v = format_datetime_filter(
            &Value::String("2024-06-15T12:34:56Z".into()),
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(v, Value::String("2024-06-15 12:34:56 UTC".into()));
    }
}
