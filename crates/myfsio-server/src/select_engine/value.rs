use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Missing,
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn is_absent(&self) -> bool {
        matches!(self, Value::Null | Value::Missing)
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Int(i) => Some(*i as f64),
            Value::Float(f) => Some(*f),
            Value::Str(s) => s.trim().parse::<f64>().ok(),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Float(f) if f.fract() == 0.0 && f.is_finite() => Some(*f as i64),
            Value::Str(s) => {
                let t = s.trim();
                t.parse::<i64>().ok().or_else(|| {
                    t.parse::<f64>()
                        .ok()
                        .filter(|f| f.fract() == 0.0)
                        .map(|f| f as i64)
                })
            }
            _ => None,
        }
    }

    pub fn to_text(&self) -> String {
        match self {
            Value::Missing | Value::Null => String::new(),
            Value::Bool(b) => b.to_string(),
            Value::Int(i) => i.to_string(),
            Value::Float(f) => format_float(*f),
            Value::Str(s) => s.clone(),
            Value::List(_) | Value::Object(_) => {
                serde_json::to_string(&self.to_json()).unwrap_or_default()
            }
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Value::Missing | Value::Null => serde_json::Value::Null,
            Value::Bool(b) => serde_json::Value::Bool(*b),
            Value::Int(i) => serde_json::Value::from(*i),
            Value::Float(f) => serde_json::Number::from_f64(*f)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
            Value::Str(s) => serde_json::Value::String(s.clone()),
            Value::List(items) => {
                serde_json::Value::Array(items.iter().map(|v| v.to_json()).collect())
            }
            Value::Object(fields) => {
                let mut map = serde_json::Map::with_capacity(fields.len());
                for (k, v) in fields {
                    if !matches!(v, Value::Missing) {
                        map.insert(k.clone(), v.to_json());
                    }
                }
                serde_json::Value::Object(map)
            }
        }
    }

    pub fn from_json(value: serde_json::Value) -> Value {
        match value {
            serde_json::Value::Null => Value::Null,
            serde_json::Value::Bool(b) => Value::Bool(b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Value::Int(i)
                } else {
                    Value::Float(n.as_f64().unwrap_or(f64::NAN))
                }
            }
            serde_json::Value::String(s) => Value::Str(s),
            serde_json::Value::Array(items) => {
                Value::List(items.into_iter().map(Value::from_json).collect())
            }
            serde_json::Value::Object(map) => Value::Object(
                map.into_iter()
                    .map(|(k, v)| (k, Value::from_json(v)))
                    .collect(),
            ),
        }
    }

    pub fn infer_from_text(text: &str) -> Value {
        if text.is_empty() {
            return Value::Null;
        }
        if is_canonical_int(text) {
            if let Ok(i) = text.parse::<i64>() {
                return Value::Int(i);
            }
        }
        if looks_like_float(text) {
            if let Ok(f) = text.parse::<f64>() {
                return Value::Float(f);
            }
        }
        match text {
            "true" | "TRUE" | "True" => Value::Bool(true),
            "false" | "FALSE" | "False" => Value::Bool(false),
            _ => Value::Str(text.to_string()),
        }
    }
}

fn is_canonical_int(s: &str) -> bool {
    let body = s.strip_prefix('-').unwrap_or(s);
    if body.is_empty() || !body.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    body.len() == 1 || !body.starts_with('0')
}

fn looks_like_float(s: &str) -> bool {
    let body = s.strip_prefix('-').unwrap_or(s);
    if body.is_empty() {
        return false;
    }
    let mut has_digit = false;
    let mut has_marker = false;
    for c in body.chars() {
        match c {
            '0'..='9' => has_digit = true,
            '.' | 'e' | 'E' | '+' | '-' => has_marker = true,
            _ => return false,
        }
    }
    has_digit && has_marker
}

pub fn format_float(f: f64) -> String {
    if f.is_nan() {
        "NaN".to_string()
    } else if f.is_infinite() {
        if f > 0.0 {
            "Infinity".to_string()
        } else {
            "-Infinity".to_string()
        }
    } else if f == f.trunc() && f.abs() < 1e15 {
        format!("{:.1}", f)
    } else {
        let mut s = format!("{}", f);
        if !s.contains('.') && !s.contains('e') && !s.contains('E') {
            s.push_str(".0");
        }
        s
    }
}

pub fn compare(left: &Value, right: &Value) -> Option<Ordering> {
    match (left, right) {
        (Value::Missing | Value::Null, _) | (_, Value::Missing | Value::Null) => None,
        (Value::Bool(a), Value::Bool(b)) => Some(a.cmp(b)),
        (Value::Int(a), Value::Int(b)) => Some(a.cmp(b)),
        (Value::Int(_) | Value::Float(_), Value::Int(_) | Value::Float(_)) => {
            let a = left.as_f64()?;
            let b = right.as_f64()?;
            a.partial_cmp(&b)
        }
        (Value::Str(a), Value::Str(b)) => Some(a.as_str().cmp(b.as_str())),
        (Value::Int(_) | Value::Float(_), Value::Str(s)) => {
            let b = s.trim().parse::<f64>().ok()?;
            left.as_f64()?.partial_cmp(&b)
        }
        (Value::Str(s), Value::Int(_) | Value::Float(_)) => {
            let a = s.trim().parse::<f64>().ok()?;
            a.partial_cmp(&right.as_f64()?)
        }
        (Value::Bool(a), Value::Str(s)) => match s.to_ascii_lowercase().as_str() {
            "true" => Some(a.cmp(&true)),
            "false" => Some(a.cmp(&false)),
            _ => None,
        },
        (Value::Str(s), Value::Bool(b)) => match s.to_ascii_lowercase().as_str() {
            "true" => Some(true.cmp(b)),
            "false" => Some(false.cmp(b)),
            _ => None,
        },
        (Value::List(a), Value::List(b)) => {
            for (x, y) in a.iter().zip(b.iter()) {
                match compare(x, y) {
                    Some(Ordering::Equal) => continue,
                    other => return other,
                }
            }
            Some(a.len().cmp(&b.len()))
        }
        _ => None,
    }
}

pub fn values_equal(left: &Value, right: &Value) -> Option<bool> {
    match (left, right) {
        (Value::Missing | Value::Null, _) | (_, Value::Missing | Value::Null) => None,
        (Value::Object(a), Value::Object(b)) => Some(a == b),
        (Value::List(_), Value::List(_)) => match compare(left, right) {
            Some(Ordering::Equal) => Some(true),
            Some(_) => Some(false),
            None => Some(false),
        },
        _ => match compare(left, right) {
            Some(ord) => Some(ord == Ordering::Equal),
            None => Some(false),
        },
    }
}
