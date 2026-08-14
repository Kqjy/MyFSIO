use std::cmp::Ordering;
use std::sync::Arc;

use super::plan::{AggFunc, AggSpec, BinOp, CastType, Expr, ScalarFunc, UnaryOp};
use super::value::{compare, values_equal, Value};

#[derive(Debug, Clone)]
pub enum Record {
    Tabular {
        columns: Arc<Vec<String>>,
        values: Vec<Value>,
    },
    Document(Value),
}

impl Record {
    pub fn get(&self, name: &str, path: &[String]) -> Value {
        let base = match self {
            Record::Tabular { columns, values } => {
                let idx = columns
                    .iter()
                    .position(|c| c == name)
                    .or_else(|| columns.iter().position(|c| c.eq_ignore_ascii_case(name)));
                match idx {
                    Some(i) => values.get(i).cloned().unwrap_or(Value::Missing),
                    None => Value::Missing,
                }
            }
            Record::Document(value) => lookup_field(value, name),
        };
        let mut current = base;
        for step in path {
            current = lookup_field(&current, step);
        }
        current
    }

    pub fn fields(&self) -> Vec<(String, Value)> {
        match self {
            Record::Tabular { columns, values } => columns
                .iter()
                .cloned()
                .zip(values.iter().cloned())
                .collect(),
            Record::Document(Value::Object(fields)) => fields.clone(),
            Record::Document(other) => vec![("_1".to_string(), other.clone())],
        }
    }
}

fn lookup_field(value: &Value, name: &str) -> Value {
    match value {
        Value::Object(fields) => fields
            .iter()
            .find(|(k, _)| k == name)
            .or_else(|| fields.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)))
            .map(|(_, v)| v.clone())
            .unwrap_or(Value::Missing),
        _ => Value::Missing,
    }
}

pub fn eval(expr: &Expr, record: &Record, agg_results: &[Value]) -> Result<Value, String> {
    match expr {
        Expr::Column { name, path } => Ok(record.get(name, path)),
        Expr::Literal(v) => Ok(v.clone()),
        Expr::Aggregate(idx) => Ok(agg_results.get(*idx).cloned().unwrap_or(Value::Null)),
        Expr::Unary(op, inner) => {
            let v = eval(inner, record, agg_results)?;
            match op {
                UnaryOp::Not => match truthiness(&v) {
                    Some(b) => Ok(Value::Bool(!b)),
                    None => Ok(Value::Null),
                },
                UnaryOp::Neg => match v {
                    Value::Null | Value::Missing => Ok(Value::Null),
                    Value::Int(i) => Ok(i
                        .checked_neg()
                        .map(Value::Int)
                        .unwrap_or(Value::Float(-(i as f64)))),
                    Value::Float(f) => Ok(Value::Float(-f)),
                    other => match other.as_f64() {
                        Some(f) => Ok(Value::Float(-f)),
                        None => Ok(Value::Null),
                    },
                },
            }
        }
        Expr::Binary(op, left, right) => eval_binary(*op, left, right, record, agg_results),
        Expr::IsNull { expr, negated } => {
            let v = eval(expr, record, agg_results)?;
            let is_null = v.is_absent();
            Ok(Value::Bool(if *negated { !is_null } else { is_null }))
        }
        Expr::Like {
            expr,
            pattern,
            escape,
            negated,
            case_insensitive,
        } => {
            let text = eval(expr, record, agg_results)?;
            let pat = eval(pattern, record, agg_results)?;
            if text.is_absent() || pat.is_absent() {
                return Ok(Value::Null);
            }
            let (text, pat) = if *case_insensitive {
                (text.to_text().to_lowercase(), pat.to_text().to_lowercase())
            } else {
                (text.to_text(), pat.to_text())
            };
            let matched = like_match(&text, &pat, *escape)?;
            Ok(Value::Bool(if *negated { !matched } else { matched }))
        }
        Expr::Between {
            expr,
            low,
            high,
            negated,
        } => {
            let v = eval(expr, record, agg_results)?;
            let lo = eval(low, record, agg_results)?;
            let hi = eval(high, record, agg_results)?;
            let ge = compare(&v, &lo).map(|ord| ord != Ordering::Less);
            let le = compare(&v, &hi).map(|ord| ord != Ordering::Greater);
            let result = three_valued_and(ge, le);
            Ok(match result {
                Some(b) => Value::Bool(if *negated { !b } else { b }),
                None => Value::Null,
            })
        }
        Expr::InList {
            expr,
            list,
            negated,
        } => {
            let v = eval(expr, record, agg_results)?;
            if v.is_absent() {
                return Ok(Value::Null);
            }
            let mut saw_null = false;
            for item in list {
                let candidate = eval(item, record, agg_results)?;
                match values_equal(&v, &candidate) {
                    Some(true) => {
                        return Ok(Value::Bool(!*negated));
                    }
                    Some(false) => {}
                    None => saw_null = true,
                }
            }
            if saw_null {
                Ok(Value::Null)
            } else {
                Ok(Value::Bool(*negated))
            }
        }
        Expr::Case {
            operand,
            branches,
            else_result,
        } => {
            match operand {
                Some(op_expr) => {
                    let op_val = eval(op_expr, record, agg_results)?;
                    for (candidate, result) in branches {
                        let c = eval(candidate, record, agg_results)?;
                        if values_equal(&op_val, &c) == Some(true) {
                            return eval(result, record, agg_results);
                        }
                    }
                }
                None => {
                    for (condition, result) in branches {
                        let c = eval(condition, record, agg_results)?;
                        if truthiness(&c) == Some(true) {
                            return eval(result, record, agg_results);
                        }
                    }
                }
            }
            match else_result {
                Some(e) => eval(e, record, agg_results),
                None => Ok(Value::Null),
            }
        }
        Expr::Cast { expr, target } => {
            let v = eval(expr, record, agg_results)?;
            cast_value(v, *target)
        }
        Expr::Func(func, args) => eval_func(*func, args, record, agg_results),
    }
}

fn eval_binary(
    op: BinOp,
    left: &Expr,
    right: &Expr,
    record: &Record,
    agg_results: &[Value],
) -> Result<Value, String> {
    match op {
        BinOp::And => {
            let l = truthiness(&eval(left, record, agg_results)?);
            if l == Some(false) {
                return Ok(Value::Bool(false));
            }
            let r = truthiness(&eval(right, record, agg_results)?);
            Ok(match three_valued_and(l, r) {
                Some(b) => Value::Bool(b),
                None => Value::Null,
            })
        }
        BinOp::Or => {
            let l = truthiness(&eval(left, record, agg_results)?);
            if l == Some(true) {
                return Ok(Value::Bool(true));
            }
            let r = truthiness(&eval(right, record, agg_results)?);
            Ok(match (l, r) {
                (_, Some(true)) => Value::Bool(true),
                (Some(false), Some(false)) => Value::Bool(false),
                _ => Value::Null,
            })
        }
        BinOp::Eq | BinOp::NotEq => {
            let l = eval(left, record, agg_results)?;
            let r = eval(right, record, agg_results)?;
            Ok(match values_equal(&l, &r) {
                Some(b) => Value::Bool(if op == BinOp::NotEq { !b } else { b }),
                None => Value::Null,
            })
        }
        BinOp::Lt | BinOp::LtEq | BinOp::Gt | BinOp::GtEq => {
            let l = eval(left, record, agg_results)?;
            let r = eval(right, record, agg_results)?;
            Ok(match compare(&l, &r) {
                Some(ord) => Value::Bool(match op {
                    BinOp::Lt => ord == Ordering::Less,
                    BinOp::LtEq => ord != Ordering::Greater,
                    BinOp::Gt => ord == Ordering::Greater,
                    BinOp::GtEq => ord != Ordering::Less,
                    _ => unreachable!(),
                }),
                None => Value::Null,
            })
        }
        BinOp::Concat => {
            let l = eval(left, record, agg_results)?;
            let r = eval(right, record, agg_results)?;
            if l.is_absent() || r.is_absent() {
                return Ok(Value::Null);
            }
            Ok(Value::Str(format!("{}{}", l.to_text(), r.to_text())))
        }
        BinOp::Plus | BinOp::Minus | BinOp::Multiply | BinOp::Divide | BinOp::Modulo => {
            let l = eval(left, record, agg_results)?;
            let r = eval(right, record, agg_results)?;
            if l.is_absent() || r.is_absent() {
                return Ok(Value::Null);
            }
            arithmetic(op, &l, &r)
        }
    }
}

fn arithmetic(op: BinOp, l: &Value, r: &Value) -> Result<Value, String> {
    if let (Value::Int(a), Value::Int(b)) = (l, r) {
        match op {
            BinOp::Plus => {
                return Ok(a
                    .checked_add(*b)
                    .map(Value::Int)
                    .unwrap_or(Value::Float(*a as f64 + *b as f64)));
            }
            BinOp::Minus => {
                return Ok(a
                    .checked_sub(*b)
                    .map(Value::Int)
                    .unwrap_or(Value::Float(*a as f64 - *b as f64)));
            }
            BinOp::Multiply => {
                return Ok(a
                    .checked_mul(*b)
                    .map(Value::Int)
                    .unwrap_or(Value::Float(*a as f64 * *b as f64)));
            }
            BinOp::Modulo => {
                return Ok(match a.checked_rem(*b) {
                    Some(v) => Value::Int(v),
                    None => Value::Null,
                });
            }
            BinOp::Divide => {}
            _ => unreachable!(),
        }
    }
    let a = match l.as_f64() {
        Some(v) => v,
        None => return Ok(Value::Null),
    };
    let b = match r.as_f64() {
        Some(v) => v,
        None => return Ok(Value::Null),
    };
    let result = match op {
        BinOp::Plus => a + b,
        BinOp::Minus => a - b,
        BinOp::Multiply => a * b,
        BinOp::Divide => {
            if b == 0.0 {
                return Ok(Value::Null);
            }
            a / b
        }
        BinOp::Modulo => {
            if b == 0.0 {
                return Ok(Value::Null);
            }
            a % b
        }
        _ => unreachable!(),
    };
    Ok(Value::Float(result))
}

fn eval_func(
    func: ScalarFunc,
    args: &[Expr],
    record: &Record,
    agg_results: &[Value],
) -> Result<Value, String> {
    match func {
        ScalarFunc::Coalesce => {
            for arg in args {
                let v = eval(arg, record, agg_results)?;
                if !v.is_absent() {
                    return Ok(v);
                }
            }
            return Ok(Value::Null);
        }
        ScalarFunc::Nullif => {
            let a = eval(&args[0], record, agg_results)?;
            let b = eval(&args[1], record, agg_results)?;
            if values_equal(&a, &b) == Some(true) {
                return Ok(Value::Null);
            }
            return Ok(a);
        }
        _ => {}
    }

    let first = eval(&args[0], record, agg_results)?;
    if first.is_absent() {
        return Ok(Value::Null);
    }

    match func {
        ScalarFunc::Lower => Ok(Value::Str(first.to_text().to_lowercase())),
        ScalarFunc::Upper => Ok(Value::Str(first.to_text().to_uppercase())),
        ScalarFunc::Trim | ScalarFunc::Ltrim | ScalarFunc::Rtrim => {
            let text = first.to_text();
            let trimmed = if args.len() == 2 {
                let what = eval(&args[1], record, agg_results)?;
                if what.is_absent() {
                    return Ok(Value::Null);
                }
                let set: Vec<char> = what.to_text().chars().collect();
                let matcher = |c: char| set.contains(&c);
                match func {
                    ScalarFunc::Trim => text.trim_matches(matcher).to_string(),
                    ScalarFunc::Ltrim => text.trim_start_matches(matcher).to_string(),
                    _ => text.trim_end_matches(matcher).to_string(),
                }
            } else {
                match func {
                    ScalarFunc::Trim => text.trim().to_string(),
                    ScalarFunc::Ltrim => text.trim_start().to_string(),
                    _ => text.trim_end().to_string(),
                }
            };
            Ok(Value::Str(trimmed))
        }
        ScalarFunc::CharLength => Ok(Value::Int(first.to_text().chars().count() as i64)),
        ScalarFunc::Substring => {
            let text: Vec<char> = first.to_text().chars().collect();
            let start = eval(&args[1], record, agg_results)?;
            if start.is_absent() {
                return Ok(Value::Null);
            }
            let start = start
                .as_i64()
                .ok_or_else(|| "SUBSTRING start must be an integer".to_string())?;
            let len = if args.len() == 3 {
                let len = eval(&args[2], record, agg_results)?;
                if len.is_absent() {
                    return Ok(Value::Null);
                }
                let len = len
                    .as_i64()
                    .ok_or_else(|| "SUBSTRING length must be an integer".to_string())?;
                if len < 0 {
                    return Err("SUBSTRING length must be non-negative".to_string());
                }
                Some(len)
            } else {
                None
            };
            let logical_end = match len {
                Some(l) => start.saturating_add(l),
                None => i64::MAX,
            };
            let begin = start.max(1);
            if logical_end <= begin {
                return Ok(Value::Str(String::new()));
            }
            let begin_idx = (begin - 1) as usize;
            if begin_idx >= text.len() {
                return Ok(Value::Str(String::new()));
            }
            let end_idx = if logical_end == i64::MAX {
                text.len()
            } else {
                ((logical_end - 1) as usize).min(text.len())
            };
            Ok(Value::Str(text[begin_idx..end_idx].iter().collect()))
        }
        ScalarFunc::Abs => match first {
            Value::Int(i) => Ok(i
                .checked_abs()
                .map(Value::Int)
                .unwrap_or(Value::Float((i as f64).abs()))),
            other => match other.as_f64() {
                Some(f) => Ok(Value::Float(f.abs())),
                None => Ok(Value::Null),
            },
        },
        ScalarFunc::Ceil | ScalarFunc::Floor => match first {
            Value::Int(i) => Ok(Value::Int(i)),
            other => match other.as_f64() {
                Some(f) => {
                    let v = if func == ScalarFunc::Ceil {
                        f.ceil()
                    } else {
                        f.floor()
                    };
                    Ok(Value::Int(v as i64))
                }
                None => Ok(Value::Null),
            },
        },
        ScalarFunc::Round => {
            let digits = if args.len() == 2 {
                let d = eval(&args[1], record, agg_results)?;
                if d.is_absent() {
                    return Ok(Value::Null);
                }
                d.as_i64()
                    .ok_or_else(|| "ROUND digits must be an integer".to_string())?
            } else {
                0
            };
            match first {
                Value::Int(i) if digits >= 0 => Ok(Value::Int(i)),
                other => match other.as_f64() {
                    Some(f) => {
                        let factor = 10f64.powi(digits.clamp(-18, 18) as i32);
                        let rounded = (f * factor).round() / factor;
                        if digits <= 0 && rounded.is_finite() && rounded.abs() < i64::MAX as f64 {
                            Ok(Value::Int(rounded as i64))
                        } else {
                            Ok(Value::Float(rounded))
                        }
                    }
                    None => Ok(Value::Null),
                },
            }
        }
        ScalarFunc::Coalesce | ScalarFunc::Nullif => unreachable!(),
    }
}

pub fn truthiness(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(b) => Some(*b),
        Value::Null | Value::Missing => None,
        Value::Str(s) => match s.to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn three_valued_and(a: Option<bool>, b: Option<bool>) -> Option<bool> {
    match (a, b) {
        (Some(false), _) | (_, Some(false)) => Some(false),
        (Some(true), Some(true)) => Some(true),
        _ => None,
    }
}

fn value_snippet(s: &str) -> String {
    const MAX: usize = 64;
    if s.len() <= MAX {
        return s.to_string();
    }
    let mut end = MAX;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

fn cast_value(value: Value, target: CastType) -> Result<Value, String> {
    if value.is_absent() {
        return Ok(Value::Null);
    }
    match target {
        CastType::Int => match &value {
            Value::Int(i) => Ok(Value::Int(*i)),
            Value::Float(f) if f.is_finite() => Ok(Value::Int(f.round() as i64)),
            Value::Bool(b) => Ok(Value::Int(if *b { 1 } else { 0 })),
            Value::Str(s) => {
                let t = s.trim();
                if let Ok(i) = t.parse::<i64>() {
                    Ok(Value::Int(i))
                } else if let Ok(f) = t.parse::<f64>() {
                    if f.is_finite() {
                        Ok(Value::Int(f.round() as i64))
                    } else {
                        Err(format!("Cannot cast '{}' to INT", value_snippet(s)))
                    }
                } else {
                    Err(format!("Cannot cast '{}' to INT", value_snippet(s)))
                }
            }
            _ => Err("Cannot cast value to INT".to_string()),
        },
        CastType::Float => match &value {
            Value::Int(i) => Ok(Value::Float(*i as f64)),
            Value::Float(f) => Ok(Value::Float(*f)),
            Value::Bool(b) => Ok(Value::Float(if *b { 1.0 } else { 0.0 })),
            Value::Str(s) => s
                .trim()
                .parse::<f64>()
                .map(Value::Float)
                .map_err(|_| format!("Cannot cast '{}' to FLOAT", value_snippet(s))),
            _ => Err("Cannot cast value to FLOAT".to_string()),
        },
        CastType::Str => Ok(Value::Str(value.to_text())),
        CastType::Bool => match &value {
            Value::Bool(b) => Ok(Value::Bool(*b)),
            Value::Int(i) => Ok(Value::Bool(*i != 0)),
            Value::Str(s) => match s.trim().to_ascii_lowercase().as_str() {
                "true" | "1" => Ok(Value::Bool(true)),
                "false" | "0" => Ok(Value::Bool(false)),
                _ => Err(format!("Cannot cast '{}' to BOOLEAN", value_snippet(s))),
            },
            _ => Err("Cannot cast value to BOOLEAN".to_string()),
        },
    }
}

fn like_match(text: &str, pattern: &str, escape: Option<char>) -> Result<bool, String> {
    #[derive(PartialEq)]
    enum Tok {
        Lit(char),
        One,
        Many,
    }
    let mut toks = Vec::new();
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if Some(c) == escape {
            match chars.next() {
                Some(next) => toks.push(Tok::Lit(next)),
                None => return Err("Invalid ESCAPE usage in LIKE pattern".to_string()),
            }
        } else if c == '%' {
            if toks.last() != Some(&Tok::Many) {
                toks.push(Tok::Many);
            }
        } else if c == '_' {
            toks.push(Tok::One);
        } else {
            toks.push(Tok::Lit(c));
        }
    }

    let text: Vec<char> = text.chars().collect();
    let mut ti = 0usize;
    let mut pi = 0usize;
    let mut star: Option<(usize, usize)> = None;
    while ti < text.len() {
        if pi < toks.len() {
            match &toks[pi] {
                Tok::Lit(c) if *c == text[ti] => {
                    ti += 1;
                    pi += 1;
                    continue;
                }
                Tok::One => {
                    ti += 1;
                    pi += 1;
                    continue;
                }
                Tok::Many => {
                    star = Some((pi, ti));
                    pi += 1;
                    continue;
                }
                _ => {}
            }
        }
        match star {
            Some((sp, st)) => {
                pi = sp + 1;
                ti = st + 1;
                star = Some((sp, st + 1));
            }
            None => return Ok(false),
        }
    }
    while pi < toks.len() && toks[pi] == Tok::Many {
        pi += 1;
    }
    Ok(pi == toks.len())
}

pub struct AggAccumulator {
    specs: Vec<AggSpec>,
    states: Vec<AggState>,
}

enum AggState {
    Count(u64),
    Sum {
        int: i64,
        float: f64,
        is_float: bool,
        seen: bool,
    },
    Extreme {
        best: Option<Value>,
        is_min: bool,
    },
    Avg {
        sum: f64,
        count: u64,
    },
}

impl AggAccumulator {
    pub fn new(specs: &[AggSpec]) -> AggAccumulator {
        let states = specs
            .iter()
            .map(|spec| match spec.func {
                AggFunc::Count => AggState::Count(0),
                AggFunc::Sum => AggState::Sum {
                    int: 0,
                    float: 0.0,
                    is_float: false,
                    seen: false,
                },
                AggFunc::Min => AggState::Extreme {
                    best: None,
                    is_min: true,
                },
                AggFunc::Max => AggState::Extreme {
                    best: None,
                    is_min: false,
                },
                AggFunc::Avg => AggState::Avg { sum: 0.0, count: 0 },
            })
            .collect();
        AggAccumulator {
            specs: specs.to_vec(),
            states,
        }
    }

    pub fn accumulate(&mut self, record: &Record) -> Result<(), String> {
        for (spec, state) in self.specs.iter().zip(self.states.iter_mut()) {
            let value = match &spec.arg {
                Some(arg) => Some(eval(arg, record, &[])?),
                None => None,
            };
            match state {
                AggState::Count(n) => {
                    let counts = match &value {
                        None => true,
                        Some(v) => !v.is_absent(),
                    };
                    if counts {
                        *n += 1;
                    }
                }
                AggState::Sum {
                    int,
                    float,
                    is_float,
                    seen,
                } => {
                    let v = value.expect("SUM requires an argument");
                    if v.is_absent() {
                        continue;
                    }
                    *seen = true;
                    match &v {
                        Value::Int(i) if !*is_float => match int.checked_add(*i) {
                            Some(total) => *int = total,
                            None => {
                                *is_float = true;
                                *float = *int as f64 + *i as f64;
                            }
                        },
                        _ => {
                            let f = v.as_f64().ok_or_else(|| {
                                "Cannot compute SUM of a non-numeric value".to_string()
                            })?;
                            if !*is_float {
                                *is_float = true;
                                *float = *int as f64;
                            }
                            *float += f;
                        }
                    }
                }
                AggState::Extreme { best, is_min } => {
                    let v = value.expect("MIN/MAX requires an argument");
                    if v.is_absent() {
                        continue;
                    }
                    match best {
                        None => *best = Some(v),
                        Some(current) => {
                            let ord = compare(current, &v)
                                .unwrap_or_else(|| current.to_text().cmp(&v.to_text()));
                            let replace = if *is_min {
                                ord == Ordering::Greater
                            } else {
                                ord == Ordering::Less
                            };
                            if replace {
                                *best = Some(v);
                            }
                        }
                    }
                }
                AggState::Avg { sum, count } => {
                    let v = value.expect("AVG requires an argument");
                    if v.is_absent() {
                        continue;
                    }
                    let f = v
                        .as_f64()
                        .ok_or_else(|| "Cannot compute AVG of a non-numeric value".to_string())?;
                    *sum += f;
                    *count += 1;
                }
            }
        }
        Ok(())
    }

    pub fn finish(self) -> Vec<Value> {
        self.states
            .into_iter()
            .map(|state| match state {
                AggState::Count(n) => Value::Int(n as i64),
                AggState::Sum {
                    int,
                    float,
                    is_float,
                    seen,
                } => {
                    if !seen {
                        Value::Null
                    } else if is_float {
                        Value::Float(float)
                    } else {
                        Value::Int(int)
                    }
                }
                AggState::Extreme { best, .. } => best.unwrap_or(Value::Null),
                AggState::Avg { sum, count } => {
                    if count == 0 {
                        Value::Null
                    } else {
                        Value::Float(sum / count as f64)
                    }
                }
            })
            .collect()
    }
}
