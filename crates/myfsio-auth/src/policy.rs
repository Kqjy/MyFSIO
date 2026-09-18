use chrono::{DateTime, Utc};
use myfsio_common::types::Principal;
use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;

use crate::s3_action::{wildcard_match, wildcard_match_case_sensitive};

pub const PRINCIPAL_ACCOUNT_ID: &str = "myfsio";

#[derive(Debug, Clone, Default)]
pub struct RequestContext {
    keys: HashMap<String, Vec<String>>,
}

impl RequestContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn for_principal(principal: Option<&Principal>) -> Self {
        let mut ctx = Self::new();
        let now = Utc::now();
        ctx.set(
            "aws:CurrentTime",
            now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        );
        ctx.set("aws:EpochTime", now.timestamp().to_string());
        match principal {
            Some(principal) => {
                ctx.set("aws:username", principal.display_name.clone());
                ctx.set("aws:userid", principal.user_id.clone());
                ctx.set("aws:PrincipalType", "User");
                ctx.set("aws:PrincipalAccount", PRINCIPAL_ACCOUNT_ID);
                ctx.set("aws:PrincipalArn", principal_arn(principal));
                ctx.set("myfsio:accesskey", principal.access_key.clone());
            }
            None => {
                ctx.set("aws:PrincipalType", "Anonymous");
            }
        }
        ctx
    }

    pub fn set(&mut self, key: &str, value: impl Into<String>) {
        self.keys
            .insert(key.trim().to_ascii_lowercase(), vec![value.into()]);
    }

    pub fn set_multi(&mut self, key: &str, values: Vec<String>) {
        self.keys.insert(key.trim().to_ascii_lowercase(), values);
    }

    pub fn remove(&mut self, key: &str) {
        self.keys.remove(&key.trim().to_ascii_lowercase());
    }

    pub fn get(&self, key: &str) -> Option<&[String]> {
        self.keys
            .get(&key.trim().to_ascii_lowercase())
            .map(|values| values.as_slice())
    }

    pub fn first(&self, key: &str) -> Option<&str> {
        self.get(key)
            .and_then(|values| values.first())
            .map(|value| value.as_str())
    }

    pub fn has(&self, key: &str) -> bool {
        self.keys.contains_key(&key.trim().to_ascii_lowercase())
    }
}

pub fn principal_arn(principal: &Principal) -> String {
    format!(
        "arn:aws:iam::{}:user/{}",
        PRINCIPAL_ACCOUNT_ID, principal.user_id
    )
}

pub fn substitute_variables(value: &str, ctx: &RequestContext) -> Option<String> {
    if !value.contains("${") {
        return Some(value.to_string());
    }
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}')?;
        let name = after[..end].trim();
        match name {
            "*" => out.push('*'),
            "?" => out.push('?'),
            "$" => out.push('$'),
            _ => {
                let mut parts = name.splitn(2, ',');
                let key = parts.next().unwrap_or("").trim();
                let default = parts
                    .next()
                    .map(|raw| raw.trim().trim_matches('\'').to_string());
                match ctx.first(key) {
                    Some(resolved) => out.push_str(resolved),
                    None => out.push_str(&default?),
                }
            }
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

pub fn principal_matches(value: &Value, principal: Option<&Principal>) -> bool {
    match value {
        Value::String(token) => principal_token_matches(token, principal),
        Value::Array(items) => items.iter().any(|item| principal_matches(item, principal)),
        Value::Object(map) => {
            map.iter()
                .any(|(kind, item)| match kind.to_ascii_lowercase().as_str() {
                    "aws" | "canonicaluser" => principal_matches(item, principal),
                    _ => false,
                })
        }
        _ => false,
    }
}

fn principal_token_matches(token: &str, principal: Option<&Principal>) -> bool {
    let token = token.trim();
    if token == "*" {
        return true;
    }
    let Some(principal) = principal else {
        return false;
    };
    if token == principal.access_key || token == principal.user_id {
        return true;
    }
    let Some(rest) = token.strip_prefix("arn:aws:iam::") else {
        return false;
    };
    let Some((_account, resource)) = rest.split_once(':') else {
        return false;
    };
    if resource == "root" {
        return true;
    }
    if let Some(name) = resource.strip_prefix("user/") {
        let name = name.rsplit('/').next().unwrap_or(name);
        return wildcard_match_case_sensitive(&principal.user_id, name)
            || wildcard_match_case_sensitive(&principal.display_name, name)
            || wildcard_match_case_sensitive(&principal.access_key, name);
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetMode {
    Single,
    ForAnyValue,
    ForAllValues,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaseOp {
    StringEquals,
    StringNotEquals,
    StringEqualsIgnoreCase,
    StringNotEqualsIgnoreCase,
    StringLike,
    StringNotLike,
    NumericEquals,
    NumericNotEquals,
    NumericLessThan,
    NumericLessThanEquals,
    NumericGreaterThan,
    NumericGreaterThanEquals,
    DateEquals,
    DateNotEquals,
    DateLessThan,
    DateLessThanEquals,
    DateGreaterThan,
    DateGreaterThanEquals,
    Bool,
    BinaryEquals,
    IpAddress,
    NotIpAddress,
    ArnEquals,
    ArnLike,
    ArnNotEquals,
    ArnNotLike,
    Null,
}

impl BaseOp {
    fn parse(name: &str) -> Option<Self> {
        Some(match name.to_ascii_lowercase().as_str() {
            "stringequals" => Self::StringEquals,
            "stringnotequals" => Self::StringNotEquals,
            "stringequalsignorecase" => Self::StringEqualsIgnoreCase,
            "stringnotequalsignorecase" => Self::StringNotEqualsIgnoreCase,
            "stringlike" => Self::StringLike,
            "stringnotlike" => Self::StringNotLike,
            "numericequals" => Self::NumericEquals,
            "numericnotequals" => Self::NumericNotEquals,
            "numericlessthan" => Self::NumericLessThan,
            "numericlessthanequals" => Self::NumericLessThanEquals,
            "numericgreaterthan" => Self::NumericGreaterThan,
            "numericgreaterthanequals" => Self::NumericGreaterThanEquals,
            "dateequals" => Self::DateEquals,
            "datenotequals" => Self::DateNotEquals,
            "datelessthan" => Self::DateLessThan,
            "datelessthanequals" => Self::DateLessThanEquals,
            "dategreaterthan" => Self::DateGreaterThan,
            "dategreaterthanequals" => Self::DateGreaterThanEquals,
            "bool" => Self::Bool,
            "binaryequals" => Self::BinaryEquals,
            "ipaddress" => Self::IpAddress,
            "notipaddress" => Self::NotIpAddress,
            "arnequals" => Self::ArnEquals,
            "arnlike" => Self::ArnLike,
            "arnnotequals" => Self::ArnNotEquals,
            "arnnotlike" => Self::ArnNotLike,
            "null" => Self::Null,
            _ => return None,
        })
    }

    fn negated(self) -> bool {
        matches!(
            self,
            Self::StringNotEquals
                | Self::StringNotEqualsIgnoreCase
                | Self::StringNotLike
                | Self::NumericNotEquals
                | Self::DateNotEquals
                | Self::NotIpAddress
                | Self::ArnNotEquals
                | Self::ArnNotLike
        )
    }

    fn positive_match(self, request: &str, policy: &str) -> bool {
        match self {
            Self::StringEquals | Self::StringNotEquals | Self::BinaryEquals => request == policy,
            Self::StringEqualsIgnoreCase | Self::StringNotEqualsIgnoreCase => {
                request.eq_ignore_ascii_case(policy)
            }
            Self::StringLike | Self::StringNotLike => {
                wildcard_match_case_sensitive(request, policy)
            }
            Self::NumericEquals | Self::NumericNotEquals => {
                numeric_cmp(request, policy).is_some_and(|ord| ord == std::cmp::Ordering::Equal)
            }
            Self::NumericLessThan => {
                numeric_cmp(request, policy).is_some_and(|ord| ord == std::cmp::Ordering::Less)
            }
            Self::NumericLessThanEquals => {
                numeric_cmp(request, policy).is_some_and(|ord| ord != std::cmp::Ordering::Greater)
            }
            Self::NumericGreaterThan => {
                numeric_cmp(request, policy).is_some_and(|ord| ord == std::cmp::Ordering::Greater)
            }
            Self::NumericGreaterThanEquals => {
                numeric_cmp(request, policy).is_some_and(|ord| ord != std::cmp::Ordering::Less)
            }
            Self::DateEquals | Self::DateNotEquals => {
                date_cmp(request, policy).is_some_and(|ord| ord == std::cmp::Ordering::Equal)
            }
            Self::DateLessThan => {
                date_cmp(request, policy).is_some_and(|ord| ord == std::cmp::Ordering::Less)
            }
            Self::DateLessThanEquals => {
                date_cmp(request, policy).is_some_and(|ord| ord != std::cmp::Ordering::Greater)
            }
            Self::DateGreaterThan => {
                date_cmp(request, policy).is_some_and(|ord| ord == std::cmp::Ordering::Greater)
            }
            Self::DateGreaterThanEquals => {
                date_cmp(request, policy).is_some_and(|ord| ord != std::cmp::Ordering::Less)
            }
            Self::Bool => match (parse_bool(request), parse_bool(policy)) {
                (Some(request), Some(policy)) => request == policy,
                _ => false,
            },
            Self::IpAddress | Self::NotIpAddress => ip_in_cidr(request, policy),
            Self::ArnEquals | Self::ArnNotEquals | Self::ArnLike | Self::ArnNotLike => {
                wildcard_match(request, policy)
            }
            Self::Null => false,
        }
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    let lower = value.trim().to_ascii_lowercase();
    match lower.as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn numeric_cmp(request: &str, policy: &str) -> Option<std::cmp::Ordering> {
    let a: f64 = request.trim().parse().ok()?;
    let b: f64 = policy.trim().parse().ok()?;
    a.partial_cmp(&b)
}

pub fn parse_date(value: &str) -> Option<DateTime<Utc>> {
    let trimmed = value.trim();
    if let Ok(epoch) = trimmed.parse::<i64>() {
        return DateTime::<Utc>::from_timestamp(epoch, 0);
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S") {
        return Some(naive.and_utc());
    }
    if let Ok(naive) = chrono::NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
        return Some(naive.and_hms_opt(0, 0, 0)?.and_utc());
    }
    None
}

fn date_cmp(request: &str, policy: &str) -> Option<std::cmp::Ordering> {
    Some(parse_date(request)?.cmp(&parse_date(policy)?))
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        other => other,
    }
}

pub fn ip_in_cidr(request: &str, cidr: &str) -> bool {
    let Ok(ip) = request.trim().parse::<IpAddr>() else {
        return false;
    };
    let ip = normalize_ip(ip);
    let cidr = cidr.trim();
    let (network, prefix) = match cidr.split_once('/') {
        Some((network, prefix)) => (network, Some(prefix)),
        None => (cidr, None),
    };
    let Ok(network) = network.trim().parse::<IpAddr>() else {
        return false;
    };
    let network = normalize_ip(network);
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let bits = match prefix {
                Some(raw) => match raw.trim().parse::<u32>() {
                    Ok(bits) if bits <= 32 => bits,
                    _ => return false,
                },
                None => 32,
            };
            let mask: u32 = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            (u32::from(ip) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let bits = match prefix {
                Some(raw) => match raw.trim().parse::<u32>() {
                    Ok(bits) if bits <= 128 => bits,
                    _ => return false,
                },
                None => 128,
            };
            let mask: u128 = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            (u128::from(ip) & mask) == (u128::from(net) & mask)
        }
        _ => false,
    }
}

fn parse_operator(name: &str) -> Option<(SetMode, bool, BaseOp)> {
    let trimmed = name.trim();
    let (mode, rest) = match trimmed.split_once(':') {
        Some((prefix, rest)) => match prefix.to_ascii_lowercase().as_str() {
            "foranyvalue" => (SetMode::ForAnyValue, rest),
            "forallvalues" => (SetMode::ForAllValues, rest),
            _ => return None,
        },
        None => (SetMode::Single, trimmed),
    };
    let lower = rest.to_ascii_lowercase();
    let (if_exists, base_name) = match lower.strip_suffix("ifexists") {
        Some(base) => (true, base),
        None => (false, lower.as_str()),
    };
    let base = BaseOp::parse(base_name)?;
    Some((mode, if_exists, base))
}

fn value_strings(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::String(s) => Some(vec![s.clone()]),
        Value::Number(n) => Some(vec![n.to_string()]),
        Value::Bool(b) => Some(vec![b.to_string()]),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                Value::Bool(b) => Some(b.to_string()),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

pub fn validate_condition(condition: &Value) -> Result<(), String> {
    let Value::Object(operators) = condition else {
        return Err("Condition must be a JSON object".to_string());
    };
    if operators.is_empty() {
        return Err("Condition must name at least one operator".to_string());
    }
    for (operator, keys) in operators {
        let Some((_, _, base)) = parse_operator(operator) else {
            return Err(format!("Unsupported condition operator '{}'", operator));
        };
        let Value::Object(keys) = keys else {
            return Err(format!(
                "Condition operator '{}' must map condition keys to values",
                operator
            ));
        };
        if keys.is_empty() {
            return Err(format!(
                "Condition operator '{}' must name at least one condition key",
                operator
            ));
        }
        for (key, values) in keys {
            if key.trim().is_empty() {
                return Err(format!(
                    "Condition operator '{}' has an empty key",
                    operator
                ));
            }
            let Some(values) = value_strings(values) else {
                return Err(format!(
                    "Condition key '{}' must map to a string, number, boolean, or array of those",
                    key
                ));
            };
            if values.is_empty() {
                return Err(format!(
                    "Condition key '{}' must list at least one value",
                    key
                ));
            }
            if matches!(base, BaseOp::IpAddress | BaseOp::NotIpAddress) {
                for value in &values {
                    let (network, prefix) = match value.split_once('/') {
                        Some((network, prefix)) => (network, Some(prefix)),
                        None => (value.as_str(), None),
                    };
                    let parsed = network.trim().parse::<IpAddr>();
                    let prefix_ok = match (parsed.as_ref(), prefix) {
                        (Ok(IpAddr::V4(_)), Some(bits)) => {
                            bits.trim().parse::<u32>().is_ok_and(|bits| bits <= 32)
                        }
                        (Ok(IpAddr::V6(_)), Some(bits)) => {
                            bits.trim().parse::<u32>().is_ok_and(|bits| bits <= 128)
                        }
                        (Ok(_), None) => true,
                        (Err(_), _) => false,
                    };
                    if !prefix_ok {
                        return Err(format!(
                            "Condition key '{}' has an invalid IP address or CIDR '{}'",
                            key, value
                        ));
                    }
                }
            }
            if matches!(base, BaseOp::Null | BaseOp::Bool) {
                for value in &values {
                    let lower = value.trim().to_ascii_lowercase();
                    if lower != "true" && lower != "false" {
                        return Err(format!(
                            "Condition key '{}' under '{}' must be true or false",
                            key, operator
                        ));
                    }
                }
            }
            if matches!(
                base,
                BaseOp::NumericEquals
                    | BaseOp::NumericNotEquals
                    | BaseOp::NumericLessThan
                    | BaseOp::NumericLessThanEquals
                    | BaseOp::NumericGreaterThan
                    | BaseOp::NumericGreaterThanEquals
            ) {
                for value in &values {
                    if value.trim().parse::<f64>().is_err() {
                        return Err(format!(
                            "Condition key '{}' under '{}' must be numeric",
                            key, operator
                        ));
                    }
                }
            }
            if matches!(
                base,
                BaseOp::DateEquals
                    | BaseOp::DateNotEquals
                    | BaseOp::DateLessThan
                    | BaseOp::DateLessThanEquals
                    | BaseOp::DateGreaterThan
                    | BaseOp::DateGreaterThanEquals
            ) {
                for value in &values {
                    if !value.contains("${") && parse_date(value).is_none() {
                        return Err(format!(
                            "Condition key '{}' under '{}' must be an RFC 3339 timestamp or epoch seconds",
                            key, operator
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn evaluate_condition(condition: &Value, ctx: &RequestContext) -> bool {
    matches!(evaluate_condition_checked(condition, ctx), Ok(true))
}

pub fn evaluate_condition_checked(condition: &Value, ctx: &RequestContext) -> Result<bool, String> {
    let Value::Object(operators) = condition else {
        return Err("Condition must be a JSON object".to_string());
    };
    if operators.is_empty() {
        return Err("Condition must name at least one operator".to_string());
    }
    for (operator, keys) in operators {
        let Some((mode, if_exists, base)) = parse_operator(operator) else {
            return Err(format!("Unsupported condition operator '{}'", operator));
        };
        let Value::Object(keys) = keys else {
            return Err(format!(
                "Condition operator '{}' must map condition keys to values",
                operator
            ));
        };
        if keys.is_empty() {
            return Err(format!(
                "Condition operator '{}' must name at least one condition key",
                operator
            ));
        }
        for (key, raw_values) in keys {
            let Some(policy_values) = value_strings(raw_values) else {
                return Err(format!("Condition key '{}' has an unsupported value", key));
            };
            if policy_values.is_empty() {
                return Err(format!(
                    "Condition key '{}' must list at least one value",
                    key
                ));
            }
            let request_values = ctx.get(key);
            if base == BaseOp::Null {
                let Some(expect_absent) = policy_values.first().and_then(|value| parse_bool(value))
                else {
                    return Err(format!("Null condition on '{}' must be true or false", key));
                };
                if request_values.is_some() == expect_absent {
                    return Ok(false);
                }
                continue;
            }
            let policy_values: Vec<String> = match policy_values
                .iter()
                .map(|value| substitute_variables(value, ctx))
                .collect::<Option<Vec<String>>>()
            {
                Some(values) => values,
                None => return Ok(false),
            };
            let matched = match request_values {
                None => {
                    if if_exists {
                        true
                    } else {
                        match mode {
                            SetMode::ForAllValues => true,
                            SetMode::ForAnyValue => false,
                            SetMode::Single => base.negated(),
                        }
                    }
                }
                Some(values) => match mode {
                    SetMode::Single => {
                        values.len() == 1 && match_one(base, &values[0], &policy_values)
                    }
                    SetMode::ForAnyValue => values
                        .iter()
                        .any(|value| match_one(base, value, &policy_values)),
                    SetMode::ForAllValues => values
                        .iter()
                        .all(|value| match_one(base, value, &policy_values)),
                },
            };
            if !matched {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn match_one(base: BaseOp, request: &str, policy_values: &[String]) -> bool {
    if base.negated() {
        policy_values
            .iter()
            .all(|policy| !base.positive_match(request, policy))
    } else {
        policy_values
            .iter()
            .any(|policy| base.positive_match(request, policy))
    }
}

pub fn condition_references_key_prefix(condition: &Value, prefix: &str) -> bool {
    let Value::Object(operators) = condition else {
        return false;
    };
    operators.values().any(|keys| match keys {
        Value::Object(keys) => keys
            .keys()
            .any(|key| key.to_ascii_lowercase().starts_with(prefix)),
        _ => false,
    })
}

pub fn condition_restricts_principal(condition: &Value) -> bool {
    const RESTRICTING_KEYS: &[&str] = &[
        "aws:sourceip",
        "aws:vpcsourceip",
        "aws:sourcevpc",
        "aws:sourcevpce",
        "aws:sourcearn",
        "aws:sourceaccount",
        "aws:principalarn",
        "aws:principalaccount",
        "aws:principalorgid",
        "aws:principalorgpaths",
        "aws:userid",
        "aws:username",
        "myfsio:accesskey",
        "s3:x-amz-server-side-encryption-aws-kms-key-id",
    ];
    let Value::Object(operators) = condition else {
        return false;
    };
    operators.iter().any(|(operator, keys)| {
        let Some((_, _, base)) = parse_operator(operator) else {
            return false;
        };
        if base.negated() || base == BaseOp::Null {
            return false;
        }
        match keys {
            Value::Object(keys) => keys.iter().any(|(key, values)| {
                let lower = key.to_ascii_lowercase();
                RESTRICTING_KEYS.contains(&lower.as_str())
                    && value_strings(values).is_some_and(|values| {
                        !values.is_empty()
                            && values.iter().all(|value| {
                                let trimmed = value.trim();
                                !trimmed.is_empty()
                                    && trimmed != "*"
                                    && trimmed != "0.0.0.0/0"
                                    && trimmed != "::/0"
                            })
                    })
            }),
            _ => false,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn principal(name: &str) -> Principal {
        Principal::new(
            "AKTEST".to_string(),
            format!("u-{}", name),
            name.to_string(),
            false,
        )
    }

    fn ctx_with(pairs: &[(&str, &str)]) -> RequestContext {
        let mut ctx = RequestContext::new();
        for (key, value) in pairs {
            ctx.set(key, *value);
        }
        ctx
    }

    #[test]
    fn string_operators() {
        let ctx = ctx_with(&[("s3:prefix", "home/alice/")]);
        assert!(evaluate_condition(
            &json!({"StringEquals": {"s3:prefix": "home/alice/"}}),
            &ctx
        ));
        assert!(!evaluate_condition(
            &json!({"StringEquals": {"s3:prefix": "HOME/alice/"}}),
            &ctx
        ));
        assert!(evaluate_condition(
            &json!({"StringEqualsIgnoreCase": {"s3:prefix": "HOME/alice/"}}),
            &ctx
        ));
        assert!(evaluate_condition(
            &json!({"StringLike": {"s3:prefix": ["other/*", "home/*"]}}),
            &ctx
        ));
        assert!(!evaluate_condition(
            &json!({"StringNotLike": {"s3:prefix": "home/*"}}),
            &ctx
        ));
        assert!(evaluate_condition(
            &json!({"StringNotEquals": {"s3:prefix": ["a", "b"]}}),
            &ctx
        ));
    }

    #[test]
    fn missing_keys_follow_aws_semantics() {
        let ctx = RequestContext::new();
        assert!(!evaluate_condition(
            &json!({"StringEquals": {"s3:prefix": "x"}}),
            &ctx
        ));
        assert!(evaluate_condition(
            &json!({"StringNotEquals": {"s3:prefix": "x"}}),
            &ctx
        ));
        assert!(evaluate_condition(
            &json!({"StringEqualsIfExists": {"s3:prefix": "x"}}),
            &ctx
        ));
        assert!(evaluate_condition(
            &json!({"ForAllValues:StringEquals": {"aws:TagKeys": ["a"]}}),
            &ctx
        ));
        assert!(!evaluate_condition(
            &json!({"ForAnyValue:StringEquals": {"aws:TagKeys": ["a"]}}),
            &ctx
        ));
        assert!(evaluate_condition(
            &json!({"Null": {"s3:prefix": "true"}}),
            &ctx
        ));
        assert!(!evaluate_condition(
            &json!({"Null": {"s3:prefix": "false"}}),
            &ctx
        ));
    }

    #[test]
    fn set_operators_over_multi_valued_keys() {
        let mut ctx = RequestContext::new();
        ctx.set_multi("aws:TagKeys", vec!["env".to_string(), "team".to_string()]);
        assert!(evaluate_condition(
            &json!({"ForAllValues:StringEquals": {"aws:TagKeys": ["env", "team", "owner"]}}),
            &ctx
        ));
        assert!(!evaluate_condition(
            &json!({"ForAllValues:StringEquals": {"aws:TagKeys": ["env"]}}),
            &ctx
        ));
        assert!(evaluate_condition(
            &json!({"ForAnyValue:StringEquals": {"aws:TagKeys": ["team"]}}),
            &ctx
        ));
        assert!(!evaluate_condition(
            &json!({"StringEquals": {"aws:TagKeys": "env"}}),
            &ctx
        ));
    }

    #[test]
    fn ip_address_operators() {
        let ctx = ctx_with(&[("aws:SourceIp", "10.1.2.3")]);
        assert!(evaluate_condition(
            &json!({"IpAddress": {"aws:SourceIp": "10.1.0.0/16"}}),
            &ctx
        ));
        assert!(!evaluate_condition(
            &json!({"IpAddress": {"aws:SourceIp": "10.2.0.0/16"}}),
            &ctx
        ));
        assert!(evaluate_condition(
            &json!({"NotIpAddress": {"aws:SourceIp": ["10.2.0.0/16", "192.168.0.0/16"]}}),
            &ctx
        ));
        assert!(evaluate_condition(
            &json!({"IpAddress": {"aws:SourceIp": "10.1.2.3"}}),
            &ctx
        ));
        let v6 = ctx_with(&[("aws:SourceIp", "2001:db8::1")]);
        assert!(evaluate_condition(
            &json!({"IpAddress": {"aws:SourceIp": "2001:db8::/32"}}),
            &v6
        ));
        let mapped = ctx_with(&[("aws:SourceIp", "::ffff:10.1.2.3")]);
        assert!(evaluate_condition(
            &json!({"IpAddress": {"aws:SourceIp": "10.1.0.0/16"}}),
            &mapped
        ));
        assert!(ip_in_cidr("10.0.0.1", "0.0.0.0/0"));
        assert!(!ip_in_cidr("10.0.0.1", "10.0.0.0/33"));
    }

    #[test]
    fn bool_numeric_and_date_operators() {
        let ctx = ctx_with(&[
            ("aws:SecureTransport", "false"),
            ("s3:max-keys", "50"),
            ("aws:CurrentTime", "2026-08-23T12:00:00Z"),
        ]);
        assert!(evaluate_condition(
            &json!({"Bool": {"aws:SecureTransport": "false"}}),
            &ctx
        ));
        assert!(!evaluate_condition(
            &json!({"Bool": {"aws:SecureTransport": true}}),
            &ctx
        ));
        assert!(evaluate_condition(
            &json!({"NumericLessThanEquals": {"s3:max-keys": 100}}),
            &ctx
        ));
        assert!(!evaluate_condition(
            &json!({"NumericGreaterThan": {"s3:max-keys": "50"}}),
            &ctx
        ));
        assert!(evaluate_condition(
            &json!({"DateGreaterThan": {"aws:CurrentTime": "2026-01-01T00:00:00Z"}}),
            &ctx
        ));
        assert!(evaluate_condition(
            &json!({"DateLessThan": {"aws:CurrentTime": "2027-01-01T00:00:00Z"}}),
            &ctx
        ));
        assert!(!evaluate_condition(
            &json!({"DateLessThan": {"aws:CurrentTime": "2026-01-01T00:00:00Z"}}),
            &ctx
        ));
        let epoch = ctx_with(&[("aws:EpochTime", "1700000000")]);
        assert!(evaluate_condition(
            &json!({"DateGreaterThan": {"aws:EpochTime": 1600000000}}),
            &epoch
        ));
    }

    #[test]
    fn multiple_operators_and_keys_are_anded() {
        let ctx = ctx_with(&[("aws:SourceIp", "10.1.2.3"), ("s3:prefix", "docs/")]);
        assert!(evaluate_condition(
            &json!({
                "IpAddress": {"aws:SourceIp": "10.0.0.0/8"},
                "StringEquals": {"s3:prefix": "docs/"}
            }),
            &ctx
        ));
        assert!(!evaluate_condition(
            &json!({
                "IpAddress": {"aws:SourceIp": "10.0.0.0/8"},
                "StringEquals": {"s3:prefix": "other/"}
            }),
            &ctx
        ));
    }

    #[test]
    fn variables_substitute_from_context() {
        let ctx = RequestContext::for_principal(Some(&principal("alice")));
        assert_eq!(
            substitute_variables("home/${aws:username}/*", &ctx).as_deref(),
            Some("home/alice/*")
        );
        assert_eq!(
            substitute_variables("${aws:userid}", &ctx).as_deref(),
            Some("u-alice")
        );
        assert_eq!(
            substitute_variables("a${*}b${?}c${$}", &ctx).as_deref(),
            Some("a*b?c$")
        );
        assert_eq!(substitute_variables("${aws:nope}", &ctx), None);
        let anon_neg = RequestContext::for_principal(None);
        assert!(!evaluate_condition(
            &json!({"StringNotLike": {"s3:prefix": "home/${aws:username}/*"}}),
            &anon_neg
        ));
        assert_eq!(
            substitute_variables("${aws:nope, 'dflt'}", &ctx).as_deref(),
            Some("dflt")
        );
        let mut with_prefix = ctx.clone();
        with_prefix.set("s3:prefix", "home/alice/");
        assert!(evaluate_condition(
            &json!({"StringLike": {"s3:prefix": "home/${aws:username}/*"}}),
            &with_prefix
        ));
        let anon = RequestContext::for_principal(None);
        assert!(!evaluate_condition(
            &json!({"StringLike": {"s3:prefix": "home/${aws:username}/*"}}),
            &anon
        ));
    }

    #[test]
    fn principal_forms() {
        let p = principal("alice");
        assert!(principal_matches(&json!("*"), None));
        assert!(principal_matches(&json!({"AWS": "*"}), None));
        assert!(!principal_matches(&json!("AKTEST"), None));
        assert!(principal_matches(&json!("AKTEST"), Some(&p)));
        assert!(principal_matches(
            &json!({"AWS": ["nope", "u-alice"]}),
            Some(&p)
        ));
        assert!(principal_matches(
            &json!({"AWS": "arn:aws:iam::123456789012:user/alice"}),
            Some(&p)
        ));
        assert!(principal_matches(
            &json!({"AWS": "arn:aws:iam::myfsio:user/u-alice"}),
            Some(&p)
        ));
        assert!(principal_matches(
            &json!({"AWS": "arn:aws:iam::123456789012:root"}),
            Some(&p)
        ));
        assert!(!principal_matches(
            &json!({"AWS": "arn:aws:iam::123456789012:root"}),
            None
        ));
        assert!(!principal_matches(
            &json!({"AWS": "arn:aws:iam::123456789012:user/bob"}),
            Some(&p)
        ));
        assert!(!principal_matches(
            &json!({"Service": "s3.amazonaws.com"}),
            Some(&p)
        ));
        assert!(principal_matches(
            &json!({"CanonicalUser": "u-alice"}),
            Some(&p)
        ));
    }

    #[test]
    fn validation_rejects_bad_shapes() {
        assert!(validate_condition(&json!({"StringEquals": {"s3:prefix": "x"}})).is_ok());
        assert!(
            validate_condition(&json!({"ForAnyValue:StringLikeIfExists": {"k": ["x"]}})).is_ok()
        );
        assert!(validate_condition(&json!({"StringEqualz": {"s3:prefix": "x"}})).is_err());
        assert!(validate_condition(&json!({"StringEquals": "x"})).is_err());
        assert!(validate_condition(&json!({"StringEquals": {}})).is_err());
        assert!(validate_condition(&json!({"StringEquals": {"k": {"nested": 1}}})).is_err());
        assert!(
            validate_condition(&json!({"IpAddress": {"aws:SourceIp": "10.0.0.0/33"}})).is_err()
        );
        assert!(validate_condition(&json!({"IpAddress": {"aws:SourceIp": "not-an-ip"}})).is_err());
        assert!(validate_condition(&json!({"Bool": {"aws:SecureTransport": "maybe"}})).is_err());
        assert!(validate_condition(&json!({"NumericLessThan": {"s3:max-keys": "ten"}})).is_err());
        assert!(validate_condition(&json!({"DateLessThan": {"aws:CurrentTime": "soon"}})).is_err());
        assert!(validate_condition(&json!([])).is_err());
        assert!(validate_condition(&json!({})).is_err());
        assert!(validate_condition(&json!({"StringEquals": {"s3:prefix": []}})).is_err());
    }

    #[test]
    fn invalid_conditions_report_errors_instead_of_false() {
        let ctx = ctx_with(&[("s3:prefix", "x")]);
        assert!(
            evaluate_condition_checked(&json!({"StringEqualz": {"s3:prefix": "x"}}), &ctx).is_err()
        );
        assert!(evaluate_condition_checked(&json!({}), &ctx).is_err());
        assert!(
            evaluate_condition_checked(&json!({"StringEquals": {"s3:prefix": []}}), &ctx).is_err()
        );
        assert_eq!(
            evaluate_condition_checked(&json!({"StringEquals": {"s3:prefix": "x"}}), &ctx),
            Ok(true)
        );
        assert_eq!(
            evaluate_condition_checked(&json!({"StringEquals": {"s3:prefix": "y"}}), &ctx),
            Ok(false)
        );
    }

    #[test]
    fn bool_operator_is_strict() {
        let odd = ctx_with(&[("aws:SecureTransport", "maybe")]);
        assert!(!evaluate_condition(
            &json!({"Bool": {"aws:SecureTransport": "false"}}),
            &odd
        ));
        assert!(!evaluate_condition(
            &json!({"Bool": {"aws:SecureTransport": "true"}}),
            &odd
        ));
        let yes = ctx_with(&[("aws:SecureTransport", "TRUE")]);
        assert!(evaluate_condition(
            &json!({"Bool": {"aws:SecureTransport": true}}),
            &yes
        ));
    }

    #[test]
    fn public_detection_helpers() {
        assert!(condition_restricts_principal(
            &json!({"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}})
        ));
        assert!(!condition_restricts_principal(
            &json!({"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}})
        ));
        assert!(!condition_restricts_principal(
            &json!({"NotIpAddress": {"aws:SourceIp": "10.0.0.0/8"}})
        ));
        assert!(!condition_restricts_principal(
            &json!({"IpAddress": {"aws:SourceIp": ["0.0.0.0/0", "10.0.0.0/8"]}})
        ));
        assert!(!condition_restricts_principal(
            &json!({"StringLike": {"aws:username": ["*", "alice"]}})
        ));
        assert!(condition_restricts_principal(
            &json!({"StringLike": {"aws:username": ["bob", "alice"]}})
        ));
        assert!(!condition_restricts_principal(
            &json!({"StringLike": {"aws:Referer": "https://example.com/*"}})
        ));
        assert!(condition_references_key_prefix(
            &json!({"StringEquals": {"s3:ExistingObjectTag/env": "prod"}}),
            "s3:existingobjecttag/"
        ));
        assert!(!condition_references_key_prefix(
            &json!({"StringEquals": {"s3:prefix": "x"}}),
            "s3:existingobjecttag/"
        ));
    }
}
