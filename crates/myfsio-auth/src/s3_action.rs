pub const S3_ACTION_TABLE: &[(&str, &str)] = &[
    ("s3:listbucket", "list"),
    ("s3:listallmybuckets", "list"),
    ("s3:listbucketversions", "list"),
    ("s3:listmultipartuploads", "list"),
    ("s3:listparts", "list"),
    ("s3:getobject", "read"),
    ("s3:getobjectversion", "read"),
    ("s3:getobjecttagging", "read"),
    ("s3:getobjectversiontagging", "read"),
    ("s3:getobjectacl", "read"),
    ("s3:getbucketversioning", "read"),
    ("s3:headobject", "read"),
    ("s3:headbucket", "read"),
    ("s3:putobject", "write"),
    ("s3:createbucket", "write"),
    ("s3:putobjecttagging", "write"),
    ("s3:putbucketversioning", "write"),
    ("s3:createmultipartupload", "write"),
    ("s3:uploadpart", "write"),
    ("s3:completemultipartupload", "write"),
    ("s3:abortmultipartupload", "write"),
    ("s3:copyobject", "write"),
    ("s3:deleteobject", "delete"),
    ("s3:deleteobjectversion", "delete"),
    ("s3:deletebucket", "delete"),
    ("s3:deleteobjecttagging", "delete"),
    ("s3:bypassgovernanceretention", "bypass_governance"),
    ("s3:putobjectacl", "share"),
    ("s3:putbucketacl", "share"),
    ("s3:getbucketacl", "share"),
    ("s3:putbucketpolicy", "policy"),
    ("s3:getbucketpolicy", "policy"),
    ("s3:deletebucketpolicy", "policy"),
    ("s3:getreplicationconfiguration", "replication"),
    ("s3:putreplicationconfiguration", "replication"),
    ("s3:deletereplicationconfiguration", "replication"),
    ("s3:replicateobject", "replication"),
    ("s3:replicatetags", "replication"),
    ("s3:replicatedelete", "replication"),
    ("s3:getlifecycleconfiguration", "lifecycle"),
    ("s3:putlifecycleconfiguration", "lifecycle"),
    ("s3:deletelifecycleconfiguration", "lifecycle"),
    ("s3:getbucketlifecycle", "lifecycle"),
    ("s3:putbucketlifecycle", "lifecycle"),
    ("s3:getbucketcors", "cors"),
    ("s3:putbucketcors", "cors"),
    ("s3:deletebucketcors", "cors"),
];

pub fn canonical_s3_action_name(name: &str) -> &str {
    match name {
        "s3:headobject" => "s3:getobject",
        "s3:headbucket" => "s3:listbucket",
        "s3:getobjectversion" => "s3:getobject",
        "s3:getobjectversiontagging" => "s3:getobjecttagging",
        "s3:deleteobjectversion" => "s3:deleteobject",
        "s3:copyobject"
        | "s3:createmultipartupload"
        | "s3:uploadpart"
        | "s3:completemultipartupload" => "s3:putobject",
        "s3:listmultipartuploads" => "s3:listbucketmultipartuploads",
        "s3:listparts" => "s3:listmultipartuploadparts",
        "s3:getbucketlifecycle" => "s3:getlifecycleconfiguration",
        "s3:putbucketlifecycle" => "s3:putlifecycleconfiguration",
        other => other,
    }
}

pub fn action_matches(
    policy_action: &str,
    requested_action: &str,
    requested_s3_action: Option<&str>,
) -> bool {
    let normalized_policy = policy_action.trim().to_ascii_lowercase();
    if normalized_policy == "*" {
        return true;
    }
    if let Some(requested_s3) = requested_s3_action {
        let requested_s3 = requested_s3.to_ascii_lowercase();
        let requested_s3 = canonical_s3_action_name(&requested_s3);
        if normalized_policy.contains('*') || normalized_policy.contains('?') {
            return wildcard_match(requested_s3, &normalized_policy)
                || S3_ACTION_TABLE.iter().any(|(candidate, _)| {
                    canonical_s3_action_name(candidate) == requested_s3
                        && wildcard_match(candidate, &normalized_policy)
                });
        }
        return if normalized_policy.starts_with("s3:") {
            canonical_s3_action_name(&normalized_policy) == requested_s3
        } else {
            normalized_policy == requested_action
        };
    }
    if normalized_policy.contains('*') || normalized_policy.contains('?') {
        return S3_ACTION_TABLE.iter().any(|(s3_action, internal_action)| {
            *internal_action == requested_action && wildcard_match(s3_action, &normalized_policy)
        });
    }
    normalize_policy_action(&normalized_policy) == requested_action
}

fn normalize_policy_action(action: &str) -> String {
    let normalized = action.trim().to_ascii_lowercase();
    if normalized == "*" {
        return normalized;
    }
    for (s3_action, internal_action) in S3_ACTION_TABLE {
        if *s3_action == normalized {
            return (*internal_action).to_string();
        }
    }
    normalized
}

pub fn wildcard_match(value: &str, pattern: &str) -> bool {
    wildcard_match_inner(value, pattern, false)
}

pub fn wildcard_match_case_sensitive(value: &str, pattern: &str) -> bool {
    wildcard_match_inner(value, pattern, true)
}

fn wildcard_match_inner(value: &str, pattern: &str, case_sensitive: bool) -> bool {
    let value = value.as_bytes();
    let pattern = pattern.as_bytes();
    let mut value_idx = 0usize;
    let mut pattern_idx = 0usize;
    let mut star_idx: Option<usize> = None;
    let mut match_idx = 0usize;

    let literal_matches = |pattern_byte: u8, value_byte: u8| {
        if case_sensitive {
            pattern_byte == value_byte
        } else {
            pattern_byte.eq_ignore_ascii_case(&value_byte)
        }
    };

    while value_idx < value.len() {
        if pattern_idx < pattern.len()
            && (pattern[pattern_idx] == b'?'
                || literal_matches(pattern[pattern_idx], value[value_idx]))
        {
            value_idx += 1;
            pattern_idx += 1;
        } else if pattern_idx < pattern.len() && pattern[pattern_idx] == b'*' {
            star_idx = Some(pattern_idx);
            pattern_idx += 1;
            match_idx = value_idx;
        } else if let Some(star) = star_idx {
            pattern_idx = star + 1;
            match_idx += 1;
            value_idx = match_idx;
        } else {
            return false;
        }
    }

    while pattern_idx < pattern.len() && pattern[pattern_idx] == b'*' {
        pattern_idx += 1;
    }

    pattern_idx == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_actions_and_aliases_are_scoped() {
        assert!(action_matches(
            "s3:GetObjectTagging",
            "read",
            Some("s3:GetObjectTagging")
        ));
        assert!(!action_matches(
            "s3:GetObjectTagging",
            "read",
            Some("s3:GetObject")
        ));
        assert!(action_matches(
            "s3:HeadObject",
            "read",
            Some("s3:GetObject")
        ));
        assert!(action_matches(
            "s3:GetObjectVersion",
            "read",
            Some("s3:GetObject")
        ));
        assert!(action_matches(
            "s3:CopyObject",
            "write",
            Some("s3:PutObject")
        ));
        assert!(action_matches(
            "s3:UploadPart",
            "write",
            Some("s3:PutObject")
        ));
    }

    #[test]
    fn coarse_and_wildcard_actions_preserve_compatibility() {
        assert!(action_matches("read", "read", Some("s3:GetObject")));
        assert!(action_matches("read", "read", Some("s3:GetObjectTagging")));
        assert!(action_matches("s3:Get*", "read", Some("s3:GetObject")));
        assert!(action_matches(
            "s3:Get*",
            "read",
            Some("s3:GetObjectTagging")
        ));
        assert!(!action_matches(
            "s3:GetObject*",
            "read",
            Some("s3:GetBucketVersioning")
        ));
        assert!(action_matches("*", "write", Some("s3:PutObject")));
    }
}
