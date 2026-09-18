use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BucketSubresource {
    Acl,
    Cors,
    Delete,
    Encryption,
    Lifecycle,
    Location,
    Logging,
    Notification,
    ObjectLock,
    OwnershipControls,
    Policy,
    PolicyStatus,
    PublicAccessBlock,
    Quota,
    Replication,
    Tagging,
    Uploads,
    Versioning,
    Versions,
    Website,
}

pub(super) const BUCKET_SUBRESOURCE_SELECTORS: &[(&str, BucketSubresource)] = &[
    ("acl", BucketSubresource::Acl),
    ("cors", BucketSubresource::Cors),
    ("delete", BucketSubresource::Delete),
    ("encryption", BucketSubresource::Encryption),
    ("lifecycle", BucketSubresource::Lifecycle),
    ("location", BucketSubresource::Location),
    ("logging", BucketSubresource::Logging),
    ("notification", BucketSubresource::Notification),
    ("object-lock", BucketSubresource::ObjectLock),
    ("ownershipControls", BucketSubresource::OwnershipControls),
    ("policy", BucketSubresource::Policy),
    ("policyStatus", BucketSubresource::PolicyStatus),
    ("publicAccessBlock", BucketSubresource::PublicAccessBlock),
    ("quota", BucketSubresource::Quota),
    ("replication", BucketSubresource::Replication),
    ("tagging", BucketSubresource::Tagging),
    ("uploads", BucketSubresource::Uploads),
    ("versioning", BucketSubresource::Versioning),
    ("versions", BucketSubresource::Versions),
    ("website", BucketSubresource::Website),
];

impl BucketSubresource {
    pub fn selector(self) -> &'static str {
        match self {
            Self::Acl => "acl",
            Self::Cors => "cors",
            Self::Delete => "delete",
            Self::Encryption => "encryption",
            Self::Lifecycle => "lifecycle",
            Self::Location => "location",
            Self::Logging => "logging",
            Self::Notification => "notification",
            Self::ObjectLock => "object-lock",
            Self::OwnershipControls => "ownershipControls",
            Self::Policy => "policy",
            Self::PolicyStatus => "policyStatus",
            Self::PublicAccessBlock => "publicAccessBlock",
            Self::Quota => "quota",
            Self::Replication => "replication",
            Self::Tagging => "tagging",
            Self::Uploads => "uploads",
            Self::Versioning => "versioning",
            Self::Versions => "versions",
            Self::Website => "website",
        }
    }

    pub fn action(self) -> &'static str {
        match self {
            Self::Acl => "share",
            Self::Cors => "cors",
            Self::Delete => "delete",
            Self::Encryption => "encryption",
            Self::Lifecycle => "lifecycle",
            Self::Location | Self::Uploads | Self::Versions => "list",
            Self::Logging => "logging",
            Self::Notification => "notification",
            Self::ObjectLock => "object_lock",
            Self::OwnershipControls => "ownership_controls",
            Self::Policy | Self::PolicyStatus => "policy",
            Self::PublicAccessBlock => "public_access_block",
            Self::Quota => "quota",
            Self::Replication => "replication",
            Self::Tagging => "tagging",
            Self::Versioning => "versioning",
            Self::Website => "website",
        }
    }

    pub fn s3_action(self, method: &Method) -> &'static str {
        let read = matches!(*method, Method::GET | Method::HEAD);
        match self {
            Self::Acl => {
                if read {
                    "s3:GetBucketAcl"
                } else {
                    "s3:PutBucketAcl"
                }
            }
            Self::Cors => {
                if read {
                    "s3:GetBucketCORS"
                } else {
                    "s3:PutBucketCORS"
                }
            }
            Self::Delete => "s3:DeleteObject",
            Self::Encryption => {
                if read {
                    "s3:GetEncryptionConfiguration"
                } else {
                    "s3:PutEncryptionConfiguration"
                }
            }
            Self::Lifecycle => {
                if read {
                    "s3:GetLifecycleConfiguration"
                } else {
                    "s3:PutLifecycleConfiguration"
                }
            }
            Self::Location => "s3:GetBucketLocation",
            Self::Logging => {
                if read {
                    "s3:GetBucketLogging"
                } else {
                    "s3:PutBucketLogging"
                }
            }
            Self::Notification => {
                if read {
                    "s3:GetBucketNotification"
                } else {
                    "s3:PutBucketNotification"
                }
            }
            Self::ObjectLock => {
                if read {
                    "s3:GetBucketObjectLockConfiguration"
                } else {
                    "s3:PutBucketObjectLockConfiguration"
                }
            }
            Self::OwnershipControls => {
                if read {
                    "s3:GetBucketOwnershipControls"
                } else {
                    "s3:PutBucketOwnershipControls"
                }
            }
            Self::Policy => match *method {
                Method::PUT | Method::POST => "s3:PutBucketPolicy",
                Method::DELETE => "s3:DeleteBucketPolicy",
                _ => "s3:GetBucketPolicy",
            },
            Self::PolicyStatus => "s3:GetBucketPolicyStatus",
            Self::PublicAccessBlock => {
                if read {
                    "s3:GetBucketPublicAccessBlock"
                } else {
                    "s3:PutBucketPublicAccessBlock"
                }
            }
            Self::Quota => {
                if read {
                    "s3:GetBucketQuota"
                } else {
                    "s3:PutBucketQuota"
                }
            }
            Self::Replication => {
                if read {
                    "s3:GetReplicationConfiguration"
                } else {
                    "s3:PutReplicationConfiguration"
                }
            }
            Self::Tagging => {
                if read {
                    "s3:GetBucketTagging"
                } else {
                    "s3:PutBucketTagging"
                }
            }
            Self::Uploads => "s3:ListBucketMultipartUploads",
            Self::Versioning => {
                if read {
                    "s3:GetBucketVersioning"
                } else {
                    "s3:PutBucketVersioning"
                }
            }
            Self::Versions => "s3:ListBucketVersions",
            Self::Website => match *method {
                Method::PUT | Method::POST => "s3:PutBucketWebsite",
                Method::DELETE => "s3:DeleteBucketWebsite",
                _ => "s3:GetBucketWebsite",
            },
        }
    }
}

pub fn bucket_method_default_s3_action(method: &Method) -> &'static str {
    match *method {
        Method::GET | Method::HEAD => "s3:ListBucket",
        Method::PUT => "s3:CreateBucket",
        Method::DELETE => "s3:DeleteBucket",
        Method::POST => "s3:PutObject",
        _ => "s3:ListBucket",
    }
}

pub(super) fn decode_query_key(raw: &str) -> String {
    percent_decode_str(raw).decode_utf8_lossy().into_owned()
}

pub fn parse_bucket_subresource(
    query: Option<&str>,
) -> Result<Option<BucketSubresource>, Vec<&'static str>> {
    let Some(q) = query else {
        return Ok(None);
    };
    if q.is_empty() {
        return Ok(None);
    }

    let mut found: Vec<BucketSubresource> = Vec::new();
    for part in q.split('&').filter(|p| !p.is_empty()) {
        let raw_key = part.split('=').next().unwrap_or("");
        if raw_key.is_empty() {
            continue;
        }
        let key = decode_query_key(raw_key);
        if let Some((_, subresource)) = BUCKET_SUBRESOURCE_SELECTORS
            .iter()
            .find(|(name, _)| *name == key.as_str())
        {
            if !found.contains(subresource) {
                found.push(*subresource);
            }
        }
    }

    match found.len() {
        0 => Ok(None),
        1 => Ok(Some(found[0])),
        _ => Err(found.into_iter().map(BucketSubresource::selector).collect()),
    }
}

pub fn ambiguous_subresource_error(selectors: &[&'static str]) -> S3Error {
    S3Error::new(
        S3ErrorCode::InvalidArgument,
        format!(
            "Request names multiple subresources ({}); specify exactly one",
            selectors.join(", ")
        ),
    )
}

pub(super) fn selector_method_not_allowed(selector: &str, method: &str) -> Response {
    s3_error_response(S3Error::new(
        S3ErrorCode::MethodNotAllowed,
        format!(
            "{} is not supported on the '?{}' subresource",
            method, selector
        ),
    ))
}

pub(super) fn subresource_method_not_allowed(
    subresource: BucketSubresource,
    method: &str,
) -> Response {
    selector_method_not_allowed(subresource.selector(), method)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectSubresource {
    Acl,
    Attributes,
    LegalHold,
    Retention,
    Select,
    Tagging,
    UploadId,
    Uploads,
}

pub(super) const OBJECT_SUBRESOURCE_SELECTORS: &[(&str, ObjectSubresource)] = &[
    ("acl", ObjectSubresource::Acl),
    ("attributes", ObjectSubresource::Attributes),
    ("legal-hold", ObjectSubresource::LegalHold),
    ("retention", ObjectSubresource::Retention),
    ("select", ObjectSubresource::Select),
    ("tagging", ObjectSubresource::Tagging),
    ("uploadId", ObjectSubresource::UploadId),
    ("uploads", ObjectSubresource::Uploads),
];

pub fn object_method_default_action(method: &Method) -> &'static str {
    match *method {
        Method::GET | Method::HEAD => "read",
        Method::PUT | Method::POST => "write",
        Method::DELETE => "delete",
        _ => "read",
    }
}

pub fn object_method_default_s3_action(method: &Method, version_scoped: bool) -> &'static str {
    match *method {
        Method::PUT | Method::POST => "s3:PutObject",
        Method::DELETE => {
            if version_scoped {
                "s3:DeleteObjectVersion"
            } else {
                "s3:DeleteObject"
            }
        }
        _ => {
            if version_scoped {
                "s3:GetObjectVersion"
            } else {
                "s3:GetObject"
            }
        }
    }
}

impl ObjectSubresource {
    pub fn selector(self) -> &'static str {
        match self {
            Self::Acl => "acl",
            Self::Attributes => "attributes",
            Self::LegalHold => "legal-hold",
            Self::Retention => "retention",
            Self::Select => "select",
            Self::Tagging => "tagging",
            Self::UploadId => "uploadId",
            Self::Uploads => "uploads",
        }
    }

    pub fn is_dispatched_for(self, method: &Method) -> bool {
        match self {
            Self::Tagging | Self::Acl => {
                matches!(*method, Method::PUT | Method::GET | Method::DELETE)
            }
            Self::Retention | Self::LegalHold => matches!(*method, Method::PUT | Method::GET),
            Self::Attributes => *method == Method::GET,
            Self::Select | Self::Uploads => *method == Method::POST,
            Self::UploadId => matches!(
                *method,
                Method::PUT | Method::GET | Method::DELETE | Method::POST
            ),
        }
    }

    pub fn action(self, method: &Method) -> &'static str {
        if !self.is_dispatched_for(method) {
            return object_method_default_action(method);
        }
        match self {
            Self::Retention | Self::LegalHold => "object_lock",
            Self::Attributes | Self::Select => "read",
            Self::Tagging | Self::Acl | Self::UploadId | Self::Uploads => {
                if matches!(*method, Method::GET | Method::HEAD) {
                    "read"
                } else {
                    "write"
                }
            }
        }
    }

    pub fn s3_action(self, method: &Method, version_scoped: bool) -> &'static str {
        if !self.is_dispatched_for(method) {
            return object_method_default_s3_action(method, version_scoped);
        }
        let read = matches!(*method, Method::GET | Method::HEAD);
        match self {
            Self::Acl => match (read, version_scoped) {
                (true, true) => "s3:GetObjectVersionAcl",
                (true, false) => "s3:GetObjectAcl",
                (false, true) => "s3:PutObjectVersionAcl",
                (false, false) => "s3:PutObjectAcl",
            },
            Self::Attributes => {
                if version_scoped {
                    "s3:GetObjectVersionAttributes"
                } else {
                    "s3:GetObjectAttributes"
                }
            }
            Self::LegalHold => {
                if read {
                    "s3:GetObjectLegalHold"
                } else {
                    "s3:PutObjectLegalHold"
                }
            }
            Self::Retention => {
                if read {
                    "s3:GetObjectRetention"
                } else {
                    "s3:PutObjectRetention"
                }
            }
            Self::Select => "s3:GetObject",
            Self::Tagging => match *method {
                Method::DELETE => "s3:DeleteObjectTagging",
                Method::PUT | Method::POST => "s3:PutObjectTagging",
                _ => {
                    if version_scoped {
                        "s3:GetObjectVersionTagging"
                    } else {
                        "s3:GetObjectTagging"
                    }
                }
            },
            Self::UploadId => match *method {
                Method::GET => "s3:ListMultipartUploadParts",
                Method::DELETE => "s3:AbortMultipartUpload",
                _ => "s3:PutObject",
            },
            Self::Uploads => "s3:PutObject",
        }
    }
}

pub fn query_has_version_id(query: Option<&str>) -> bool {
    let Some(q) = query else {
        return false;
    };
    q.split('&').filter(|p| !p.is_empty()).any(|part| {
        part.split_once('=').is_some_and(|(raw_key, value)| {
            !value.is_empty() && decode_query_key(raw_key) == "versionId"
        })
    })
}

pub fn parse_object_subresource(
    query: Option<&str>,
) -> Result<Option<ObjectSubresource>, Vec<&'static str>> {
    let Some(q) = query else {
        return Ok(None);
    };
    if q.is_empty() {
        return Ok(None);
    }

    let mut found: Vec<ObjectSubresource> = Vec::new();
    for part in q.split('&').filter(|p| !p.is_empty()) {
        let raw_key = part.split('=').next().unwrap_or("");
        if raw_key.is_empty() {
            continue;
        }
        let key = decode_query_key(raw_key);
        if let Some((_, subresource)) = OBJECT_SUBRESOURCE_SELECTORS
            .iter()
            .find(|(name, _)| *name == key.as_str())
        {
            if !found.contains(subresource) {
                found.push(*subresource);
            }
        }
    }

    match found.len() {
        0 => Ok(None),
        1 => Ok(Some(found[0])),
        _ => Err(found.into_iter().map(ObjectSubresource::selector).collect()),
    }
}

pub(super) fn guard_object_subresource(query: Option<&str>, method: &Method) -> Option<Response> {
    match parse_object_subresource(query) {
        Err(selectors) => Some(s3_error_response(ambiguous_subresource_error(&selectors))),
        Ok(Some(subresource)) if !subresource.is_dispatched_for(method) => Some(
            selector_method_not_allowed(subresource.selector(), method.as_str()),
        ),
        Ok(_) => None,
    }
}

pub(super) const SUPPORTED_BUCKET_LIST_PARAMS: &[&str] = &[
    "list-type",
    "marker",
    "prefix",
    "delimiter",
    "max-keys",
    "max-uploads",
    "continuation-token",
    "start-after",
    "encoding-type",
    "fetch-owner",
    "key-marker",
    "version-id-marker",
    "upload-id-marker",
];

pub(super) fn unsupported_bucket_subresource(query: Option<&str>) -> Option<String> {
    let q = query?;
    if q.is_empty() {
        return None;
    }
    for part in q.split('&').filter(|p| !p.is_empty()) {
        let raw_key = part.split('=').next().unwrap_or("");
        if raw_key.is_empty() {
            continue;
        }
        let key_owned = decode_query_key(raw_key);
        let lower = key_owned.to_ascii_lowercase();
        let known = BUCKET_SUBRESOURCE_SELECTORS
            .iter()
            .any(|(name, _)| *name == key_owned.as_str())
            || SUPPORTED_BUCKET_LIST_PARAMS
                .iter()
                .any(|known| known.eq_ignore_ascii_case(&key_owned))
            || lower.starts_with("x-amz-")
            || lower.starts_with("x-id");
        if !known {
            return Some(key_owned);
        }
    }
    None
}

pub(super) const SUPPORTED_OBJECT_PARAMS: &[&str] = &[
    "versionId",
    "partNumber",
    "part-number-marker",
    "max-parts",
    "select-type",
    "response-content-type",
    "response-content-language",
    "response-expires",
    "response-cache-control",
    "response-content-disposition",
    "response-content-encoding",
];

pub(super) fn unsupported_object_subresource(query: Option<&str>) -> Option<String> {
    let q = query?;
    if q.is_empty() {
        return None;
    }
    for part in q.split('&').filter(|p| !p.is_empty()) {
        let raw_key = part.split('=').next().unwrap_or("");
        if raw_key.is_empty() {
            continue;
        }
        let key_owned = decode_query_key(raw_key);
        let lower = key_owned.to_ascii_lowercase();
        let known = OBJECT_SUBRESOURCE_SELECTORS
            .iter()
            .any(|(name, _)| *name == key_owned.as_str())
            || SUPPORTED_OBJECT_PARAMS
                .iter()
                .any(|known| known.eq_ignore_ascii_case(&key_owned))
            || lower.starts_with("x-amz-")
            || lower.starts_with("x-id");
        if !known {
            return Some(key_owned);
        }
    }
    None
}
