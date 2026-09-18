use super::*;

pub(super) const VALID_STORAGE_CLASSES: &[&str] = &[
    "STANDARD",
    "REDUCED_REDUNDANCY",
    "STANDARD_IA",
    "ONEZONE_IA",
    "INTELLIGENT_TIERING",
    "GLACIER",
    "GLACIER_IR",
    "DEEP_ARCHIVE",
    "OUTPOSTS",
    "SNOW",
    "EXPRESS_ONEZONE",
];

pub(super) const CANNED_ACL_VALUES: &[&str] = &[
    "private",
    "public-read",
    "public-read-write",
    "authenticated-read",
    "bucket-owner-read",
    "bucket-owner-full-control",
    "aws-exec-read",
];

pub(super) enum HeaderAcl {
    Canned(String),
    Grants(Vec<crate::services::acl::AclGrant>),
}

impl HeaderAcl {
    pub(super) fn into_acl(self, owner: &str) -> crate::services::acl::Acl {
        match self {
            HeaderAcl::Canned(canned) => crate::services::acl::create_canned_acl(&canned, owner),
            HeaderAcl::Grants(grants) => crate::services::acl::Acl {
                owner: owner.to_string(),
                grants,
            },
        }
    }
}

pub(super) fn header_acl_request(headers: &HeaderMap) -> Result<Option<HeaderAcl>, Response> {
    let canned = canned_acl_value(headers)?;
    let mut grants: Vec<crate::services::acl::AclGrant> = Vec::new();
    for header in crate::services::acl::ACL_GRANT_HEADERS {
        let Some(value) = headers.get(*header) else {
            continue;
        };
        let Ok(raw) = value.to_str() else {
            return Err(s3_error_response(S3Error::new(
                S3ErrorCode::InvalidArgument,
                format!("Invalid grantee list in {}", header),
            )));
        };
        if raw.trim().is_empty() {
            continue;
        }
        match crate::services::acl::grants_from_header(header, raw) {
            Ok(parsed) => {
                for grant in parsed {
                    if !grants.contains(&grant) {
                        grants.push(grant);
                    }
                }
            }
            Err(message) => {
                return Err(s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    message,
                )));
            }
        }
    }
    if canned.is_some() && !grants.is_empty() {
        return Err(s3_error_response(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "Specifying both Canned ACLs and Header Grants is not allowed",
        )));
    }
    if !grants.is_empty() {
        return Ok(Some(HeaderAcl::Grants(grants)));
    }
    Ok(canned.map(HeaderAcl::Canned))
}

pub(super) fn apply_object_acl(
    headers: &HeaderMap,
    metadata: &mut HashMap<String, String>,
    owner: &str,
) -> Result<(), Response> {
    let acl = match header_acl_request(headers)? {
        Some(request) => request.into_acl(owner),
        None => crate::services::acl::create_canned_acl("private", owner),
    };
    crate::services::acl::store_object_acl(metadata, &acl);
    Ok(())
}

pub(super) fn canned_acl_value(headers: &HeaderMap) -> Result<Option<String>, Response> {
    let Some(raw) = headers.get("x-amz-acl").and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if !CANNED_ACL_VALUES
        .iter()
        .any(|known| known.eq_ignore_ascii_case(value))
    {
        return Err(s3_error_response(S3Error::new(
            S3ErrorCode::InvalidArgument,
            format!("Unsupported canned ACL: {}", value),
        )));
    }
    Ok(Some(value.to_string()))
}
