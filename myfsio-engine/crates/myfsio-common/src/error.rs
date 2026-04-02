use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3ErrorCode {
    AccessDenied,
    BucketAlreadyExists,
    BucketNotEmpty,
    EntityTooLarge,
    InternalError,
    InvalidAccessKeyId,
    InvalidArgument,
    InvalidBucketName,
    InvalidKey,
    InvalidRange,
    InvalidRequest,
    MalformedXML,
    MethodNotAllowed,
    NoSuchBucket,
    NoSuchKey,
    NoSuchUpload,
    NoSuchVersion,
    NoSuchTagSet,
    PreconditionFailed,
    NotModified,
    QuotaExceeded,
    SignatureDoesNotMatch,
    SlowDown,
}

impl S3ErrorCode {
    pub fn http_status(&self) -> u16 {
        match self {
            Self::AccessDenied => 403,
            Self::BucketAlreadyExists => 409,
            Self::BucketNotEmpty => 409,
            Self::EntityTooLarge => 413,
            Self::InternalError => 500,
            Self::InvalidAccessKeyId => 403,
            Self::InvalidArgument => 400,
            Self::InvalidBucketName => 400,
            Self::InvalidKey => 400,
            Self::InvalidRange => 416,
            Self::InvalidRequest => 400,
            Self::MalformedXML => 400,
            Self::MethodNotAllowed => 405,
            Self::NoSuchBucket => 404,
            Self::NoSuchKey => 404,
            Self::NoSuchUpload => 404,
            Self::NoSuchVersion => 404,
            Self::NoSuchTagSet => 404,
            Self::PreconditionFailed => 412,
            Self::NotModified => 304,
            Self::QuotaExceeded => 403,
            Self::SignatureDoesNotMatch => 403,
            Self::SlowDown => 429,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AccessDenied => "AccessDenied",
            Self::BucketAlreadyExists => "BucketAlreadyExists",
            Self::BucketNotEmpty => "BucketNotEmpty",
            Self::EntityTooLarge => "EntityTooLarge",
            Self::InternalError => "InternalError",
            Self::InvalidAccessKeyId => "InvalidAccessKeyId",
            Self::InvalidArgument => "InvalidArgument",
            Self::InvalidBucketName => "InvalidBucketName",
            Self::InvalidKey => "InvalidKey",
            Self::InvalidRange => "InvalidRange",
            Self::InvalidRequest => "InvalidRequest",
            Self::MalformedXML => "MalformedXML",
            Self::MethodNotAllowed => "MethodNotAllowed",
            Self::NoSuchBucket => "NoSuchBucket",
            Self::NoSuchKey => "NoSuchKey",
            Self::NoSuchUpload => "NoSuchUpload",
            Self::NoSuchVersion => "NoSuchVersion",
            Self::NoSuchTagSet => "NoSuchTagSet",
            Self::PreconditionFailed => "PreconditionFailed",
            Self::NotModified => "NotModified",
            Self::QuotaExceeded => "QuotaExceeded",
            Self::SignatureDoesNotMatch => "SignatureDoesNotMatch",
            Self::SlowDown => "SlowDown",
        }
    }

    pub fn default_message(&self) -> &'static str {
        match self {
            Self::AccessDenied => "Access Denied",
            Self::BucketAlreadyExists => "The requested bucket name is not available",
            Self::BucketNotEmpty => "The bucket you tried to delete is not empty",
            Self::EntityTooLarge => "Your proposed upload exceeds the maximum allowed size",
            Self::InternalError => "We encountered an internal error. Please try again.",
            Self::InvalidAccessKeyId => "The access key ID you provided does not exist",
            Self::InvalidArgument => "Invalid argument",
            Self::InvalidBucketName => "The specified bucket is not valid",
            Self::InvalidKey => "The specified key is not valid",
            Self::InvalidRange => "The requested range is not satisfiable",
            Self::InvalidRequest => "Invalid request",
            Self::MalformedXML => "The XML you provided was not well-formed",
            Self::MethodNotAllowed => "The specified method is not allowed against this resource",
            Self::NoSuchBucket => "The specified bucket does not exist",
            Self::NoSuchKey => "The specified key does not exist",
            Self::NoSuchUpload => "The specified multipart upload does not exist",
            Self::NoSuchVersion => "The specified version does not exist",
            Self::NoSuchTagSet => "The TagSet does not exist",
            Self::PreconditionFailed => "At least one of the preconditions you specified did not hold",
            Self::NotModified => "Not Modified",
            Self::QuotaExceeded => "The bucket quota has been exceeded",
            Self::SignatureDoesNotMatch => "The request signature we calculated does not match the signature you provided",
            Self::SlowDown => "Please reduce your request rate",
        }
    }
}

impl fmt::Display for S3ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct S3Error {
    pub code: S3ErrorCode,
    pub message: String,
    pub resource: String,
    pub request_id: String,
}

impl S3Error {
    pub fn new(code: S3ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            resource: String::new(),
            request_id: String::new(),
        }
    }

    pub fn from_code(code: S3ErrorCode) -> Self {
        Self::new(code, code.default_message())
    }

    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = resource.into();
        self
    }

    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = request_id.into();
        self
    }

    pub fn http_status(&self) -> u16 {
        self.code.http_status()
    }

    pub fn to_xml(&self) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
            <Error>\
            <Code>{}</Code>\
            <Message>{}</Message>\
            <Resource>{}</Resource>\
            <RequestId>{}</RequestId>\
            </Error>",
            self.code.as_str(),
            xml_escape(&self.message),
            xml_escape(&self.resource),
            xml_escape(&self.request_id),
        )
    }
}

impl fmt::Display for S3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for S3Error {}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        assert_eq!(S3ErrorCode::NoSuchKey.http_status(), 404);
        assert_eq!(S3ErrorCode::AccessDenied.http_status(), 403);
        assert_eq!(S3ErrorCode::NoSuchBucket.as_str(), "NoSuchBucket");
    }

    #[test]
    fn test_error_to_xml() {
        let err = S3Error::from_code(S3ErrorCode::NoSuchKey)
            .with_resource("/test-bucket/test-key")
            .with_request_id("abc123");
        let xml = err.to_xml();
        assert!(xml.contains("<Code>NoSuchKey</Code>"));
        assert!(xml.contains("<Resource>/test-bucket/test-key</Resource>"));
        assert!(xml.contains("<RequestId>abc123</RequestId>"));
    }

    #[test]
    fn test_xml_escape() {
        let err = S3Error::new(S3ErrorCode::InvalidArgument, "key <test> & \"value\"")
            .with_resource("/bucket/key&amp");
        let xml = err.to_xml();
        assert!(xml.contains("&lt;test&gt;"));
        assert!(xml.contains("&amp;"));
    }
}
