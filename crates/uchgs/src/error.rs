use std::fmt;

/// A fail-closed wire, cryptographic, authority, or durable-I/O error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    EmptyInput,
    EncodedLengthExceeded {
        maximum: usize,
        actual: usize,
    },
    InvalidJson(String),
    NonCanonicalJson,
    InvalidField {
        field: &'static str,
        reason: String,
    },
    AuthorityConflict(String),
    AuthorityNotFound(String),
    UnauthorizedApproval(String),
    PolicyMissing(String),
    PolicyInvalid(String),
    JudgmentMissing {
        count: usize,
    },
    GitUnavailable(String),
    UnsupportedPlatform(String),
    Io {
        operation: &'static str,
        kind: std::io::ErrorKind,
        message: String,
    },
}

impl Error {
    pub(crate) fn field(field: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidField {
            field,
            reason: reason.into(),
        }
    }

    pub(crate) fn io(operation: &'static str, error: std::io::Error) -> Self {
        Self::Io {
            operation,
            kind: error.kind(),
            message: error.to_string(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => formatter.write_str("wire input is empty"),
            Self::EncodedLengthExceeded { maximum, actual } => write!(
                formatter,
                "encoded wire length {actual} exceeds maximum {maximum}"
            ),
            Self::InvalidJson(reason) => write!(formatter, "invalid JSON: {reason}"),
            Self::NonCanonicalJson => {
                formatter.write_str("JSON is not the exact RFC 8785 canonical encoding")
            }
            Self::InvalidField { field, reason } => {
                write!(formatter, "invalid {field}: {reason}")
            }
            Self::AuthorityConflict(reason) => write!(formatter, "authority conflict: {reason}"),
            Self::AuthorityNotFound(reason) => {
                write!(formatter, "authority not found: {reason}")
            }
            Self::UnauthorizedApproval(reason) => {
                write!(formatter, "unauthorized approval: {reason}")
            }
            Self::PolicyMissing(reason) => write!(formatter, "policy missing: {reason}"),
            Self::PolicyInvalid(reason) => write!(formatter, "policy invalid: {reason}"),
            Self::JudgmentMissing { count } => {
                write!(formatter, "{count} required judgment(s) are missing")
            }
            Self::GitUnavailable(reason) => write!(formatter, "git unavailable: {reason}"),
            Self::UnsupportedPlatform(reason) => {
                write!(formatter, "unsupported platform: {reason}")
            }
            Self::Io {
                operation,
                kind,
                message,
            } => write!(formatter, "{operation} failed ({kind:?}): {message}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
