//! Canonical, byte-preserving pre-push input.
//!
//! Normative source: SPEC §2.4 and §11.1.

use std::ffi::OsStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{Error, Result, extract::JudgmentUnit};

use super::{Digest32, ExactJson, ObjectFormatName, PushIntentId, WireValidate};

pub const PUSH_INTENT_MAX_BYTES: usize = 16 * 1024 * 1024;
pub const PUSH_UPDATE_MAX_COUNT: usize = 65_536;
pub const PUSH_FIELD_MAX_BYTES: usize = 65_535;

/// The three closed byte encodings used by one push intent.
///
/// Both OS encodings remain decodable on every platform; the creating
/// platform is what selects one for `remote_name`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PushBytesEncoding {
    #[serde(rename = "stdin-bytes-v1")]
    StdinBytesV1,
    #[serde(rename = "unix-osstr-bytes-v1")]
    UnixOsstrBytesV1,
    #[serde(rename = "windows-utf16le-v1")]
    WindowsUtf16leV1,
}

/// One exact byte field together with its origin-specific encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushBytes {
    pub bytes_hex: String,
    pub encoding: PushBytesEncoding,
}

impl PushBytes {
    pub(crate) fn stdin(bytes: &[u8], field: &'static str) -> Result<Self> {
        validate_bytes(bytes, field)?;
        Ok(Self {
            bytes_hex: hex::encode(bytes),
            encoding: PushBytesEncoding::StdinBytesV1,
        })
    }

    pub(crate) fn remote_name(value: &OsStr) -> Result<Self> {
        let (encoding, bytes) = native_os_string_bytes(value)?;
        validate_bytes(&bytes, "remote_name")?;
        Ok(Self {
            bytes_hex: hex::encode(bytes),
            encoding,
        })
    }

    pub(crate) fn decoded(&self, field: &'static str) -> Result<Vec<u8>> {
        if self.bytes_hex.len() % 2 != 0
            || !self
                .bytes_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(Error::field(field, "must be even-length lowercase hex"));
        }
        let bytes = hex::decode(&self.bytes_hex)
            .map_err(|_| Error::field(field, "must be lowercase hex"))?;
        validate_bytes(&bytes, field)?;
        if self.encoding == PushBytesEncoding::WindowsUtf16leV1 && bytes.len() % 2 != 0 {
            return Err(Error::field(
                field,
                "windows-utf16le-v1 must contain complete 16-bit code units",
            ));
        }
        Ok(bytes)
    }
}

/// One line from Git's pre-push stdin, retaining its original order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushUpdate {
    pub index: u64,
    pub local_oid: String,
    pub local_ref: PushBytes,
    pub remote_oid: String,
    pub remote_ref: PushBytes,
}

/// The exact §11.1 snapshot. It intentionally has no connection-URL field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushIntent {
    pub kind: String,
    pub object_format: ObjectFormatName,
    pub remote_name: PushBytes,
    pub schema: u64,
    pub updates: Vec<PushUpdate>,
}

impl WireValidate for PushIntent {
    fn validate(&self) -> Result<()> {
        if self.schema != 1 || self.kind != "push-intent" {
            return Err(Error::field(
                "push intent",
                "schema/kind must be 1/`push-intent`",
            ));
        }
        if self.updates.len() > PUSH_UPDATE_MAX_COUNT {
            return Err(Error::InvalidArguments(format!(
                "push update count exceeds {PUSH_UPDATE_MAX_COUNT}"
            )));
        }
        if self.remote_name.encoding != native_remote_encoding()? {
            return Err(Error::field(
                "remote_name.encoding",
                "remote name must use the native OS-string encoding",
            ));
        }
        self.remote_name.decoded("remote_name.bytes_hex")?;

        let oid_width = self.object_format.oid_hex_len();
        for (position, update) in self.updates.iter().enumerate() {
            if update.index != position as u64 {
                return Err(Error::field("updates.index", "indices must be contiguous"));
            }
            if update.local_ref.encoding != PushBytesEncoding::StdinBytesV1
                || update.remote_ref.encoding != PushBytesEncoding::StdinBytesV1
            {
                return Err(Error::field(
                    "updates encoding",
                    "ref fields must use stdin-bytes-v1",
                ));
            }
            let local_ref = update.local_ref.decoded("local_ref.bytes_hex")?;
            let remote_ref = update.remote_ref.decoded("remote_ref.bytes_hex")?;
            validate_oid(&update.local_oid, oid_width, "local_oid")?;
            validate_oid(&update.remote_oid, oid_width, "remote_oid")?;
            JudgmentUnit::ref_name(remote_ref)?;
            if update.local_oid.bytes().all(|byte| byte == b'0') {
                if local_ref != b"(delete)" {
                    return Err(Error::field(
                        "local_ref",
                        "a deletion must use Git's `(delete)` marker",
                    ));
                }
            } else {
                JudgmentUnit::ref_name(local_ref)?;
            }
        }
        Ok(())
    }
}

/// Exact PushIntent bytes and their content-addressed identifier.
#[derive(Debug, Clone)]
pub struct PushIntentDocument {
    exact: ExactJson<PushIntent>,
    id: PushIntentId,
}

impl PushIntentDocument {
    pub(crate) fn encode(value: PushIntent) -> Result<Self> {
        let exact = ExactJson::encode(value, PUSH_INTENT_MAX_BYTES)?;
        let id = PushIntentId::from_digest(Digest32::from_bytes(exact.sha256()));
        Ok(Self { exact, id })
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let exact = ExactJson::parse(bytes, PUSH_INTENT_MAX_BYTES)?;
        let id = PushIntentId::from_digest(Digest32::from_bytes(exact.sha256()));
        Ok(Self { exact, id })
    }

    pub fn value(&self) -> &PushIntent {
        self.exact.value()
    }

    pub fn bytes(&self) -> &[u8] {
        self.exact.bytes()
    }

    pub fn id(&self) -> &PushIntentId {
        &self.id
    }

    pub fn sha256(&self) -> Digest32 {
        Digest32::from_bytes(Sha256::digest(self.bytes()).into())
    }
}

fn validate_oid(value: &str, width: usize, field: &'static str) -> Result<()> {
    if value.len() != width
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(Error::field(field, "object id must be exact lowercase hex"));
    }
    Ok(())
}

fn validate_bytes(bytes: &[u8], field: &'static str) -> Result<()> {
    if bytes.is_empty() {
        return Err(Error::field(field, "must not be empty"));
    }
    if bytes.len() > PUSH_FIELD_MAX_BYTES {
        return Err(Error::InvalidArguments(format!(
            "{field} exceeds {PUSH_FIELD_MAX_BYTES} bytes"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn native_os_string_bytes(value: &OsStr) -> Result<(PushBytesEncoding, Vec<u8>)> {
    use std::os::unix::ffi::OsStrExt as _;
    Ok((
        PushBytesEncoding::UnixOsstrBytesV1,
        value.as_bytes().to_vec(),
    ))
}

#[cfg(windows)]
fn native_os_string_bytes(value: &OsStr) -> Result<(PushBytesEncoding, Vec<u8>)> {
    use std::os::windows::ffi::OsStrExt as _;
    let mut bytes = Vec::new();
    for unit in value.encode_wide() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    Ok((PushBytesEncoding::WindowsUtf16leV1, bytes))
}

#[cfg(not(any(unix, windows)))]
fn native_os_string_bytes(_value: &OsStr) -> Result<(PushBytesEncoding, Vec<u8>)> {
    Err(Error::UnsupportedPlatform(
        "native remote-name encoding is unavailable".to_owned(),
    ))
}

#[cfg(unix)]
fn native_remote_encoding() -> Result<PushBytesEncoding> {
    Ok(PushBytesEncoding::UnixOsstrBytesV1)
}

#[cfg(windows)]
fn native_remote_encoding() -> Result<PushBytesEncoding> {
    Ok(PushBytesEncoding::WindowsUtf16leV1)
}

#[cfg(not(any(unix, windows)))]
fn native_remote_encoding() -> Result<PushBytesEncoding> {
    Err(Error::UnsupportedPlatform(
        "native remote-name encoding is unavailable".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_intent_has_no_url_and_rejects_unknown_fields() {
        let intent = PushIntentDocument::encode(PushIntent {
            kind: "push-intent".to_owned(),
            object_format: ObjectFormatName::Sha1,
            remote_name: PushBytes::remote_name(OsStr::new("origin")).unwrap(),
            schema: 1,
            updates: Vec::new(),
        })
        .unwrap();
        assert!(!intent.bytes().windows(3).any(|bytes| bytes == b"url"));
        let reparsed = PushIntentDocument::parse(intent.bytes()).unwrap();
        assert_eq!(reparsed.bytes(), intent.bytes());
        assert_eq!(reparsed.id(), intent.id());
        assert_eq!(reparsed.sha256(), intent.sha256());
        assert!(PushIntentDocument::parse(
            br#"{"kind":"push-intent","object_format":"sha1","remote_name":{"bytes_hex":"6f726967696e","encoding":"unix-osstr-bytes-v1"},"schema":1,"unknown":0,"updates":[]}"#
        )
        .is_err());
    }

    #[test]
    fn windows_encoding_requires_complete_code_units_after_hex_decode() {
        for bytes_hex in ["00", "000000"] {
            let encoded = PushBytes {
                bytes_hex: bytes_hex.to_owned(),
                encoding: PushBytesEncoding::WindowsUtf16leV1,
            };
            assert!(matches!(
                encoded.decoded("remote_name.bytes_hex"),
                Err(Error::InvalidField { .. })
            ));
        }

        for bytes_hex in ["0000", "00d8", "ffdf"] {
            let encoded = PushBytes {
                bytes_hex: bytes_hex.to_owned(),
                encoding: PushBytesEncoding::WindowsUtf16leV1,
            };
            assert_eq!(
                encoded.decoded("remote_name.bytes_hex").unwrap(),
                hex::decode(bytes_hex).unwrap()
            );
        }
    }

    #[test]
    #[cfg(windows)]
    fn windows_documents_require_code_unit_alignment_without_unicode_normalization() {
        let document = |bytes_hex: &str| {
            format!(
                "{{\"kind\":\"push-intent\",\"object_format\":\"sha1\",\"remote_name\":{{\"bytes_hex\":\"{bytes_hex}\",\"encoding\":\"windows-utf16le-v1\"}},\"schema\":1,\"updates\":[]}}"
            )
        };
        for bytes_hex in ["00", "000000"] {
            assert!(matches!(
                PushIntentDocument::parse(document(bytes_hex).as_bytes()),
                Err(Error::InvalidField { .. })
            ));
        }

        for bytes_hex in ["0000", "00d8", "ffdf"] {
            let bytes = document(bytes_hex);
            let parsed = PushIntentDocument::parse(bytes.as_bytes()).unwrap();
            assert_eq!(parsed.bytes(), bytes.as_bytes());
            assert_eq!(parsed.id(), &PushIntentId::from_digest(parsed.sha256()));
        }
    }

    #[test]
    #[cfg(any(unix, windows))]
    fn non_native_remote_encoding_is_rejected_after_schema_parse() {
        let mut value = PushIntent {
            kind: "push-intent".to_owned(),
            object_format: ObjectFormatName::Sha1,
            remote_name: PushBytes::remote_name(OsStr::new("origin")).unwrap(),
            schema: 1,
            updates: Vec::new(),
        };
        value.remote_name.encoding = if cfg!(unix) {
            PushBytesEncoding::WindowsUtf16leV1
        } else {
            PushBytesEncoding::UnixOsstrBytesV1
        };
        assert!(matches!(
            PushIntentDocument::encode(value),
            Err(Error::InvalidField { .. })
        ));
    }
}
