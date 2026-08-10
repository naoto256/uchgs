//! Pure judgment-unit extraction and identifier derivation.
//!
//! Normative source: SPEC §2.2–§2.3, §3.0–§3.3, and §4.

use std::{fmt, str::FromStr};

use sha2::{Digest as _, Sha256};

use crate::{Error, Result, wire::Digest32};

const UNIT_ID_PREFIX: &str = "unit/v1/sha256/";

/// Git object format needed to validate binary tree-entry object IDs.
///
/// Normative source: SPEC §2.3 and §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectFormat {
    Sha1,
    Sha256,
}

impl ObjectFormat {
    /// Returns the exact binary object-ID width for this repository format.
    ///
    /// Normative source: SPEC §2.3 and §3.3.
    fn oid_bytes(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    /// Returns the exact hexadecimal object-ID width for this repository format.
    ///
    /// Normative source: SPEC §2.3 and §3.3.
    fn oid_hex_bytes(self) -> usize {
        self.oid_bytes() * 2
    }
}

/// The closed set of judgment-unit kinds.
///
/// Normative source: SPEC §3 and §4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UnitKind {
    File,
    Path,
    Commit,
    Tag,
    Ref,
}

impl UnitKind {
    /// Returns the exact identifier segment for this unit kind.
    ///
    /// Normative source: SPEC §2.2 and §4.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Path => "path",
            Self::Commit => "commit",
            Self::Tag => "tag",
            Self::Ref => "ref",
        }
    }
}

impl FromStr for UnitKind {
    type Err = Error;

    /// Parses only the five unit-kind spellings closed by SPEC §3.
    fn from_str(value: &str) -> Result<Self> {
        match value {
            "file" => Ok(Self::File),
            "path" => Ok(Self::Path),
            "commit" => Ok(Self::Commit),
            "tag" => Ok(Self::Tag),
            "ref" => Ok(Self::Ref),
            _ => Err(Error::field("unit kind", "unknown unit kind")),
        }
    }
}

/// A versioned unit identifier derived only from kind and extracted bytes.
///
/// Normative source: SPEC §2.2 and §4.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnitId {
    kind: UnitKind,
    digest: Digest32,
}

impl UnitId {
    /// Constructs the exact `unit/v1/sha256/<kind>/<digest>` identifier.
    ///
    /// Normative source: SPEC §2.2 and §4.
    pub fn from_parts(kind: UnitKind, digest: Digest32) -> Self {
        Self { kind, digest }
    }

    /// Returns the unit kind bound into this identifier.
    ///
    /// Normative source: SPEC §4.
    pub fn kind(&self) -> UnitKind {
        self.kind
    }

    /// Returns the SHA-256 digest bound into this identifier.
    ///
    /// Normative source: SPEC §4.
    pub fn digest(&self) -> Digest32 {
        self.digest
    }
}

impl fmt::Display for UnitId {
    /// Renders the exact versioned unit identifier from SPEC §2.2.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}{}/{}",
            UNIT_ID_PREFIX,
            self.kind.as_str(),
            self.digest
        )
    }
}

impl FromStr for UnitId {
    type Err = Error;

    /// Parses and validates the exact versioned unit identifier grammar.
    ///
    /// Normative source: SPEC §2.2 and §4.
    fn from_str(value: &str) -> Result<Self> {
        let remainder = value
            .strip_prefix(UNIT_ID_PREFIX)
            .ok_or_else(|| Error::field("unit id", "wrong versioned prefix"))?;
        let (kind, digest) = remainder
            .split_once('/')
            .ok_or_else(|| Error::field("unit id", "missing kind separator"))?;
        Ok(Self::from_parts(kind.parse()?, digest.parse()?))
    }
}

/// One extracted byte string together with its kind-bound identifier.
///
/// Normative source: SPEC §3 and §4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JudgmentUnit {
    kind: UnitKind,
    bytes: Vec<u8>,
    id: UnitId,
}

impl JudgmentUnit {
    /// Creates a `file` unit from exact blob contents, including the empty blob.
    ///
    /// Normative source: SPEC §3 and §3.3.
    pub fn file(bytes: impl Into<Vec<u8>>) -> Self {
        Self::from_extracted(UnitKind::File, bytes.into())
    }

    /// Creates a `path` unit after validating its root-relative byte grammar.
    ///
    /// Normative source: SPEC §3.0.
    pub fn path(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        validate_path(&bytes)?;
        Ok(Self::from_extracted(UnitKind::Path, bytes))
    }

    /// Creates a `ref` unit after validating the closed ref grammar.
    ///
    /// Normative source: SPEC §3.3.
    pub fn ref_name(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        validate_ref(&bytes)?;
        Ok(Self::from_extracted(UnitKind::Ref, bytes))
    }

    /// Returns this unit's closed kind.
    ///
    /// Normative source: SPEC §3.
    pub fn kind(&self) -> UnitKind {
        self.kind
    }

    /// Returns the exact extracted bytes that are the judgment subject.
    ///
    /// Normative source: SPEC §3.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the kind-bound unit identifier.
    ///
    /// Normative source: SPEC §4.
    pub fn id(&self) -> &UnitId {
        &self.id
    }

    /// Returns the SHA-256 of the exact extracted bytes.
    ///
    /// Normative source: SPEC §4.
    pub fn digest(&self) -> Digest32 {
        self.id.digest()
    }

    /// Binds a validated extracted byte string to its kind and digest.
    ///
    /// Normative source: SPEC §4.
    fn from_extracted(kind: UnitKind, bytes: Vec<u8>) -> Self {
        let digest = Digest32::from_bytes(Sha256::digest(&bytes).into());
        Self {
            kind,
            bytes,
            id: UnitId::from_parts(kind, digest),
        }
    }
}

/// Validates one complete canonical Git object and extracts zero or one unit.
///
/// `object` includes the exact `<type> <length>\0<body>` framing. Trees produce
/// no unit; their body is still validated before an empty result is returned.
///
/// Normative source: SPEC §3.0–§3.3 and §4.
pub fn extract_git_object(object_format: ObjectFormat, object: &[u8]) -> Result<Vec<JudgmentUnit>> {
    let (kind, body) = parse_object_frame(object)?;
    match kind {
        ObjectKind::Blob => Ok(vec![JudgmentUnit::file(body)]),
        ObjectKind::Tree => {
            validate_tree(object_format, body)?;
            Ok(Vec::new())
        }
        ObjectKind::Commit => Ok(vec![JudgmentUnit::from_extracted(
            UnitKind::Commit,
            extract_commit(object_format, body)?,
        )]),
        ObjectKind::Tag => Ok(vec![JudgmentUnit::from_extracted(
            UnitKind::Tag,
            extract_tag(object_format, body)?,
        )]),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObjectKind {
    Blob,
    Tree,
    Commit,
    Tag,
}

/// Parses and verifies the canonical Git object frame before body inspection.
///
/// Normative source: SPEC §3.3.
fn parse_object_frame(object: &[u8]) -> Result<(ObjectKind, &[u8])> {
    let nul = object
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| invalid_object("missing object-header terminator"))?;
    let header = &object[..nul];
    let (kind, length) = split_once_byte(header, b' ')
        .ok_or_else(|| invalid_object("object header must contain type and length"))?;
    if kind.is_empty() || length.is_empty() || length.contains(&b' ') {
        return Err(invalid_object("object header has invalid fields"));
    }
    let kind = match kind {
        b"blob" => ObjectKind::Blob,
        b"tree" => ObjectKind::Tree,
        b"commit" => ObjectKind::Commit,
        b"tag" => ObjectKind::Tag,
        _ => return Err(invalid_object("unknown object type")),
    };
    let declared = parse_canonical_decimal(length, "object length")?;
    let body = &object[nul + 1..];
    if declared != body.len() {
        return Err(invalid_object("declared object length does not match body"));
    }
    Ok((kind, body))
}

/// Extracts the identity and message fields from a validated commit body.
///
/// Normative source: SPEC §3.1 and §3.3.
fn extract_commit(object_format: ObjectFormat, body: &[u8]) -> Result<Vec<u8>> {
    let (headers, message) = parse_header_block(body)?;
    let mut index = 0;

    let tree = required_header(&headers, index, b"tree", "commit tree")?;
    require_single_line(tree, "commit tree")?;
    validate_hex_oid(tree.value, object_format, "commit tree")?;
    index += 1;

    while headers
        .get(index)
        .is_some_and(|header| header.name == b"parent")
    {
        let parent = &headers[index];
        require_single_line(parent, "commit parent")?;
        validate_hex_oid(parent.value, object_format, "commit parent")?;
        index += 1;
    }

    let author = required_header(&headers, index, b"author", "commit author")?;
    require_single_line(author, "commit author")?;
    let author_identity = extract_identity(author.value, "commit author")?;
    index += 1;

    let committer = required_header(&headers, index, b"committer", "commit committer")?;
    require_single_line(committer, "commit committer")?;
    let committer_identity = extract_identity(committer.value, "commit committer")?;
    index += 1;

    if headers[index..]
        .iter()
        .any(|header| matches!(header.name, b"tree" | b"parent" | b"author" | b"committer"))
    {
        return Err(invalid_object(
            "commit repeats or reorders a required header",
        ));
    }

    let mut extracted = Vec::with_capacity(
        b"author \ncommitter \n\n".len()
            + author_identity.len()
            + committer_identity.len()
            + message.len(),
    );
    extracted.extend_from_slice(b"author ");
    extracted.extend_from_slice(author_identity);
    extracted.push(b'\n');
    extracted.extend_from_slice(b"committer ");
    extracted.extend_from_slice(committer_identity);
    extracted.extend_from_slice(b"\n\n");
    extracted.extend_from_slice(message);
    Ok(extracted)
}

/// Extracts the tag name, tagger identity, and message from a validated tag.
///
/// Normative source: SPEC §3.2 and §3.3.
fn extract_tag(object_format: ObjectFormat, body: &[u8]) -> Result<Vec<u8>> {
    let (headers, message) = parse_header_block(body)?;
    let object = required_header(&headers, 0, b"object", "tag object")?;
    require_single_line(object, "tag object")?;
    validate_hex_oid(object.value, object_format, "tag object")?;

    let target_type = required_header(&headers, 1, b"type", "tag type")?;
    require_single_line(target_type, "tag type")?;
    if !matches!(target_type.value, b"blob" | b"tree" | b"commit" | b"tag") {
        return Err(invalid_object("tag target type is not a Git object type"));
    }

    let tag = required_header(&headers, 2, b"tag", "tag name")?;
    require_single_line(tag, "tag name")?;
    if tag.value.is_empty() {
        return Err(invalid_object("tag name is empty"));
    }

    let tagger = required_header(&headers, 3, b"tagger", "tag tagger")?;
    require_single_line(tagger, "tag tagger")?;
    let tagger_identity = extract_identity(tagger.value, "tag tagger")?;

    if headers[4..]
        .iter()
        .any(|header| matches!(header.name, b"object" | b"type" | b"tag" | b"tagger"))
    {
        return Err(invalid_object("tag repeats or reorders a required header"));
    }

    let mut extracted = Vec::with_capacity(
        b"tag \ntagger \n\n".len() + tag.value.len() + tagger_identity.len() + message.len(),
    );
    extracted.extend_from_slice(b"tag ");
    extracted.extend_from_slice(tag.value);
    extracted.push(b'\n');
    extracted.extend_from_slice(b"tagger ");
    extracted.extend_from_slice(tagger_identity);
    extracted.extend_from_slice(b"\n\n");
    extracted.extend_from_slice(message);
    Ok(extracted)
}

#[derive(Debug)]
struct Header<'a> {
    name: &'a [u8],
    value: &'a [u8],
    has_continuation: bool,
}

/// Parses the Git header block while retaining message bytes unchanged.
///
/// Normative source: SPEC §3.1–§3.3.
fn parse_header_block(body: &[u8]) -> Result<(Vec<Header<'_>>, &[u8])> {
    let separator = body
        .windows(2)
        .position(|window| window == b"\n\n")
        .ok_or_else(|| invalid_object("missing header/message separator"))?;
    let header_bytes = &body[..separator];
    if header_bytes.is_empty() {
        return Err(invalid_object("object header block is empty"));
    }

    let mut headers: Vec<Header<'_>> = Vec::new();
    for line in header_bytes.split(|byte| *byte == b'\n') {
        if line.first() == Some(&b' ') {
            if line.contains(&0) {
                return Err(invalid_object("header continuation contains NUL"));
            }
            let previous = headers
                .last_mut()
                .ok_or_else(|| invalid_object("header continuation has no field"))?;
            previous.has_continuation = true;
            continue;
        }
        let (name, value) = split_once_byte(line, b' ')
            .ok_or_else(|| invalid_object("header line has no value separator"))?;
        if name.is_empty()
            || name
                .iter()
                .any(|byte| *byte == 0 || byte.is_ascii_control() || *byte == b' ')
        {
            return Err(invalid_object("header name is malformed"));
        }
        if value.contains(&0) {
            return Err(invalid_object("header value contains NUL"));
        }
        headers.push(Header {
            name,
            value,
            has_continuation: false,
        });
    }
    Ok((headers, &body[separator + 2..]))
}

/// Returns one required header at its required position.
///
/// Normative source: SPEC §3.3.
fn required_header<'a>(
    headers: &'a [Header<'a>],
    index: usize,
    name: &[u8],
    label: &'static str,
) -> Result<&'a Header<'a>> {
    let header = headers
        .get(index)
        .ok_or_else(|| Error::field(label, "required header is missing"))?;
    if header.name != name {
        return Err(Error::field(label, "required header is out of order"));
    }
    Ok(header)
}

/// Rejects continuation lines on required single-line Git headers.
///
/// Normative source: SPEC §3.1–§3.3.
fn require_single_line(header: &Header<'_>, label: &'static str) -> Result<()> {
    if header.has_continuation {
        return Err(Error::field(label, "required header must be one line"));
    }
    Ok(())
}

/// Removes the validated timestamp and zone suffix from a Git identity.
///
/// Normative source: SPEC §3.1–§3.3.
fn extract_identity<'a>(value: &'a [u8], label: &'static str) -> Result<&'a [u8]> {
    let zone_separator = value
        .iter()
        .rposition(|byte| *byte == b' ')
        .ok_or_else(|| Error::field(label, "missing timezone"))?;
    let zone = &value[zone_separator + 1..];
    validate_timezone(zone, label)?;

    let before_zone = &value[..zone_separator];
    let time_separator = before_zone
        .iter()
        .rposition(|byte| *byte == b' ')
        .ok_or_else(|| Error::field(label, "missing timestamp"))?;
    let timestamp = &before_zone[time_separator + 1..];
    validate_git_timestamp(timestamp, label)?;

    let identity = &before_zone[..time_separator];
    let email_start = identity
        .iter()
        .position(|byte| *byte == b'<')
        .ok_or_else(|| Error::field(label, "identity is missing email delimiters"))?;
    if email_start == 0
        || identity[email_start - 1] != b' '
        || identity[..email_start - 1].contains(&b'>')
    {
        return Err(Error::field(label, "identity name has invalid grammar"));
    }
    let email = &identity[email_start + 1..];
    let email_end = email
        .iter()
        .position(|byte| *byte == b'>')
        .ok_or_else(|| Error::field(label, "identity is missing email terminator"))?;
    if email[..email_end].contains(&b'<') || email_end + 1 != email.len() {
        return Err(Error::field(label, "identity email has invalid grammar"));
    }
    Ok(identity)
}

/// Validates Git's signed, non-zero-padded decimal identity timestamp.
///
/// Normative source: SPEC §3.3.
fn validate_git_timestamp(value: &[u8], label: &'static str) -> Result<()> {
    let digits = match value.first() {
        Some(b'+' | b'-') => &value[1..],
        _ => value,
    };
    if digits.is_empty()
        || !digits.iter().all(u8::is_ascii_digit)
        || (digits.len() > 1 && digits[0] == b'0')
    {
        return Err(Error::field(label, "timestamp has invalid grammar"));
    }
    Ok(())
}

/// Validates Git's signed four-digit timezone suffix.
///
/// Normative source: SPEC §3.3.
fn validate_timezone(value: &[u8], label: &'static str) -> Result<()> {
    if value.len() != 5
        || !matches!(value[0], b'+' | b'-')
        || !value[1..].iter().all(u8::is_ascii_digit)
    {
        return Err(Error::field(label, "timezone has invalid grammar"));
    }
    Ok(())
}

/// Validates canonical tree modes, entries, OID widths, and sort order.
///
/// Normative source: SPEC §3.0 and §3.3.
fn validate_tree(object_format: ObjectFormat, body: &[u8]) -> Result<()> {
    let mut cursor = 0;
    let mut previous: Option<(Vec<u8>, Vec<u8>)> = None;
    while cursor < body.len() {
        let mode_end = body[cursor..]
            .iter()
            .position(|byte| *byte == b' ')
            .map(|offset| cursor + offset)
            .ok_or_else(|| invalid_object("tree entry is missing mode separator"))?;
        let mode = &body[cursor..mode_end];
        let is_tree = match mode {
            b"40000" => true,
            b"100644" | b"100755" | b"120000" | b"160000" => false,
            _ => return Err(invalid_object("tree entry has noncanonical mode")),
        };

        let name_start = mode_end + 1;
        let name_end = body[name_start..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| name_start + offset)
            .ok_or_else(|| invalid_object("tree entry is missing name terminator"))?;
        let name = &body[name_start..name_end];
        if !is_valid_path_component(name) {
            return Err(invalid_object("tree entry name is malformed"));
        }

        let oid_start = name_end + 1;
        let oid_end = oid_start
            .checked_add(object_format.oid_bytes())
            .ok_or_else(|| invalid_object("tree entry length overflow"))?;
        if oid_end > body.len() {
            return Err(invalid_object("tree entry object ID is truncated"));
        }

        let mut sort_key = name.to_vec();
        if is_tree {
            sort_key.push(b'/');
        }
        if let Some((previous_name, previous_key)) = &previous {
            if previous_name.as_slice() == name {
                return Err(invalid_object("tree contains a duplicate name"));
            }
            if previous_key.as_slice() >= sort_key.as_slice() {
                return Err(invalid_object("tree entries are not strictly sorted"));
            }
        }
        previous = Some((name.to_vec(), sort_key));
        cursor = oid_end;
    }
    Ok(())
}

/// Validates a textual OID against the selected repository object format.
///
/// Normative source: SPEC §2.3 and §3.3.
fn validate_hex_oid(value: &[u8], object_format: ObjectFormat, label: &'static str) -> Result<()> {
    if value.len() != object_format.oid_hex_bytes()
        || !value
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(Error::field(
            label,
            "object ID has invalid width or spelling",
        ));
    }
    Ok(())
}

/// Validates one root-relative path unit.
///
/// Normative source: SPEC §3.0.
fn validate_path(path: &[u8]) -> Result<()> {
    if path.is_empty()
        || path
            .split(|byte| *byte == b'/')
            .any(|component| !is_valid_path_component(component))
    {
        return Err(Error::field("path", "invalid root-relative path"));
    }
    Ok(())
}

/// Validates the closed tree/path component grammar before unit extraction.
///
/// Normative source: SPEC §3.0 and §3.3.
fn is_valid_path_component(component: &[u8]) -> bool {
    !component.is_empty()
        && component != b"."
        && component != b".."
        && !component.contains(&0)
        && !component.contains(&b'/')
}

/// Validates the closed Git ref grammar used for `ref` units.
///
/// Normative source: SPEC §3.3.
fn validate_ref(reference: &[u8]) -> Result<()> {
    if !reference.starts_with(b"refs/")
        || reference.windows(2).any(|window| window == b"..")
        || reference.windows(2).any(|window| window == b"@{")
        || reference.iter().any(|byte| {
            byte.is_ascii_control()
                || *byte == b' '
                || matches!(*byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
    {
        return Err(Error::field("ref", "invalid ref name"));
    }
    for component in reference.split(|byte| *byte == b'/') {
        if component.is_empty()
            || component.first() == Some(&b'.')
            || component.last() == Some(&b'.')
            || component.ends_with(b".lock")
        {
            return Err(Error::field("ref", "invalid ref component"));
        }
    }
    Ok(())
}

/// Parses an unsigned canonical decimal length without allocating.
///
/// Normative source: SPEC §3.3.
fn parse_canonical_decimal(value: &[u8], field: &'static str) -> Result<usize> {
    if value.is_empty()
        || !value.iter().all(u8::is_ascii_digit)
        || (value.len() > 1 && value[0] == b'0')
    {
        return Err(Error::field(field, "noncanonical decimal"));
    }
    value.iter().try_fold(0_usize, |number, digit| {
        number
            .checked_mul(10)
            .and_then(|number| number.checked_add(usize::from(*digit - b'0')))
            .ok_or_else(|| Error::field(field, "decimal value overflows usize"))
    })
}

/// Splits a byte string at its first delimiter byte.
///
/// Normative source: SPEC §3.3 parsing mechanics.
fn split_once_byte(value: &[u8], delimiter: u8) -> Option<(&[u8], &[u8])> {
    let index = value.iter().position(|byte| *byte == delimiter)?;
    Some((&value[..index], &value[index + 1..]))
}

/// Constructs one typed fail-closed malformed-object error.
///
/// Normative source: SPEC §3.3 and §15.
fn invalid_object(reason: impl Into<String>) -> Error {
    Error::field("git object", reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds exact Git object framing for SPEC §3.3 tests.
    fn frame(kind: &str, body: &[u8]) -> Vec<u8> {
        let mut object = format!("{kind} {}\0", body.len()).into_bytes();
        object.extend_from_slice(body);
        object
    }

    /// SPEC §3.3 rejects unknown types and noncanonical or mismatched lengths.
    #[test]
    fn object_frame_is_closed_and_exact() {
        assert!(extract_git_object(ObjectFormat::Sha1, b"note 0\0").is_err());
        assert!(extract_git_object(ObjectFormat::Sha1, b"blob 00\0").is_err());
        assert!(extract_git_object(ObjectFormat::Sha1, b"blob 1\0").is_err());
        assert!(extract_git_object(ObjectFormat::Sha1, b"blob 0").is_err());
        assert!(extract_git_object(ObjectFormat::Sha1, b"blob 0\0").is_ok());
    }

    /// SPEC §3.3 requires every discarded additional header to remain well formed.
    #[test]
    fn additional_header_continuations_reject_nul() {
        let body = b"tree 0000000000000000000000000000000000000000\n\
author A <a@x> 1 +0000\n\
committer C <c@x> 2 +0000\n\
extra value\n\
\x20contains\0nul\n\
\n\
message\n";
        assert!(extract_git_object(ObjectFormat::Sha1, &frame("commit", body)).is_err());
    }

    /// SPEC §3.3 validates both SHA-1 and SHA-256 tree-entry OID widths.
    #[test]
    fn tree_object_format_controls_binary_oid_width() {
        for (format, oid_length) in [(ObjectFormat::Sha1, 20), (ObjectFormat::Sha256, 32)] {
            let mut body = b"100644 file\0".to_vec();
            body.extend(std::iter::repeat_n(1, oid_length));
            assert!(extract_git_object(format, &frame("tree", &body)).is_ok());
        }
    }

    /// SPEC §3.3 rejects noncanonical modes, duplicate names, and sort inversions.
    #[test]
    fn tree_entries_are_canonical_and_strictly_sorted() {
        let oid = [1_u8; 20];
        let mut wrong_mode = b"100664 file\0".to_vec();
        wrong_mode.extend_from_slice(&oid);
        assert!(extract_git_object(ObjectFormat::Sha1, &frame("tree", &wrong_mode)).is_err());

        let mut duplicate = b"100644 same\0".to_vec();
        duplicate.extend_from_slice(&oid);
        duplicate.extend_from_slice(b"100755 same\0");
        duplicate.extend_from_slice(&oid);
        assert!(extract_git_object(ObjectFormat::Sha1, &frame("tree", &duplicate)).is_err());

        let mut reversed = b"100644 z\0".to_vec();
        reversed.extend_from_slice(&oid);
        reversed.extend_from_slice(b"100644 a\0");
        reversed.extend_from_slice(&oid);
        assert!(extract_git_object(ObjectFormat::Sha1, &frame("tree", &reversed)).is_err());

        for malformed_name in [b".".as_slice(), b".."] {
            let mut malformed = b"100644 ".to_vec();
            malformed.extend_from_slice(malformed_name);
            malformed.push(0);
            malformed.extend_from_slice(&oid);
            assert!(extract_git_object(ObjectFormat::Sha1, &frame("tree", &malformed)).is_err());
        }
    }

    /// SPEC §2.2 and §4 bind equal bytes to different IDs when kinds differ.
    #[test]
    fn unit_kind_is_part_of_the_identifier() {
        let file = JudgmentUnit::file(b"same".to_vec());
        let path = JudgmentUnit::path(b"same".to_vec()).expect("valid path");
        assert_eq!(file.digest(), path.digest());
        assert_ne!(file.id(), path.id());
        assert_ne!(file.id().to_string(), path.id().to_string());
    }

    /// SPEC §2.2 and §4 fix the complete versioned unit-ID grammar.
    #[test]
    fn unit_identifier_round_trips_exact_grammar() {
        let unit = JudgmentUnit::file(Vec::new());
        let rendered = "unit/v1/sha256/file/\
                        e3b0c44298fc1c149afbf4c8996fb924\
                        27ae41e4649b934ca495991b7852b855";
        assert_eq!(unit.id().to_string(), rendered);
        assert_eq!(
            rendered.parse::<UnitId>().expect("valid unit ID"),
            *unit.id()
        );
        assert!(rendered.replace("file", "state").parse::<UnitId>().is_err());
        assert!(rendered.to_ascii_uppercase().parse::<UnitId>().is_err());
    }

    /// SPEC §3.3 applies the exact closed ref-name grammar.
    #[test]
    fn ref_name_grammar_is_closed() {
        assert!(JudgmentUnit::ref_name(b"refs/heads/main".to_vec()).is_ok());
        for invalid in [
            b"main".as_slice(),
            b"refs//main",
            b"refs/.hidden",
            b"refs/heads/main.lock",
            b"refs/heads/a..b",
            b"refs/heads/a@{b",
            b"refs/heads/a b",
        ] {
            assert!(JudgmentUnit::ref_name(invalid.to_vec()).is_err());
        }
    }

    /// SPEC §3.0 and §3.3 reject malformed components through the public path API.
    #[test]
    fn path_components_reject_dot_dotdot_empty_nul_and_separator() {
        assert!(JudgmentUnit::path(b"valid/name".to_vec()).is_ok());
        for invalid in [
            b".".as_slice(),
            b"..",
            b"a/./b",
            b"a/../b",
            b"a//b",
            b"a\0b",
            b"/a",
            b"a/",
        ] {
            assert!(JudgmentUnit::path(invalid.to_vec()).is_err());
        }
    }

    /// SPEC §3.1–§3.3 require Git's exact `name <email> time zone` framing.
    #[test]
    fn identity_name_and_email_delimiters_are_closed() {
        let valid = frame(
            "commit",
            b"tree 0000000000000000000000000000000000000000\n\
author Ren\xe9 Dubois <rene@example.com> -1 +0900\n\
committer A <a@x> +2 -0500\n\
\n\
message\n",
        );
        assert!(extract_git_object(ObjectFormat::Sha1, &valid).is_ok());

        for author in [
            b"A a@x 1 +0000".as_slice(),
            b"A<a@x> 1 +0000".as_slice(),
            b"A > <a@x> 1 +0000".as_slice(),
            b"A <a<x> 1 +0000".as_slice(),
            b"A <a@x> trailing 1 +0000".as_slice(),
        ] {
            let mut body = b"tree 0000000000000000000000000000000000000000\nauthor ".to_vec();
            body.extend_from_slice(author);
            body.extend_from_slice(b"\ncommitter A <a@x> 1 +0000\n\nmessage\n");
            assert!(extract_git_object(ObjectFormat::Sha1, &frame("commit", &body)).is_err());
        }
    }
}
