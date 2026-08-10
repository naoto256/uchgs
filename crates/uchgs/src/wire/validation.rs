use crate::{Error, Result};
use unicode_normalization::UnicodeNormalization as _;

pub(crate) fn project(value: &str) -> Result<()> {
    let len = value.len();
    if !(1..=128).contains(&len)
        || value == "*"
        || value.chars().any(|ch| {
            ch.is_whitespace()
                || ch == '\0'
                || (ch as u32) <= 0x1f
                || ch == '\u{7f}'
                || ('\u{80}'..='\u{9f}').contains(&ch)
        })
    {
        return Err(Error::field(
            "project",
            "violates the closed project grammar",
        ));
    }
    if !value.nfc().eq(value.chars()) {
        return Err(Error::field("project", "must already be NFC"));
    }
    Ok(())
}

pub(crate) fn scope(value: &str) -> Result<()> {
    if !(1..=64).contains(&value.len())
        || !value.is_ascii()
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && b"._-".contains(&byte))
        })
    {
        return Err(Error::field("scope", "violates the closed scope grammar"));
    }
    Ok(())
}

pub(crate) fn principal(value: &str) -> Result<()> {
    if !(1..=128).contains(&value.len())
        || value.chars().any(|ch| {
            ch == '\0'
                || (ch as u32) <= 0x1f
                || ch == '\u{7f}'
                || ('\u{80}'..='\u{9f}').contains(&ch)
        })
    {
        return Err(Error::field(
            "principal",
            "violates the closed principal grammar",
        ));
    }
    Ok(())
}

pub(crate) fn note(value: &str) -> Result<()> {
    if !(1..=65_536).contains(&value.len()) || value.contains('\0') {
        return Err(Error::field(
            "note",
            "must be 1..=65536 UTF-8 bytes without NUL",
        ));
    }
    Ok(())
}

pub(crate) fn timestamp(value: &str, field: &'static str) -> Result<u128> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Error::field(
            field,
            "must be canonical unsigned decimal nanoseconds",
        ));
    }
    value
        .parse()
        .map_err(|_| Error::field(field, "nanoseconds do not fit in u128"))
}

pub(crate) fn lower_hex(value: &str, bytes: usize, field: &'static str) -> Result<Vec<u8>> {
    super::id::decode_lower_hex_exact(value, bytes, field)
}
