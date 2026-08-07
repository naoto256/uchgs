use std::{collections::HashSet, fmt};

use serde::{
    Serialize,
    de::{DeserializeOwned, DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor},
};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// Semantic validation performed after exact canonical JSON decoding.
pub trait WireValidate {
    fn validate(&self) -> Result<()>;
}

/// A typed wire value retained together with the exact bytes that name it.
#[derive(Debug, Clone)]
pub struct ExactJson<T> {
    value: T,
    bytes: Vec<u8>,
    sha256: [u8; 32],
}

impl<T> ExactJson<T>
where
    T: DeserializeOwned + Serialize + WireValidate,
{
    pub fn parse(bytes: &[u8], maximum: usize) -> Result<Self> {
        check_bound(bytes, maximum)?;
        reject_duplicate_keys(bytes)?;

        let generic: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|error| Error::InvalidJson(error.to_string()))?;
        let canonical = serde_json_canonicalizer::to_vec(&generic)
            .map_err(|error| Error::InvalidJson(error.to_string()))?;
        // Signature preimages and content-addressed IDs bind these exact input
        // bytes, so input that merely re-serializes to canonical form is not
        // interchangeable with input already in it. Reject non-canonical bytes
        // rather than normalizing on the caller's behalf, or two distinct inputs
        // could map to one logical value and one digest.
        if canonical != bytes {
            return Err(Error::NonCanonicalJson);
        }

        let value: T = serde_json::from_value(generic)
            .map_err(|error| Error::InvalidJson(error.to_string()))?;
        value.validate()?;
        Ok(Self::from_parts(value, canonical))
    }

    pub fn encode(value: T, maximum: usize) -> Result<Self> {
        value.validate()?;
        let bytes = serde_json_canonicalizer::to_vec(&value)
            .map_err(|error| Error::InvalidJson(error.to_string()))?;
        check_bound(&bytes, maximum)?;
        Ok(Self::from_parts(value, bytes))
    }

    fn from_parts(value: T, bytes: Vec<u8>) -> Self {
        let sha256 = Sha256::digest(&bytes).into();
        Self {
            value,
            bytes,
            sha256,
        }
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    pub fn sha256_hex(&self) -> String {
        hex::encode(self.sha256)
    }
}

fn reject_duplicate_keys(bytes: &[u8]) -> Result<()> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    RejectDuplicateKeys
        .deserialize(&mut deserializer)
        .map_err(|error| Error::InvalidJson(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| Error::InvalidJson(error.to_string()))
}

struct RejectDuplicateKeys;

impl<'de> DeserializeSeed<'de> for RejectDuplicateKeys {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(RejectDuplicateKeysVisitor)
    }
}

struct RejectDuplicateKeysVisitor;

impl<'de> Visitor<'de> for RejectDuplicateKeysVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(A::Error::custom(format!("duplicate object key: {key}")));
            }
            map.next_value_seed(RejectDuplicateKeys)?;
        }
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(RejectDuplicateKeys)?.is_some() {}
        Ok(())
    }

    fn visit_bool<E>(self, _value: bool) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_none<E>(self) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RejectDuplicateKeys.deserialize(deserializer)
    }

    fn visit_unit<E>(self) -> std::result::Result<(), E> {
        Ok(())
    }
}

fn check_bound(bytes: &[u8], maximum: usize) -> Result<()> {
    if bytes.is_empty() {
        return Err(Error::EmptyInput);
    }
    if bytes.len() > maximum {
        return Err(Error::EncodedLengthExceeded {
            maximum,
            actual: bytes.len(),
        });
    }
    Ok(())
}
