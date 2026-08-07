use std::{fmt, ops::Deref, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{Error, Result};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Digest32")
            .field(&self.to_hex())
            .finish()
    }
}

impl fmt::Display for Digest32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl FromStr for Digest32 {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        let decoded = decode_lower_hex_exact(value, 32, "sha256 digest")?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| Error::field("sha256 digest", "must contain 32 bytes"))?;
        Ok(Self(bytes))
    }
}

impl Serialize for Digest32 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest32 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

macro_rules! versioned_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub const PREFIX: &'static str = $prefix;

            pub fn from_digest(digest: Digest32) -> Self {
                Self(format!("{}{}", Self::PREFIX, digest))
            }

            pub fn digest(&self) -> Digest32 {
                self.0[Self::PREFIX.len()..]
                    .parse()
                    .expect("validated versioned identifier")
            }
        }

        impl TryFrom<String> for $name {
            type Error = Error;

            fn try_from(value: String) -> Result<Self> {
                let digest = value
                    .strip_prefix(Self::PREFIX)
                    .ok_or_else(|| Error::field(stringify!($name), "wrong versioned prefix"))?;
                digest.parse::<Digest32>()?;
                Ok(Self(value))
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl Deref for $name {
            type Target = str;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = Error;

            fn from_str(value: &str) -> Result<Self> {
                Self::try_from(value.to_owned())
            }
        }
    };
}

versioned_id!(CredentialId, "credential/v1/sha256/");

pub(crate) fn decode_lower_hex_exact(
    value: &str,
    byte_length: usize,
    field: &'static str,
) -> Result<Vec<u8>> {
    if value.len() != byte_length * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::field(
            field,
            format!("must be exactly {} lower-hex characters", byte_length * 2),
        ));
    }
    hex::decode(value).map_err(|error| Error::field(field, error.to_string()))
}
