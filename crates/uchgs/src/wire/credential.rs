use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

use super::{
    CREDENTIAL_MAX_BYTES, CredentialId, Digest32, ExactJson, WireValidate,
    id::decode_lower_hex_exact,
};

const CREDENTIAL_KIND: &str = "uchgs-public-credential";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PublicCredential {
    SoftwareEd25519(SoftwareEd25519Credential),
    SecureEnclaveP256TouchId(SecureEnclaveP256Credential),
}

impl WireValidate for PublicCredential {
    fn validate(&self) -> Result<()> {
        match self {
            Self::SoftwareEd25519(credential) => credential.validate(),
            Self::SecureEnclaveP256TouchId(credential) => credential.validate(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareEd25519Credential {
    pub kind: String,
    pub public_key_hex: String,
    pub schema: u64,
    #[serde(rename = "type")]
    pub credential_type: String,
}

impl WireValidate for SoftwareEd25519Credential {
    fn validate(&self) -> Result<()> {
        validate_common(self.schema, &self.kind)?;
        if self.credential_type != "software-ed25519" {
            return Err(Error::field(
                "credential.type",
                "must be `software-ed25519`",
            ));
        }
        let bytes: [u8; 32] = decode_lower_hex_exact(&self.public_key_hex, 32, "public_key_hex")?
            .try_into()
            .map_err(|_| Error::field("public_key_hex", "must contain 32 bytes"))?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map_err(|_| Error::field("public_key_hex", "invalid Ed25519 point"))?;
        if key.is_weak() {
            return Err(Error::field(
                "public_key_hex",
                "weak Ed25519 public keys are forbidden",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecureEnclaveP256Credential {
    pub kind: String,
    pub public_key_x963_hex: String,
    pub schema: u64,
    #[serde(rename = "type")]
    pub credential_type: String,
}

impl WireValidate for SecureEnclaveP256Credential {
    fn validate(&self) -> Result<()> {
        validate_common(self.schema, &self.kind)?;
        if self.credential_type != "secure-enclave-p256-touch-id" {
            return Err(Error::field(
                "credential.type",
                "must be `secure-enclave-p256-touch-id`",
            ));
        }
        let key = decode_lower_hex_exact(&self.public_key_x963_hex, 65, "public_key_x963_hex")?;
        if key.first() != Some(&0x04) {
            return Err(Error::field(
                "public_key_x963_hex",
                "must be an uncompressed X9.63 point beginning with 04",
            ));
        }
        p256::PublicKey::from_sec1_bytes(&key)
            .map_err(|_| Error::field("public_key_x963_hex", "invalid P-256 point"))?;
        Ok(())
    }
}

fn validate_common(schema: u64, kind: &str) -> Result<()> {
    if schema != 1 {
        return Err(Error::field("credential.schema", "must be 1"));
    }
    if kind != CREDENTIAL_KIND {
        return Err(Error::field(
            "credential.kind",
            "must be `uchgs-public-credential`",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct PublicCredentialDocument {
    exact: ExactJson<PublicCredential>,
    id: CredentialId,
}

impl PublicCredentialDocument {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Self::from_exact(ExactJson::parse(bytes, CREDENTIAL_MAX_BYTES)?)
    }

    pub fn encode(credential: PublicCredential) -> Result<Self> {
        Self::from_exact(ExactJson::encode(credential, CREDENTIAL_MAX_BYTES)?)
    }

    fn from_exact(exact: ExactJson<PublicCredential>) -> Result<Self> {
        let digest = Digest32::from_bytes(Sha256::digest(exact.bytes()).into());
        let id = CredentialId::from_digest(digest);
        Ok(Self { exact, id })
    }

    pub fn credential(&self) -> &PublicCredential {
        self.exact.value()
    }

    pub fn bytes(&self) -> &[u8] {
        self.exact.bytes()
    }

    pub fn sha256(&self) -> Digest32 {
        Digest32::from_bytes(self.exact.sha256())
    }

    pub fn id(&self) -> &CredentialId {
        &self.id
    }
}
