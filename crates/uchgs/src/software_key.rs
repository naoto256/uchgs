//! Native software-key custody envelope.
//!
//! Normative source: SPEC §8.4–§8.6.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    KeyInit as _, XChaCha20Poly1305, XNonce,
    aead::{Aead as _, Payload},
};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    Error, Result,
    wire::{
        ApprovalMaterial, CREDENTIAL_MAX_BYTES, ExactJson, PublicCredential,
        PublicCredentialDocument, SoftwareEd25519Credential, WireValidate,
    },
};

pub(crate) const ENVELOPE_MAX_BYTES: usize = CREDENTIAL_MAX_BYTES;
const ARGON2_M_KIB: u32 = 19_456;
const ARGON2_T: u32 = 2;
const ARGON2_P: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Argon2Parameters {
    m_kib: u32,
    p: u32,
    t: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Argon2Container {
    argon2id: Argon2Parameters,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SoftwareKeyEnvelope {
    algorithm: String,
    ciphertext: String,
    credential: PublicCredential,
    kdf: Argon2Container,
    kind: String,
    nonce: String,
    purpose: String,
    salt: String,
    schema: u64,
}

#[derive(Serialize)]
struct EnvelopeAad<'a> {
    algorithm: &'a str,
    credential: &'a PublicCredential,
    kdf: &'a Argon2Container,
    kind: &'a str,
    nonce: &'a str,
    purpose: &'a str,
    salt: &'a str,
    schema: u64,
}

impl SoftwareKeyEnvelope {
    fn aad(&self) -> EnvelopeAad<'_> {
        EnvelopeAad {
            algorithm: &self.algorithm,
            credential: &self.credential,
            kdf: &self.kdf,
            kind: &self.kind,
            nonce: &self.nonce,
            purpose: &self.purpose,
            salt: &self.salt,
            schema: self.schema,
        }
    }
}

impl WireValidate for SoftwareKeyEnvelope {
    fn validate(&self) -> Result<()> {
        if self.schema != 1
            || self.kind != "software-key-envelope"
            || self.purpose != "approval"
            || self.algorithm != "xchacha20poly1305-argon2id-v1"
        {
            return Err(Error::field(
                "software-key-envelope",
                "schema/kind/purpose/algorithm are invalid",
            ));
        }
        if self.kdf.argon2id
            != (Argon2Parameters {
                m_kib: ARGON2_M_KIB,
                p: ARGON2_P,
                t: ARGON2_T,
            })
        {
            return Err(Error::field("kdf", "unsupported Argon2id parameters"));
        }
        let PublicCredential::SoftwareEd25519(_) = &self.credential else {
            return Err(Error::field(
                "credential",
                "software envelope requires software-ed25519",
            ));
        };
        PublicCredentialDocument::encode(self.credential.clone())?;
        decode_base64_exact::<16>(&self.salt, "salt")?;
        decode_base64_exact::<24>(&self.nonce, "nonce")?;
        let ciphertext = decode_base64(&self.ciphertext, "ciphertext")?;
        if ciphertext.len() != 48 {
            return Err(Error::field(
                "ciphertext",
                "must contain a 32-byte seed and 16-byte tag",
            ));
        }
        Ok(())
    }
}

/// Exact canonical native envelope and its public credential.
#[derive(Debug, Clone)]
pub struct SoftwareKeyEnvelopeDocument {
    exact: ExactJson<SoftwareKeyEnvelope>,
    credential: PublicCredentialDocument,
}

impl SoftwareKeyEnvelopeDocument {
    /// Parses only the exact closed canonical §8.6 envelope.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let exact: ExactJson<SoftwareKeyEnvelope> = ExactJson::parse(bytes, ENVELOPE_MAX_BYTES)?;
        let credential = PublicCredentialDocument::encode(exact.value().credential.clone())?;
        Ok(Self { exact, credential })
    }

    /// Generates an encrypted Ed25519 seed using only §8.6 parameters.
    pub(crate) fn generate(passphrase: &str) -> Result<Self> {
        require_passphrase(passphrase)?;
        let mut seed = Zeroizing::new([0_u8; 32]);
        let mut salt = [0_u8; 16];
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut *seed).map_err(|error| Error::field("seed", error.to_string()))?;
        getrandom::fill(&mut salt).map_err(|error| Error::field("salt", error.to_string()))?;
        getrandom::fill(&mut nonce).map_err(|error| Error::field("nonce", error.to_string()))?;
        let signing_key = SigningKey::from_bytes(&seed);
        let credential = PublicCredential::SoftwareEd25519(SoftwareEd25519Credential {
            kind: "uchgs-public-credential".to_owned(),
            public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
            schema: 1,
            credential_type: "software-ed25519".to_owned(),
        });
        let mut envelope = SoftwareKeyEnvelope {
            algorithm: "xchacha20poly1305-argon2id-v1".to_owned(),
            ciphertext: String::new(),
            credential,
            kdf: Argon2Container {
                argon2id: Argon2Parameters {
                    m_kib: ARGON2_M_KIB,
                    p: ARGON2_P,
                    t: ARGON2_T,
                },
            },
            kind: "software-key-envelope".to_owned(),
            nonce: STANDARD.encode(nonce),
            purpose: "approval".to_owned(),
            salt: STANDARD.encode(salt),
            schema: 1,
        };
        let aad = canonical_aad(&envelope)?;
        let mut key = derive_key(passphrase, &salt, &envelope.kdf.argon2id)?;
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let nonce_value = XNonce::from(nonce);
        let ciphertext = cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: &*seed,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                Error::UnauthorizedApproval("software key encryption failed".to_owned())
            })?;
        key.zeroize();
        envelope.ciphertext = STANDARD.encode(ciphertext);
        let exact = ExactJson::encode(envelope, ENVELOPE_MAX_BYTES)?;
        let credential = PublicCredentialDocument::encode(exact.value().credential.clone())?;
        Ok(Self { exact, credential })
    }

    pub fn bytes(&self) -> &[u8] {
        self.exact.bytes()
    }

    pub fn credential(&self) -> &PublicCredentialDocument {
        &self.credential
    }

    /// Produces exact direct approval material and zeroizes decrypted seed bytes.
    pub(crate) fn sign_approval_message(
        &self,
        passphrase: &str,
        message: &[u8],
    ) -> Result<ApprovalMaterial> {
        let seed = self.decrypt_seed(passphrase)?;
        let signature = SigningKey::from_bytes(&seed).sign(message);
        Ok(ApprovalMaterial::Ed25519 {
            signature: hex::encode(signature.to_bytes()),
        })
    }

    pub(crate) fn possession_material(
        &self,
        passphrase: &str,
        message: &[u8],
    ) -> Result<ApprovalMaterial> {
        let material = self.sign_approval_message(passphrase, message)?;
        let ApprovalMaterial::Ed25519 { signature } = &material else {
            unreachable!("software signer produces Ed25519 material")
        };
        let signature: [u8; 64] = hex::decode(signature)
            .map_err(|error| Error::field("signature", error.to_string()))?
            .try_into()
            .map_err(|_| Error::field("signature", "must contain 64 bytes"))?;
        let PublicCredential::SoftwareEd25519(credential) = self.credential.credential() else {
            return Err(Error::field("credential", "must be software-ed25519"));
        };
        let key: [u8; 32] = hex::decode(&credential.public_key_hex)
            .map_err(|error| Error::field("public_key_hex", error.to_string()))?
            .try_into()
            .map_err(|_| Error::field("public_key_hex", "must contain 32 bytes"))?;
        ed25519_dalek::VerifyingKey::from_bytes(&key)
            .map_err(|_| Error::UnauthorizedApproval("invalid Ed25519 key".to_owned()))?
            .verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature))
            .map_err(|_| Error::UnauthorizedApproval("possession proof failed".to_owned()))?;
        Ok(material)
    }

    fn decrypt_seed(&self, passphrase: &str) -> Result<Zeroizing<[u8; 32]>> {
        require_passphrase(passphrase)?;
        let envelope = self.exact.value();
        let salt = decode_base64_exact::<16>(&envelope.salt, "salt")?;
        let nonce = decode_base64_exact::<24>(&envelope.nonce, "nonce")?;
        let ciphertext = decode_base64(&envelope.ciphertext, "ciphertext")?;
        let aad = canonical_aad(envelope)?;
        let mut key = derive_key(passphrase, &salt, &envelope.kdf.argon2id)?;
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let nonce_value = XNonce::from(nonce);
        let plaintext = cipher
            .decrypt(
                &nonce_value,
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                Error::UnauthorizedApproval("software key decryption failed".to_owned())
            })?;
        key.zeroize();
        let plaintext = Zeroizing::new(plaintext);
        let seed = Zeroizing::new(
            plaintext
                .as_slice()
                .try_into()
                .map_err(|_| Error::field("ciphertext", "decrypted seed must be 32 bytes"))?,
        );
        let signing_key = SigningKey::from_bytes(&seed);
        let PublicCredential::SoftwareEd25519(credential) = &envelope.credential else {
            return Err(Error::field("credential", "must be software-ed25519"));
        };
        if hex::encode(signing_key.verifying_key().to_bytes()) != credential.public_key_hex {
            return Err(Error::UnauthorizedApproval(
                "decrypted seed does not match public credential".to_owned(),
            ));
        }
        Ok(seed)
    }
}

fn require_passphrase(passphrase: &str) -> Result<()> {
    if passphrase.is_empty() {
        Err(Error::field("passphrase", "must be non-empty"))
    } else {
        Ok(())
    }
}

fn derive_key(
    passphrase: &str,
    salt: &[u8; 16],
    parameters: &Argon2Parameters,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(parameters.m_kib, parameters.t, parameters.p, Some(32))
        .map_err(|error| Error::field("kdf", error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|error| Error::field("kdf", error.to_string()))?;
    Ok(key)
}

fn canonical_aad(envelope: &SoftwareKeyEnvelope) -> Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(&envelope.aad())
        .map_err(|error| Error::InvalidJson(error.to_string()))
}

fn decode_base64(value: &str, field: &'static str) -> Result<Vec<u8>> {
    if value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(Error::field(field, "base64 must not contain whitespace"));
    }
    let decoded = STANDARD
        .decode(value)
        .map_err(|error| Error::field(field, error.to_string()))?;
    if STANDARD.encode(&decoded) != value {
        return Err(Error::field(
            field,
            "base64 is not canonical padded RFC 4648",
        ));
    }
    Ok(decoded)
}

fn decode_base64_exact<const N: usize>(value: &str, field: &'static str) -> Result<[u8; N]> {
    decode_base64(value, field)?
        .try_into()
        .map_err(|_| Error::field(field, format!("must contain {N} bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trip() {
        let document = SoftwareKeyEnvelopeDocument::generate("correct horse").unwrap();
        let parsed = SoftwareKeyEnvelopeDocument::parse(document.bytes()).unwrap();
        parsed
            .sign_approval_message("correct horse", b"message")
            .unwrap();
    }

    #[test]
    fn registry_10_wrong_passphrase_fails_decryption() {
        let parsed = SoftwareKeyEnvelopeDocument::generate("correct horse").unwrap();
        assert!(matches!(
            parsed.sign_approval_message("wrong", b"message"),
            Err(Error::UnauthorizedApproval(_))
        ));
    }

    #[test]
    fn registry_08_empty_passphrase_is_rejected() {
        assert!(matches!(
            SoftwareKeyEnvelopeDocument::generate(""),
            Err(Error::InvalidField {
                field: "passphrase",
                ..
            })
        ));
    }

    #[test]
    fn registry_09_envelope_public_tamper_breaks_decryption() {
        let document = SoftwareKeyEnvelopeDocument::generate("secret").unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(document.bytes()).unwrap();
        value["purpose"] = serde_json::Value::String("approval-x".to_owned());
        let bytes = serde_json_canonicalizer::to_vec(&value).unwrap();
        assert!(SoftwareKeyEnvelopeDocument::parse(&bytes).is_err());

        let mut value: serde_json::Value = serde_json::from_slice(document.bytes()).unwrap();
        value["salt"] = serde_json::Value::String(STANDARD.encode([7_u8; 16]));
        let bytes = serde_json_canonicalizer::to_vec(&value).unwrap();
        let tampered = SoftwareKeyEnvelopeDocument::parse(&bytes).unwrap();
        assert!(matches!(
            tampered.sign_approval_message("secret", b"message"),
            Err(Error::UnauthorizedApproval(_))
        ));
    }

    #[test]
    fn registry_11_seed_public_key_must_match_credential() {
        let document = SoftwareKeyEnvelopeDocument::generate("secret").unwrap();
        let seed = document.decrypt_seed("secret").unwrap();
        let other = SoftwareKeyEnvelopeDocument::generate("other").unwrap();
        let mut envelope = document.exact.value().clone();
        envelope.credential = other.exact.value().credential.clone();
        let salt = decode_base64_exact::<16>(&envelope.salt, "salt").unwrap();
        let nonce = decode_base64_exact::<24>(&envelope.nonce, "nonce").unwrap();
        let aad = canonical_aad(&envelope).unwrap();
        let key = derive_key("secret", &salt, &envelope.kdf.argon2id).unwrap();
        let cipher = XChaCha20Poly1305::new((&*key).into());
        envelope.ciphertext = STANDARD.encode(
            cipher
                .encrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &*seed,
                        aad: &aad,
                    },
                )
                .unwrap(),
        );
        let mismatched = SoftwareKeyEnvelopeDocument::parse(
            ExactJson::encode(envelope, ENVELOPE_MAX_BYTES)
                .unwrap()
                .bytes(),
        )
        .unwrap();
        assert!(matches!(
            mismatched.sign_approval_message("secret", b"message"),
            Err(Error::UnauthorizedApproval(_))
        ));
    }

    #[test]
    fn registry_06_plaintext_private_keys_are_unsupported() {
        assert!(SoftwareKeyEnvelopeDocument::parse(&[7_u8; 32]).is_err());
    }

    #[test]
    fn registry_12_openssh_private_keys_are_unsupported() {
        assert!(
            SoftwareKeyEnvelopeDocument::parse(b"-----BEGIN OPENSSH PRIVATE KEY-----").is_err()
        );
    }
}
