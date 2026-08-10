//! Human-custody signing surfaces used by signer ceremonies.
//!
//! Normative source: SPEC §7.3–§7.4, §8.2, §8.5, and §12.1.

use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest as _, Sha256};

use crate::{
    Error, Result,
    authority_file::{PublishOutcome, TrustedRoot},
    software_key::{ENVELOPE_MAX_BYTES, SoftwareKeyEnvelopeDocument},
    wire::{
        Approval, ApprovalDocument, ApprovalMaterial, CredentialId, PublicCredential,
        PublicCredentialDocument, RequestDocument, signing_message,
    },
};

/// An opaque, non-persistent proof made by the exact key being bootstrapped.
#[derive(Debug, Clone)]
pub struct PossessionProof {
    credential_id: CredentialId,
    material: ApprovalMaterial,
}

impl PossessionProof {
    pub(crate) fn new(credential_id: CredentialId, material: ApprovalMaterial) -> Self {
        Self {
            credential_id,
            material,
        }
    }
}

/// Exact locator grammar from SPEC §12.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyLocator {
    Software(std::path::PathBuf),
    SecureEnclave(String),
}

impl KeyLocator {
    pub fn parse(value: &str) -> Result<Self> {
        if let Some(key_id) = value.strip_prefix("se:") {
            validate_secure_enclave_key_id(key_id)?;
            return Ok(Self::SecureEnclave(key_id.to_owned()));
        }
        if value.is_empty() {
            return Err(Error::field("key", "software key path must be non-empty"));
        }
        Ok(Self::Software(value.into()))
    }
}

/// Generates one native envelope after reading a non-empty passphrase solely
/// from the controlling terminal.
pub fn generate_software_key_interactive(prompt: &str) -> Result<SoftwareKeyEnvelopeDocument> {
    let passphrase = uchgs_custody_platform::prompt_hidden(prompt)
        .map_err(|error| Error::io("read software-key passphrase", io_other(error)))?;
    SoftwareKeyEnvelopeDocument::generate(&passphrase)
}

/// Saves a generated native envelope without replacing an existing path.
pub fn save_software_key(
    path: impl AsRef<Path>,
    envelope: &SoftwareKeyEnvelopeDocument,
) -> Result<()> {
    let (parent, name) = TrustedRoot::open_operator_parent(path.as_ref())?;
    match parent.publish_private_file(Path::new(&name), envelope.bytes())? {
        PublishOutcome::Published => Ok(()),
        PublishOutcome::Existing => Err(Error::io(
            "create software-key envelope",
            std::io::Error::from(std::io::ErrorKind::AlreadyExists),
        )),
    }
}

/// Loads only a protected, bounded native §8.6 envelope.
pub fn load_software_key(path: impl AsRef<Path>) -> Result<SoftwareKeyEnvelopeDocument> {
    let (parent, name) = TrustedRoot::open_operator_parent(path.as_ref())?;
    let bytes = parent.read_private_file(Path::new(&name), ENVELOPE_MAX_BYTES)?;
    SoftwareKeyEnvelopeDocument::parse(&bytes)
}

/// Signs a saved Request with a software envelope. The passphrase has no API,
/// argv, environment, or standard-input route.
pub fn approve_with_software_key_interactive(
    request: &RequestDocument,
    envelope: &SoftwareKeyEnvelopeDocument,
    prompt: &str,
) -> Result<ApprovalDocument> {
    let passphrase = uchgs_custody_platform::prompt_hidden(prompt)
        .map_err(|error| Error::io("read software-key passphrase", io_other(error)))?;
    let material =
        envelope.sign_approval_message(&passphrase, &signing_message(request.bytes()))?;
    direct_approval(request, envelope.credential(), material)
}

/// Creates a genesis possession proof through the software-key custody prompt.
pub fn prove_software_genesis_possession_interactive(
    envelope: &SoftwareKeyEnvelopeDocument,
    prompt: &str,
) -> Result<PossessionProof> {
    let passphrase = uchgs_custody_platform::prompt_hidden(prompt)
        .map_err(|error| Error::io("read software-key passphrase", io_other(error)))?;
    let material = envelope.possession_material(
        &passphrase,
        &genesis_possession_message(envelope.credential()),
    )?;
    Ok(PossessionProof::new(
        envelope.credential().id().clone(),
        material,
    ))
}

#[cfg(target_os = "macos")]
pub struct SecureEnclaveCreation {
    creation: uchgs_macos_secure_enclave::Creation,
    credential: PublicCredentialDocument,
}

#[cfg(target_os = "macos")]
impl SecureEnclaveCreation {
    pub fn create(key_id: &str) -> Result<Self> {
        validate_secure_enclave_key_id(key_id)?;
        let creation = uchgs_macos_secure_enclave::create(key_id)
            .map_err(|error| Error::UnsupportedPlatform(error.to_string()))?;
        let credential = p256_credential(creation.public_key_x963())?;
        Ok(Self {
            creation,
            credential,
        })
    }

    pub fn credential(&self) -> &PublicCredentialDocument {
        &self.credential
    }

    /// Disarms platform rollback only after the matching public credential is durable.
    pub fn disarm(self) {
        self.creation.disarm();
    }
}

#[cfg(not(target_os = "macos"))]
pub struct SecureEnclaveCreation;

#[cfg(not(target_os = "macos"))]
impl SecureEnclaveCreation {
    pub fn create(_key_id: &str) -> Result<Self> {
        Err(Error::UnsupportedPlatform(
            "Secure Enclave requires macOS".to_owned(),
        ))
    }
}

#[cfg(target_os = "macos")]
pub fn secure_enclave_credential(key_id: &str) -> Result<PublicCredentialDocument> {
    validate_secure_enclave_key_id(key_id)?;
    let public = uchgs_macos_secure_enclave::public_key(key_id)
        .map_err(|error| Error::UnsupportedPlatform(error.to_string()))?;
    p256_credential(&public)
}

#[cfg(not(target_os = "macos"))]
pub fn secure_enclave_credential(_key_id: &str) -> Result<PublicCredentialDocument> {
    Err(Error::UnsupportedPlatform(
        "Secure Enclave requires macOS".to_owned(),
    ))
}

#[cfg(target_os = "macos")]
pub fn approve_with_secure_enclave(
    request: &RequestDocument,
    key_id: &str,
) -> Result<ApprovalDocument> {
    let credential = secure_enclave_credential(key_id)?;
    let PublicCredential::SecureEnclaveP256TouchId(value) = credential.credential() else {
        return Err(Error::field("credential", "must be Secure Enclave P-256"));
    };
    let public: [u8; 65] = hex::decode(&value.public_key_x963_hex)
        .map_err(|error| Error::field("public_key_x963_hex", error.to_string()))?
        .try_into()
        .map_err(|_| Error::field("public_key_x963_hex", "must contain 65 bytes"))?;
    let challenge: [u8; 32] = Sha256::digest(signing_message(request.bytes())).into();
    let signature = uchgs_macos_secure_enclave::sign_prehash(key_id, &public, &challenge)
        .map_err(|error| Error::UnauthorizedApproval(error.to_string()))?;
    direct_approval(
        request,
        &credential,
        ApprovalMaterial::EcdsaP256Sha256 {
            r: hex::encode(&signature[..32]),
            s: hex::encode(&signature[32..]),
        },
    )
}

#[cfg(not(target_os = "macos"))]
pub fn approve_with_secure_enclave(
    _request: &RequestDocument,
    _key_id: &str,
) -> Result<ApprovalDocument> {
    Err(Error::UnsupportedPlatform(
        "Secure Enclave requires macOS".to_owned(),
    ))
}

#[cfg(target_os = "macos")]
pub fn prove_secure_enclave_genesis_possession(key_id: &str) -> Result<PossessionProof> {
    let credential = secure_enclave_credential(key_id)?;
    let PublicCredential::SecureEnclaveP256TouchId(value) = credential.credential() else {
        return Err(Error::field("credential", "must be Secure Enclave P-256"));
    };
    let public: [u8; 65] = hex::decode(&value.public_key_x963_hex)
        .map_err(|error| Error::field("public_key_x963_hex", error.to_string()))?
        .try_into()
        .map_err(|_| Error::field("public_key_x963_hex", "must contain 65 bytes"))?;
    let challenge: [u8; 32] = Sha256::digest(genesis_possession_message(&credential)).into();
    let signature = uchgs_macos_secure_enclave::sign_prehash(key_id, &public, &challenge)
        .map_err(|error| Error::UnauthorizedApproval(error.to_string()))?;
    Ok(PossessionProof::new(
        credential.id().clone(),
        ApprovalMaterial::EcdsaP256Sha256 {
            r: hex::encode(&signature[..32]),
            s: hex::encode(&signature[32..]),
        },
    ))
}

#[cfg(not(target_os = "macos"))]
pub fn prove_secure_enclave_genesis_possession(_key_id: &str) -> Result<PossessionProof> {
    Err(Error::UnsupportedPlatform(
        "Secure Enclave requires macOS".to_owned(),
    ))
}

pub(crate) fn verify_possession(
    credential: &PublicCredentialDocument,
    proof: &PossessionProof,
) -> Result<()> {
    if proof.credential_id != *credential.id() {
        return Err(Error::UnauthorizedApproval(
            "possession proof is for a different credential".to_owned(),
        ));
    }
    let message = genesis_possession_message(credential);
    match (&proof.material, credential.credential()) {
        (ApprovalMaterial::Ed25519 { signature }, PublicCredential::SoftwareEd25519(value)) => {
            let key: [u8; 32] = hex::decode(&value.public_key_hex)
                .map_err(|error| Error::field("public_key_hex", error.to_string()))?
                .try_into()
                .map_err(|_| Error::field("public_key_hex", "must contain 32 bytes"))?;
            let signature: [u8; 64] = hex::decode(signature)
                .map_err(|error| Error::field("material.signature", error.to_string()))?
                .try_into()
                .map_err(|_| Error::field("material.signature", "must contain 64 bytes"))?;
            ed25519_dalek::VerifyingKey::from_bytes(&key)
                .map_err(|_| Error::UnauthorizedApproval("invalid Ed25519 key".to_owned()))?
                .verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&signature))
                .map_err(|_| Error::UnauthorizedApproval("possession proof failed".to_owned()))
        }
        (
            ApprovalMaterial::EcdsaP256Sha256 { r, s },
            PublicCredential::SecureEnclaveP256TouchId(value),
        ) => {
            use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
            let key = hex::decode(&value.public_key_x963_hex)
                .map_err(|error| Error::field("public_key_x963_hex", error.to_string()))?;
            let r: [u8; 32] = hex::decode(r)
                .map_err(|error| Error::field("material.r", error.to_string()))?
                .try_into()
                .map_err(|_| Error::field("material.r", "must contain 32 bytes"))?;
            let s: [u8; 32] = hex::decode(s)
                .map_err(|error| Error::field("material.s", error.to_string()))?
                .try_into()
                .map_err(|_| Error::field("material.s", "must contain 32 bytes"))?;
            let signature = Signature::from_scalars(r, s)
                .map_err(|_| Error::UnauthorizedApproval("invalid P-256 signature".to_owned()))?;
            if signature.normalize_s().is_some() {
                return Err(Error::UnauthorizedApproval(
                    "P-256 possession proof is not low-S".to_owned(),
                ));
            }
            VerifyingKey::from_sec1_bytes(&key)
                .map_err(|_| Error::UnauthorizedApproval("invalid P-256 key".to_owned()))?
                .verify(&message, &signature)
                .map_err(|_| Error::UnauthorizedApproval("possession proof failed".to_owned()))
        }
        _ => Err(Error::UnauthorizedApproval(
            "possession material does not match credential type".to_owned(),
        )),
    }
}

pub(crate) fn direct_approval(
    request: &RequestDocument,
    credential: &PublicCredentialDocument,
    material: ApprovalMaterial,
) -> Result<ApprovalDocument> {
    ApprovalDocument::encode(Approval {
        approved_at: wall_clock_nanos()?,
        credential_id: credential.id().clone(),
        delegation: None,
        kind: "approval".to_owned(),
        material,
        request_id: request.id().clone(),
        request_sha256: request.sha256(),
        schema: 1,
    })
}

pub(crate) fn wall_clock_nanos() -> Result<String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().to_string())
        .map_err(|_| Error::field("time", "system clock precedes Unix epoch"))
}

pub(crate) fn genesis_possession_message(credential: &PublicCredentialDocument) -> Vec<u8> {
    let mut message = b"uchgs-genesis-possession-v1\0".to_vec();
    message.extend_from_slice(&Sha256::digest(credential.bytes()));
    message
}

fn validate_secure_enclave_key_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || value.starts_with('.')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(Error::field("key", "invalid Secure Enclave key identifier"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn p256_credential(public: &[u8; 65]) -> Result<PublicCredentialDocument> {
    use crate::wire::SecureEnclaveP256Credential;

    PublicCredentialDocument::encode(PublicCredential::SecureEnclaveP256TouchId(
        SecureEnclaveP256Credential {
            credential_type: "secure-enclave-p256-touch-id".to_owned(),
            kind: "uchgs-public-credential".to_owned(),
            public_key_x963_hex: hex::encode(public),
            schema: 1,
        },
    ))
}

fn io_other(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn key_locator_grammar_is_shape_based() {
        assert_eq!(
            KeyLocator::parse("se:key-1").unwrap(),
            KeyLocator::SecureEnclave("key-1".to_owned())
        );
        assert!(matches!(
            KeyLocator::parse("keys/a.json").unwrap(),
            KeyLocator::Software(_)
        ));
        for invalid in ["se:", "se:.hidden", "se:key/one"] {
            assert!(KeyLocator::parse(invalid).is_err());
        }
    }

    #[test]
    fn native_envelope_file_is_private_and_never_replaced() {
        let temp = tempfile::tempdir().unwrap();
        let path = fs::canonicalize(temp.path()).unwrap().join("approval.key");
        let envelope = SoftwareKeyEnvelopeDocument::generate("correct horse").unwrap();
        save_software_key(&path, &envelope).unwrap();
        assert_eq!(load_software_key(&path).unwrap().bytes(), envelope.bytes());
        assert!(save_software_key(&path, &envelope).is_err());
        assert_eq!(load_software_key(&path).unwrap().bytes(), envelope.bytes());
        assert_ne!(fs::read(&path).unwrap(), [0_u8; 32]);
    }

    #[cfg(unix)]
    #[test]
    fn operator_key_paths_reject_fifo_and_symlink_resolution() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let fifo = root.join("pipe.key");
        #[cfg(not(target_vendor = "apple"))]
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .unwrap();
        #[cfg(target_vendor = "apple")]
        assert!(
            std::process::Command::new("/usr/bin/mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        assert!(load_software_key(&fifo).is_err());

        let envelope = SoftwareKeyEnvelopeDocument::generate("correct horse").unwrap();
        let real_parent = root.join("real");
        fs::create_dir(&real_parent).unwrap();
        let real_key = real_parent.join("real.key");
        save_software_key(&real_key, &envelope).unwrap();

        let linked_parent = root.join("linked-parent");
        symlink(&real_parent, &linked_parent).unwrap();
        assert!(save_software_key(linked_parent.join("new.key"), &envelope).is_err());

        let linked_key = root.join("linked.key");
        symlink(&real_key, &linked_key).unwrap();
        assert!(load_software_key(&linked_key).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn operator_key_paths_reject_reparse_points() {
        use std::os::windows::fs::{symlink_dir, symlink_file};

        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let envelope = SoftwareKeyEnvelopeDocument::generate("correct horse").unwrap();
        let real_parent = root.join("real");
        fs::create_dir(&real_parent).unwrap();
        let real_key = real_parent.join("real.key");
        save_software_key(&real_key, &envelope).unwrap();

        let linked_parent = root.join("linked-parent");
        symlink_dir(&real_parent, &linked_parent).unwrap();
        assert!(save_software_key(linked_parent.join("new.key"), &envelope).is_err());

        let linked_key = root.join("linked.key");
        symlink_file(&real_key, &linked_key).unwrap();
        assert!(load_software_key(&linked_key).is_err());
    }
}
