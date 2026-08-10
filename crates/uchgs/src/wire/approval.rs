use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use p256::ecdsa::{
    Signature as P256Signature, VerifyingKey as P256VerifyingKey, signature::Verifier as _,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{Error, Result};

use super::{
    APPROVAL_MAX_BYTES, CredentialId, Digest32, ExactJson, PublicCredential,
    PublicCredentialDocument, RequestDocument, RequestId, WireValidate, request::Action,
    validation,
};

pub trait CredentialResolver {
    fn resolve(
        &self,
        project: &str,
        credential_id: &CredentialId,
    ) -> Result<PublicCredentialDocument>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub approved_at: String,
    pub credential_id: CredentialId,
    pub delegation: Option<DelegationEvidence>,
    pub kind: String,
    pub material: ApprovalMaterial,
    pub request_id: RequestId,
    pub request_sha256: Digest32,
    pub schema: u64,
}

impl WireValidate for Approval {
    fn validate(&self) -> Result<()> {
        if self.schema != 1 || self.kind != "approval" {
            return Err(Error::field("approval", "schema/kind must be 1/`approval`"));
        }
        if self.request_id.digest() != self.request_sha256 {
            return Err(Error::field("approval", "request identity is inconsistent"));
        }
        validation::timestamp(&self.approved_at, "approved_at")?;
        self.material.validate()?;
        if let Some(delegation) = &self.delegation {
            delegation.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "algorithm", deny_unknown_fields)]
pub enum ApprovalMaterial {
    #[serde(rename = "ed25519")]
    Ed25519 { signature: String },
    #[serde(rename = "ecdsa-p256-sha256")]
    EcdsaP256Sha256 { r: String, s: String },
}

impl ApprovalMaterial {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Ed25519 { signature } => {
                validation::lower_hex(signature, 64, "material.signature")?;
            }
            Self::EcdsaP256Sha256 { r, s } => {
                let r: [u8; 32] = validation::lower_hex(r, 32, "material.r")?
                    .try_into()
                    .map_err(|_| Error::field("material.r", "must contain 32 bytes"))?;
                let s: [u8; 32] = validation::lower_hex(s, 32, "material.s")?
                    .try_into()
                    .map_err(|_| Error::field("material.s", "must contain 32 bytes"))?;
                let signature = P256Signature::from_scalars(r, s)
                    .map_err(|_| Error::field("material", "invalid P-256 signature scalars"))?;
                if signature.normalize_s().is_some() {
                    return Err(Error::field("material.s", "must be low-S normalized"));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationEvidence {
    pub credential: String,
    pub grant_approval: String,
    pub grant_request: String,
}

impl DelegationEvidence {
    fn validate(&self) -> Result<()> {
        decode_canonical_base64(&self.credential, "delegation.credential")?;
        decode_canonical_base64(&self.grant_approval, "delegation.grant_approval")?;
        decode_canonical_base64(&self.grant_request, "delegation.grant_request")?;
        Ok(())
    }
}

fn decode_canonical_base64(value: &str, field: &'static str) -> Result<Vec<u8>> {
    if value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(Error::field(field, "base64 must not contain whitespace"));
    }
    let decoded = STANDARD
        .decode(value)
        .map_err(|error| Error::field(field, error.to_string()))?;
    if STANDARD.encode(&decoded) != value {
        return Err(Error::field(
            field,
            "base64 is not the canonical padded encoding",
        ));
    }
    Ok(decoded)
}

#[derive(Debug, Clone)]
pub struct ApprovalDocument {
    exact: ExactJson<Approval>,
}

impl ApprovalDocument {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            exact: ExactJson::parse(bytes, APPROVAL_MAX_BYTES)?,
        })
    }

    pub fn encode(approval: Approval) -> Result<Self> {
        Ok(Self {
            exact: ExactJson::encode(approval, APPROVAL_MAX_BYTES)?,
        })
    }

    pub fn approval(&self) -> &Approval {
        self.exact.value()
    }
    pub fn bytes(&self) -> &[u8] {
        self.exact.bytes()
    }
    pub fn sha256(&self) -> Digest32 {
        Digest32::from_bytes(self.exact.sha256())
    }

    pub fn verify(
        &self,
        request: &RequestDocument,
        resolver: &impl CredentialResolver,
    ) -> Result<()> {
        verify_request_binding(self.approval(), request)?;
        match &self.approval().delegation {
            None => {
                let credential =
                    resolver.resolve(&request.request().project, &self.approval().credential_id)?;
                verify_material(
                    &self.approval().material,
                    credential.credential(),
                    request.bytes(),
                )
            }
            Some(evidence) => self.verify_delegated(request, evidence, resolver),
        }
        .map_err(|error| match error {
            Error::UnauthorizedApproval(_) => error,
            other => Error::UnauthorizedApproval(other.to_string()),
        })
    }

    fn verify_delegated(
        &self,
        request: &RequestDocument,
        evidence: &DelegationEvidence,
        resolver: &impl CredentialResolver,
    ) -> Result<()> {
        if !request.request().action.allows_delegated_approval() {
            return Err(Error::UnauthorizedApproval(
                "delegated keys may approve only attest-content/attest-tree".to_owned(),
            ));
        }
        let grant_request_bytes =
            decode_canonical_base64(&evidence.grant_request, "delegation.grant_request")?;
        let grant_approval_bytes =
            decode_canonical_base64(&evidence.grant_approval, "delegation.grant_approval")?;
        let delegated_credential_bytes =
            decode_canonical_base64(&evidence.credential, "delegation.credential")?;
        let grant_request = RequestDocument::parse(&grant_request_bytes)?;
        let grant_approval = ApprovalDocument::parse(&grant_approval_bytes)?;
        if grant_approval.approval().delegation.is_some() {
            return Err(Error::UnauthorizedApproval(
                "delegation grants require a registered direct signer".to_owned(),
            ));
        }
        grant_approval.verify(&grant_request, resolver)?;

        let delegated_credential = PublicCredentialDocument::parse(&delegated_credential_bytes)?;
        let Action::DelegationGrant(grant) = &grant_request.request().action else {
            return Err(Error::UnauthorizedApproval(
                "delegation evidence request is not delegation-grant".to_owned(),
            ));
        };
        if grant.credential_id != *delegated_credential.id()
            || grant.credential_sha256 != delegated_credential.sha256()
            || grant.credential_length != delegated_credential.bytes().len() as u64
            || self.approval().credential_id != *delegated_credential.id()
        {
            return Err(Error::UnauthorizedApproval(
                "delegated credential does not match the grant".to_owned(),
            ));
        }
        let PublicCredential::SoftwareEd25519(_) = delegated_credential.credential() else {
            return Err(Error::UnauthorizedApproval(
                "delegated credential must be software-ed25519".to_owned(),
            ));
        };
        if request.request().project != grant_request.request().project {
            return Err(Error::UnauthorizedApproval(
                "delegated project is out of scope".to_owned(),
            ));
        }
        let scope = request.request().action.scope().ok_or_else(|| {
            Error::UnauthorizedApproval("delegated action has no scope".to_owned())
        })?;
        if grant
            .scopes
            .binary_search_by(|item| item.as_str().cmp(scope))
            .is_err()
        {
            return Err(Error::UnauthorizedApproval(
                "delegated scope is out of range".to_owned(),
            ));
        }
        let approved_at = validation::timestamp(&self.approval().approved_at, "approved_at")?;
        let not_before = validation::timestamp(&grant.not_before, "not_before")?;
        let expires_at = validation::timestamp(&grant.expires_at, "expires_at")?;
        if !(not_before <= approved_at && approved_at < expires_at) {
            return Err(Error::UnauthorizedApproval(
                "delegated approval is outside the half-open grant interval".to_owned(),
            ));
        }
        verify_material(
            &self.approval().material,
            delegated_credential.credential(),
            request.bytes(),
        )
    }
}

fn verify_request_binding(approval: &Approval, request: &RequestDocument) -> Result<()> {
    if approval.request_id != *request.id() || approval.request_sha256 != request.sha256() {
        return Err(Error::UnauthorizedApproval(
            "approval is not bound to the saved exact request bytes".to_owned(),
        ));
    }
    Ok(())
}

fn signing_message(request_bytes: &[u8]) -> Vec<u8> {
    let mut message = b"uchgs-approval-v1\0".to_vec();
    message.extend_from_slice(&Sha256::digest(request_bytes));
    message
}

fn verify_material(
    material: &ApprovalMaterial,
    credential: &PublicCredential,
    request_bytes: &[u8],
) -> Result<()> {
    let message = signing_message(request_bytes);
    match (material, credential) {
        (
            ApprovalMaterial::Ed25519 { signature },
            PublicCredential::SoftwareEd25519(credential),
        ) => {
            let key: [u8; 32] =
                validation::lower_hex(&credential.public_key_hex, 32, "public_key_hex")?
                    .try_into()
                    .map_err(|_| Error::field("public_key_hex", "must contain 32 bytes"))?;
            let signature: [u8; 64] = validation::lower_hex(signature, 64, "material.signature")?
                .try_into()
                .map_err(|_| Error::field("material.signature", "must contain 64 bytes"))?;
            Ed25519VerifyingKey::from_bytes(&key)
                .map_err(|_| Error::UnauthorizedApproval("invalid Ed25519 key".to_owned()))?
                .verify_strict(&message, &Ed25519Signature::from_bytes(&signature))
                .map_err(|_| Error::UnauthorizedApproval("invalid Ed25519 signature".to_owned()))
        }
        (
            ApprovalMaterial::EcdsaP256Sha256 { r, s },
            PublicCredential::SecureEnclaveP256TouchId(credential),
        ) => {
            let key =
                validation::lower_hex(&credential.public_key_x963_hex, 65, "public_key_x963_hex")?;
            let r: [u8; 32] = validation::lower_hex(r, 32, "material.r")?
                .try_into()
                .map_err(|_| Error::field("material.r", "must contain 32 bytes"))?;
            let s: [u8; 32] = validation::lower_hex(s, 32, "material.s")?
                .try_into()
                .map_err(|_| Error::field("material.s", "must contain 32 bytes"))?;
            let signature = P256Signature::from_scalars(r, s)
                .map_err(|_| Error::UnauthorizedApproval("invalid P-256 signature".to_owned()))?;
            if signature.normalize_s().is_some() {
                return Err(Error::UnauthorizedApproval(
                    "P-256 signature is not low-S".to_owned(),
                ));
            }
            P256VerifyingKey::from_sec1_bytes(&key)
                .map_err(|_| Error::UnauthorizedApproval("invalid P-256 key".to_owned()))?
                .verify(&message, &signature)
                .map_err(|_| Error::UnauthorizedApproval("invalid P-256 signature".to_owned()))
        }
        _ => Err(Error::UnauthorizedApproval(
            "signature material does not match credential type".to_owned(),
        )),
    }
}
