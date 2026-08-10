use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{Error, Result, extract::UnitId};

use super::{
    CredentialId, Digest32, ExactJson, PolicyId, PushIntentId, REQUEST_MAX_BYTES, RequestId,
    WireValidate, validation,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub action: Action,
    pub kind: String,
    pub project: String,
    pub request_nonce: String,
    pub requested_at: String,
    pub schema: u64,
}

impl WireValidate for Request {
    fn validate(&self) -> Result<()> {
        if self.schema != 1 || self.kind != "request" {
            return Err(Error::field("request", "schema/kind must be 1/`request`"));
        }
        validation::project(&self.project)?;
        validation::lower_hex(&self.request_nonce, 16, "request_nonce")?;
        validation::timestamp(&self.requested_at, "requested_at")?;
        self.action.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Action {
    #[serde(rename = "policy-update")]
    PolicyUpdate(PolicyUpdateAction),
    #[serde(rename = "attest-content")]
    AttestContent(AttestContentAction),
    #[serde(rename = "attest-tree")]
    AttestTree(AttestTreeAction),
    #[serde(rename = "signer-enroll")]
    SignerEnroll(SignerEnrollAction),
    #[serde(rename = "delegation-grant")]
    DelegationGrant(DelegationGrantAction),
}

impl Action {
    fn validate(&self) -> Result<()> {
        match self {
            Self::PolicyUpdate(value) => value.validate(),
            Self::AttestContent(value) => value.validate(),
            Self::AttestTree(value) => value.validate(),
            Self::SignerEnroll(value) => value.validate(),
            Self::DelegationGrant(value) => value.validate(),
        }
    }

    pub fn scope(&self) -> Option<&str> {
        match self {
            Self::AttestContent(value) => Some(&value.scope),
            Self::AttestTree(value) => Some(&value.scope),
            _ => None,
        }
    }

    pub fn allows_delegated_approval(&self) -> bool {
        matches!(self, Self::AttestContent(_) | Self::AttestTree(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyUpdateAction {
    pub config_id: Digest32,
    pub config_length: u64,
    pub expected_active: Option<Digest32>,
    pub note: String,
}

impl PolicyUpdateAction {
    fn validate(&self) -> Result<()> {
        validation::note(&self.note)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceName {
    #[serde(rename = "staged")]
    Staged,
    #[serde(rename = "push")]
    Push,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectFormatName {
    #[serde(rename = "sha1")]
    Sha1,
    #[serde(rename = "sha256")]
    Sha256,
}

impl ObjectFormatName {
    pub fn oid_hex_len(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitDescriptor {
    pub bytes_hex: Option<String>,
    pub length: u64,
    pub unit_id: UnitId,
}

impl UnitDescriptor {
    pub fn validate(&self) -> Result<()> {
        use crate::extract::UnitKind;
        match self.unit_id.kind() {
            UnitKind::Path | UnitKind::Ref => {
                let encoded = self
                    .bytes_hex
                    .as_deref()
                    .ok_or_else(|| Error::field("units.bytes_hex", "is required for path/ref"))?;
                if encoded.len() % 2 != 0
                    || !encoded
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(Error::field("units.bytes_hex", "must be lower hex"));
                }
                let bytes = hex::decode(encoded)
                    .map_err(|error| Error::field("units.bytes_hex", error.to_string()))?;
                if bytes.len() as u64 != self.length
                    || Digest32::from_bytes(Sha256::digest(&bytes).into()) != self.unit_id.digest()
                {
                    return Err(Error::field(
                        "units",
                        "bytes_hex must match length and unit_id digest",
                    ));
                }
            }
            UnitKind::File | UnitKind::Commit | UnitKind::Tag => {
                if self.bytes_hex.is_some() {
                    return Err(Error::field(
                        "units.bytes_hex",
                        "must be null for file/commit/tag",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestContentAction {
    pub note: String,
    pub object_format: ObjectFormatName,
    pub policy: PolicyId,
    pub push_intent: Option<PushIntentId>,
    pub scope: String,
    pub source: SourceName,
    pub staged_tree: Option<String>,
    pub units: Vec<UnitDescriptor>,
}

impl AttestContentAction {
    fn validate(&self) -> Result<()> {
        validation::scope(&self.scope)?;
        validation::note(&self.note)?;
        match self.source {
            SourceName::Staged if self.push_intent.is_none() && self.staged_tree.is_some() => {}
            SourceName::Push if self.push_intent.is_some() && self.staged_tree.is_none() => {}
            _ => {
                return Err(Error::field(
                    "attest-content",
                    "source fields are inconsistent",
                ));
            }
        }
        if let Some(oid) = &self.staged_tree {
            validate_oid(oid, self.object_format, "staged_tree")?;
        }
        if self.units.is_empty() {
            return Err(Error::field("units", "must be non-empty"));
        }
        let mut previous: Option<String> = None;
        for unit in &self.units {
            unit.validate()?;
            let id = unit.unit_id.to_string();
            if previous.as_ref().is_some_and(|value| value >= &id) {
                return Err(Error::field("units", "must be strictly sorted by unit_id"));
            }
            previous = Some(id);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestTreeAction {
    pub note: String,
    pub object_format: ObjectFormatName,
    pub policy: PolicyId,
    pub push_intent: Option<PushIntentId>,
    pub scope: String,
    pub tree_oid: String,
    pub tree_sha256: Digest32,
}

impl AttestTreeAction {
    fn validate(&self) -> Result<()> {
        validation::scope(&self.scope)?;
        validation::note(&self.note)?;
        validate_oid(&self.tree_oid, self.object_format, "tree_oid")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryName {
    #[serde(rename = "repository")]
    Repository,
    #[serde(rename = "global")]
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerEnrollAction {
    pub credential_id: CredentialId,
    pub credential_length: u64,
    pub credential_sha256: Digest32,
    pub note: String,
    pub policy: PolicyId,
    pub principal: String,
    pub registry: RegistryName,
}

impl SignerEnrollAction {
    fn validate(&self) -> Result<()> {
        if self.credential_length == 0 || self.credential_id.digest() != self.credential_sha256 {
            return Err(Error::field(
                "signer-enroll",
                "credential identity is inconsistent",
            ));
        }
        validation::principal(&self.principal)?;
        validation::note(&self.note)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationGrantAction {
    pub credential_id: CredentialId,
    pub credential_length: u64,
    pub credential_sha256: Digest32,
    pub expires_at: String,
    pub not_before: String,
    pub note: String,
    pub policy: PolicyId,
    pub scopes: Vec<String>,
}

impl DelegationGrantAction {
    fn validate(&self) -> Result<()> {
        if self.credential_length == 0 || self.credential_id.digest() != self.credential_sha256 {
            return Err(Error::field(
                "delegation-grant",
                "credential identity is inconsistent",
            ));
        }
        validation::note(&self.note)?;
        if self.scopes.is_empty() {
            return Err(Error::field("scopes", "must be non-empty"));
        }
        let mut previous: Option<&str> = None;
        for scope in &self.scopes {
            validation::scope(scope)?;
            if previous.is_some_and(|value| value >= scope.as_str()) {
                return Err(Error::field("scopes", "must be strictly sorted"));
            }
            previous = Some(scope);
        }
        let start = validation::timestamp(&self.not_before, "not_before")?;
        let end = validation::timestamp(&self.expires_at, "expires_at")?;
        if start >= end {
            return Err(Error::field(
                "delegation-grant",
                "must have a non-empty half-open interval",
            ));
        }
        Ok(())
    }
}

fn validate_oid(value: &str, format: ObjectFormatName, field: &'static str) -> Result<()> {
    if value.len() != format.oid_hex_len()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::field(
            field,
            "does not match the repository object format",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct RequestDocument {
    exact: ExactJson<Request>,
    id: RequestId,
}

impl RequestDocument {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Self::from_exact(ExactJson::parse(bytes, REQUEST_MAX_BYTES)?)
    }

    /// Constructs an auditor-side request. Nonce and wall-clock fields are not
    /// accepted from the caller (SPEC §7.1).
    pub fn new(project: String, action: Action) -> Result<Self> {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|error| Error::field("request_nonce", error.to_string()))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::field("requested_at", "system clock precedes Unix epoch"))?
            .as_nanos()
            .to_string();
        Self::from_exact(ExactJson::encode(
            Request {
                action,
                kind: "request".to_owned(),
                project,
                request_nonce: hex::encode(nonce),
                requested_at: now,
                schema: 1,
            },
            REQUEST_MAX_BYTES,
        )?)
    }

    fn from_exact(exact: ExactJson<Request>) -> Result<Self> {
        let id = RequestId::from_digest(Digest32::from_bytes(exact.sha256()));
        Ok(Self { exact, id })
    }

    pub fn request(&self) -> &Request {
        self.exact.value()
    }
    pub fn bytes(&self) -> &[u8] {
        self.exact.bytes()
    }
    pub fn sha256(&self) -> Digest32 {
        Digest32::from_bytes(self.exact.sha256())
    }
    pub fn id(&self) -> &RequestId {
        &self.id
    }
}
