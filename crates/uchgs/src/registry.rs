use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    Error, Result,
    authority_file::TrustedRoot,
    wire::{
        APPROVAL_MAX_BYTES, Action, ApprovalDocument, CREDENTIAL_MAX_BYTES, CredentialId,
        CredentialResolver, Digest32, ExactJson, GenesisId, PublicCredentialDocument,
        REQUEST_MAX_BYTES, RegistryName, RequestDocument, RequestId, WireValidate,
    },
};

const REGISTRY_DOCUMENT_MAX_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Presence {
    #[serde(rename = "tty-confirmed")]
    TtyConfirmed,
    #[serde(rename = "headless-asserted")]
    HeadlessAsserted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    pub credential_id: CredentialId,
    pub credential_length: u64,
    pub credential_sha256: Digest32,
    pub kind: String,
    pub presence: Presence,
    pub principal: String,
    pub registry: RegistryName,
    pub schema: u64,
}

impl WireValidate for Genesis {
    fn validate(&self) -> Result<()> {
        if self.schema != 1 || self.kind != "uchgs-genesis" || self.registry != RegistryName::Global
        {
            return Err(Error::field("genesis", "schema/kind/registry are invalid"));
        }
        if self.credential_length == 0 || self.credential_id.digest() != self.credential_sha256 {
            return Err(Error::field(
                "genesis",
                "credential identity is inconsistent",
            ));
        }
        crate::wire::validation::principal(&self.principal)
    }
}

#[derive(Debug, Clone)]
pub struct GenesisDocument {
    exact: ExactJson<Genesis>,
    id: GenesisId,
}

impl GenesisDocument {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let exact = ExactJson::parse(bytes, REGISTRY_DOCUMENT_MAX_BYTES)?;
        let id = GenesisId::from_digest(Digest32::from_bytes(exact.sha256()));
        Ok(Self { exact, id })
    }
    pub fn genesis(&self) -> &Genesis {
        self.exact.value()
    }
    pub fn id(&self) -> &GenesisId {
        &self.id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub active_policy_sha256: Digest32,
    pub approval_sha256: Digest32,
    pub credential_id: CredentialId,
    pub credential_length: u64,
    pub credential_sha256: Digest32,
    pub enrollment_id: Digest32,
    pub kind: String,
    pub principal: String,
    pub project: String,
    pub registry: RegistryName,
    pub request_id: RequestId,
    pub request_sha256: Digest32,
    pub schema: u64,
}

#[derive(Serialize)]
struct EnrollmentPreimage<'a> {
    active_policy_sha256: Digest32,
    approval_sha256: Digest32,
    credential_id: &'a CredentialId,
    credential_length: u64,
    credential_sha256: Digest32,
    kind: &'a str,
    principal: &'a str,
    project: &'a str,
    registry: RegistryName,
    request_id: &'a RequestId,
    request_sha256: Digest32,
    schema: u64,
}

impl Enrollment {
    fn preimage(&self) -> EnrollmentPreimage<'_> {
        EnrollmentPreimage {
            active_policy_sha256: self.active_policy_sha256,
            approval_sha256: self.approval_sha256,
            credential_id: &self.credential_id,
            credential_length: self.credential_length,
            credential_sha256: self.credential_sha256,
            kind: &self.kind,
            principal: &self.principal,
            project: &self.project,
            registry: self.registry,
            request_id: &self.request_id,
            request_sha256: self.request_sha256,
            schema: self.schema,
        }
    }
}

impl WireValidate for Enrollment {
    fn validate(&self) -> Result<()> {
        if self.schema != 1 || self.kind != "uchgs-enrollment" {
            return Err(Error::field(
                "enrollment",
                "schema/kind must be 1/`uchgs-enrollment`",
            ));
        }
        if self.credential_length == 0 || self.credential_id.digest() != self.credential_sha256 {
            return Err(Error::field(
                "enrollment",
                "credential identity is inconsistent",
            ));
        }
        if self.request_id.digest() != self.request_sha256 {
            return Err(Error::field(
                "enrollment",
                "request identity is inconsistent",
            ));
        }
        crate::wire::validation::project(&self.project)?;
        crate::wire::validation::principal(&self.principal)?;
        let bytes = serde_json_canonicalizer::to_vec(&self.preimage())
            .map_err(|error| Error::InvalidJson(error.to_string()))?;
        let expected = Digest32::from_bytes(Sha256::digest(bytes).into());
        if self.enrollment_id != expected {
            return Err(Error::field(
                "enrollment_id",
                "does not match the canonical preimage",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct EnrollmentDocument {
    exact: ExactJson<Enrollment>,
}

impl EnrollmentDocument {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            exact: ExactJson::parse(bytes, REGISTRY_DOCUMENT_MAX_BYTES)?,
        })
    }
    pub fn enrollment(&self) -> &Enrollment {
        self.exact.value()
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedCredential {
    pub credential: PublicCredentialDocument,
    pub principal: String,
}

struct EnrollmentBundle {
    approval: ApprovalDocument,
    credential: PublicCredentialDocument,
    enrollment: EnrollmentDocument,
    request: RequestDocument,
}

struct TrustResolver {
    enrolled: BTreeMap<(String, CredentialId), ResolvedCredential>,
    genesis: ResolvedCredential,
}

impl CredentialResolver for TrustResolver {
    fn resolve(
        &self,
        project: &str,
        credential_id: &CredentialId,
    ) -> Result<PublicCredentialDocument> {
        if self.genesis.credential.id() == credential_id {
            return Ok(self.genesis.credential.clone());
        }
        self.enrolled
            .get(&(project.to_owned(), credential_id.clone()))
            .map(|resolved| resolved.credential.clone())
            .ok_or_else(|| {
                Error::AuthorityNotFound(format!(
                    "credential {credential_id} is not trusted for project {project}"
                ))
            })
    }
}

/// Read-only trust resolver fixed by SPEC §8.1 and §8.4.
pub struct Registry<'a> {
    global: &'a TrustedRoot,
    repository: &'a TrustedRoot,
}

impl<'a> Registry<'a> {
    pub fn new(global: &'a TrustedRoot, repository: &'a TrustedRoot) -> Self {
        Self { global, repository }
    }

    /// Grows trust to a fixed point before answering. An enrollment may be approved
    /// by a credential that another enrollment establishes, so each pass admits only
    /// bundles whose approver is already trusted and defers the rest. A pass that
    /// admits nothing means the remaining bundles are unrooted or mutually
    /// referential; that fails closed instead of trusting them.
    pub fn resolve_full(
        &self,
        project: &str,
        credential_id: &CredentialId,
    ) -> Result<ResolvedCredential> {
        crate::wire::validation::project(project)?;
        let genesis = self.load_genesis()?;
        let mut trust = TrustResolver {
            enrolled: BTreeMap::new(),
            genesis,
        };
        let mut unresolved = self.load_enrollments()?;
        while !unresolved.is_empty() {
            let mut deferred = Vec::new();
            let mut progressed = false;
            for bundle in unresolved {
                if bundle.approval.approval().delegation.is_some() {
                    return Err(Error::UnauthorizedApproval(
                        "signer-enroll cannot be approved through delegation".to_owned(),
                    ));
                }
                let signer_id = &bundle.approval.approval().credential_id;
                if trust
                    .resolve(&bundle.request.request().project, signer_id)
                    .is_err()
                {
                    deferred.push(bundle);
                    continue;
                }
                bundle.approval.verify(&bundle.request, &trust)?;
                let enrollment = bundle.enrollment.enrollment();
                let key = (enrollment.project.clone(), enrollment.credential_id.clone());
                let candidate = ResolvedCredential {
                    credential: bundle.credential,
                    principal: enrollment.principal.clone(),
                };
                if let Some(existing) = trust.enrolled.get(&key) {
                    if existing.principal != candidate.principal
                        || existing.credential.bytes() != candidate.credential.bytes()
                    {
                        return Err(Error::AuthorityConflict(format!(
                            "ambiguous registry entry for ({}, {})",
                            key.0, key.1
                        )));
                    }
                } else {
                    trust.enrolled.insert(key, candidate);
                }
                progressed = true;
            }
            if !progressed {
                return Err(Error::UnauthorizedApproval(
                    "enrollment authority graph is unresolved or cyclic".to_owned(),
                ));
            }
            unresolved = deferred;
        }
        if trust.genesis.credential.id() == credential_id {
            return Ok(trust.genesis);
        }
        let Some(resolved) = trust
            .enrolled
            .remove(&(project.to_owned(), credential_id.clone()))
        else {
            return Err(Error::AuthorityNotFound(format!(
                "credential {credential_id} is not enrolled for project {project}"
            )));
        };
        Ok(resolved)
    }

    fn load_genesis(&self) -> Result<ResolvedCredential> {
        let base = Path::new("genesis/v1/sha256");
        let entries = entries_or_empty(self.global, base)?;
        if entries.is_empty() {
            return Err(Error::AuthorityNotFound(
                "the global registry has no genesis".to_owned(),
            ));
        }
        if entries.len() != 1 {
            return Err(Error::AuthorityConflict(
                "the global registry must contain exactly one genesis".to_owned(),
            ));
        }
        let digest = entries
            .into_iter()
            .next()
            .expect("non-empty genesis entries");
        let digest_text = strict_component(&digest, "genesis directory")?;
        let path = base.join(&digest).join("genesis.json");
        let bytes = self.global.read_file(path, REGISTRY_DOCUMENT_MAX_BYTES)?;
        let document = GenesisDocument::parse(&bytes)?;
        if document.id().digest().to_hex() != digest_text {
            return Err(Error::AuthorityConflict(
                "genesis path digest does not match genesis.json".to_owned(),
            ));
        }
        let genesis = document.genesis();
        let credential = load_credential(self.global, &genesis.credential_id)?;
        check_credential_binding(
            &credential,
            genesis.credential_sha256,
            genesis.credential_length,
        )?;
        Ok(ResolvedCredential {
            credential,
            principal: genesis.principal.clone(),
        })
    }

    fn load_enrollments(&self) -> Result<Vec<EnrollmentBundle>> {
        let mut output = Vec::new();
        self.load_enrollments_from(self.global, RegistryName::Global, &mut output)?;
        self.load_enrollments_from(self.repository, RegistryName::Repository, &mut output)?;
        Ok(output)
    }

    fn load_enrollments_from(
        &self,
        root: &TrustedRoot,
        expected_registry: RegistryName,
        output: &mut Vec<EnrollmentBundle>,
    ) -> Result<()> {
        let base = Path::new("enrollments/v1/sha256");
        for request_digest in entries_or_empty(root, base)? {
            let request_digest_text = strict_component(&request_digest, "enrollment directory")?;
            let directory = base.join(&request_digest);
            require_exact_bundle(root, &directory)?;
            let request = RequestDocument::parse(
                &root.read_file(directory.join("request.json"), REQUEST_MAX_BYTES)?,
            )?;
            let approval = ApprovalDocument::parse(
                &root.read_file(directory.join("approval.json"), APPROVAL_MAX_BYTES)?,
            )?;
            let credential = PublicCredentialDocument::parse(
                &root.read_file(directory.join("credential.json"), CREDENTIAL_MAX_BYTES)?,
            )?;
            let document = EnrollmentDocument::parse(&root.read_file(
                directory.join("enrollment.json"),
                REGISTRY_DOCUMENT_MAX_BYTES,
            )?)?;
            let enrollment = document.enrollment();
            if enrollment.request_sha256.to_hex() != request_digest_text
                || request.sha256() != enrollment.request_sha256
                || request.id() != &enrollment.request_id
                || approval.sha256() != enrollment.approval_sha256
            {
                return Err(Error::AuthorityConflict(
                    "enrollment bundle request/approval binding is inconsistent".to_owned(),
                ));
            }
            check_credential_binding(
                &credential,
                enrollment.credential_sha256,
                enrollment.credential_length,
            )?;
            if credential.id() != &enrollment.credential_id {
                return Err(Error::AuthorityConflict(
                    "enrollment credential id does not match credential.json".to_owned(),
                ));
            }
            let central = load_credential(root, &enrollment.credential_id)?;
            if central.bytes() != credential.bytes() {
                return Err(Error::AuthorityConflict(
                    "enrollment credential.json differs from the content-addressed credential"
                        .to_owned(),
                ));
            }
            let Action::SignerEnroll(action) = &request.request().action else {
                return Err(Error::AuthorityConflict(
                    "enrollment request action is not signer-enroll".to_owned(),
                ));
            };
            if request.request().project != enrollment.project
                || action.registry != expected_registry
                || enrollment.registry != expected_registry
                || action.policy.digest() != enrollment.active_policy_sha256
                || action.principal != enrollment.principal
                || action.credential_id != enrollment.credential_id
                || action.credential_sha256 != enrollment.credential_sha256
                || action.credential_length != enrollment.credential_length
            {
                return Err(Error::AuthorityConflict(
                    "enrollment record does not match its signer-enroll request".to_owned(),
                ));
            }
            output.push(EnrollmentBundle {
                approval,
                credential,
                enrollment: document,
                request,
            });
        }
        Ok(())
    }
}

impl CredentialResolver for Registry<'_> {
    fn resolve(
        &self,
        project: &str,
        credential_id: &CredentialId,
    ) -> Result<PublicCredentialDocument> {
        Ok(self.resolve_full(project, credential_id)?.credential)
    }
}

fn entries_or_empty(root: &TrustedRoot, path: &Path) -> Result<Vec<std::ffi::OsString>> {
    match root.entries(path) {
        Ok(entries) => Ok(entries
            .into_iter()
            .filter(|entry| !entry.to_string_lossy().starts_with(".tmp-"))
            .collect()),
        Err(Error::Io {
            kind: std::io::ErrorKind::NotFound,
            ..
        }) => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

fn strict_component(value: &std::ffi::OsString, field: &'static str) -> Result<String> {
    value
        .clone()
        .into_string()
        .map_err(|_| Error::AuthorityConflict(format!("{field} is not UTF-8")))
}

fn require_exact_bundle(root: &TrustedRoot, directory: &Path) -> Result<()> {
    let mut entries = root
        .entries(directory)?
        .into_iter()
        .map(|entry| strict_component(&entry, "enrollment bundle entry"))
        .collect::<Result<Vec<_>>>()?;
    entries.sort();
    let expected = [
        "approval.json".to_owned(),
        "credential.json".to_owned(),
        "enrollment.json".to_owned(),
        "request.json".to_owned(),
    ];
    if entries != expected {
        return Err(Error::AuthorityConflict(
            "enrollment bundle must contain exactly request.json, approval.json, credential.json, and enrollment.json"
                .to_owned(),
        ));
    }
    Ok(())
}

fn load_credential(root: &TrustedRoot, id: &CredentialId) -> Result<PublicCredentialDocument> {
    let path = PathBuf::from("credentials/v1/sha256").join(format!("{}.json", id.digest()));
    let bytes = root.read_file(path, crate::wire::CREDENTIAL_MAX_BYTES)?;
    let document = PublicCredentialDocument::parse(&bytes)?;
    if document.id() != id {
        return Err(Error::AuthorityConflict(
            "credential path digest does not match content".to_owned(),
        ));
    }
    Ok(document)
}

fn check_credential_binding(
    credential: &PublicCredentialDocument,
    expected_digest: Digest32,
    expected_length: u64,
) -> Result<()> {
    if credential.sha256() != expected_digest || credential.bytes().len() as u64 != expected_length
    {
        return Err(Error::AuthorityConflict(
            "credential bytes do not match registry record".to_owned(),
        ));
    }
    Ok(())
}
