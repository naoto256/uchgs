//! Signed policy parsing, authority loading, and compare-and-swap activation.
//!
//! Normative source: SPEC §2.2, §5, §7, and §14.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::{
    Error, Result,
    authority_file::{PublishOutcome, TrustedRoot, is_authority_temporary_name},
    pending::{PendingHandle, PendingStore},
    wire::{
        Action, ApprovalDocument, CredentialResolver, Digest32, PolicyId, PolicyUpdateAction,
        RequestDocument, RequestId, validation,
    },
};

const CONFIG_MAX_BYTES: usize = 1024 * 1024;
const ACTIVE_MAX_BYTES: usize = 128;
const ACTIVE_PATH: &str = "policy/ACTIVE";
const BUNDLES_PATH: &str = "policy/bundles/v1";
const BUNDLE_FILES: [&str; 3] = ["approval.json", "config.toml", "request.json"];

/// The two closed policy scope kinds.
///
/// Normative source: SPEC §5.2–§5.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeType {
    Content,
    State,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeDefinition {
    #[serde(rename = "type")]
    kind: ScopeType,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct GateRequirement {
    require: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gates {
    commit: GateRequirement,
    push: GateRequirement,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyWire {
    project: String,
    gate: Gates,
    scope: BTreeMap<String, ScopeDefinition>,
}

/// One exact, strictly validated `config.toml`.
///
/// The original bytes are retained because their SHA-256 and length are part
/// of the signed policy-update request.
///
/// Normative source: SPEC §5.1–§5.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyConfig {
    bytes: Vec<u8>,
    digest: Digest32,
    wire: PolicyWire,
}

impl PolicyConfig {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > CONFIG_MAX_BYTES {
            return Err(Error::PolicyInvalid(format!(
                "config.toml is {} bytes; maximum is {CONFIG_MAX_BYTES}",
                bytes.len()
            )));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|error| Error::PolicyInvalid(format!("config.toml is not UTF-8: {error}")))?;
        let wire: PolicyWire = toml::from_str(text)
            .map_err(|error| Error::PolicyInvalid(format!("invalid strict TOML: {error}")))?;
        validate_policy(&wire)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            digest: sha256(bytes),
            wire,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn digest(&self) -> Digest32 {
        self.digest
    }

    pub fn project(&self) -> &str {
        &self.wire.project
    }

    pub fn scope_type(&self, name: &str) -> Option<ScopeType> {
        self.wire.scope.get(name).map(|scope| scope.kind)
    }

    pub fn commit_requirements(&self) -> &[String] {
        &self.wire.gate.commit.require
    }

    pub fn push_requirements(&self) -> &[String] {
        &self.wire.gate.push.require
    }
}

/// The exact three-file bundle selected by `policy/ACTIVE`.
///
/// Normative source: SPEC §5.1.
#[derive(Debug, Clone)]
pub struct ActivePolicy {
    id: PolicyId,
    config: PolicyConfig,
    request: RequestDocument,
    approval: ApprovalDocument,
}

impl ActivePolicy {
    pub fn id(&self) -> &PolicyId {
        &self.id
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    pub fn request(&self) -> &RequestDocument {
        &self.request
    }

    pub fn approval(&self) -> &ApprovalDocument {
        &self.approval
    }
}

/// Capability-bound policy authority.
///
/// This layer has no git, gate, CLI, daemon, or status behavior. Later gate
/// layers consume the loaded `ActivePolicy`.
///
/// Every entry point here holds `.policy.lock` for its whole duration, and the
/// two that reach the pending transport take `.pending.lock` inside it. That
/// nesting is one-way: nothing under `pending` acquires the policy lock, so the
/// pair cannot invert into a cycle.
///
/// Normative source: SPEC §5.
pub struct PolicyStore<'a> {
    root: &'a TrustedRoot,
}

impl<'a> PolicyStore<'a> {
    pub fn new(root: &'a TrustedRoot) -> Self {
        Self { root }
    }

    /// Loads and verifies the only authoritative policy bundle.
    ///
    /// Normative source: SPEC §5.1.
    pub fn load(&self, resolver: &impl CredentialResolver) -> Result<ActivePolicy> {
        let _lock = self.root.lock(".policy.lock")?;
        self.load_locked(resolver)
    }

    fn load_locked(&self, resolver: &impl CredentialResolver) -> Result<ActivePolicy> {
        let id = self
            .read_active_optional()?
            .ok_or_else(|| Error::PolicyMissing("policy/ACTIVE is absent".to_owned()))?;
        self.load_bundle_locked(&id, resolver)
    }

    /// Safely reads a candidate config and publishes its signed update request.
    ///
    /// Nonce and wall-clock time are created by `RequestDocument`; the caller
    /// supplies neither.
    ///
    /// Normative source: SPEC §5.5 steps 1–2 and §7.1.
    pub fn request_update(
        &self,
        candidate_path: &Path,
        note: String,
        resolver: &impl CredentialResolver,
    ) -> Result<PendingHandle> {
        let _lock = self.root.lock(".policy.lock")?;
        let active_id = self.read_active_optional()?;
        let active = match &active_id {
            Some(id) => Some(self.load_bundle_locked(id, resolver)?),
            None => None,
        };
        self.cleanup_residues(active_id.as_ref())?;
        let candidate = read_candidate(candidate_path)?;
        if let Some(active) = &active {
            if candidate.project() != active.config().project() {
                return Err(Error::PolicyInvalid(
                    "candidate project differs from the active project".to_owned(),
                ));
            }
        }
        let config_length = u64::try_from(candidate.bytes().len())
            .map_err(|_| Error::PolicyInvalid("config length does not fit u64".to_owned()))?;
        let request = RequestDocument::new(
            candidate.project().to_owned(),
            Action::PolicyUpdate(PolicyUpdateAction {
                config_id: candidate.digest(),
                config_length,
                expected_active: active.as_ref().map(|policy| policy.id().digest()),
                note,
            }),
        )?;
        PendingStore::new(self.root).publish_request(&request)
    }

    /// Verifies the retained approval and activates its exact candidate.
    ///
    /// `ACTIVE` replacement is the sole authority commit point. Re-entering
    /// after that point completes old-bundle cleanup and pending archival.
    ///
    /// Normative source: SPEC §5.5 and §7.6.
    pub fn activate(
        &self,
        request_id: &RequestId,
        candidate_path: &Path,
        resolver: &impl CredentialResolver,
    ) -> Result<ActivePolicy> {
        let _lock = self.root.lock(".policy.lock")?;
        let current_id = self.read_active_optional()?;
        let current = match &current_id {
            Some(id) => Some(self.load_bundle_locked(id, resolver)?),
            None => None,
        };
        self.cleanup_residues(current_id.as_ref())?;
        let pending = PendingStore::new(self.root);
        let request = pending.load_retained_request(request_id)?;
        let candidate = read_candidate(candidate_path)?;
        let action = policy_action(&request)?;
        verify_candidate_binding(&candidate, action)?;
        verify_request_project(&candidate, &request)?;
        let approval = pending.accept_candidates(request_id, resolver)?;

        let target_id = PolicyId::from_digest(request.sha256());

        if current_id.as_ref() == Some(&target_id) {
            let active = self.load_bundle_locked(&target_id, resolver)?;
            self.remove_previous_bundle(action.expected_active, &target_id)?;
            pending.archive_verified_pair(&request, &approval, resolver)?;
            return Ok(active);
        }

        let observed = current_id.as_ref().map(|id| id.digest());
        if observed != action.expected_active {
            return Err(Error::AuthorityConflict(
                "policy ACTIVE changed since the request was created".to_owned(),
            ));
        }
        if let Some(current) = &current {
            if current.config().project() != candidate.project() {
                return Err(Error::PolicyInvalid(
                    "candidate project differs from the active project".to_owned(),
                ));
            }
        }

        self.write_bundle(&target_id, &candidate, &request, &approval)?;
        // Verify all three exact files and the registered direct signer before
        // making the bundle authoritative.
        self.load_bundle_locked(&target_id, resolver)?;

        let active_bytes = format!("{target_id}\n").into_bytes();
        match self
            .root
            .publish_file(Path::new(ACTIVE_PATH), &active_bytes, true)?
        {
            PublishOutcome::Published => {}
            PublishOutcome::Existing => {
                return Err(Error::AuthorityConflict(
                    "ACTIVE atomic replacement did not publish".to_owned(),
                ));
            }
        }
        if self.root.read_file(ACTIVE_PATH, ACTIVE_MAX_BYTES)? != active_bytes {
            return Err(Error::AuthorityConflict(
                "ACTIVE readback differs from the committed bytes".to_owned(),
            ));
        }

        self.remove_previous_bundle(action.expected_active, &target_id)?;
        pending.archive_verified_pair(&request, &approval, resolver)?;
        self.load_bundle_locked(&target_id, resolver)
    }

    fn load_bundle_locked(
        &self,
        id: &PolicyId,
        resolver: &impl CredentialResolver,
    ) -> Result<ActivePolicy> {
        let directory = bundle_path(id);
        let config_bytes =
            read_policy_file(self.root, &directory.join("config.toml"), CONFIG_MAX_BYTES)?;
        let request_bytes = read_policy_file(
            self.root,
            &directory.join("request.json"),
            crate::wire::REQUEST_MAX_BYTES,
        )?;
        let approval_bytes = read_policy_file(
            self.root,
            &directory.join("approval.json"),
            crate::wire::APPROVAL_MAX_BYTES,
        )?;

        let config = PolicyConfig::parse(&config_bytes)?;
        let request = RequestDocument::parse(&request_bytes).map_err(as_policy_invalid)?;
        let approval = ApprovalDocument::parse(&approval_bytes).map_err(as_policy_invalid)?;
        if request.sha256() != id.digest() {
            return Err(Error::PolicyInvalid(
                "ACTIVE, bundle directory, and request digest differ".to_owned(),
            ));
        }
        let action = policy_action(&request)?;
        verify_candidate_binding(&config, action)?;
        verify_request_project(&config, &request)?;
        approval
            .verify(&request, resolver)
            .map_err(as_policy_invalid)?;
        Ok(ActivePolicy {
            id: id.clone(),
            config,
            request,
            approval,
        })
    }

    fn write_bundle(
        &self,
        id: &PolicyId,
        config: &PolicyConfig,
        request: &RequestDocument,
        approval: &ApprovalDocument,
    ) -> Result<()> {
        let directory = bundle_path(id);
        for (name, bytes) in [
            ("config.toml", config.bytes()),
            ("request.json", request.bytes()),
            ("approval.json", approval.bytes()),
        ] {
            let path = directory.join(name);
            match self.root.publish_file(&path, bytes, false)? {
                PublishOutcome::Published => {}
                PublishOutcome::Existing => {
                    let existing = self.root.read_file(&path, bytes.len())?;
                    if existing != bytes {
                        return Err(Error::AuthorityConflict(format!(
                            "policy bundle file {name} conflicts with the approved bytes"
                        )));
                    }
                }
            }
        }
        self.root.sync_directory(&directory)
    }

    fn read_active_optional(&self) -> Result<Option<PolicyId>> {
        let bytes = match self.root.read_file(ACTIVE_PATH, ACTIVE_MAX_BYTES) {
            Ok(bytes) => bytes,
            Err(Error::Io {
                kind: std::io::ErrorKind::NotFound,
                ..
            }) => return Ok(None),
            Err(error @ Error::EncodedLengthExceeded { .. }) => {
                return Err(policy_artifact_read_error(Path::new(ACTIVE_PATH), error));
            }
            Err(error) => return Err(error),
        };
        let line = bytes
            .strip_suffix(b"\n")
            .ok_or_else(|| Error::PolicyInvalid("ACTIVE must end in one newline".to_owned()))?;
        if line.contains(&b'\n') {
            return Err(Error::PolicyInvalid(
                "ACTIVE must contain exactly one line".to_owned(),
            ));
        }
        let text = std::str::from_utf8(line)
            .map_err(|_| Error::PolicyInvalid("ACTIVE is not UTF-8".to_owned()))?;
        text.parse().map(Some).map_err(as_policy_invalid)
    }

    fn cleanup_residues(&self, active: Option<&PolicyId>) -> Result<()> {
        match self.root.cleanup_temporary_entries(Path::new(BUNDLES_PATH)) {
            Ok(())
            | Err(Error::Io {
                kind: std::io::ErrorKind::NotFound,
                ..
            }) => {}
            Err(error) => return Err(error),
        }
        let entries = match self.root.entries(Path::new(BUNDLES_PATH)) {
            Ok(entries) => entries,
            Err(Error::Io {
                kind: std::io::ErrorKind::NotFound,
                ..
            }) => return Ok(()),
            Err(error) => return Err(error),
        };
        for name in entries {
            if is_authority_temporary_name(&name) {
                continue;
            }
            let text = name.to_str().ok_or_else(|| {
                Error::PolicyInvalid("policy bundle name is not UTF-8".to_owned())
            })?;
            validation::lower_hex(text, 32, "policy_bundle").map_err(as_policy_invalid)?;
            if active.is_some_and(|id| id.digest().to_hex() == text) {
                continue;
            }
            self.remove_bundle_directory(Path::new(BUNDLES_PATH).join(&name))?;
        }
        Ok(())
    }

    fn remove_previous_bundle(&self, previous: Option<Digest32>, current: &PolicyId) -> Result<()> {
        if let Some(previous) = previous {
            if previous != current.digest() {
                self.remove_bundle_directory(Path::new(BUNDLES_PATH).join(previous.to_hex()))?;
            }
        }
        Ok(())
    }

    /// Removes one bundle directory only after every non-temporary entry in it is
    /// recognized.
    ///
    /// The two passes are deliberate: the first recognizes all non-temporary
    /// entries — removing recognized temporary residue as it goes — and the second
    /// deletes the bundle files. An unknown entry therefore aborts before any
    /// authority file is removed, so the directory is never left partially emptied
    /// of its bundle.
    fn remove_bundle_directory(&self, directory: PathBuf) -> Result<()> {
        let entries = match self.root.entries(&directory) {
            Ok(entries) => entries,
            Err(Error::Io {
                kind: std::io::ErrorKind::NotFound,
                ..
            }) => return Ok(()),
            Err(error) => return Err(error),
        };
        for name in &entries {
            if is_authority_temporary_name(name) {
                let _ = self.root.remove_file(&directory.join(name));
                continue;
            }
            if !BUNDLE_FILES
                .iter()
                .any(|expected| name == OsStr::new(expected))
            {
                return Err(Error::PolicyInvalid(format!(
                    "unknown entry in policy bundle: {}",
                    name.to_string_lossy()
                )));
            }
        }
        for name in entries {
            if !is_authority_temporary_name(&name) {
                self.root.remove_file(&directory.join(name))?;
            }
        }
        self.root.remove_empty_directory(&directory)
    }
}

fn read_candidate(path: &Path) -> Result<PolicyConfig> {
    let (root, name) = TrustedRoot::open_operator_parent(path)?;
    let bytes = root.read_file(Path::new(&name), CONFIG_MAX_BYTES)?;
    PolicyConfig::parse(&bytes)
}

fn read_policy_file(root: &TrustedRoot, path: &Path, maximum: usize) -> Result<Vec<u8>> {
    root.read_file(path, maximum)
        .map_err(|error| policy_artifact_read_error(path, error))
}

fn policy_artifact_read_error(path: &Path, error: Error) -> Error {
    match error {
        Error::Io {
            kind: std::io::ErrorKind::NotFound,
            ..
        } => Error::PolicyInvalid(format!("required policy file {} is absent", path.display())),
        Error::EncodedLengthExceeded { maximum, actual } => Error::PolicyInvalid(format!(
            "policy file {} is {actual} bytes; maximum is {maximum}",
            path.display()
        )),
        other => other,
    }
}

fn validate_policy(wire: &PolicyWire) -> Result<()> {
    validation::project(&wire.project).map_err(as_policy_invalid)?;
    for name in wire.scope.keys() {
        validation::scope(name).map_err(as_policy_invalid)?;
    }
    validate_requirements(
        "gate.commit.require",
        &wire.gate.commit.require,
        &wire.scope,
    )?;
    validate_requirements("gate.push.require", &wire.gate.push.require, &wire.scope)?;
    for name in &wire.gate.commit.require {
        if wire.scope[name].kind != ScopeType::Content {
            return Err(Error::PolicyInvalid(format!(
                "commit requirement {name} is not a content scope"
            )));
        }
    }
    Ok(())
}

fn validate_requirements(
    field: &'static str,
    values: &[String],
    scopes: &BTreeMap<String, ScopeDefinition>,
) -> Result<()> {
    if values.is_empty() {
        return Err(Error::PolicyInvalid(format!("{field} must be non-empty")));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validation::scope(value).map_err(as_policy_invalid)?;
        if !seen.insert(value) {
            return Err(Error::PolicyInvalid(format!(
                "{field} contains duplicate scope {value}"
            )));
        }
        if !scopes.contains_key(value) {
            return Err(Error::PolicyInvalid(format!(
                "{field} references undeclared scope {value}"
            )));
        }
    }
    Ok(())
}

fn policy_action(request: &RequestDocument) -> Result<&PolicyUpdateAction> {
    match &request.request().action {
        Action::PolicyUpdate(action) => Ok(action),
        _ => Err(Error::PolicyInvalid(
            "policy bundle request is not policy-update".to_owned(),
        )),
    }
}

fn verify_candidate_binding(config: &PolicyConfig, action: &PolicyUpdateAction) -> Result<()> {
    let length = u64::try_from(config.bytes().len())
        .map_err(|_| Error::PolicyInvalid("config length does not fit u64".to_owned()))?;
    if action.config_id != config.digest() || action.config_length != length {
        return Err(Error::PolicyInvalid(
            "policy request config digest or length does not match config.toml".to_owned(),
        ));
    }
    Ok(())
}

/// Ties the signed request to the project its own `config.toml` declares.
///
/// Credential resolution is keyed by the request's project, so this equality is
/// what keeps that lookup pointed at the config's project: without it a request
/// naming project A could carry a config for project B and be approved by A's
/// enrolled signers.
fn verify_request_project(config: &PolicyConfig, request: &RequestDocument) -> Result<()> {
    if request.request().project != config.project() {
        return Err(Error::PolicyInvalid(
            "policy request project differs from config.toml".to_owned(),
        ));
    }
    Ok(())
}

fn bundle_path(id: &PolicyId) -> PathBuf {
    Path::new(BUNDLES_PATH).join(id.digest().to_hex())
}

fn sha256(bytes: &[u8]) -> Digest32 {
    Digest32::from_bytes(Sha256::digest(bytes).into())
}

fn as_policy_invalid(error: Error) -> Error {
    match error {
        Error::Io { .. } | Error::UnsupportedPlatform(_) => error,
        Error::PolicyMissing(_) | Error::PolicyInvalid(_) => error,
        other => Error::PolicyInvalid(other.to_string()),
    }
}
