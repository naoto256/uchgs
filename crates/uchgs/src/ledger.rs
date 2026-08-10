//! Durable append-only judgment records.
//!
//! Normative source: SPEC §6 and §14.

use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    Error, Result,
    authority_file::{PublishOutcome, TrustedRoot},
    extract::{UnitId, UnitKind},
    wire::{
        APPROVAL_MAX_BYTES, Action, ApprovalDocument, CredentialResolver, Digest32,
        ObjectFormatName, PolicyId, PushIntentId, REQUEST_MAX_BYTES, RequestDocument, RequestId,
        SourceName, WireValidate,
    },
};

const RECORD_MAX_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum ContentProvenance {
    #[serde(rename = "staged")]
    Staged {
        object_format: ObjectFormatName,
        staged_tree: String,
    },
    #[serde(rename = "push")]
    Push { push_intent: PushIntentId },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum TreeProvenance {
    #[serde(rename = "staged")]
    Staged {
        object_format: ObjectFormatName,
        staged_tree: String,
        tree_oid: String,
    },
    #[serde(rename = "push")]
    Push {
        push_intent: PushIntentId,
        tree_oid: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentJudgment {
    pub approval_sha256: Digest32,
    pub date: String,
    pub judgment_id: Digest32,
    pub note: String,
    pub policy: PolicyId,
    pub provenance: ContentProvenance,
    pub request_id: RequestId,
    pub request_sha256: Digest32,
    pub scope: String,
}

#[derive(Serialize)]
struct ContentJudgmentPreimage<'a> {
    approval_sha256: Digest32,
    date: &'a str,
    note: &'a str,
    policy: &'a PolicyId,
    provenance: &'a ContentProvenance,
    request_id: &'a RequestId,
    request_sha256: Digest32,
    scope: &'a str,
}

impl ContentJudgment {
    fn new(
        request: &RequestDocument,
        approval: &ApprovalDocument,
        action: &crate::wire::AttestContentAction,
    ) -> Result<Self> {
        Self::new_at(request, approval, action, wall_clock_nanoseconds()?)
    }

    fn new_at(
        request: &RequestDocument,
        approval: &ApprovalDocument,
        action: &crate::wire::AttestContentAction,
        date: String,
    ) -> Result<Self> {
        let provenance = match action.source {
            SourceName::Staged => ContentProvenance::Staged {
                object_format: action.object_format,
                staged_tree: action.staged_tree.clone().ok_or_else(|| {
                    Error::field("staged_tree", "is required for staged provenance")
                })?,
            },
            SourceName::Push => ContentProvenance::Push {
                push_intent: action.push_intent.clone().ok_or_else(|| {
                    Error::field("push_intent", "is required for push provenance")
                })?,
            },
        };
        let mut judgment = Self {
            approval_sha256: approval.sha256(),
            date,
            judgment_id: Digest32::from_bytes([0; 32]),
            note: action.note.clone(),
            policy: action.policy.clone(),
            provenance,
            request_id: request.id().clone(),
            request_sha256: request.sha256(),
            scope: action.scope.clone(),
        };
        judgment.judgment_id = judgment.recompute_id()?;
        Ok(judgment)
    }

    fn recompute_id(&self) -> Result<Digest32> {
        canonical_digest(&ContentJudgmentPreimage {
            approval_sha256: self.approval_sha256,
            date: &self.date,
            note: &self.note,
            policy: &self.policy,
            provenance: &self.provenance,
            request_id: &self.request_id,
            request_sha256: self.request_sha256,
            scope: &self.scope,
        })
    }

    fn validate(&self) -> Result<()> {
        crate::wire::validation::timestamp(&self.date, "date")?;
        crate::wire::validation::note(&self.note)?;
        crate::wire::validation::scope(&self.scope)?;
        if self.request_id.digest() != self.request_sha256
            || self.recompute_id()? != self.judgment_id
        {
            return Err(Error::field("judgment", "identity fields are inconsistent"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_hex: Option<String>,
    pub judgments: Vec<ContentJudgment>,
    pub kind: String,
    pub length: u64,
    pub schema: u64,
    pub sha256: Digest32,
    pub unit_kind: String,
}

impl WireValidate for UnitRecord {
    fn validate(&self) -> Result<()> {
        if self.schema != 1 || self.kind != "unit-record" {
            return Err(Error::field(
                "unit_record",
                "schema/kind must be 1/`unit-record`",
            ));
        }
        let kind: UnitKind = self.unit_kind.parse()?;
        match kind {
            UnitKind::Path | UnitKind::Ref => {
                let encoded = self.bytes_hex.as_deref().ok_or_else(|| {
                    Error::field("unit_record.bytes_hex", "is required for path/ref")
                })?;
                if encoded.len() % 2 != 0
                    || !encoded
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(Error::field("unit_record.bytes_hex", "must be lower hex"));
                }
                let bytes = hex::decode(encoded)
                    .map_err(|error| Error::field("unit_record.bytes_hex", error.to_string()))?;
                if bytes.len() as u64 != self.length
                    || Digest32::from_bytes(Sha256::digest(&bytes).into()) != self.sha256
                {
                    return Err(Error::field(
                        "unit_record",
                        "bytes_hex does not match length and sha256",
                    ));
                }
            }
            UnitKind::File | UnitKind::Commit | UnitKind::Tag if self.bytes_hex.is_none() => {}
            _ => {
                return Err(Error::field(
                    "unit_record.bytes_hex",
                    "must be absent for file/commit/tag",
                ));
            }
        }
        if self.judgments.is_empty() {
            return Err(Error::field("judgments", "must be non-empty"));
        }
        let mut scopes = std::collections::BTreeSet::new();
        for judgment in &self.judgments {
            judgment.validate()?;
            if !scopes.insert(&judgment.scope) {
                return Err(Error::field("judgments", "contains duplicate scope"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateJudgment {
    pub approval_sha256: Digest32,
    pub date: String,
    pub note: String,
    pub policy: PolicyId,
    pub provenance: TreeProvenance,
    pub request_id: RequestId,
    pub request_sha256: Digest32,
    pub scope: String,
    pub state_judgment_id: Digest32,
}

#[derive(Serialize)]
struct StateJudgmentPreimage<'a> {
    approval_sha256: Digest32,
    date: &'a str,
    note: &'a str,
    policy: &'a PolicyId,
    provenance: &'a TreeProvenance,
    request_id: &'a RequestId,
    request_sha256: Digest32,
    scope: &'a str,
}

impl StateJudgment {
    fn new(
        request: &RequestDocument,
        approval: &ApprovalDocument,
        action: &crate::wire::AttestTreeAction,
    ) -> Result<Self> {
        Self::new_at(request, approval, action, wall_clock_nanoseconds()?)
    }

    fn new_at(
        request: &RequestDocument,
        approval: &ApprovalDocument,
        action: &crate::wire::AttestTreeAction,
        date: String,
    ) -> Result<Self> {
        let provenance = match &action.push_intent {
            Some(push_intent) => TreeProvenance::Push {
                push_intent: push_intent.clone(),
                tree_oid: action.tree_oid.clone(),
            },
            None => TreeProvenance::Staged {
                object_format: action.object_format,
                staged_tree: action.tree_oid.clone(),
                tree_oid: action.tree_oid.clone(),
            },
        };
        let mut judgment = Self {
            approval_sha256: approval.sha256(),
            date,
            note: action.note.clone(),
            policy: action.policy.clone(),
            provenance,
            request_id: request.id().clone(),
            request_sha256: request.sha256(),
            scope: action.scope.clone(),
            state_judgment_id: Digest32::from_bytes([0; 32]),
        };
        judgment.state_judgment_id = judgment.recompute_id()?;
        Ok(judgment)
    }

    fn recompute_id(&self) -> Result<Digest32> {
        canonical_digest(&StateJudgmentPreimage {
            approval_sha256: self.approval_sha256,
            date: &self.date,
            note: &self.note,
            policy: &self.policy,
            provenance: &self.provenance,
            request_id: &self.request_id,
            request_sha256: self.request_sha256,
            scope: &self.scope,
        })
    }

    fn validate(&self) -> Result<()> {
        crate::wire::validation::timestamp(&self.date, "date")?;
        crate::wire::validation::note(&self.note)?;
        crate::wire::validation::scope(&self.scope)?;
        if self.request_id.digest() != self.request_sha256
            || self.recompute_id()? != self.state_judgment_id
        {
            return Err(Error::field(
                "state_judgment",
                "identity fields are inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeRecord {
    pub judgments: Vec<StateJudgment>,
    pub kind: String,
    pub schema: u64,
    pub sha256: Digest32,
}

impl WireValidate for TreeRecord {
    fn validate(&self) -> Result<()> {
        if self.schema != 1 || self.kind != "tree-record" {
            return Err(Error::field(
                "tree_record",
                "schema/kind must be 1/`tree-record`",
            ));
        }
        if self.judgments.is_empty() {
            return Err(Error::field("judgments", "must be non-empty"));
        }
        let mut scopes = std::collections::BTreeSet::new();
        for judgment in &self.judgments {
            judgment.validate()?;
            if !scopes.insert(&judgment.scope) {
                return Err(Error::field("judgments", "contains duplicate scope"));
            }
        }
        Ok(())
    }
}

/// Capability-bound append-only ledger.
///
/// Normative source: SPEC §6.
pub struct Ledger<'a> {
    root: &'a TrustedRoot,
}

impl<'a> Ledger<'a> {
    pub fn new(root: &'a TrustedRoot) -> Self {
        Self { root }
    }

    pub fn validate_layout(&self) -> Result<()> {
        let entries = match self.root.entries(std::path::Path::new("ledger")) {
            Ok(entries) => entries,
            Err(Error::Io {
                kind: std::io::ErrorKind::NotFound,
                ..
            }) => return Ok(()),
            Err(error) => return Err(error),
        };
        for entry in entries {
            let name = entry.to_string_lossy();
            if name.starts_with(".tmp-") {
                continue;
            }
            if name != "unit" && name != "tree" {
                return Err(Error::AuthorityConflict(format!(
                    "unexpected ledger entry `{name}`"
                )));
            }
        }
        Ok(())
    }

    /// The presence of a record is not authority. The archived Request/Approval pair
    /// is reloaded and re-verified against the current registry on every read, so a
    /// judgment whose signer no longer resolves, or whose retained bytes were altered,
    /// stops satisfying the scope instead of remaining permanently satisfied on disk.
    pub fn has_unit_scope(
        &self,
        unit_id: &UnitId,
        scope: &str,
        resolver: &impl CredentialResolver,
    ) -> Result<bool> {
        let path = unit_record_path(unit_id);
        let Some(record) = self.read_unit(&path)? else {
            return Ok(false);
        };
        self.verify_unit_path(&record, unit_id)?;
        let Some(judgment) = record.judgments.iter().find(|item| item.scope == scope) else {
            return Ok(false);
        };
        let (request, approval) = self.load_archived_pair(judgment, resolver)?;
        self.verify_unit_judgment(&record, judgment, &request, &approval)?;
        Ok(true)
    }

    pub fn has_tree_scope(
        &self,
        digest: Digest32,
        scope: &str,
        resolver: &impl CredentialResolver,
    ) -> Result<bool> {
        let path = tree_record_path(digest);
        let Some(record) = self.read_tree(&path)? else {
            return Ok(false);
        };
        if record.sha256 != digest {
            return Err(Error::AuthorityConflict(
                "tree record path and body differ".to_owned(),
            ));
        }
        let Some(judgment) = record.judgments.iter().find(|item| item.scope == scope) else {
            return Ok(false);
        };
        let (request, approval) = self.load_archived_pair(judgment, resolver)?;
        self.verify_tree_judgment(&record, judgment, &request, &approval)?;
        Ok(true)
    }

    pub fn append_content(
        &self,
        request: &RequestDocument,
        approval: &ApprovalDocument,
        unit_id: &UnitId,
        resolver: &impl CredentialResolver,
    ) -> Result<()> {
        approval.verify(request, resolver)?;
        let Action::AttestContent(action) = &request.request().action else {
            return Err(Error::field("request.action", "must be attest-content"));
        };
        let unit = action
            .units
            .iter()
            .find(|unit| &unit.unit_id == unit_id)
            .ok_or_else(|| Error::field("unit_id", "is not present in request.action.units"))?;
        self.validate_layout()?;
        let _lock = self.root.lock(".ledger.lock")?;
        let path = unit_record_path(&unit.unit_id);
        loop {
            let current = self.read_unit(&path)?;
            if let Some(record) = &current {
                self.verify_unit_path(record, &unit.unit_id)?;
                if let Some(existing) = record
                    .judgments
                    .iter()
                    .find(|item| item.scope == action.scope)
                {
                    if existing.request_id == *request.id()
                        && existing.request_sha256 == request.sha256()
                        && existing.approval_sha256 == approval.sha256()
                    {
                        self.verify_unit_judgment(record, existing, request, approval)?;
                        return Ok(());
                    }
                    return Err(Error::AuthorityConflict(format!(
                        "unit {} already has a different judgment for scope {}",
                        unit.unit_id, action.scope
                    )));
                }
            }
            let judgment = ContentJudgment::new(request, approval, action)?;
            let mut next = current.clone().unwrap_or(UnitRecord {
                bytes_hex: unit.bytes_hex.clone(),
                judgments: Vec::new(),
                kind: "unit-record".to_owned(),
                length: unit.length,
                schema: 1,
                sha256: unit.unit_id.digest(),
                unit_kind: unit.unit_id.kind().as_str().to_owned(),
            });
            next.judgments.push(judgment);
            let bytes = encode_record(&next)?;
            if let Some(previous) = current {
                let observed = self.root.read_file(&path, RECORD_MAX_BYTES)?;
                let expected = encode_record(&previous)?;
                if observed != expected {
                    continue;
                }
                self.root.publish_file(&path, &bytes, true)?;
            } else if self.root.publish_file(&path, &bytes, false)? == PublishOutcome::Existing {
                continue;
            }
            let committed = self.read_unit(&path)?.ok_or_else(|| {
                Error::AuthorityNotFound(format!(
                    "committed unit record {} disappeared",
                    path.display()
                ))
            })?;
            if encode_record(&committed)? != bytes {
                return Err(Error::AuthorityConflict(
                    "unit record changed after publication".to_owned(),
                ));
            }
            return Ok(());
        }
    }

    pub fn append_tree(
        &self,
        request: &RequestDocument,
        approval: &ApprovalDocument,
        resolver: &impl CredentialResolver,
    ) -> Result<()> {
        approval.verify(request, resolver)?;
        let Action::AttestTree(action) = &request.request().action else {
            return Err(Error::field("request.action", "must be attest-tree"));
        };
        self.validate_layout()?;
        let _lock = self.root.lock(".ledger.lock")?;
        let path = tree_record_path(action.tree_sha256);
        loop {
            let current = self.read_tree(&path)?;
            if let Some(record) = &current {
                if record.sha256 != action.tree_sha256 {
                    return Err(Error::AuthorityConflict(
                        "tree record path and body differ".to_owned(),
                    ));
                }
                if let Some(existing) = record
                    .judgments
                    .iter()
                    .find(|item| item.scope == action.scope)
                {
                    if existing.request_id == *request.id()
                        && existing.request_sha256 == request.sha256()
                        && existing.approval_sha256 == approval.sha256()
                    {
                        self.verify_tree_judgment(record, existing, request, approval)?;
                        return Ok(());
                    }
                    return Err(Error::AuthorityConflict(format!(
                        "tree {} already has a different judgment for scope {}",
                        action.tree_sha256, action.scope
                    )));
                }
            }
            let judgment = StateJudgment::new(request, approval, action)?;
            let mut next = current.clone().unwrap_or(TreeRecord {
                judgments: Vec::new(),
                kind: "tree-record".to_owned(),
                schema: 1,
                sha256: action.tree_sha256,
            });
            next.judgments.push(judgment);
            let bytes = encode_record(&next)?;
            if let Some(previous) = current {
                let observed = self.root.read_file(&path, RECORD_MAX_BYTES)?;
                let expected = encode_record(&previous)?;
                if observed != expected {
                    continue;
                }
                self.root.publish_file(&path, &bytes, true)?;
            } else if self.root.publish_file(&path, &bytes, false)? == PublishOutcome::Existing {
                continue;
            }
            let committed = self.read_tree(&path)?.ok_or_else(|| {
                Error::AuthorityNotFound(format!(
                    "committed tree record {} disappeared",
                    path.display()
                ))
            })?;
            if encode_record(&committed)? != bytes {
                return Err(Error::AuthorityConflict(
                    "tree record changed after publication".to_owned(),
                ));
            }
            return Ok(());
        }
    }

    pub(crate) fn has_unit_scope_for_pair(
        &self,
        unit_id: &UnitId,
        request: &RequestDocument,
        approval: &ApprovalDocument,
        resolver: &impl CredentialResolver,
    ) -> Result<bool> {
        approval.verify(request, resolver)?;
        let Action::AttestContent(action) = &request.request().action else {
            return Err(Error::field("request.action", "must be attest-content"));
        };
        let path = unit_record_path(unit_id);
        let Some(record) = self.read_unit(&path)? else {
            return Ok(false);
        };
        self.verify_unit_path(&record, unit_id)?;
        let Some(judgment) = record
            .judgments
            .iter()
            .find(|judgment| judgment.scope == action.scope)
        else {
            return Ok(false);
        };
        self.verify_unit_judgment(&record, judgment, request, approval)?;
        Ok(true)
    }

    pub(crate) fn has_tree_scope_for_pair(
        &self,
        request: &RequestDocument,
        approval: &ApprovalDocument,
        resolver: &impl CredentialResolver,
    ) -> Result<bool> {
        approval.verify(request, resolver)?;
        let Action::AttestTree(action) = &request.request().action else {
            return Err(Error::field("request.action", "must be attest-tree"));
        };
        let path = tree_record_path(action.tree_sha256);
        let Some(record) = self.read_tree(&path)? else {
            return Ok(false);
        };
        if record.sha256 != action.tree_sha256 {
            return Err(Error::AuthorityConflict(
                "tree record path and body differ".to_owned(),
            ));
        }
        let Some(judgment) = record
            .judgments
            .iter()
            .find(|judgment| judgment.scope == action.scope)
        else {
            return Ok(false);
        };
        self.verify_tree_judgment(&record, judgment, request, approval)?;
        Ok(true)
    }

    fn read_unit(&self, path: &std::path::Path) -> Result<Option<UnitRecord>> {
        read_optional(self.root, path)?
            .map(|bytes| parse_record(&bytes))
            .transpose()
    }

    fn read_tree(&self, path: &std::path::Path) -> Result<Option<TreeRecord>> {
        read_optional(self.root, path)?
            .map(|bytes| parse_record(&bytes))
            .transpose()
    }

    fn verify_unit_path(&self, record: &UnitRecord, expected: &UnitId) -> Result<()> {
        if record.unit_kind != expected.kind().as_str() || record.sha256 != expected.digest() {
            return Err(Error::AuthorityConflict(
                "unit record path and body differ".to_owned(),
            ));
        }
        Ok(())
    }

    fn load_archived_pair(
        &self,
        judgment: &impl JudgmentBinding,
        resolver: &impl CredentialResolver,
    ) -> Result<(RequestDocument, ApprovalDocument)> {
        let digest = judgment.request_sha256().to_hex();
        let base = PathBuf::from("approvals/v1/sha256").join(digest);
        let request = RequestDocument::parse(
            &self
                .root
                .read_file(base.join("request.json"), REQUEST_MAX_BYTES)?,
        )?;
        let approval = ApprovalDocument::parse(
            &self
                .root
                .read_file(base.join("approval.json"), APPROVAL_MAX_BYTES)?,
        )?;
        if request.id() != judgment.request_id()
            || request.sha256() != judgment.request_sha256()
            || approval.sha256() != judgment.approval_sha256()
        {
            return Err(Error::AuthorityConflict(
                "ledger judgment and archived approval pair differ".to_owned(),
            ));
        }
        approval.verify(&request, resolver)?;
        Ok((request, approval))
    }

    fn verify_unit_judgment(
        &self,
        record: &UnitRecord,
        judgment: &ContentJudgment,
        request: &RequestDocument,
        approval: &ApprovalDocument,
    ) -> Result<()> {
        let Action::AttestContent(action) = &request.request().action else {
            return Err(Error::AuthorityConflict(
                "unit judgment request action is not attest-content".to_owned(),
            ));
        };
        let unit = action
            .units
            .iter()
            .find(|unit| {
                unit.unit_id.digest() == record.sha256
                    && unit.unit_id.kind().as_str() == record.unit_kind
            })
            .ok_or_else(|| {
                Error::AuthorityConflict(
                    "unit judgment request does not contain the recorded unit".to_owned(),
                )
            })?;
        if unit.length != record.length || unit.bytes_hex != record.bytes_hex {
            return Err(Error::AuthorityConflict(
                "unit judgment descriptor and record differ".to_owned(),
            ));
        }
        // Re-derive the judgment from the approved pair and accept only an exact match.
        // `date` is fed back in because the observation time is the one field the
        // approval does not cover; every other field must be a pure function of the
        // request and approval, so any drift means the record was not produced by this
        // authorization.
        let expected = ContentJudgment::new_at(request, approval, action, judgment.date.clone())?;
        if &expected != judgment {
            return Err(Error::AuthorityConflict(
                "unit judgment does not match its approved request".to_owned(),
            ));
        }
        Ok(())
    }

    fn verify_tree_judgment(
        &self,
        record: &TreeRecord,
        judgment: &StateJudgment,
        request: &RequestDocument,
        approval: &ApprovalDocument,
    ) -> Result<()> {
        let Action::AttestTree(action) = &request.request().action else {
            return Err(Error::AuthorityConflict(
                "tree judgment request action is not attest-tree".to_owned(),
            ));
        };
        if action.tree_sha256 != record.sha256 {
            return Err(Error::AuthorityConflict(
                "tree judgment request and record differ".to_owned(),
            ));
        }
        let expected = StateJudgment::new_at(request, approval, action, judgment.date.clone())?;
        if &expected != judgment {
            return Err(Error::AuthorityConflict(
                "tree judgment does not match its approved request".to_owned(),
            ));
        }
        Ok(())
    }
}

trait JudgmentBinding {
    fn approval_sha256(&self) -> Digest32;
    fn request_id(&self) -> &RequestId;
    fn request_sha256(&self) -> Digest32;
}

impl JudgmentBinding for ContentJudgment {
    fn approval_sha256(&self) -> Digest32 {
        self.approval_sha256
    }
    fn request_id(&self) -> &RequestId {
        &self.request_id
    }
    fn request_sha256(&self) -> Digest32 {
        self.request_sha256
    }
}

impl JudgmentBinding for StateJudgment {
    fn approval_sha256(&self) -> Digest32 {
        self.approval_sha256
    }
    fn request_id(&self) -> &RequestId {
        &self.request_id
    }
    fn request_sha256(&self) -> Digest32 {
        self.request_sha256
    }
}

fn unit_record_path(unit_id: &UnitId) -> PathBuf {
    PathBuf::from("ledger/unit/v1/sha256")
        .join(unit_id.kind().as_str())
        .join(format!("{}.json", unit_id.digest()))
}

fn tree_record_path(digest: Digest32) -> PathBuf {
    PathBuf::from("ledger/tree/v1/sha256").join(format!("{digest}.json"))
}

fn read_optional(root: &TrustedRoot, path: &std::path::Path) -> Result<Option<Vec<u8>>> {
    match root.read_file(path, RECORD_MAX_BYTES) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(Error::Io {
            kind: std::io::ErrorKind::NotFound,
            ..
        }) => Ok(None),
        Err(error) => Err(error),
    }
}

fn parse_record<T>(bytes: &[u8]) -> Result<T>
where
    T: serde::de::DeserializeOwned + Serialize + WireValidate + Clone,
{
    Ok(crate::wire::ExactJson::<T>::parse(bytes, RECORD_MAX_BYTES)?
        .value()
        .clone())
}

fn encode_record<T>(value: &T) -> Result<Vec<u8>>
where
    T: serde::de::DeserializeOwned + Serialize + WireValidate + Clone,
{
    Ok(
        crate::wire::ExactJson::encode(value.clone(), RECORD_MAX_BYTES)?
            .bytes()
            .to_vec(),
    )
}

fn canonical_digest(value: &impl Serialize) -> Result<Digest32> {
    let bytes = serde_json_canonicalizer::to_vec(value)
        .map_err(|error| Error::field("judgment", error.to_string()))?;
    Ok(Digest32::from_bytes(Sha256::digest(bytes).into()))
}

fn wall_clock_nanoseconds() -> Result<String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::field("date", "system clock precedes Unix epoch"))?
        .as_nanos()
        .to_string())
}
