//! Durable pending Request/Approval transport and judgment reconciliation.
//!
//! Normative source: SPEC §7.5, §7.6, §9.3, and §14.

use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::{
    Error, Result,
    authority_file::{PublishOutcome, TrustedRoot, is_authority_temporary_name},
    ledger::Ledger,
    wire::{
        APPROVAL_MAX_BYTES, Action, ApprovalDocument, CredentialResolver, Digest32,
        REQUEST_MAX_BYTES, RequestDocument, RequestId,
    },
};

pub const DEFAULT_APPROVAL_TIMEOUT: Duration = Duration::from_secs(600);

/// Process-local monotonic anchor taken only after request publication.
///
/// Normative source: SPEC §7.5 steps 1-2.
pub struct PendingHandle {
    request_id: RequestId,
    started: Instant,
}

impl PendingHandle {
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

#[derive(Debug, Clone)]
pub enum ExpirationOutcome {
    Pending,
    Approved(Box<ApprovalDocument>),
    TimedOut,
}

/// Capability-bound pending transport.
///
/// This type accepts already-constructed auditor Requests and already-signed
/// Approval bytes. It does not expose a gate/author-side request generator or
/// a signing surface.
///
/// Normative source: SPEC §7.
pub struct PendingStore<'a> {
    root: &'a TrustedRoot,
}

impl<'a> PendingStore<'a> {
    pub fn new(root: &'a TrustedRoot) -> Self {
        Self { root }
    }

    pub fn publish_request(&self, request: &RequestDocument) -> Result<PendingHandle> {
        let _lock = self.root.lock(".pending.lock")?;
        let id = request.id();
        if self.exists(&terminal_request_path(id))? || self.exists(&approved_request_path(id))? {
            return Err(Error::AuthorityConflict(format!(
                "request {id} has already reached a terminal state"
            )));
        }
        let path = pending_request_path(id);
        match self.root.publish_file(&path, request.bytes(), false)? {
            PublishOutcome::Published => {}
            PublishOutcome::Existing => {
                let existing = self.root.read_file(&path, REQUEST_MAX_BYTES)?;
                if existing != request.bytes() {
                    return Err(Error::AuthorityConflict(format!(
                        "request {id} conflicts with the existing exact bytes"
                    )));
                }
            }
        }
        // The monotonic sample intentionally occurs after the durable write.
        Ok(PendingHandle {
            request_id: id.clone(),
            started: Instant::now(),
        })
    }

    /// Loads the exact request bytes retained by the pending transport.
    ///
    /// Policy activation uses this crate-private seam to resume the same
    /// approved operation without duplicating the §7.5 path grammar. The
    /// complete approved/terminal/pending lookup is serialized with timeout
    /// transitions so no intermediate `NotFound` escapes as an I/O failure.
    ///
    /// Normative source: SPEC §5.5 and §7.5–§7.6.
    pub(crate) fn load_retained_request(&self, request_id: &RequestId) -> Result<RequestDocument> {
        let _lock = self.root.lock(".pending.lock")?;
        if self.exists(&approved_request_path(request_id))? {
            return Ok(self.load_approved_pair(request_id)?.0);
        }
        if self.exists(&terminal_request_path(request_id))? {
            return Err(Error::AuthorityConflict(format!(
                "request {request_id} is terminal"
            )));
        }
        if self.exists(&pending_request_path(request_id))? {
            return self.load_pending_request(request_id);
        }
        Err(Error::AuthorityNotFound(format!(
            "retained request {request_id} does not exist"
        )))
    }

    /// Publishes one signed approval candidate under a non-final name.
    ///
    /// Normative source: SPEC §7.5 step 3.
    pub fn stage_approval_candidate(
        &self,
        request_id: &RequestId,
        approval_bytes: &[u8],
    ) -> Result<PathBuf> {
        // Parsing before publication prevents an oversized/non-canonical blob
        // from becoming a durable candidate. Authorization remains intake's job.
        ApprovalDocument::parse(approval_bytes)?;
        let _lock = self.root.lock(".pending.lock")?;
        self.load_pending_request(request_id)?;
        if self.exists(&terminal_request_path(request_id))? {
            return Err(Error::AuthorityConflict(format!(
                "request {request_id} is terminal"
            )));
        }
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|error| Error::field("approval_candidate", error.to_string()))?;
        let path =
            pending_dir(request_id).join(format!("approval-candidate-{}.json", hex::encode(nonce)));
        match self.root.publish_file(&path, approval_bytes, false)? {
            PublishOutcome::Published => Ok(path),
            PublishOutcome::Existing => Err(Error::AuthorityConflict(
                "random approval candidate name collided".to_owned(),
            )),
        }
    }

    /// Builds and publishes a delegated candidate while holding the pending
    /// lock, so the approval timestamp is observed only after that lock is held.
    ///
    /// Normative source: SPEC §9.3 step 4 and §7.5 step 3.
    pub(crate) fn stage_delegated_candidate(
        &self,
        request_id: &RequestId,
        build: impl FnOnce(&RequestDocument) -> Result<ApprovalDocument>,
    ) -> Result<PathBuf> {
        let _lock = self.root.lock(".pending.lock")?;
        let request = self.load_pending_request(request_id)?;
        if self.exists(&terminal_request_path(request_id))? {
            return Err(Error::AuthorityConflict(format!(
                "request {request_id} is terminal"
            )));
        }
        let approval = build(&request)?;
        ApprovalDocument::parse(approval.bytes())?;
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|error| Error::field("approval_candidate", error.to_string()))?;
        let path =
            pending_dir(request_id).join(format!("approval-candidate-{}.json", hex::encode(nonce)));
        match self.root.publish_file(&path, approval.bytes(), false)? {
            PublishOutcome::Published => Ok(path),
            PublishOutcome::Existing => Err(Error::AuthorityConflict(
                "random approval candidate name collided".to_owned(),
            )),
        }
    }

    /// Selects the first valid candidate under the pending lock. Invalid
    /// candidates are removed and cannot poison a later valid candidate.
    ///
    /// Normative source: SPEC §7.5 step 3.
    pub fn accept_candidates(
        &self,
        request_id: &RequestId,
        resolver: &impl CredentialResolver,
    ) -> Result<ApprovalDocument> {
        let _lock = self.root.lock(".pending.lock")?;
        if self.exists(&approved_request_path(request_id))? {
            let (request, winner) = self.load_approved_pair(request_id)?;
            winner.verify(&request, resolver)?;
            return Ok(winner);
        }
        if self.exists(&terminal_request_path(request_id))? {
            return Err(Error::AuthorityConflict(format!(
                "request {request_id} has timed out"
            )));
        }
        let request = self.load_pending_request(request_id)?;
        if let Some(winner) = self.load_pending_approval(request_id)? {
            winner.verify(&request, resolver)?;
            return Ok(winner);
        }

        for name in self.root.entries(&pending_dir(request_id))? {
            let name_text = name.to_string_lossy();
            if !name_text.starts_with("approval-candidate-") || !name_text.ends_with(".json") {
                continue;
            }
            let path = pending_dir(request_id).join(&name);
            let bytes = self.root.read_file(&path, APPROVAL_MAX_BYTES)?;
            let candidate = match ApprovalDocument::parse(&bytes) {
                Ok(candidate) => candidate,
                Err(_) => {
                    // A failed cleanup must not replace the authorization
                    // verdict or prevent subsequent candidates from being read.
                    let _ = self.root.remove_file(&path);
                    continue;
                }
            };
            match candidate.verify(&request, resolver) {
                Ok(()) => {}
                Err(error @ (Error::Io { .. } | Error::UnsupportedPlatform(_))) => {
                    return Err(error);
                }
                Err(_) => {
                    // Only a proven validation failure makes this candidate
                    // disposable. Resolver substrate failures remain retryable.
                    let _ = self.root.remove_file(&path);
                    continue;
                }
            }
            let final_path = pending_approval_path(request_id);
            match self
                .root
                .publish_file(&final_path, candidate.bytes(), false)?
            {
                PublishOutcome::Published => {
                    let _ = self.root.remove_file(&path);
                    return Ok(candidate);
                }
                PublishOutcome::Existing => {
                    let winner = self.load_pending_approval(request_id)?.ok_or_else(|| {
                        Error::AuthorityNotFound("approval winner disappeared".to_owned())
                    })?;
                    winner.verify(&request, resolver)?;
                    return Ok(winner);
                }
            }
        }
        Err(Error::AuthorityNotFound(format!(
            "no valid approval candidate exists for {request_id}"
        )))
    }

    /// Applies the durable timeout transition when the process-local monotonic
    /// deadline has elapsed.
    ///
    /// Normative source: SPEC §7.5 step 4.
    pub fn expire_if_due(
        &self,
        handle: &PendingHandle,
        timeout: Duration,
        resolver: &impl CredentialResolver,
    ) -> Result<ExpirationOutcome> {
        if handle.elapsed() < timeout {
            return Ok(ExpirationOutcome::Pending);
        }
        let _lock = self.root.lock(".pending.lock")?;
        if self.exists(&approved_request_path(&handle.request_id))? {
            let (request, winner) = self.load_approved_pair(&handle.request_id)?;
            winner.verify(&request, resolver)?;
            return Ok(ExpirationOutcome::Approved(Box::new(winner)));
        }
        if self.exists(&terminal_request_path(&handle.request_id))? {
            return Ok(ExpirationOutcome::TimedOut);
        }
        let request = self.load_pending_request(&handle.request_id)?;
        if let Some(winner) = self.load_pending_approval(&handle.request_id)? {
            winner.verify(&request, resolver)?;
            return Ok(ExpirationOutcome::Approved(Box::new(winner)));
        }
        self.remove_candidate_files(&handle.request_id)?;
        match self.root.rename_directory_no_replace(
            &pending_dir(&handle.request_id),
            &terminal_dir(&handle.request_id),
        )? {
            PublishOutcome::Published => Ok(ExpirationOutcome::TimedOut),
            PublishOutcome::Existing => Err(Error::AuthorityConflict(format!(
                "terminal request {} already exists",
                handle.request_id
            ))),
        }
    }

    /// Verifies and completes one judgment-producing pending pair, then moves
    /// the exact pair to approvals only after every requested record exists.
    ///
    /// Normative source: SPEC §6.4 and §7.6.
    pub fn finalize_judgment(
        &self,
        request_id: &RequestId,
        resolver: &impl CredentialResolver,
    ) -> Result<()> {
        let _pending_lock = self.root.lock(".pending.lock")?;
        if self.exists(&approved_request_path(request_id))? {
            let (request, approval) = self.load_approved_pair(request_id)?;
            approval.verify(&request, resolver)?;
            self.verify_archived_judgments(&request, resolver)?;
            return Ok(());
        }
        let request = self.load_pending_request(request_id)?;
        let approval = self.load_pending_approval(request_id)?.ok_or_else(|| {
            Error::AuthorityNotFound(format!("approval.json is absent for {request_id}"))
        })?;
        approval.verify(&request, resolver)?;

        let ledger = Ledger::new(self.root);
        match &request.request().action {
            Action::AttestContent(action) => {
                for unit in &action.units {
                    if !ledger.has_unit_scope_for_pair(
                        &unit.unit_id,
                        &request,
                        &approval,
                        resolver,
                    )? {
                        ledger.append_content(&request, &approval, &unit.unit_id, resolver)?;
                    }
                }
                for unit in &action.units {
                    if !ledger.has_unit_scope_for_pair(
                        &unit.unit_id,
                        &request,
                        &approval,
                        resolver,
                    )? {
                        return Err(Error::AuthorityNotFound(format!(
                            "unit record {} is still missing after finalization",
                            unit.unit_id
                        )));
                    }
                }
            }
            Action::AttestTree(_) => {
                if !ledger.has_tree_scope_for_pair(&request, &approval, resolver)? {
                    ledger.append_tree(&request, &approval, resolver)?;
                }
                if !ledger.has_tree_scope_for_pair(&request, &approval, resolver)? {
                    return Err(Error::AuthorityNotFound(
                        "tree record is still missing after finalization".to_owned(),
                    ));
                }
            }
            _ => {
                return Err(Error::field(
                    "finalization",
                    "this authority-core boundary finalizes only ledger-producing actions",
                ));
            }
        }

        self.remove_candidate_files(request_id)?;
        self.verify_pending_pair_contents(request_id)?;
        match self
            .root
            .rename_directory_no_replace(&pending_dir(request_id), &approved_dir(request_id))?
        {
            PublishOutcome::Published => {
                let (saved_request, saved_approval) = self.load_approved_pair(request_id)?;
                if saved_request.bytes() != request.bytes()
                    || saved_approval.bytes() != approval.bytes()
                {
                    return Err(Error::AuthorityConflict(
                        "approved pair changed across final publication".to_owned(),
                    ));
                }
                self.verify_archived_judgments(&saved_request, resolver)?;
                Ok(())
            }
            PublishOutcome::Existing => Err(Error::AuthorityConflict(format!(
                "approval destination for {request_id} already exists"
            ))),
        }
    }

    /// Archives a verified non-judgment request/approval pair after its durable
    /// authority effect has been independently confirmed by the caller.
    ///
    /// Normative source: SPEC §7.6 and §8.3.
    pub(crate) fn archive_verified_pair(
        &self,
        request: &RequestDocument,
        approval: &ApprovalDocument,
        resolver: &impl CredentialResolver,
    ) -> Result<()> {
        let request_id = request.id();
        let _pending_lock = self.root.lock(".pending.lock")?;
        if self.exists(&approved_request_path(request_id))? {
            let (saved_request, saved_approval) = self.load_approved_pair(request_id)?;
            if saved_request.bytes() != request.bytes()
                || saved_approval.bytes() != approval.bytes()
            {
                return Err(Error::AuthorityConflict(
                    "archived approval pair differs from the completed operation".to_owned(),
                ));
            }
            saved_approval.verify(&saved_request, resolver)?;
            return Ok(());
        }
        let saved_request = self.load_pending_request(request_id)?;
        let saved_approval = self.load_pending_approval(request_id)?.ok_or_else(|| {
            Error::AuthorityNotFound(format!("approval.json is absent for {request_id}"))
        })?;
        if saved_request.bytes() != request.bytes() || saved_approval.bytes() != approval.bytes() {
            return Err(Error::AuthorityConflict(
                "pending approval pair differs from the completed operation".to_owned(),
            ));
        }
        saved_approval.verify(&saved_request, resolver)?;
        self.remove_candidate_files(request_id)?;
        self.verify_pending_pair_contents(request_id)?;
        match self
            .root
            .rename_directory_no_replace(&pending_dir(request_id), &approved_dir(request_id))?
        {
            PublishOutcome::Published => Ok(()),
            PublishOutcome::Existing => Err(Error::AuthorityConflict(format!(
                "approval destination for {request_id} already exists"
            ))),
        }
    }

    fn verify_archived_judgments(
        &self,
        request: &RequestDocument,
        resolver: &impl CredentialResolver,
    ) -> Result<()> {
        let ledger = Ledger::new(self.root);
        match &request.request().action {
            Action::AttestContent(action) => {
                for unit in &action.units {
                    if !ledger.has_unit_scope(&unit.unit_id, &action.scope, resolver)? {
                        return Err(Error::AuthorityNotFound(format!(
                            "unit record {} is absent from an archived approval",
                            unit.unit_id
                        )));
                    }
                }
                Ok(())
            }
            Action::AttestTree(action) => {
                if !ledger.has_tree_scope(action.tree_sha256, &action.scope, resolver)? {
                    return Err(Error::AuthorityNotFound(
                        "tree record is absent from an archived approval".to_owned(),
                    ));
                }
                Ok(())
            }
            _ => Err(Error::field(
                "finalization",
                "this authority-core boundary finalizes only ledger-producing actions",
            )),
        }
    }

    /// Reconciles all complete pending judgment pairs. Incomplete requests are
    /// left pending; invalid pairs fail without deletion.
    ///
    /// Normative source: SPEC §7.6.
    pub fn reconcile_judgments(&self, resolver: &impl CredentialResolver) -> Result<usize> {
        let base = Path::new("pending/v1/sha256");
        let entries = match self.root.entries(base) {
            Ok(entries) => entries,
            Err(Error::Io {
                kind: std::io::ErrorKind::NotFound,
                ..
            }) => return Ok(0),
            Err(error) => return Err(error),
        };
        let mut completed = 0;
        // One unusable directory must not strand the other complete pairs, so the
        // sweep records the first failure and keeps going. That error is still
        // returned at the end, so a partially successful sweep reports failure
        // instead of a success count that hides it.
        let mut first_error = None;
        for entry in entries {
            let value = entry.to_string_lossy();
            if is_authority_temporary_name(&entry) {
                continue;
            }
            let Ok(bytes) = hex::decode(value.as_ref()) else {
                first_error.get_or_insert_with(|| {
                    Error::AuthorityConflict(format!("invalid pending request directory `{value}`"))
                });
                continue;
            };
            let Ok(digest_bytes) = <[u8; 32]>::try_from(bytes) else {
                first_error.get_or_insert_with(|| {
                    Error::AuthorityConflict(format!("invalid pending request digest `{value}`"))
                });
                continue;
            };
            let request_id = RequestId::from_digest(Digest32::from_bytes(digest_bytes));
            match self.exists(&pending_approval_path(&request_id)) {
                Ok(true) => match self.finalize_judgment(&request_id, resolver) {
                    Ok(()) => completed += 1,
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                },
                Ok(false) => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(completed),
        }
    }

    fn load_pending_request(&self, request_id: &RequestId) -> Result<RequestDocument> {
        let bytes = self
            .root
            .read_file(pending_request_path(request_id), REQUEST_MAX_BYTES)?;
        let request = RequestDocument::parse(&bytes)?;
        if request.id() != request_id {
            return Err(Error::AuthorityConflict(
                "pending request path and exact bytes disagree".to_owned(),
            ));
        }
        Ok(request)
    }

    fn load_pending_approval(&self, request_id: &RequestId) -> Result<Option<ApprovalDocument>> {
        match self
            .root
            .read_file(pending_approval_path(request_id), APPROVAL_MAX_BYTES)
        {
            Ok(bytes) => Ok(Some(ApprovalDocument::parse(&bytes)?)),
            Err(Error::Io {
                kind: std::io::ErrorKind::NotFound,
                ..
            }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn load_approved_pair(
        &self,
        request_id: &RequestId,
    ) -> Result<(RequestDocument, ApprovalDocument)> {
        let request_bytes = self
            .root
            .read_file(approved_request_path(request_id), REQUEST_MAX_BYTES)?;
        let approval_bytes = self
            .root
            .read_file(approved_approval_path(request_id), APPROVAL_MAX_BYTES)?;
        let request = RequestDocument::parse(&request_bytes)?;
        if request.id() != request_id {
            return Err(Error::AuthorityConflict(
                "approved request path and exact bytes disagree".to_owned(),
            ));
        }
        Ok((request, ApprovalDocument::parse(&approval_bytes)?))
    }

    fn verify_pending_pair_contents(&self, request_id: &RequestId) -> Result<()> {
        let names = self.root.entries(&pending_dir(request_id))?;
        for name in names {
            let value = name.to_string_lossy();
            if value == "request.json" || value == "approval.json" {
                continue;
            }
            return Err(Error::AuthorityConflict(format!(
                "unexpected pending pair entry `{value}`"
            )));
        }
        Ok(())
    }

    fn remove_candidate_files(&self, request_id: &RequestId) -> Result<()> {
        for name in self.root.entries(&pending_dir(request_id))? {
            let value = name.to_string_lossy();
            if value.starts_with("approval-candidate-") || is_authority_temporary_name(&name) {
                self.root.remove_file(&pending_dir(request_id).join(name))?;
            }
        }
        Ok(())
    }

    fn exists(&self, path: &Path) -> Result<bool> {
        match self
            .root
            .read_file(path, REQUEST_MAX_BYTES.max(APPROVAL_MAX_BYTES))
        {
            Ok(_) => Ok(true),
            Err(Error::Io {
                kind: std::io::ErrorKind::NotFound,
                ..
            }) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

fn digest_component(request_id: &RequestId) -> String {
    request_id.digest().to_string()
}

fn pending_dir(request_id: &RequestId) -> PathBuf {
    PathBuf::from("pending/v1/sha256").join(digest_component(request_id))
}
fn pending_request_path(request_id: &RequestId) -> PathBuf {
    pending_dir(request_id).join("request.json")
}
fn pending_approval_path(request_id: &RequestId) -> PathBuf {
    pending_dir(request_id).join("approval.json")
}
fn terminal_dir(request_id: &RequestId) -> PathBuf {
    PathBuf::from("pending-terminal/v1/sha256").join(digest_component(request_id))
}
fn terminal_request_path(request_id: &RequestId) -> PathBuf {
    terminal_dir(request_id).join("request.json")
}
fn approved_dir(request_id: &RequestId) -> PathBuf {
    PathBuf::from("approvals/v1/sha256").join(digest_component(request_id))
}
fn approved_request_path(request_id: &RequestId) -> PathBuf {
    approved_dir(request_id).join("request.json")
}
fn approved_approval_path(request_id: &RequestId) -> PathBuf {
    approved_dir(request_id).join("approval.json")
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, mpsc},
        thread,
        time::Duration,
    };

    use tempfile::tempdir;

    use super::*;
    use crate::wire::PolicyUpdateAction;

    /// A timeout rename and retained-request lookup share one lock boundary,
    /// so lookup observes either the retained request or a typed terminal
    /// state, never a raw `NotFound` from between those states.
    ///
    /// Normative source: SPEC §5.5, §7.5, and §14.1.
    #[test]
    fn retained_request_lookup_serializes_with_timeout_rename() {
        let directory = tempdir().unwrap();
        let root = Arc::new(TrustedRoot::open(directory.path()).unwrap());
        let request = RequestDocument::new(
            "demo".to_owned(),
            Action::PolicyUpdate(PolicyUpdateAction {
                config_id: Digest32::from_bytes([0x11; 32]),
                config_length: 1,
                expected_active: None,
                note: "test timeout transition".to_owned(),
            }),
        )
        .unwrap();
        let handle = PendingStore::new(&root).publish_request(&request).unwrap();
        let request_id = handle.request_id().clone();

        let lock = root.lock(".pending.lock").unwrap();
        let worker_root = Arc::clone(&root);
        let worker_id = request_id.clone();
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            sender
                .send(PendingStore::new(&worker_root).load_retained_request(&worker_id))
                .unwrap();
        });
        assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());

        match root
            .rename_directory_no_replace(&pending_dir(&request_id), &terminal_dir(&request_id))
            .unwrap()
        {
            PublishOutcome::Published => {}
            PublishOutcome::Existing => panic!("terminal directory unexpectedly existed"),
        }
        drop(lock);

        let result = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(result, Err(Error::AuthorityConflict(_))));
        worker.join().unwrap();
    }
}
