//! Ephemeral delegated approval authority.
//!
//! Normative source: SPEC §9.1–§9.5.

use std::{
    collections::BTreeSet,
    path::Path,
    str::FromStr as _,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer as _, SigningKey};
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    authority_file::TrustedRoot,
    pending::PendingStore,
    signer::wall_clock_nanos,
    wire::{
        Action, Approval, ApprovalDocument, ApprovalMaterial, CredentialResolver,
        DelegationEvidence, DelegationGrantAction, Digest32, PolicyId, PublicCredential,
        PublicCredentialDocument, REQUEST_MAX_BYTES, RequestDocument, RequestId,
        SoftwareEd25519Credential, signing_message,
    },
};

/// In-memory key plus the unsigned grant request awaiting direct approval.
pub struct PendingDelegation {
    credential: PublicCredentialDocument,
    grant_request: RequestDocument,
    seed: Zeroizing<[u8; 32]>,
}

impl PendingDelegation {
    /// Creates an ephemeral key and derives the half-open grant interval from TTL.
    pub fn new(
        project: String,
        policy: PolicyId,
        mut scopes: Vec<String>,
        ttl: Duration,
        note: String,
    ) -> Result<Self> {
        if ttl.is_zero() {
            return Err(Error::field("ttl", "must be greater than zero"));
        }
        scopes.sort();
        if scopes.is_empty() || scopes.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::field(
                "scopes",
                "must be non-empty and contain no duplicates",
            ));
        }
        let not_before = now_nanos()?;
        let expires_at = not_before
            .checked_add(ttl.as_nanos())
            .ok_or_else(|| Error::field("ttl", "expiration overflows the timestamp range"))?;
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut *seed)
            .map_err(|error| Error::field("delegate_key", error.to_string()))?;
        let key = SigningKey::from_bytes(&seed);
        let credential = PublicCredentialDocument::encode(PublicCredential::SoftwareEd25519(
            SoftwareEd25519Credential {
                credential_type: "software-ed25519".to_owned(),
                kind: "uchgs-public-credential".to_owned(),
                public_key_hex: hex::encode(key.verifying_key().to_bytes()),
                schema: 1,
            },
        ))?;
        let grant_request = RequestDocument::new(
            project,
            Action::DelegationGrant(DelegationGrantAction {
                credential_id: credential.id().clone(),
                credential_length: credential.bytes().len() as u64,
                credential_sha256: credential.sha256(),
                expires_at: expires_at.to_string(),
                not_before: not_before.to_string(),
                note,
                policy,
                scopes,
            }),
        )?;
        Ok(Self {
            credential,
            grant_request,
            seed,
        })
    }

    pub fn request(&self) -> &RequestDocument {
        &self.grant_request
    }

    pub fn credential(&self) -> &PublicCredentialDocument {
        &self.credential
    }

    /// Activates only a registered direct approval of the exact grant request.
    pub fn activate(
        self,
        grant_approval: ApprovalDocument,
        resolver: &impl CredentialResolver,
    ) -> Result<DelegateSession> {
        if grant_approval.approval().delegation.is_some() {
            return Err(Error::UnauthorizedApproval(
                "delegation grants require a registered direct signer".to_owned(),
            ));
        }
        grant_approval.verify(&self.grant_request, resolver)?;
        Ok(DelegateSession {
            credential: self.credential,
            grant_approval,
            grant_request: self.grant_request,
            retired: false,
            seed: self.seed,
            staged_requests: BTreeSet::new(),
        })
    }
}

/// Active delegated authority. Its secret is zeroized on drop and is never serializable.
pub struct DelegateSession {
    credential: PublicCredentialDocument,
    grant_approval: ApprovalDocument,
    grant_request: RequestDocument,
    retired: bool,
    seed: Zeroizing<[u8; 32]>,
    staged_requests: BTreeSet<RequestId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegateExit {
    Expired,
    Signal,
}

/// Process-local SIGINT/SIGTERM state. It has no filesystem or IPC surface.
pub struct DelegateTermination {
    requested: Arc<AtomicBool>,
}

impl DelegateTermination {
    pub fn install() -> Result<Self> {
        let requested = Arc::new(AtomicBool::new(false));
        let handler_flag = Arc::clone(&requested);
        ctrlc::set_handler(move || handler_flag.store(true, Ordering::SeqCst))
            .map_err(|error| Error::io("install delegate signal handler", io_other(error)))?;
        Ok(Self { requested })
    }

    fn requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }
}

impl DelegateSession {
    pub fn grant_request_id(&self) -> &RequestId {
        self.grant_request.id()
    }

    pub fn is_expired(&self) -> Result<bool> {
        Ok(now_nanos()? >= self.expires_at()?)
    }

    /// Runs the foreground daemon until its half-open authority expires or a
    /// SIGINT/SIGTERM is observed. The seed is zeroized before returning.
    pub fn run_foreground(
        &mut self,
        repository: &TrustedRoot,
        termination: &DelegateTermination,
    ) -> Result<DelegateExit> {
        self.require_active()?;
        loop {
            if termination.requested() {
                self.retire();
                return Ok(DelegateExit::Signal);
            }
            match self.is_expired() {
                Ok(true) => {
                    self.retire();
                    return Ok(DelegateExit::Expired);
                }
                Ok(false) => {}
                Err(error) => {
                    self.retire();
                    return Err(error);
                }
            }
            if let Err(error) = self.process_pending(repository) {
                self.retire();
                return Err(error);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Discovers pending requests through the sole §9.4 filesystem channel and
    /// stages approvals for every currently eligible request.
    pub fn process_pending(&mut self, repository: &TrustedRoot) -> Result<usize> {
        self.require_active()?;
        match self.is_expired() {
            Ok(true) => {
                self.retire();
                return Ok(0);
            }
            Ok(false) => {}
            Err(error) => {
                self.retire();
                return Err(error);
            }
        }
        let result = self.process_pending_active(repository);
        if result.is_err() {
            self.retire();
        }
        result
    }

    fn process_pending_active(&mut self, repository: &TrustedRoot) -> Result<usize> {
        let entries = match repository.entries(Path::new("pending/v1/sha256")) {
            Ok(entries) => entries,
            Err(Error::Io {
                kind: std::io::ErrorKind::NotFound,
                ..
            }) => return Ok(0),
            Err(error) => return Err(error),
        };
        let pending = PendingStore::new(repository);
        let mut completed = 0;
        let mut first_error = None;
        for entry in entries {
            let Some(digest) = entry.to_str() else {
                continue;
            };
            let Ok(digest) = Digest32::from_str(digest) else {
                continue;
            };
            let request_id = RequestId::from_digest(digest);
            if self.staged_requests.contains(&request_id) {
                continue;
            }
            let request_path = Path::new("pending/v1/sha256")
                .join(&entry)
                .join("request.json");
            let bytes = match repository.read_file(&request_path, REQUEST_MAX_BYTES) {
                Ok(bytes) => bytes,
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            };
            let request = match RequestDocument::parse(&bytes) {
                Ok(request) if request.id() == &request_id => request,
                Ok(_) => {
                    first_error.get_or_insert_with(|| {
                        Error::AuthorityConflict(
                            "pending request path does not match exact request bytes".to_owned(),
                        )
                    });
                    continue;
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            };
            if !self.eligible(&request, now_nanos()?) {
                continue;
            }
            match pending.stage_delegated_candidate(request.id(), |locked_request| {
                if locked_request.bytes() != request.bytes() {
                    return Err(Error::AuthorityConflict(
                        "pending request changed before delegated approval".to_owned(),
                    ));
                }
                self.approval_at(locked_request, now_nanos()?)
            }) {
                Ok(_) => {
                    self.staged_requests.insert(request_id);
                    completed += 1;
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(completed)
        }
    }

    fn approval_at(
        &self,
        request: &RequestDocument,
        approved_at: u128,
    ) -> Result<ApprovalDocument> {
        self.require_active()?;
        if !self.eligible(request, approved_at) {
            return Err(Error::UnauthorizedApproval(
                "request is outside delegated authority".to_owned(),
            ));
        }
        let signature = SigningKey::from_bytes(&self.seed).sign(&signing_message(request.bytes()));
        ApprovalDocument::encode(Approval {
            approved_at: approved_at.to_string(),
            credential_id: self.credential.id().clone(),
            delegation: Some(DelegationEvidence {
                credential: STANDARD.encode(self.credential.bytes()),
                grant_approval: STANDARD.encode(self.grant_approval.bytes()),
                grant_request: STANDARD.encode(self.grant_request.bytes()),
            }),
            kind: "approval".to_owned(),
            material: ApprovalMaterial::Ed25519 {
                signature: hex::encode(signature.to_bytes()),
            },
            request_id: request.id().clone(),
            request_sha256: request.sha256(),
            schema: 1,
        })
    }

    fn eligible(&self, request: &RequestDocument, observed_at: u128) -> bool {
        let Action::DelegationGrant(grant) = &self.grant_request.request().action else {
            return false;
        };
        if request.request().project != self.grant_request.request().project
            || !request.request().action.allows_delegated_approval()
        {
            return false;
        }
        let Some(scope) = request.request().action.scope() else {
            return false;
        };
        grant
            .scopes
            .binary_search_by(|item| item.as_str().cmp(scope))
            .is_ok()
            && self
                .interval()
                .is_ok_and(|(start, end)| start <= observed_at && observed_at < end)
    }

    fn interval(&self) -> Result<(u128, u128)> {
        let Action::DelegationGrant(grant) = &self.grant_request.request().action else {
            return Err(Error::field("delegation", "grant action is missing"));
        };
        let start = grant
            .not_before
            .parse::<u128>()
            .map_err(|_| Error::field("not_before", "must be a decimal timestamp"))?;
        let end = grant
            .expires_at
            .parse::<u128>()
            .map_err(|_| Error::field("expires_at", "must be a decimal timestamp"))?;
        Ok((start, end))
    }

    fn expires_at(&self) -> Result<u128> {
        self.interval().map(|(_, end)| end)
    }

    fn require_active(&self) -> Result<()> {
        if self.retired {
            return Err(Error::UnauthorizedApproval(
                "delegated authority is retired".to_owned(),
            ));
        }
        Ok(())
    }

    /// Ends this session's authority: the seed is zeroized and every later
    /// authority-bearing operation is refused.
    ///
    /// Zeroizing alone would not end it. `SigningKey::from_bytes` accepts an
    /// all-zero seed, so a session that only wiped its seed would keep signing under
    /// a key anyone can derive. The flag is what makes retirement final, and every
    /// exit path — expiry, signal, or any processing error — takes it, so a fault
    /// cannot leave a half-trusted session running.
    fn retire(&mut self) {
        self.seed.fill(0);
        self.retired = true;
    }
}

fn now_nanos() -> Result<u128> {
    wall_clock_nanos()?
        .parse()
        .map_err(|_| Error::field("time", "wall clock timestamp is invalid"))
}

fn io_other(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs};

    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::{
        extract::{UnitId, UnitKind},
        wire::{
            AttestContentAction, CredentialId, Digest32, ObjectFormatName, PolicyUpdateAction,
            SourceName, UnitDescriptor,
        },
    };

    struct Resolver(BTreeMap<CredentialId, PublicCredentialDocument>);

    impl CredentialResolver for Resolver {
        fn resolve(
            &self,
            _project: &str,
            credential_id: &CredentialId,
        ) -> Result<PublicCredentialDocument> {
            self.0.get(credential_id).cloned().ok_or_else(|| {
                Error::AuthorityNotFound("test credential is not registered".to_owned())
            })
        }
    }

    fn credential(key: &SigningKey) -> PublicCredentialDocument {
        PublicCredentialDocument::encode(PublicCredential::SoftwareEd25519(
            SoftwareEd25519Credential {
                credential_type: "software-ed25519".to_owned(),
                kind: "uchgs-public-credential".to_owned(),
                public_key_hex: hex::encode(key.verifying_key().to_bytes()),
                schema: 1,
            },
        ))
        .unwrap()
    }

    fn direct_approval(request: &RequestDocument, key: &SigningKey) -> ApprovalDocument {
        ApprovalDocument::encode(Approval {
            approved_at: "1".to_owned(),
            credential_id: credential(key).id().clone(),
            delegation: None,
            kind: "approval".to_owned(),
            material: ApprovalMaterial::Ed25519 {
                signature: hex::encode(key.sign(&signing_message(request.bytes())).to_bytes()),
            },
            request_id: request.id().clone(),
            request_sha256: request.sha256(),
            schema: 1,
        })
        .unwrap()
    }

    fn content_request() -> RequestDocument {
        let bytes = b"content";
        RequestDocument::new(
            "example/project".to_owned(),
            Action::AttestContent(AttestContentAction {
                note: "reviewed".to_owned(),
                object_format: ObjectFormatName::Sha1,
                policy: PolicyId::from_digest(Digest32::from_bytes([4; 32])),
                push_intent: None,
                scope: "security".to_owned(),
                source: SourceName::Staged,
                staged_tree: Some("0123456789012345678901234567890123456789".to_owned()),
                units: vec![UnitDescriptor {
                    bytes_hex: None,
                    length: bytes.len() as u64,
                    unit_id: UnitId::from_parts(
                        UnitKind::File,
                        Digest32::from_bytes(Sha256::digest(bytes).into()),
                    ),
                }],
            }),
        )
        .unwrap()
    }

    #[test]
    fn delegate_07_approval_verifies_after_authority_expires() {
        let human_key = SigningKey::from_bytes(&[10; 32]);
        let human_credential = credential(&human_key);
        let resolver = Resolver(BTreeMap::from([(
            human_credential.id().clone(),
            human_credential,
        )]));
        let pending_grant = PendingDelegation::new(
            "example/project".to_owned(),
            PolicyId::from_digest(Digest32::from_bytes([4; 32])),
            vec!["security".to_owned()],
            Duration::from_secs(60),
            "delegate security".to_owned(),
        )
        .unwrap();
        let grant_approval = direct_approval(pending_grant.request(), &human_key);
        let mut session = pending_grant.activate(grant_approval, &resolver).unwrap();

        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path()).unwrap();
        let root = TrustedRoot::open(temp.path()).unwrap();
        let request = content_request();
        PendingStore::new(&root).publish_request(&request).unwrap();
        assert_eq!(session.process_pending(&root).unwrap(), 1);
        assert_eq!(session.process_pending(&root).unwrap(), 0);
        let approval = PendingStore::new(&root)
            .accept_candidates(request.id(), &resolver)
            .unwrap();
        approval.verify(&request, &resolver).unwrap();
        assert!(approval.approval().delegation.is_some());
    }

    #[test]
    fn delegate_02_binary_derives_interval_from_ttl() {
        let human_key = SigningKey::from_bytes(&[11; 32]);
        let human_credential = credential(&human_key);
        let resolver = Resolver(BTreeMap::from([(
            human_credential.id().clone(),
            human_credential,
        )]));
        let pending = PendingDelegation::new(
            "example/project".to_owned(),
            PolicyId::from_digest(Digest32::from_bytes([5; 32])),
            vec!["security".to_owned()],
            Duration::from_secs(60),
            "delegate security".to_owned(),
        )
        .unwrap();
        let approval = direct_approval(pending.request(), &human_key);
        let session = pending.activate(approval, &resolver).unwrap();
        let (start, end) = session.interval().unwrap();
        assert!(session.eligible(&content_request(), start));
        assert!(!session.eligible(&content_request(), end));

        let policy_request = RequestDocument::new(
            "example/project".to_owned(),
            Action::PolicyUpdate(PolicyUpdateAction {
                config_id: Digest32::from_bytes([1; 32]),
                config_length: 1,
                expected_active: None,
                note: "policy".to_owned(),
            }),
        )
        .unwrap();
        assert!(!session.eligible(&policy_request, start));
    }

    #[test]
    fn delegate_03_exits_on_expiry() {
        let human_key = SigningKey::from_bytes(&[16; 32]);
        let human_credential = credential(&human_key);
        let resolver = Resolver(BTreeMap::from([(
            human_credential.id().clone(),
            human_credential,
        )]));
        let pending = PendingDelegation::new(
            "example/project".to_owned(),
            PolicyId::from_digest(Digest32::from_bytes([6; 32])),
            vec!["security".to_owned()],
            Duration::from_nanos(1),
            "short delegation".to_owned(),
        )
        .unwrap();
        let approval = direct_approval(pending.request(), &human_key);
        let mut session = pending.activate(approval, &resolver).unwrap();
        let termination = DelegateTermination {
            requested: Arc::new(AtomicBool::new(false)),
        };
        let temp = tempfile::tempdir().unwrap();
        let root = TrustedRoot::open(temp.path()).unwrap();
        assert_eq!(
            session.run_foreground(&root, &termination).unwrap(),
            DelegateExit::Expired
        );
        assert_eq!(&*session.seed, &[0; 32]);
        assert!(session.retired);
        assert!(matches!(
            session.process_pending(&root),
            Err(Error::UnauthorizedApproval(_))
        ));
    }

    #[test]
    fn delegate_04_zeroizes_key_on_sigint_and_sigterm() {
        let human_key = SigningKey::from_bytes(&[17; 32]);
        let human_credential = credential(&human_key);
        let resolver = Resolver(BTreeMap::from([(
            human_credential.id().clone(),
            human_credential,
        )]));
        let pending = PendingDelegation::new(
            "example/project".to_owned(),
            PolicyId::from_digest(Digest32::from_bytes([7; 32])),
            vec!["security".to_owned()],
            Duration::from_secs(60),
            "interruptible delegation".to_owned(),
        )
        .unwrap();
        let approval = direct_approval(pending.request(), &human_key);
        let mut session = pending.activate(approval, &resolver).unwrap();
        let termination = DelegateTermination {
            requested: Arc::new(AtomicBool::new(true)),
        };
        let temp = tempfile::tempdir().unwrap();
        let root = TrustedRoot::open(temp.path()).unwrap();
        assert_eq!(
            session.run_foreground(&root, &termination).unwrap(),
            DelegateExit::Signal
        );
        assert_eq!(&*session.seed, &[0; 32]);
        assert!(session.retired);
        assert!(matches!(
            session.approval_at(&content_request(), now_nanos().unwrap()),
            Err(Error::UnauthorizedApproval(_))
        ));
    }

    #[test]
    fn delegate_key_is_zeroized_when_foreground_processing_fails() {
        let human_key = SigningKey::from_bytes(&[18; 32]);
        let human_credential = credential(&human_key);
        let resolver = Resolver(BTreeMap::from([(
            human_credential.id().clone(),
            human_credential,
        )]));
        let pending = PendingDelegation::new(
            "example/project".to_owned(),
            PolicyId::from_digest(Digest32::from_bytes([8; 32])),
            vec!["security".to_owned()],
            Duration::from_secs(60),
            "failing delegation".to_owned(),
        )
        .unwrap();
        let approval = direct_approval(pending.request(), &human_key);
        let mut session = pending.activate(approval, &resolver).unwrap();
        let termination = DelegateTermination {
            requested: Arc::new(AtomicBool::new(false)),
        };
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("pending/v1")).unwrap();
        fs::write(temp.path().join("pending/v1/sha256"), b"not a directory").unwrap();
        let root = TrustedRoot::open(temp.path()).unwrap();
        assert!(session.run_foreground(&root, &termination).is_err());
        assert_eq!(&*session.seed, &[0; 32]);
        assert!(session.retired);
        assert!(matches!(
            session.process_pending(&root),
            Err(Error::UnauthorizedApproval(_))
        ));
    }

    #[test]
    fn delegate_pending_scan_skips_only_non_digest_entry_names() {
        let human_key = SigningKey::from_bytes(&[19; 32]);
        let human_credential = credential(&human_key);
        let resolver = Resolver(BTreeMap::from([(
            human_credential.id().clone(),
            human_credential,
        )]));
        let pending = PendingDelegation::new(
            "example/project".to_owned(),
            PolicyId::from_digest(Digest32::from_bytes([9; 32])),
            vec!["security".to_owned()],
            Duration::from_secs(60),
            "strict pending names".to_owned(),
        )
        .unwrap();
        let approval = direct_approval(pending.request(), &human_key);
        let mut session = pending.activate(approval, &resolver).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let pending_root = temp.path().join("pending/v1/sha256");
        fs::create_dir_all(pending_root.join("not-a-request-digest")).unwrap();
        let root = TrustedRoot::open(temp.path()).unwrap();

        assert_eq!(session.process_pending(&root).unwrap(), 0);
        assert!(!session.retired);

        let valid_digest = Digest32::from_bytes([0xaa; 32]).to_hex();
        fs::create_dir(pending_root.join(valid_digest)).unwrap();
        assert!(matches!(
            session.process_pending(&root),
            Err(Error::Io {
                kind: std::io::ErrorKind::NotFound,
                ..
            })
        ));
        assert!(session.retired);
    }
}
