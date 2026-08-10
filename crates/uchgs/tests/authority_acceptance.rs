//! Library-level acceptance tests for the authority core.
//!
//! Normative source: SPEC §6–§9 and §16.

use std::{
    collections::BTreeMap,
    fs,
    sync::{Arc, Barrier},
    thread,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};
use uchgs::{
    Error,
    authority_file::TrustedRoot,
    extract::{UnitId, UnitKind},
    pending::{ExpirationOutcome, PendingStore},
    registry::{Enrollment, EnrollmentDocument, Genesis, Presence, Registry},
    wire::{
        Action, Approval, ApprovalDocument, ApprovalMaterial, AttestContentAction,
        AttestTreeAction, CredentialId, CredentialResolver, DelegationEvidence,
        DelegationGrantAction, Digest32, ObjectFormatName, PolicyId, PublicCredential,
        PublicCredentialDocument, RegistryName, RequestDocument, SecureEnclaveP256Credential,
        SoftwareEd25519Credential, SourceName, UnitDescriptor,
    },
};

const PROJECT: &str = "example/project";
const SCOPE: &str = "security";

#[derive(Clone, Default)]
struct MemoryResolver {
    credentials: BTreeMap<(String, CredentialId), PublicCredentialDocument>,
}

impl MemoryResolver {
    fn with(project: &str, credential: PublicCredentialDocument) -> Self {
        let mut credentials = BTreeMap::new();
        credentials.insert((project.to_owned(), credential.id().clone()), credential);
        Self { credentials }
    }

    fn and(mut self, project: &str, credential: PublicCredentialDocument) -> Self {
        self.credentials
            .insert((project.to_owned(), credential.id().clone()), credential);
        self
    }
}

impl CredentialResolver for MemoryResolver {
    fn resolve(
        &self,
        project: &str,
        credential_id: &CredentialId,
    ) -> uchgs::Result<PublicCredentialDocument> {
        self.credentials
            .get(&(project.to_owned(), credential_id.clone()))
            .cloned()
            .ok_or_else(|| Error::AuthorityNotFound("test credential is not registered".to_owned()))
    }
}

fn software_credential(key: &SigningKey) -> PublicCredentialDocument {
    PublicCredentialDocument::encode(PublicCredential::SoftwareEd25519(
        SoftwareEd25519Credential {
            credential_type: "software-ed25519".to_owned(),
            kind: "uchgs-public-credential".to_owned(),
            public_key_hex: hex::encode(key.verifying_key().as_bytes()),
            schema: 1,
        },
    ))
    .expect("valid software credential")
}

fn signing_message(request: &RequestDocument) -> Vec<u8> {
    let mut bytes = b"uchgs-approval-v1\0".to_vec();
    bytes.extend_from_slice(&Sha256::digest(request.bytes()));
    bytes
}

fn direct_approval(
    request: &RequestDocument,
    key: &SigningKey,
    approved_at: u128,
) -> ApprovalDocument {
    let signature = key.sign(&signing_message(request));
    ApprovalDocument::encode(Approval {
        approved_at: approved_at.to_string(),
        credential_id: software_credential(key).id().clone(),
        delegation: None,
        kind: "approval".to_owned(),
        material: ApprovalMaterial::Ed25519 {
            signature: hex::encode(signature.to_bytes()),
        },
        request_id: request.id().clone(),
        request_sha256: request.sha256(),
        schema: 1,
    })
    .expect("valid direct approval")
}

fn p256_credential(key: &p256::ecdsa::SigningKey) -> PublicCredentialDocument {
    PublicCredentialDocument::encode(PublicCredential::SecureEnclaveP256TouchId(
        SecureEnclaveP256Credential {
            credential_type: "secure-enclave-p256-touch-id".to_owned(),
            kind: "uchgs-public-credential".to_owned(),
            public_key_x963_hex: hex::encode(
                key.verifying_key().to_encoded_point(false).as_bytes(),
            ),
            schema: 1,
        },
    ))
    .expect("valid P-256 credential")
}

fn p256_approval(
    request: &RequestDocument,
    key: &p256::ecdsa::SigningKey,
    approved_at: u128,
) -> ApprovalDocument {
    let signature: p256::ecdsa::Signature = key.sign(&signing_message(request));
    let signature = signature.normalize_s().unwrap_or(signature);
    ApprovalDocument::encode(Approval {
        approved_at: approved_at.to_string(),
        credential_id: p256_credential(key).id().clone(),
        delegation: None,
        kind: "approval".to_owned(),
        material: ApprovalMaterial::EcdsaP256Sha256 {
            r: hex::encode(signature.r().to_bytes()),
            s: hex::encode(signature.s().to_bytes()),
        },
        request_id: request.id().clone(),
        request_sha256: request.sha256(),
        schema: 1,
    })
    .expect("valid P-256 approval")
}

fn path_unit(path: &[u8]) -> UnitDescriptor {
    let digest = Digest32::from_bytes(Sha256::digest(path).into());
    UnitDescriptor {
        bytes_hex: Some(hex::encode(path)),
        length: path.len() as u64,
        unit_id: UnitId::from_parts(UnitKind::Path, digest),
    }
}

fn file_unit(bytes: &[u8]) -> UnitDescriptor {
    UnitDescriptor {
        bytes_hex: None,
        length: bytes.len() as u64,
        unit_id: UnitId::from_parts(
            UnitKind::File,
            Digest32::from_bytes(Sha256::digest(bytes).into()),
        ),
    }
}

fn content_request(units: Vec<UnitDescriptor>) -> RequestDocument {
    RequestDocument::new(
        PROJECT.to_owned(),
        Action::AttestContent(AttestContentAction {
            note: "reviewed exact content".to_owned(),
            object_format: ObjectFormatName::Sha1,
            policy: PolicyId::from_digest(Digest32::from_bytes([9; 32])),
            push_intent: None,
            scope: SCOPE.to_owned(),
            source: SourceName::Staged,
            staged_tree: Some("0123456789012345678901234567890123456789".to_owned()),
            units,
        }),
    )
    .expect("valid content request")
}

fn tree_request(tree_bytes: &[u8]) -> RequestDocument {
    RequestDocument::new(
        PROJECT.to_owned(),
        Action::AttestTree(AttestTreeAction {
            note: "reviewed exact tree".to_owned(),
            object_format: ObjectFormatName::Sha1,
            policy: PolicyId::from_digest(Digest32::from_bytes([9; 32])),
            push_intent: None,
            scope: SCOPE.to_owned(),
            tree_oid: "0123456789012345678901234567890123456789".to_owned(),
            tree_sha256: Digest32::from_bytes(Sha256::digest(tree_bytes).into()),
        }),
    )
    .expect("valid tree request")
}

fn signer_enroll_request(
    credential: &PublicCredentialDocument,
    principal: &str,
    registry: RegistryName,
) -> RequestDocument {
    RequestDocument::new(
        PROJECT.to_owned(),
        Action::SignerEnroll(uchgs::wire::SignerEnrollAction {
            credential_id: credential.id().clone(),
            credential_length: credential.bytes().len() as u64,
            credential_sha256: credential.sha256(),
            note: "enroll exact credential".to_owned(),
            policy: PolicyId::from_digest(Digest32::from_bytes([3; 32])),
            principal: principal.to_owned(),
            registry,
        }),
    )
    .expect("valid signer-enroll request")
}

fn install_credential(root: &std::path::Path, credential: &PublicCredentialDocument) {
    let directory = root.join("credentials/v1/sha256");
    fs::create_dir_all(&directory).expect("credential directory");
    fs::write(
        directory.join(format!("{}.json", credential.sha256())),
        credential.bytes(),
    )
    .expect("credential bytes");
}

fn install_genesis(
    root: &std::path::Path,
    credential: &PublicCredentialDocument,
    principal: &str,
) -> std::path::PathBuf {
    install_credential(root, credential);
    let genesis = Genesis {
        credential_id: credential.id().clone(),
        credential_length: credential.bytes().len() as u64,
        credential_sha256: credential.sha256(),
        kind: "uchgs-genesis".to_owned(),
        presence: Presence::TtyConfirmed,
        principal: principal.to_owned(),
        registry: RegistryName::Global,
        schema: 1,
    };
    let bytes = serde_json_canonicalizer::to_vec(&genesis).expect("genesis JSON");
    let digest = hex::encode(Sha256::digest(&bytes));
    let directory = root.join(format!("genesis/v1/sha256/{digest}"));
    fs::create_dir_all(&directory).expect("genesis directory");
    fs::write(directory.join("genesis.json"), bytes).expect("genesis bytes");
    directory
}

fn enrollment_document(
    request: &RequestDocument,
    approval: &ApprovalDocument,
    credential: &PublicCredentialDocument,
    principal: &str,
    registry: RegistryName,
) -> Enrollment {
    let Action::SignerEnroll(action) = &request.request().action else {
        panic!("signer-enroll request")
    };
    let mut enrollment = Enrollment {
        active_policy_sha256: action.policy.digest(),
        approval_sha256: approval.sha256(),
        credential_id: credential.id().clone(),
        credential_length: credential.bytes().len() as u64,
        credential_sha256: credential.sha256(),
        enrollment_id: Digest32::from_bytes([0; 32]),
        kind: "uchgs-enrollment".to_owned(),
        principal: principal.to_owned(),
        project: PROJECT.to_owned(),
        registry,
        request_id: request.id().clone(),
        request_sha256: request.sha256(),
        schema: 1,
    };
    let mut preimage = serde_json::to_value(&enrollment)
        .expect("enrollment value")
        .as_object()
        .expect("enrollment object")
        .clone();
    preimage.remove("enrollment_id");
    enrollment.enrollment_id = Digest32::from_bytes(
        Sha256::digest(serde_json_canonicalizer::to_vec(&preimage).expect("preimage")).into(),
    );
    enrollment
}

fn install_enrollment_bundle(
    root: &std::path::Path,
    request: &RequestDocument,
    approval: &ApprovalDocument,
    credential: &PublicCredentialDocument,
    enrollment: &Enrollment,
) -> std::path::PathBuf {
    install_credential(root, credential);
    let directory = root.join(format!("enrollments/v1/sha256/{}", request.sha256()));
    fs::create_dir_all(&directory).expect("enrollment directory");
    fs::write(directory.join("request.json"), request.bytes()).expect("request bytes");
    fs::write(directory.join("approval.json"), approval.bytes()).expect("approval bytes");
    fs::write(directory.join("credential.json"), credential.bytes()).expect("credential bytes");
    fs::write(
        directory.join("enrollment.json"),
        serde_json_canonicalizer::to_vec(enrollment).expect("enrollment bytes"),
    )
    .expect("enrollment bytes");
    directory
}

/// SPEC §16 approval_01/02/05; normative source: SPEC §7.1–§7.2.
#[test]
fn approval_request_generation_and_whole_scope_are_pinned() {
    let units = vec![file_unit(b""), path_unit(b"src/lib.rs")];
    let first = content_request(units.clone());
    let second = content_request(units);
    assert_ne!(first.id(), second.id());
    assert_eq!(first.request().request_nonce.len(), 32);
    assert!(
        first
            .request()
            .requested_at
            .bytes()
            .all(|byte| byte.is_ascii_digit())
    );
    let Action::AttestContent(action) = &first.request().action else {
        panic!("content")
    };
    assert_eq!(action.units.len(), 2);
}

/// SPEC §16 approval_04 and registry_05; normative source: SPEC §7.4, §8.4.
#[test]
fn approval_verifies_exact_request_and_matching_material_only() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let credential = software_credential(&key);
    let resolver = MemoryResolver::with(PROJECT, credential);
    let request = content_request(vec![path_unit(b"a")]);
    let approval = direct_approval(&request, &key, 100);
    approval
        .verify(&request, &resolver)
        .expect("exact request verifies");

    let other_request = content_request(vec![path_unit(b"b")]);
    assert!(matches!(
        approval.verify(&other_request, &resolver),
        Err(Error::UnauthorizedApproval(_))
    ));

    let mut extra =
        serde_json::from_slice::<serde_json::Value>(approval.bytes()).expect("approval JSON");
    extra["material"]["extra"] = serde_json::Value::Bool(true);
    let extra = serde_json_canonicalizer::to_vec(&extra).expect("canonical extra material");
    assert!(ApprovalDocument::parse(&extra).is_err());
}

/// SPEC §16 registry_05; normative source: SPEC §7.4, §8.4.
#[test]
fn p256_material_is_positive_and_cross_type_material_is_rejected() {
    let p256_key = p256::ecdsa::SigningKey::from_slice(&[5; 32]).expect("P-256 key");
    let credential = p256_credential(&p256_key);
    let resolver = MemoryResolver::with(PROJECT, credential.clone());
    let request = content_request(vec![path_unit(b"p256")]);
    p256_approval(&request, &p256_key, 100)
        .verify(&request, &resolver)
        .expect("matching P-256 material");

    let ed_key = SigningKey::from_bytes(&[6; 32]);
    let ed_signature = ed_key.sign(&signing_message(&request));
    let mismatched = ApprovalDocument::encode(Approval {
        approved_at: "100".to_owned(),
        credential_id: credential.id().clone(),
        delegation: None,
        kind: "approval".to_owned(),
        material: ApprovalMaterial::Ed25519 {
            signature: hex::encode(ed_signature.to_bytes()),
        },
        request_id: request.id().clone(),
        request_sha256: request.sha256(),
        schema: 1,
    })
    .expect("canonical mismatched approval");
    assert!(matches!(
        mismatched.verify(&request, &resolver),
        Err(Error::UnauthorizedApproval(_))
    ));
}

/// SPEC §16 self_contained_01–05; normative source: SPEC §7.3–§7.4, §9.3.
#[test]
fn delegated_approval_is_self_contained_and_registry_anchored() {
    let human_key = SigningKey::from_bytes(&[11; 32]);
    let delegated_key = SigningKey::from_bytes(&[12; 32]);
    let delegated_credential = software_credential(&delegated_key);
    let grant_request = RequestDocument::new(
        PROJECT.to_owned(),
        Action::DelegationGrant(DelegationGrantAction {
            credential_id: delegated_credential.id().clone(),
            credential_length: delegated_credential.bytes().len() as u64,
            credential_sha256: delegated_credential.sha256(),
            expires_at: "200".to_owned(),
            not_before: "10".to_owned(),
            note: "delegate content review".to_owned(),
            policy: PolicyId::from_digest(Digest32::from_bytes([3; 32])),
            scopes: vec![SCOPE.to_owned()],
        }),
    )
    .expect("valid grant request");
    let grant_approval = direct_approval(&grant_request, &human_key, 20);
    let request = content_request(vec![path_unit(b"src/main.rs")]);
    let delegated_signature = delegated_key.sign(&signing_message(&request));
    let approval = ApprovalDocument::encode(Approval {
        approved_at: "100".to_owned(),
        credential_id: delegated_credential.id().clone(),
        delegation: Some(DelegationEvidence {
            credential: STANDARD.encode(delegated_credential.bytes()),
            grant_approval: STANDARD.encode(grant_approval.bytes()),
            grant_request: STANDARD.encode(grant_request.bytes()),
        }),
        kind: "approval".to_owned(),
        material: ApprovalMaterial::Ed25519 {
            signature: hex::encode(delegated_signature.to_bytes()),
        },
        request_id: request.id().clone(),
        request_sha256: request.sha256(),
        schema: 1,
    })
    .expect("valid delegated approval document");

    let registered = MemoryResolver::with(PROJECT, software_credential(&human_key));
    approval
        .verify(&request, &registered)
        .expect("embedded chain verifies without daemon state");
    assert!(matches!(
        approval.verify(&request, &MemoryResolver::default()),
        Err(Error::UnauthorizedApproval(_))
    ));
    assert!(
        direct_approval(&request, &human_key, 100)
            .approval()
            .delegation
            .is_none()
    );
}

/// SPEC §16 approval_03; normative source: SPEC §7.5.
#[test]
fn timed_out_request_is_non_resurrectable() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = TrustedRoot::open(directory.path()).expect("trusted root");
    let store = PendingStore::new(&root);
    let request = content_request(vec![path_unit(b"timeout")]);
    let handle = store.publish_request(&request).expect("publish request");
    assert!(matches!(
        store.expire_if_due(&handle, Duration::ZERO, &MemoryResolver::default()),
        Ok(ExpirationOutcome::TimedOut)
    ));
    assert!(matches!(
        store.publish_request(&request),
        Err(Error::AuthorityConflict(_))
    ));
}

/// SPEC §7.5 invalid-first rule; normative source: SPEC §7.4–§7.5.
#[test]
fn invalid_candidate_does_not_block_a_later_valid_winner() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = TrustedRoot::open(directory.path()).expect("trusted root");
    let store = PendingStore::new(&root);
    let key = SigningKey::from_bytes(&[21; 32]);
    let resolver = MemoryResolver::with(PROJECT, software_credential(&key));
    let request = content_request(vec![path_unit(b"candidate")]);
    store.publish_request(&request).expect("publish request");

    let wrong_key = SigningKey::from_bytes(&[22; 32]);
    let invalid = direct_approval(&request, &wrong_key, 100);
    store
        .stage_approval_candidate(request.id(), invalid.bytes())
        .expect("stage invalid candidate");
    assert!(matches!(
        store.accept_candidates(request.id(), &resolver),
        Err(Error::AuthorityNotFound(_))
    ));

    let valid = direct_approval(&request, &key, 100);
    store
        .stage_approval_candidate(request.id(), valid.bytes())
        .expect("stage valid candidate");
    let winner = store
        .accept_candidates(request.id(), &resolver)
        .expect("accept valid candidate");
    assert_eq!(winner.bytes(), valid.bytes());
    assert_eq!(
        store
            .accept_candidates(request.id(), &resolver)
            .expect("idempotent winner")
            .bytes(),
        valid.bytes()
    );
}

/// SPEC §7.5 terminal race; normative source: SPEC §7.5.
#[test]
fn approval_timeout_race_has_one_terminal_winner() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().to_owned();
    let key = SigningKey::from_bytes(&[31; 32]);
    let resolver = MemoryResolver::with(PROJECT, software_credential(&key));
    let request = content_request(vec![path_unit(b"race")]);
    let root = TrustedRoot::open(&path).expect("trusted root");
    let store = PendingStore::new(&root);
    let handle = store.publish_request(&request).expect("publish request");
    let approval = direct_approval(&request, &key, 100);
    store
        .stage_approval_candidate(request.id(), approval.bytes())
        .expect("stage approval");

    let barrier = Arc::new(Barrier::new(2));
    let request_id = request.id().clone();
    let path_for_accept = path.clone();
    let resolver_for_accept = resolver.clone();
    let barrier_for_accept = barrier.clone();
    let accept = thread::spawn(move || {
        let root = TrustedRoot::open(path_for_accept).expect("accept root");
        barrier_for_accept.wait();
        PendingStore::new(&root).accept_candidates(&request_id, &resolver_for_accept)
    });
    barrier.wait();
    let timeout = store.expire_if_due(&handle, Duration::ZERO, &resolver);
    let accepted = accept.join().expect("accept thread");
    assert!(matches!(
        (&timeout, &accepted),
        (Ok(ExpirationOutcome::Approved(_)), Ok(_)) | (Ok(ExpirationOutcome::TimedOut), Err(_))
    ));
}

/// SPEC §16 approval_06/07 and §6.4; normative source: SPEC §6, §7.6.
#[test]
fn multi_unit_finalization_is_idempotent_and_crash_reconcilable() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = TrustedRoot::open(directory.path()).expect("trusted root");
    let store = PendingStore::new(&root);
    let key = SigningKey::from_bytes(&[41; 32]);
    let resolver = MemoryResolver::with(PROJECT, software_credential(&key));
    let units = vec![file_unit(b"payload"), path_unit(b"src/lib.rs")];
    let request = content_request(units.clone());
    let approval = direct_approval(&request, &key, 100);
    store.publish_request(&request).expect("publish request");
    store
        .stage_approval_candidate(request.id(), approval.bytes())
        .expect("stage approval");
    store
        .accept_candidates(request.id(), &resolver)
        .expect("accept approval");

    // Simulate a crash after the first record is durable but before pair move.
    uchgs::ledger::Ledger::new(&root)
        .append_content(&request, &approval, &units[0].unit_id, &resolver)
        .expect("first record");
    assert_eq!(store.reconcile_judgments(&resolver).expect("reconcile"), 1);
    assert_eq!(
        store
            .reconcile_judgments(&resolver)
            .expect("idempotent reconcile"),
        0
    );

    let digest = request.id().digest();
    assert!(
        directory
            .path()
            .join(format!("approvals/v1/sha256/{digest}/request.json"))
            .is_file()
    );
    for unit in units {
        assert!(
            uchgs::ledger::Ledger::new(&root)
                .has_unit_scope(&unit.unit_id, SCOPE, &resolver)
                .expect("verified archived judgment")
        );
        assert!(
            directory
                .path()
                .join(format!(
                    "ledger/unit/v1/sha256/{}/{}.json",
                    unit.unit_id.kind().as_str(),
                    unit.unit_id.digest()
                ))
                .is_file()
        );
    }
}

/// SPEC §6.3 and §16 key_03/approval_06; normative source: SPEC §6.3, §7.6.
#[test]
fn tree_finalization_records_the_canonical_tree_key_and_moves_the_pair() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = TrustedRoot::open(directory.path()).expect("trusted root");
    let store = PendingStore::new(&root);
    let key = SigningKey::from_bytes(&[45; 32]);
    let resolver = MemoryResolver::with(PROJECT, software_credential(&key));
    let request = tree_request(b"tree 0\0");
    let approval = direct_approval(&request, &key, 100);
    store.publish_request(&request).expect("publish request");
    store
        .stage_approval_candidate(request.id(), approval.bytes())
        .expect("stage approval");
    store
        .accept_candidates(request.id(), &resolver)
        .expect("accept approval");
    store
        .finalize_judgment(request.id(), &resolver)
        .expect("finalize tree judgment");

    let Action::AttestTree(action) = &request.request().action else {
        panic!("tree")
    };
    let record_path = directory
        .path()
        .join(format!("ledger/tree/v1/sha256/{}.json", action.tree_sha256));
    let mut record: serde_json::Value =
        serde_json::from_slice(&fs::read(&record_path).expect("tree record"))
            .expect("valid tree record");
    assert_eq!(record["sha256"], action.tree_sha256.to_string());
    assert_eq!(record["judgments"][0]["provenance"]["kind"], "staged");
    assert_eq!(
        record["judgments"][0]["provenance"]["tree_oid"],
        action.tree_oid
    );
    assert!(
        directory
            .path()
            .join(format!(
                "approvals/v1/sha256/{}/approval.json",
                request.id().digest()
            ))
            .is_file()
    );

    record["judgments"][0]["provenance"]["extra"] = serde_json::Value::Bool(true);
    fs::write(
        &record_path,
        serde_json_canonicalizer::to_vec(&record).expect("tampered record"),
    )
    .expect("tamper provenance");
    assert!(
        uchgs::ledger::Ledger::new(&root)
            .has_tree_scope(action.tree_sha256, SCOPE, &resolver)
            .is_err()
    );
}

/// Reviewer exact4 ledger authority boundary; normative source: SPEC §6, §7.4, §7.6.
#[test]
fn ledger_rejects_unverified_pairs_action_mismatch_and_unarchived_records() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = TrustedRoot::open(directory.path()).expect("trusted root");
    let key = SigningKey::from_bytes(&[49; 32]);
    let resolver = MemoryResolver::with(PROJECT, software_credential(&key));
    let unit = path_unit(b"trusted/unit");
    let request = content_request(vec![unit.clone()]);
    let approval = direct_approval(&request, &key, 100);
    let mut forged = approval.approval().clone();
    forged.material = ApprovalMaterial::Ed25519 {
        signature: "00".repeat(64),
    };
    let forged = ApprovalDocument::encode(forged).expect("canonical forged approval");
    assert!(matches!(
        uchgs::ledger::Ledger::new(&root).append_content(
            &request,
            &forged,
            &unit.unit_id,
            &resolver,
        ),
        Err(Error::UnauthorizedApproval(_))
    ));

    let absent = path_unit(b"not/in/request");
    assert!(matches!(
        uchgs::ledger::Ledger::new(&root).append_content(
            &request,
            &approval,
            &absent.unit_id,
            &resolver,
        ),
        Err(Error::InvalidField {
            field: "unit_id",
            ..
        })
    ));

    uchgs::ledger::Ledger::new(&root)
        .append_content(&request, &approval, &unit.unit_id, &resolver)
        .expect("locally written canonical record");
    assert!(
        uchgs::ledger::Ledger::new(&root)
            .has_unit_scope(&unit.unit_id, SCOPE, &resolver)
            .is_err(),
        "a locally canonical record without its archived authority pair is not trusted"
    );
}

/// SPEC §6.4 conflict/atomicity; normative source: SPEC §6.4, §14.2.
#[test]
fn concurrent_different_judgments_leave_one_valid_record() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().to_owned();
    let unit = path_unit(b"same-unit");
    let first_request = content_request(vec![unit.clone()]);
    let second_request = content_request(vec![unit.clone()]);
    let first_key = SigningKey::from_bytes(&[51; 32]);
    let second_key = SigningKey::from_bytes(&[52; 32]);
    let first_approval = direct_approval(&first_request, &first_key, 100);
    let second_approval = direct_approval(&second_request, &second_key, 100);
    let resolver = Arc::new(
        MemoryResolver::with(PROJECT, software_credential(&first_key))
            .and(PROJECT, software_credential(&second_key)),
    );
    let barrier = Arc::new(Barrier::new(2));

    let spawn = |request: RequestDocument,
                 approval: ApprovalDocument,
                 barrier: Arc<Barrier>,
                 resolver: Arc<MemoryResolver>| {
        let path = path.clone();
        let unit = unit.clone();
        thread::spawn(move || {
            let root = TrustedRoot::open(path).expect("trusted root");
            barrier.wait();
            uchgs::ledger::Ledger::new(&root).append_content(
                &request,
                &approval,
                &unit.unit_id,
                resolver.as_ref(),
            )
        })
    };
    let first = spawn(
        first_request,
        first_approval,
        barrier.clone(),
        resolver.clone(),
    );
    let second = spawn(second_request, second_approval, barrier, resolver);
    let results = [
        first.join().expect("thread"),
        second.join().expect("thread"),
    ];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(Error::AuthorityConflict(_))))
            .count(),
        1
    );
    let record_path = directory.path().join(format!(
        "ledger/unit/v1/sha256/path/{}.json",
        unit.unit_id.digest()
    ));
    let bytes = fs::read(record_path).expect("record bytes");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).expect("valid json")["judgments"]
            .as_array()
            .expect("array")
            .len(),
        1
    );
}

/// SPEC §16 registry_03/04; normative source: SPEC §8.1, §8.4.
#[test]
fn registry_documents_and_ids_are_recomputed_on_read() {
    let global_dir = tempfile::tempdir().expect("global");
    let repository_dir = tempfile::tempdir().expect("repository");
    let key = SigningKey::from_bytes(&[61; 32]);
    let credential = software_credential(&key);
    let genesis_dir = install_genesis(global_dir.path(), &credential, "human");

    let global = TrustedRoot::open(global_dir.path()).expect("global root");
    let repository = TrustedRoot::open(repository_dir.path()).expect("repository root");
    let resolved = Registry::new(&global, &repository)
        .resolve_full(PROJECT, credential.id())
        .expect("registered credential");
    assert_eq!(resolved.principal, "human");
    assert_eq!(resolved.credential.bytes(), credential.bytes());

    let wrong_dir = global_dir
        .path()
        .join("genesis/v1/sha256")
        .join("00".repeat(32));
    fs::rename(genesis_dir, wrong_dir).expect("tamper path");
    assert!(matches!(
        Registry::new(&global, &repository).resolve_full(PROJECT, credential.id()),
        Err(Error::AuthorityConflict(_))
    ));
}

/// Reviewer exact4 registry trust graph; normative source: SPEC §8.1–§8.4.
#[test]
fn registry_resolves_only_complete_authorized_enrollment_bundles() {
    let global_dir = tempfile::tempdir().expect("global");
    let repository_dir = tempfile::tempdir().expect("repository");
    let genesis_key = SigningKey::from_bytes(&[62; 32]);
    let genesis_credential = software_credential(&genesis_key);
    install_genesis(global_dir.path(), &genesis_credential, "root");

    let first_key = SigningKey::from_bytes(&[63; 32]);
    let first_credential = software_credential(&first_key);
    let first_request = signer_enroll_request(&first_credential, "first", RegistryName::Repository);
    let first_approval = direct_approval(&first_request, &genesis_key, 100);
    let first_enrollment = enrollment_document(
        &first_request,
        &first_approval,
        &first_credential,
        "first",
        RegistryName::Repository,
    );
    install_enrollment_bundle(
        repository_dir.path(),
        &first_request,
        &first_approval,
        &first_credential,
        &first_enrollment,
    );

    let second_key = SigningKey::from_bytes(&[64; 32]);
    let second_credential = software_credential(&second_key);
    let second_request =
        signer_enroll_request(&second_credential, "second", RegistryName::Repository);
    let second_approval = direct_approval(&second_request, &first_key, 101);
    let second_enrollment = enrollment_document(
        &second_request,
        &second_approval,
        &second_credential,
        "second",
        RegistryName::Repository,
    );
    install_enrollment_bundle(
        repository_dir.path(),
        &second_request,
        &second_approval,
        &second_credential,
        &second_enrollment,
    );

    let global = TrustedRoot::open(global_dir.path()).expect("global root");
    let repository = TrustedRoot::open(repository_dir.path()).expect("repository root");
    let resolved = Registry::new(&global, &repository)
        .resolve_full(PROJECT, second_credential.id())
        .expect("fixed-point enrollment chain");
    assert_eq!(resolved.principal, "second");
    assert_eq!(resolved.credential.bytes(), second_credential.bytes());
}

/// Reviewer exact4 registry failures; normative source: SPEC §8.1–§8.4.
#[test]
fn registry_rejects_multiple_genesis_self_approval_and_incomplete_bundle() {
    let global_dir = tempfile::tempdir().expect("global");
    let repository_dir = tempfile::tempdir().expect("repository");
    let genesis_key = SigningKey::from_bytes(&[65; 32]);
    let genesis_credential = software_credential(&genesis_key);
    install_genesis(global_dir.path(), &genesis_credential, "root");
    let other_genesis = software_credential(&SigningKey::from_bytes(&[66; 32]));
    install_genesis(global_dir.path(), &other_genesis, "other-root");
    let global = TrustedRoot::open(global_dir.path()).expect("global root");
    let repository = TrustedRoot::open(repository_dir.path()).expect("repository root");
    assert!(matches!(
        Registry::new(&global, &repository).resolve_full(PROJECT, genesis_credential.id()),
        Err(Error::AuthorityConflict(_))
    ));

    let global_dir = tempfile::tempdir().expect("global");
    let repository_dir = tempfile::tempdir().expect("repository");
    install_genesis(global_dir.path(), &genesis_credential, "root");
    let target_key = SigningKey::from_bytes(&[67; 32]);
    let target_credential = software_credential(&target_key);
    let request = signer_enroll_request(&target_credential, "self", RegistryName::Repository);
    let self_approval = direct_approval(&request, &target_key, 100);
    let enrollment = enrollment_document(
        &request,
        &self_approval,
        &target_credential,
        "self",
        RegistryName::Repository,
    );
    let bundle = install_enrollment_bundle(
        repository_dir.path(),
        &request,
        &self_approval,
        &target_credential,
        &enrollment,
    );
    let global = TrustedRoot::open(global_dir.path()).expect("global root");
    let repository = TrustedRoot::open(repository_dir.path()).expect("repository root");
    assert!(matches!(
        Registry::new(&global, &repository).resolve_full(PROJECT, target_credential.id()),
        Err(Error::UnauthorizedApproval(_))
    ));

    fs::remove_file(bundle.join("approval.json")).expect("remove bundle member");
    assert!(matches!(
        Registry::new(&global, &repository).resolve_full(PROJECT, target_credential.id()),
        Err(Error::AuthorityConflict(_))
    ));
    let other_request = signer_enroll_request(&target_credential, "self", RegistryName::Repository);
    fs::write(
        bundle.join("approval.json"),
        direct_approval(&other_request, &genesis_key, 101).bytes(),
    )
    .expect("mismatched approval");
    assert!(matches!(
        Registry::new(&global, &repository).resolve_full(PROJECT, target_credential.id()),
        Err(Error::AuthorityConflict(_))
    ));
}

/// SPEC §16 registry_03/04; normative source: SPEC §8.4.
#[test]
fn enrollment_schema_and_self_excluding_id_are_exact() {
    let key = SigningKey::from_bytes(&[71; 32]);
    let credential = software_credential(&key);
    let request = content_request(vec![path_unit(b"enrollment")]);
    let approval = direct_approval(&request, &key, 100);
    let preimage = serde_json::json!({
        "active_policy_sha256": "01".repeat(32),
        "approval_sha256": approval.sha256().to_string(),
        "credential_id": credential.id().to_string(),
        "credential_length": credential.bytes().len(),
        "credential_sha256": credential.sha256().to_string(),
        "kind": "uchgs-enrollment",
        "principal": "human",
        "project": PROJECT,
        "registry": "repository",
        "request_id": request.id().to_string(),
        "request_sha256": request.sha256().to_string(),
        "schema": 1
    });
    let preimage_bytes = serde_json_canonicalizer::to_vec(&preimage).expect("preimage");
    let enrollment_id = hex::encode(Sha256::digest(preimage_bytes));
    let mut complete = preimage.as_object().expect("object").clone();
    complete.insert(
        "enrollment_id".to_owned(),
        serde_json::Value::String(enrollment_id),
    );
    let bytes = serde_json_canonicalizer::to_vec(&complete).expect("enrollment");
    EnrollmentDocument::parse(&bytes).expect("valid enrollment");

    complete.insert(
        "enrollment_id".to_owned(),
        serde_json::Value::String("00".repeat(32)),
    );
    let tampered = serde_json_canonicalizer::to_vec(&complete).expect("tampered");
    assert!(EnrollmentDocument::parse(&tampered).is_err());

    complete.insert("extra".to_owned(), serde_json::Value::Bool(true));
    let extra = serde_json_canonicalizer::to_vec(&complete).expect("extra");
    assert!(EnrollmentDocument::parse(&extra).is_err());
}
