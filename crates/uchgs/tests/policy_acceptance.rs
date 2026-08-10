//! Library-level policy acceptance tests.
//!
//! Normative source: SPEC §5 and §16 (`project`, `設定`, `policy の同一性`).

use std::{
    fs::{self, OpenOptions},
    path::Path,
    sync::mpsc,
    thread,
    time::Duration,
};

use ed25519_dalek::{Signer as _, SigningKey};
use fs2::FileExt as _;
use tempfile::TempDir;
use uchgs::{
    Error,
    authority_file::TrustedRoot,
    pending::{PendingHandle, PendingStore},
    policy::{ActivePolicy, PolicyConfig, PolicyStore, ScopeType},
    wire::{
        Action, Approval, ApprovalDocument, ApprovalMaterial, CredentialId, CredentialResolver,
        Digest32, PolicyId, PolicyUpdateAction, PublicCredential, PublicCredentialDocument,
        RequestDocument, SoftwareEd25519Credential,
    },
};

const CONFIG_A: &str = r#"project = "demo"

[gate.commit]
require = ["review"]

[gate.push]
require = ["review", "state"]

[scope.review]
type = "content"

[scope.state]
type = "state"
"#;

const CONFIG_B: &str = r#"project = "demo"

[gate.commit]
require = ["review"]

[gate.push]
require = ["review"]

[scope.review]
type = "content"
"#;

#[derive(Clone)]
struct OneCredential {
    document: PublicCredentialDocument,
}

impl CredentialResolver for OneCredential {
    fn resolve(
        &self,
        project: &str,
        credential_id: &CredentialId,
    ) -> uchgs::Result<PublicCredentialDocument> {
        if matches!(project, "demo" | "other") && credential_id == self.document.id() {
            Ok(self.document.clone())
        } else {
            Err(Error::AuthorityNotFound("credential is absent".to_owned()))
        }
    }
}

struct Fixture {
    authority_dir: TempDir,
    candidate_dir: TempDir,
    root: TrustedRoot,
    resolver: OneCredential,
    signing_key: SigningKey,
}

impl Fixture {
    fn new() -> Self {
        let authority_dir = tempfile::tempdir().unwrap();
        let candidate_dir = tempfile::tempdir().unwrap();
        let root = TrustedRoot::open(authority_dir.path()).unwrap();
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let credential = PublicCredentialDocument::encode(PublicCredential::SoftwareEd25519(
            SoftwareEd25519Credential {
                credential_type: "software-ed25519".to_owned(),
                kind: "uchgs-public-credential".to_owned(),
                public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
                schema: 1,
            },
        ))
        .unwrap();
        Self {
            authority_dir,
            candidate_dir,
            root,
            resolver: OneCredential {
                document: credential,
            },
            signing_key,
        }
    }

    fn candidate(&self, name: &str, bytes: &str) -> std::path::PathBuf {
        let path = fs::canonicalize(self.candidate_dir.path())
            .unwrap()
            .join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    fn request(&self, path: &Path) -> PendingHandle {
        PolicyStore::new(&self.root)
            .request_update(path, "review policy".to_owned(), &self.resolver)
            .unwrap()
    }

    fn request_for(
        &self,
        path: &Path,
        project: &str,
        expected_active: Option<Digest32>,
    ) -> PendingHandle {
        let config = PolicyConfig::parse(&fs::read(path).unwrap()).unwrap();
        let request = RequestDocument::new(
            project.to_owned(),
            Action::PolicyUpdate(PolicyUpdateAction {
                config_id: config.digest(),
                config_length: config.bytes().len() as u64,
                expected_active,
                note: "review policy".to_owned(),
            }),
        )
        .unwrap();
        PendingStore::new(&self.root)
            .publish_request(&request)
            .unwrap()
    }

    fn approval_for(&self, request: &RequestDocument) -> ApprovalDocument {
        let mut message = b"uchgs-approval-v1\0".to_vec();
        message.extend_from_slice(request.sha256().as_bytes());
        let signature = self.signing_key.sign(&message);
        ApprovalDocument::encode(Approval {
            approved_at: "1".to_owned(),
            credential_id: self.resolver.document.id().clone(),
            delegation: None,
            kind: "approval".to_owned(),
            material: ApprovalMaterial::Ed25519 {
                signature: hex::encode(signature.to_bytes()),
            },
            request_id: request.id().clone(),
            request_sha256: request.sha256(),
            schema: 1,
        })
        .unwrap()
    }

    fn approve(&self, handle: &PendingHandle) -> (RequestDocument, ApprovalDocument) {
        let digest = handle.request_id().digest().to_hex();
        let request_bytes = fs::read(
            self.authority_dir
                .path()
                .join("pending/v1/sha256")
                .join(digest)
                .join("request.json"),
        )
        .unwrap();
        let request = RequestDocument::parse(&request_bytes).unwrap();
        let approval = self.approval_for(&request);
        PendingStore::new(&self.root)
            .stage_approval_candidate(handle.request_id(), approval.bytes())
            .unwrap();
        (request, approval)
    }

    fn activate(&self, path: &Path) -> ActivePolicy {
        let handle = self.request(path);
        self.approve(&handle);
        PolicyStore::new(&self.root)
            .activate(handle.request_id(), path, &self.resolver)
            .unwrap()
    }
}

/// SPEC §16「設定には観点名・型・gate要求だけ」; SPEC §5.2–§5.4.
#[test]
fn policy_01_config_has_only_scope_name_type_and_gate_requirements() {
    let config = PolicyConfig::parse(CONFIG_A.as_bytes()).unwrap();
    assert_eq!(config.project(), "demo");
    assert_eq!(config.scope_type("review"), Some(ScopeType::Content));
    assert_eq!(config.scope_type("state"), Some(ScopeType::State));
    assert_eq!(config.commit_requirements(), ["review"]);
    assert_eq!(config.push_requirements(), ["review", "state"]);

    for invalid in [
        CONFIG_A.replace("type = \"content\"", "type = \"content\"\nrecall = \"x\""),
        CONFIG_A.replace("project = \"demo\"", "project = \"demo\"\nunknown = true"),
        CONFIG_A.replace(
            "require = [\"review\"]",
            "require = [\"review\", \"review\"]",
        ),
        CONFIG_A.replace("require = [\"review\"]", "require = [\"state\"]"),
    ] {
        assert!(matches!(
            PolicyConfig::parse(invalid.as_bytes()),
            Err(Error::PolicyInvalid(_))
        ));
    }
}

/// SPEC §16「候補projectが現ACTIVEと違えば失敗」; SPEC §5.5.
#[test]
fn project_01_policy_update_rejects_project_change() {
    let fixture = Fixture::new();
    let first = fixture.candidate("first.toml", CONFIG_A);
    fixture.activate(&first);
    let changed = fixture.candidate("changed.toml", &CONFIG_B.replace("demo", "other"));
    assert!(matches!(
        PolicyStore::new(&fixture.root).request_update(
            &changed,
            "change project".to_owned(),
            &fixture.resolver
        ),
        Err(Error::PolicyInvalid(_))
    ));
}

/// SPEC §16「期待ACTIVEとの不一致を拒否」; SPEC §5.5.
#[test]
fn policy_02_active_mismatch_fails() {
    let fixture = Fixture::new();
    let first = fixture.candidate("first.toml", CONFIG_A);
    fixture.activate(&first);
    let second = fixture.candidate("second.toml", CONFIG_B);
    let left = fixture.request(&second);
    let right = fixture.request(&second);
    fixture.approve(&left);
    fixture.approve(&right);
    PolicyStore::new(&fixture.root)
        .activate(left.request_id(), &second, &fixture.resolver)
        .unwrap();
    assert!(matches!(
        PolicyStore::new(&fixture.root).activate(right.request_id(), &second, &fixture.resolver),
        Err(Error::AuthorityConflict(_))
    ));
}

/// SPEC §16「古いbundleを直後に消す」; SPEC §5.5.
#[test]
fn policy_03_old_bundle_is_removed_after_activation() {
    let fixture = Fixture::new();
    let first = fixture.candidate("first.toml", CONFIG_A);
    let old = fixture.activate(&first);
    let old_directory = fixture
        .authority_dir
        .path()
        .join("policy/bundles/v1")
        .join(old.id().digest().to_hex());
    let second = fixture.candidate("second.toml", CONFIG_B);
    fixture.activate(&second);
    assert!(!old_directory.exists());
}

/// SPEC §16「policy変更後も過去判定は有効」; SPEC §5.5, §6.
#[test]
fn policy_04_old_judgments_survive_policy_change() {
    let fixture = Fixture::new();
    let first = fixture.candidate("first.toml", CONFIG_A);
    fixture.activate(&first);
    let judgment = fixture.authority_dir.path().join("ledger/sentinel");
    fs::create_dir_all(judgment.parent().unwrap()).unwrap();
    fs::write(&judgment, b"unchanged").unwrap();

    let second = fixture.candidate("second.toml", CONFIG_B);
    fixture.activate(&second);
    assert_eq!(fs::read(judgment).unwrap(), b"unchanged");
}

/// SPEC §16「ACTIVE/bundle/request digestが一致」; SPEC §5.1.
#[test]
fn policy_identity_01_active_directory_and_request_digest_match() {
    let fixture = Fixture::new();
    let candidate = fixture.candidate("policy.toml", CONFIG_A);
    let active = fixture.activate(&candidate);
    let active_bytes = fs::read(fixture.authority_dir.path().join("policy/ACTIVE")).unwrap();
    assert_eq!(active_bytes, format!("{}\n", active.id()).as_bytes());
    assert_eq!(active.id().digest(), active.request().sha256());
    assert!(
        fixture
            .authority_dir
            .path()
            .join("policy/bundles/v1")
            .join(active.id().digest().to_hex())
            .is_dir()
    );
}

/// SPEC §16「request config_id不一致をpolicy-invalidにする」; SPEC §5.1.
#[test]
fn policy_identity_02_config_id_matches_config_digest() {
    let fixture = Fixture::new();
    let candidate = fixture.candidate("policy.toml", CONFIG_A);
    let active = fixture.activate(&candidate);
    let bundle = fixture
        .authority_dir
        .path()
        .join("policy/bundles/v1")
        .join(active.id().digest().to_hex());
    fs::write(bundle.join("config.toml"), CONFIG_B).unwrap();
    assert!(matches!(
        PolicyStore::new(&fixture.root).load(&fixture.resolver),
        Err(Error::PolicyInvalid(_))
    ));
}

/// SPEC §16「bundle三点のどの差替えも失敗」; SPEC §5.1.
#[test]
fn policy_identity_03_any_bundle_substitution_fails() {
    let fixture = Fixture::new();
    let candidate = fixture.candidate("policy.toml", CONFIG_A);
    let active = fixture.activate(&candidate);
    let bundle = fixture
        .authority_dir
        .path()
        .join("policy/bundles/v1")
        .join(active.id().digest().to_hex());
    for name in ["config.toml", "request.json", "approval.json"] {
        let path = bundle.join(name);
        let exact = fs::read(&path).unwrap();
        fs::write(&path, b"x").unwrap();
        assert!(matches!(
            PolicyStore::new(&fixture.root).load(&fixture.resolver),
            Err(Error::PolicyInvalid(_))
        ));
        fs::write(path, exact).unwrap();
    }
}

/// SPEC §5.5 crash recovery: ACTIVE is the sole commit point.
#[test]
fn policy_recovery_resumes_after_active_replacement() {
    let fixture = Fixture::new();
    let first = fixture.candidate("first.toml", CONFIG_A);
    let old = fixture.activate(&first);
    let second = fixture.candidate("second.toml", CONFIG_B);
    let handle = fixture.request(&second);
    let (request, approval) = fixture.approve(&handle);
    let target_digest = request.sha256().to_hex();
    let target = fixture
        .authority_dir
        .path()
        .join("policy/bundles/v1")
        .join(&target_digest);
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("config.toml"), CONFIG_B).unwrap();
    fs::write(target.join("request.json"), request.bytes()).unwrap();
    fs::write(target.join("approval.json"), approval.bytes()).unwrap();
    fs::write(
        fixture.authority_dir.path().join("policy/ACTIVE"),
        format!("policy/v1/sha256/{target_digest}\n"),
    )
    .unwrap();

    let resumed = PolicyStore::new(&fixture.root)
        .activate(handle.request_id(), &second, &fixture.resolver)
        .unwrap();
    assert_eq!(resumed.id().digest(), request.sha256());
    assert!(
        !fixture
            .authority_dir
            .path()
            .join("policy/bundles/v1")
            .join(old.id().digest().to_hex())
            .exists()
    );
    assert!(
        !fixture
            .authority_dir
            .path()
            .join("pending/v1/sha256")
            .join(&target_digest)
            .exists()
    );
    assert!(
        fixture
            .authority_dir
            .path()
            .join("approvals/v1/sha256")
            .join(target_digest)
            .is_dir()
    );
}

/// SPEC §5.5 cleanup removes only recognized policy residues.
#[test]
fn policy_recovery_next_operation_cleans_partial_and_temporary_residue() {
    let fixture = Fixture::new();
    let first = fixture.candidate("first.toml", CONFIG_A);
    fixture.activate(&first);
    let bundles = fixture.authority_dir.path().join("policy/bundles/v1");
    let partial = bundles.join("11".repeat(32));
    fs::create_dir_all(&partial).unwrap();
    fs::write(partial.join("config.toml"), CONFIG_A).unwrap();
    let temporary = bundles.join(format!(
        ".tmp-authority-{}-1-residue",
        std::process::id().saturating_add(1)
    ));
    fs::create_dir(&temporary).unwrap();

    let second = fixture.candidate("second.toml", CONFIG_B);
    fixture.request(&second);
    assert!(!partial.exists());
    assert!(!temporary.exists());

    fs::create_dir(bundles.join(".tmp-garbage")).unwrap();
    assert!(matches!(
        PolicyStore::new(&fixture.root).request_update(
            &second,
            "unknown residue".to_owned(),
            &fixture.resolver
        ),
        Err(Error::PolicyInvalid(_))
    ));
}

/// SPEC §15: absence and malformed authority have distinct typed failures.
#[test]
fn policy_errors_missing_and_invalid_are_typed() {
    let fixture = Fixture::new();
    assert!(matches!(
        PolicyStore::new(&fixture.root).load(&fixture.resolver),
        Err(Error::PolicyMissing(_))
    ));
    fs::create_dir_all(fixture.authority_dir.path().join("policy")).unwrap();
    fs::write(
        fixture.authority_dir.path().join("policy/ACTIVE"),
        b"broken\n",
    )
    .unwrap();
    assert!(matches!(
        PolicyStore::new(&fixture.root).load(&fixture.resolver),
        Err(Error::PolicyInvalid(_))
    ));
}

/// SPEC §5.1/§5.5: request and config project are one immutable authority binding.
#[test]
fn policy_request_project_must_match_config_before_initial_or_updated_activation() {
    let fixture = Fixture::new();
    let first = fixture.candidate("first.toml", CONFIG_A);
    let initial = fixture.request_for(&first, "other", None);
    fixture.approve(&initial);
    assert!(matches!(
        PolicyStore::new(&fixture.root).activate(initial.request_id(), &first, &fixture.resolver),
        Err(Error::PolicyInvalid(_))
    ));
    assert!(!fixture.authority_dir.path().join("policy/ACTIVE").exists());

    let active = fixture.activate(&first);
    let second = fixture.candidate("second.toml", CONFIG_B);
    let update = fixture.request_for(&second, "other", Some(active.id().digest()));
    fixture.approve(&update);
    assert!(matches!(
        PolicyStore::new(&fixture.root).activate(update.request_id(), &second, &fixture.resolver),
        Err(Error::PolicyInvalid(_))
    ));
    assert_eq!(
        PolicyStore::new(&fixture.root)
            .load(&fixture.resolver)
            .unwrap()
            .id(),
        active.id()
    );
}

/// SPEC §5.1: persisted request/config project mismatch is never authoritative.
#[test]
fn policy_bundle_load_rejects_request_config_project_mismatch() {
    let fixture = Fixture::new();
    let candidate = fixture.candidate("policy.toml", CONFIG_A);
    let handle = fixture.request_for(&candidate, "other", None);
    let (request, approval) = fixture.approve(&handle);
    let policy_id = PolicyId::from_digest(request.sha256());
    let bundle = fixture
        .authority_dir
        .path()
        .join("policy/bundles/v1")
        .join(policy_id.digest().to_hex());
    fs::create_dir_all(&bundle).unwrap();
    fs::write(bundle.join("config.toml"), CONFIG_A).unwrap();
    fs::write(bundle.join("request.json"), request.bytes()).unwrap();
    fs::write(bundle.join("approval.json"), approval.bytes()).unwrap();
    fs::write(
        fixture.authority_dir.path().join("policy/ACTIVE"),
        format!("{policy_id}\n"),
    )
    .unwrap();

    assert!(matches!(
        PolicyStore::new(&fixture.root).load(&fixture.resolver),
        Err(Error::PolicyInvalid(_))
    ));
}

/// SPEC §5.1/§5.5: readers serialize with the policy mutation lock.
#[test]
fn concurrent_load_waits_for_policy_update_lock_and_reads_a_valid_state() {
    let fixture = Fixture::new();
    let candidate = fixture.candidate("policy.toml", CONFIG_A);
    let active = fixture.activate(&candidate);
    let expected = active.id().clone();
    let authority = fixture.authority_dir.path().to_path_buf();
    let resolver = fixture.resolver.clone();
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(authority.join(".policy.lock"))
        .unwrap();
    lock.lock_exclusive().unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let loader = thread::spawn(move || {
        let root = TrustedRoot::open(&authority).unwrap();
        started_tx.send(()).unwrap();
        let result = PolicyStore::new(&root)
            .load(&resolver)
            .map(|policy| policy.id().clone());
        result_tx.send(result).unwrap();
    });
    started_rx.recv().unwrap();
    thread::sleep(Duration::from_millis(50));
    assert!(matches!(
        result_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    fs2::FileExt::unlock(&lock).unwrap();
    assert_eq!(result_rx.recv().unwrap().unwrap(), expected);
    loader.join().unwrap();
}

/// SPEC §5.1 and §15: bounded policy artifacts fail as typed policy-invalid.
#[test]
fn oversized_active_and_config_are_typed_policy_invalid() {
    let active_fixture = Fixture::new();
    fs::create_dir_all(active_fixture.authority_dir.path().join("policy")).unwrap();
    fs::write(
        active_fixture.authority_dir.path().join("policy/ACTIVE"),
        vec![b'a'; 129],
    )
    .unwrap();
    assert!(matches!(
        PolicyStore::new(&active_fixture.root).load(&active_fixture.resolver),
        Err(Error::PolicyInvalid(_))
    ));

    let config_fixture = Fixture::new();
    let candidate = config_fixture.candidate("policy.toml", CONFIG_A);
    let active = config_fixture.activate(&candidate);
    let config = config_fixture
        .authority_dir
        .path()
        .join("policy/bundles/v1")
        .join(active.id().digest().to_hex())
        .join("config.toml");
    fs::write(config, vec![b'a'; 1024 * 1024 + 1]).unwrap();
    assert!(matches!(
        PolicyStore::new(&config_fixture.root).load(&config_fixture.resolver),
        Err(Error::PolicyInvalid(_))
    ));
}
