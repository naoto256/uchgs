//! Durable genesis and signer-enrollment ceremonies.
//!
//! Normative source: SPEC §7.5–§7.6 and §8.1–§8.5.

use std::path::{Path, PathBuf};

use crate::{
    Error, Result,
    authority_file::{PublishOutcome, TrustedRoot, is_authority_temporary_name},
    pending::{PendingHandle, PendingStore},
    registry::{Enrollment, EnrollmentDocument, Genesis, GenesisDocument, Presence, Registry},
    signer::{PossessionProof, verify_possession},
    wire::{
        APPROVAL_MAX_BYTES, Action, CREDENTIAL_MAX_BYTES, PolicyId, PublicCredentialDocument,
        REQUEST_MAX_BYTES, RegistryName, RequestDocument, SignerEnrollAction,
    },
};

const REGISTRY_DOCUMENT_MAX_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EnrollmentPublishStage {
    FileWritten(usize),
    TemporaryDirectorySynced,
    BeforeRename,
    AfterRenameBeforeParentSync,
    BeforeReadback,
}

/// Presence evidence accepted by the one-time global bootstrap.
pub enum BootstrapPresence<'a> {
    TtyConfirmed(&'a PossessionProof),
    HeadlessAsserted,
}

/// Creates or resumes the exact one-time global genesis publication.
pub fn bootstrap_global(
    global: &TrustedRoot,
    credential: &PublicCredentialDocument,
    principal: String,
    presence: BootstrapPresence<'_>,
) -> Result<GenesisDocument> {
    let _lock = global.lock(".registry.lock")?;
    let recorded_presence = match &presence {
        BootstrapPresence::TtyConfirmed(_) => Presence::TtyConfirmed,
        BootstrapPresence::HeadlessAsserted => Presence::HeadlessAsserted,
    };
    let genesis = GenesisDocument::encode(Genesis {
        credential_id: credential.id().clone(),
        credential_length: credential.bytes().len() as u64,
        credential_sha256: credential.sha256(),
        kind: "uchgs-genesis".to_owned(),
        presence: recorded_presence,
        principal,
        registry: RegistryName::Global,
        schema: 1,
    })?;
    require_uninitialized(global, credential, &genesis)?;
    if let BootstrapPresence::TtyConfirmed(proof) = presence {
        verify_possession(credential, proof)?;
    }

    publish_exact(
        global,
        &credential_path(credential),
        credential.bytes(),
        CREDENTIAL_MAX_BYTES,
    )?;
    let genesis_path = PathBuf::from("genesis/v1/sha256")
        .join(genesis.id().digest().to_hex())
        .join("genesis.json");
    publish_exact(
        global,
        &genesis_path,
        genesis.bytes(),
        REGISTRY_DOCUMENT_MAX_BYTES,
    )?;
    Ok(genesis)
}

/// Publishes the exact signer-enroll Request into the repository pending area.
pub fn begin_enrollment(
    repository: &TrustedRoot,
    project: String,
    policy: PolicyId,
    registry: RegistryName,
    principal: String,
    credential: &PublicCredentialDocument,
    note: String,
) -> Result<(RequestDocument, PendingHandle)> {
    let request = RequestDocument::new(
        project,
        Action::SignerEnroll(SignerEnrollAction {
            credential_id: credential.id().clone(),
            credential_length: credential.bytes().len() as u64,
            credential_sha256: credential.sha256(),
            note,
            policy,
            principal,
            registry,
        }),
    )?;
    let handle = PendingStore::new(repository).publish_request(&request)?;
    Ok((request, handle))
}

/// Accepts the winning approval, durably publishes the exact §8.1 bundle,
/// verifies that it resolves from the registry, and archives the pending pair.
pub fn complete_enrollment(
    global: &TrustedRoot,
    repository: &TrustedRoot,
    request: &RequestDocument,
    credential: &PublicCredentialDocument,
) -> Result<EnrollmentDocument> {
    complete_enrollment_with(global, repository, request, credential, |_| Ok(()))
}

fn complete_enrollment_with(
    global: &TrustedRoot,
    repository: &TrustedRoot,
    request: &RequestDocument,
    credential: &PublicCredentialDocument,
    mut after_stage: impl FnMut(EnrollmentPublishStage) -> Result<()>,
) -> Result<EnrollmentDocument> {
    let registry = Registry::new(global, repository);
    let pending = PendingStore::new(repository);
    let approval = pending.accept_candidates(request.id(), &registry)?;
    approval.verify(request, &registry)?;

    let Action::SignerEnroll(action) = &request.request().action else {
        return Err(Error::field(
            "enrollment",
            "request action must be signer-enroll",
        ));
    };
    if action.credential_id != *credential.id()
        || action.credential_sha256 != credential.sha256()
        || action.credential_length != credential.bytes().len() as u64
    {
        return Err(Error::AuthorityConflict(
            "enrollment credential differs from the signed request".to_owned(),
        ));
    }

    // Everything gating the commit is evaluated again against the locked view: the
    // approval above was accepted, and the registry first read, while no registry
    // lock was held, so the trust set could have moved in between.
    let (global_lock, repository_lock) = lock_registries(global, repository)?;
    let locked_registry = Registry::new(global, repository);
    approval.verify(request, &locked_registry)?;
    require_unambiguous_candidate(
        &locked_registry,
        &request.request().project,
        action,
        credential,
    )?;

    let enrollment =
        EnrollmentDocument::encode(Enrollment::from_authority(request, &approval, credential)?)?;
    let target = match action.registry {
        RegistryName::Global => global,
        RegistryName::Repository => repository,
    };
    publish_exact(
        target,
        &credential_path(credential),
        credential.bytes(),
        CREDENTIAL_MAX_BYTES,
    )?;
    publish_enrollment_bundle(
        target,
        request,
        &approval,
        credential,
        &enrollment,
        &mut after_stage,
    )?;

    let completed_registry = Registry::new(global, repository);
    let resolved = completed_registry.resolve_full(&request.request().project, credential.id())?;
    if resolved.credential.bytes() != credential.bytes() || resolved.principal != action.principal {
        return Err(Error::AuthorityConflict(
            "published enrollment does not resolve to the exact requested identity".to_owned(),
        ));
    }
    drop(repository_lock);
    drop(global_lock);
    pending.archive_verified_pair(request, &approval, &completed_registry)?;
    Ok(enrollment)
}

/// Takes the registry locks in a fixed global-then-repository order, and only once
/// when both capabilities name the same physical root.
///
/// The two roots may be the same directory, where a second acquisition would block
/// on the lock this call already holds. Fixing the order also keeps concurrent
/// processes from interleaving their two acquisitions into a cycle.
fn lock_registries(
    global: &TrustedRoot,
    repository: &TrustedRoot,
) -> Result<(
    crate::authority_file::AuthorityLock,
    Option<crate::authority_file::AuthorityLock>,
)> {
    let same_root = global.same_root(repository)?;
    let global_lock = global.lock(".registry.lock")?;
    let repository_lock = if same_root {
        None
    } else {
        Some(repository.lock(".registry.lock")?)
    };
    Ok((global_lock, repository_lock))
}

fn require_unambiguous_candidate(
    registry: &Registry<'_>,
    project: &str,
    action: &SignerEnrollAction,
    credential: &PublicCredentialDocument,
) -> Result<()> {
    match registry.resolve_full(project, credential.id()) {
        Ok(existing)
            if existing.principal == action.principal
                && existing.credential.bytes() == credential.bytes() =>
        {
            Ok(())
        }
        Ok(_) => Err(Error::AuthorityConflict(format!(
            "ambiguous registry entry for ({}, {})",
            project,
            credential.id()
        ))),
        Err(Error::AuthorityNotFound(_)) => Ok(()),
        Err(error) => Err(error),
    }
}

fn publish_enrollment_bundle(
    target: &TrustedRoot,
    request: &RequestDocument,
    approval: &crate::wire::ApprovalDocument,
    credential: &PublicCredentialDocument,
    enrollment: &EnrollmentDocument,
    after_stage: &mut impl FnMut(EnrollmentPublishStage) -> Result<()>,
) -> Result<()> {
    let final_directory = enrollment_directory(request);
    let parent = final_directory
        .parent()
        .expect("fixed enrollment directory has a parent");
    let final_name = final_directory
        .file_name()
        .expect("fixed enrollment directory has a final name");

    match target.entries(&final_directory) {
        Ok(_) => {
            target.sync_directory(parent)?;
            return verify_enrollment_bundle(
                target,
                &final_directory,
                request,
                approval,
                credential,
                enrollment,
            );
        }
        Err(Error::Io {
            kind: std::io::ErrorKind::NotFound,
            ..
        }) => {}
        Err(error) => return Err(error),
    }

    let temporary = target.create_temporary_directory(parent, final_name)?;
    let documents: [(&str, &[u8], usize); 4] = [
        ("request.json", request.bytes(), REQUEST_MAX_BYTES),
        ("approval.json", approval.bytes(), APPROVAL_MAX_BYTES),
        ("credential.json", credential.bytes(), CREDENTIAL_MAX_BYTES),
        (
            "enrollment.json",
            enrollment.bytes(),
            REGISTRY_DOCUMENT_MAX_BYTES,
        ),
    ];
    for (index, (name, bytes, maximum)) in documents.into_iter().enumerate() {
        publish_exact(target, &temporary.join(name), bytes, maximum)?;
        after_stage(EnrollmentPublishStage::FileWritten(index))?;
    }
    target.sync_directory(&temporary)?;
    after_stage(EnrollmentPublishStage::TemporaryDirectorySynced)?;
    after_stage(EnrollmentPublishStage::BeforeRename)?;
    target.rename_directory_no_replace_with(&temporary, &final_directory, || {
        after_stage(EnrollmentPublishStage::AfterRenameBeforeParentSync)
    })?;
    after_stage(EnrollmentPublishStage::BeforeReadback)?;
    verify_enrollment_bundle(
        target,
        &final_directory,
        request,
        approval,
        credential,
        enrollment,
    )
}

fn verify_enrollment_bundle(
    root: &TrustedRoot,
    directory: &Path,
    request: &RequestDocument,
    approval: &crate::wire::ApprovalDocument,
    credential: &PublicCredentialDocument,
    enrollment: &EnrollmentDocument,
) -> Result<()> {
    require_bundle_entries(root, directory)?;
    for (name, expected, maximum) in [
        ("request.json", request.bytes(), REQUEST_MAX_BYTES),
        ("approval.json", approval.bytes(), APPROVAL_MAX_BYTES),
        ("credential.json", credential.bytes(), CREDENTIAL_MAX_BYTES),
        (
            "enrollment.json",
            enrollment.bytes(),
            REGISTRY_DOCUMENT_MAX_BYTES,
        ),
    ] {
        let path = directory.join(name);
        if root.read_file(&path, maximum)? != expected {
            return Err(Error::AuthorityConflict(format!(
                "{} already exists with different bytes",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Accepts an empty global root, or the exact unfinished publication of this same
/// genesis, and rejects everything else.
///
/// A directory named for the expected digest that still holds no final
/// `genesis.json` is this operation's own interrupted attempt, so it may be resumed.
/// A different digest, different final bytes, unknown entries, any enrollment, or an
/// unrelated credential is foreign residue and fails closed instead of being
/// absorbed into a new genesis.
fn require_uninitialized(
    global: &TrustedRoot,
    credential: &PublicCredentialDocument,
    expected_genesis: &GenesisDocument,
) -> Result<()> {
    let genesis = entries_or_empty(global, Path::new("genesis/v1/sha256"))?;
    let enrollments = entries_or_empty(global, Path::new("enrollments/v1/sha256"))?;
    if !enrollments.is_empty() {
        return Err(Error::AuthorityConflict(
            "global authority is already initialized".to_owned(),
        ));
    }

    let expected_digest = expected_genesis.id().digest().to_hex();
    match genesis.as_slice() {
        [] => {}
        [name] if name == std::ffi::OsStr::new(&expected_digest) => {
            let directory = PathBuf::from("genesis/v1/sha256").join(&expected_digest);
            let entries = entries_or_empty(global, &directory)?;
            match entries.as_slice() {
                [] => {}
                [name] if name == std::ffi::OsStr::new("genesis.json") => {
                    let path = directory.join("genesis.json");
                    let existing = global.read_file(&path, REGISTRY_DOCUMENT_MAX_BYTES)?;
                    let existing = GenesisDocument::parse(&existing).map_err(|_| {
                        Error::AuthorityConflict(
                            "the expected genesis path contains an invalid final document"
                                .to_owned(),
                        )
                    })?;
                    let detail = if existing.bytes() == expected_genesis.bytes() {
                        "global authority is already initialized"
                    } else {
                        "the expected genesis path contains different final bytes"
                    };
                    return Err(Error::AuthorityConflict(detail.to_owned()));
                }
                _ => {
                    return Err(Error::AuthorityConflict(
                        "the expected genesis directory contains unknown entries".to_owned(),
                    ));
                }
            }
        }
        _ => {
            return Err(Error::AuthorityConflict(
                "global authority contains a foreign or ambiguous genesis".to_owned(),
            ));
        }
    }

    let expected_name = format!("{}.json", credential.sha256());
    let credentials = entries_or_empty(global, Path::new("credentials/v1/sha256"))?;
    let mut unexpected = Vec::new();
    for name in credentials {
        if name.to_string_lossy() == expected_name {
            let existing = global.read_file(credential_path(credential), CREDENTIAL_MAX_BYTES)?;
            if existing != credential.bytes() {
                return Err(Error::AuthorityConflict(
                    "pre-genesis credential digest path has different bytes".to_owned(),
                ));
            }
        } else {
            unexpected.push(name.to_string_lossy().into_owned());
        }
    }
    if !unexpected.is_empty() {
        return Err(Error::AuthorityConflict(format!(
            "unexpected pre-genesis credentials: {}",
            unexpected.join(", ")
        )));
    }
    Ok(())
}

fn require_bundle_entries(root: &TrustedRoot, directory: &Path) -> Result<()> {
    let mut entries = entries_or_empty(root, directory)?
        .into_iter()
        .map(|entry| entry.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    entries.sort();
    let expected = [
        "approval.json",
        "credential.json",
        "enrollment.json",
        "request.json",
    ];
    if entries.iter().map(String::as_str).ne(expected) {
        return Err(Error::AuthorityConflict(format!(
            "enrollment bundle does not contain exact required entries: {}",
            entries.join(", ")
        )));
    }
    Ok(())
}

fn entries_or_empty(root: &TrustedRoot, path: &Path) -> Result<Vec<std::ffi::OsString>> {
    match root.entries(path) {
        Ok(mut entries) => {
            entries.retain(|name| !is_authority_temporary_name(name));
            Ok(entries)
        }
        Err(Error::Io {
            kind: std::io::ErrorKind::NotFound,
            ..
        }) => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

fn publish_exact(root: &TrustedRoot, path: &Path, bytes: &[u8], maximum: usize) -> Result<()> {
    match root.publish_file(path, bytes, false)? {
        PublishOutcome::Published => Ok(()),
        PublishOutcome::Existing => {
            if root.read_file(path, maximum)? == bytes {
                Ok(())
            } else {
                Err(Error::AuthorityConflict(format!(
                    "{} already exists with different bytes",
                    path.display()
                )))
            }
        }
    }
}

fn credential_path(credential: &PublicCredentialDocument) -> PathBuf {
    PathBuf::from("credentials/v1/sha256").join(format!("{}.json", credential.sha256()))
}

fn enrollment_directory(request: &RequestDocument) -> PathBuf {
    PathBuf::from("enrollments/v1/sha256").join(request.sha256().to_hex())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::{Arc, Barrier},
        thread,
    };

    use ed25519_dalek::{Signer as _, SigningKey};
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::wire::{
        Approval, ApprovalDocument, ApprovalMaterial, Digest32, PublicCredential,
        SoftwareEd25519Credential,
    };

    fn root(path: &Path) -> TrustedRoot {
        fs::create_dir_all(path).unwrap();
        TrustedRoot::open(path).unwrap()
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

    fn approval(request: &RequestDocument, key: &SigningKey) -> ApprovalDocument {
        let mut message = b"uchgs-approval-v1\0".to_vec();
        message.extend_from_slice(&Sha256::digest(request.bytes()));
        ApprovalDocument::encode(Approval {
            approved_at: "1".to_owned(),
            credential_id: credential(key).id().clone(),
            delegation: None,
            kind: "approval".to_owned(),
            material: ApprovalMaterial::Ed25519 {
                signature: hex::encode(key.sign(&message).to_bytes()),
            },
            request_id: request.id().clone(),
            request_sha256: request.sha256(),
            schema: 1,
        })
        .unwrap()
    }

    fn headless_genesis(credential: &PublicCredentialDocument, principal: &str) -> GenesisDocument {
        GenesisDocument::encode(Genesis {
            credential_id: credential.id().clone(),
            credential_length: credential.bytes().len() as u64,
            credential_sha256: credential.sha256(),
            kind: "uchgs-genesis".to_owned(),
            presence: Presence::HeadlessAsserted,
            principal: principal.to_owned(),
            registry: RegistryName::Global,
            schema: 1,
        })
        .unwrap()
    }

    fn stage_enrollment(
        repository: &TrustedRoot,
        approver: &SigningKey,
        enrolled: &PublicCredentialDocument,
        registry: RegistryName,
        principal: &str,
    ) -> RequestDocument {
        let (request, _) = begin_enrollment(
            repository,
            "example/project".to_owned(),
            PolicyId::from_digest(Digest32::from_bytes([3; 32])),
            registry,
            principal.to_owned(),
            enrolled,
            "enroll reviewer".to_owned(),
        )
        .unwrap();
        PendingStore::new(repository)
            .stage_approval_candidate(request.id(), approval(&request, approver).bytes())
            .unwrap();
        request
    }

    #[test]
    fn bootstrap_is_one_time_and_resumes_an_exact_credential() {
        let temp = tempfile::tempdir().unwrap();
        let global = root(&temp.path().join("global"));
        let key = SigningKey::from_bytes(&[7; 32]);
        let credential = credential(&key);

        publish_exact(
            &global,
            &credential_path(&credential),
            credential.bytes(),
            CREDENTIAL_MAX_BYTES,
        )
        .unwrap();
        let genesis = bootstrap_global(
            &global,
            &credential,
            "owner".to_owned(),
            BootstrapPresence::HeadlessAsserted,
        )
        .unwrap();
        assert_eq!(genesis.genesis().presence, Presence::HeadlessAsserted);
        assert!(matches!(
            bootstrap_global(
                &global,
                &credential,
                "owner".to_owned(),
                BootstrapPresence::HeadlessAsserted,
            ),
            Err(Error::AuthorityConflict(_))
        ));
    }

    #[test]
    fn bootstrap_resumes_only_the_exact_unfinished_genesis_publication() {
        let temp = tempfile::tempdir().unwrap();
        let global_path = temp.path().join("global");
        let global = root(&global_path);
        let credential = credential(&SigningKey::from_bytes(&[31; 32]));
        let expected = headless_genesis(&credential, "owner");

        publish_exact(
            &global,
            &credential_path(&credential),
            credential.bytes(),
            CREDENTIAL_MAX_BYTES,
        )
        .unwrap();
        let directory = global_path
            .join("genesis/v1/sha256")
            .join(expected.id().digest().to_hex());
        fs::create_dir_all(&directory).unwrap();
        let temporary = format!(".tmp-authority-{}-0-genesis.json", std::process::id());
        assert!(is_authority_temporary_name(temporary.as_ref()));
        fs::write(directory.join(temporary), expected.bytes()).unwrap();

        let published = bootstrap_global(
            &global,
            &credential,
            "owner".to_owned(),
            BootstrapPresence::HeadlessAsserted,
        )
        .unwrap();
        assert_eq!(published.bytes(), expected.bytes());
        assert_eq!(
            global
                .read_file(
                    PathBuf::from("genesis/v1/sha256")
                        .join(expected.id().digest().to_hex())
                        .join("genesis.json"),
                    REGISTRY_DOCUMENT_MAX_BYTES,
                )
                .unwrap(),
            expected.bytes()
        );
    }

    #[test]
    fn bootstrap_rejects_foreign_and_contradictory_genesis_residue() {
        let temp = tempfile::tempdir().unwrap();
        let foreign_path = temp.path().join("foreign");
        let foreign = root(&foreign_path);
        let credential = credential(&SigningKey::from_bytes(&[32; 32]));
        fs::create_dir_all(foreign_path.join("genesis/v1/sha256").join("00".repeat(32))).unwrap();
        assert!(matches!(
            bootstrap_global(
                &foreign,
                &credential,
                "owner".to_owned(),
                BootstrapPresence::HeadlessAsserted,
            ),
            Err(Error::AuthorityConflict(_))
        ));

        let contradictory_path = temp.path().join("contradictory");
        let contradictory = root(&contradictory_path);
        let expected = headless_genesis(&credential, "owner");
        let different = headless_genesis(&credential, "different-owner");
        let directory = contradictory_path
            .join("genesis/v1/sha256")
            .join(expected.id().digest().to_hex());
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("genesis.json"), different.bytes()).unwrap();
        assert!(matches!(
            bootstrap_global(
                &contradictory,
                &credential,
                "owner".to_owned(),
                BootstrapPresence::HeadlessAsserted,
            ),
            Err(Error::AuthorityConflict(_))
        ));
    }

    #[test]
    fn bootstrap_rejects_unowned_or_extra_credentials() {
        let temp = tempfile::tempdir().unwrap();
        let global = root(&temp.path().join("global"));
        let wanted = credential(&SigningKey::from_bytes(&[15; 32]));
        let other = crate::software_key::SoftwareKeyEnvelopeDocument::generate("secret").unwrap();
        let material = other
            .possession_material(
                "secret",
                &crate::signer::genesis_possession_message(other.credential()),
            )
            .unwrap();
        let proof = PossessionProof::new(other.credential().id().clone(), material);
        assert!(matches!(
            bootstrap_global(
                &global,
                &wanted,
                "owner".to_owned(),
                BootstrapPresence::TtyConfirmed(&proof),
            ),
            Err(Error::UnauthorizedApproval(_))
        ));

        publish_exact(
            &global,
            &credential_path(other.credential()),
            other.credential().bytes(),
            CREDENTIAL_MAX_BYTES,
        )
        .unwrap();
        assert!(matches!(
            bootstrap_global(
                &global,
                &wanted,
                "owner".to_owned(),
                BootstrapPresence::HeadlessAsserted,
            ),
            Err(Error::AuthorityConflict(_))
        ));
    }

    #[test]
    fn registry_01_genesis_can_approve_later_enrollment() {
        let temp = tempfile::tempdir().unwrap();
        let global = root(&temp.path().join("global"));
        let repository = root(&temp.path().join("repository"));
        let genesis_key = SigningKey::from_bytes(&[8; 32]);
        let genesis_credential = credential(&genesis_key);
        bootstrap_global(
            &global,
            &genesis_credential,
            "owner".to_owned(),
            BootstrapPresence::HeadlessAsserted,
        )
        .unwrap();

        let enrolled = credential(&SigningKey::from_bytes(&[9; 32]));
        let (request, _) = begin_enrollment(
            &repository,
            "example/project".to_owned(),
            PolicyId::from_digest(Digest32::from_bytes([3; 32])),
            RegistryName::Repository,
            "reviewer".to_owned(),
            &enrolled,
            "enroll reviewer".to_owned(),
        )
        .unwrap();
        let approval = approval(&request, &genesis_key);
        PendingStore::new(&repository)
            .stage_approval_candidate(request.id(), approval.bytes())
            .unwrap();
        complete_enrollment(&global, &repository, &request, &enrolled).unwrap();

        let resolved = Registry::new(&global, &repository)
            .resolve_full("example/project", enrolled.id())
            .unwrap();
        assert_eq!(resolved.principal, "reviewer");
        assert_eq!(resolved.credential.bytes(), enrolled.bytes());
        assert!(
            repository
                .read_file(
                    Path::new("approvals/v1/sha256")
                        .join(request.sha256().to_hex())
                        .join("approval.json"),
                    APPROVAL_MAX_BYTES,
                )
                .is_ok()
        );
    }

    #[test]
    fn registry_02_unregistered_signer_cannot_enroll() {
        let temp = tempfile::tempdir().unwrap();
        let global = root(&temp.path().join("global"));
        let repository = root(&temp.path().join("repository"));
        let genesis_key = SigningKey::from_bytes(&[12; 32]);
        bootstrap_global(
            &global,
            &credential(&genesis_key),
            "owner".to_owned(),
            BootstrapPresence::HeadlessAsserted,
        )
        .unwrap();
        let enrolled = credential(&SigningKey::from_bytes(&[13; 32]));
        let (request, _) = begin_enrollment(
            &repository,
            "example/project".to_owned(),
            PolicyId::from_digest(Digest32::from_bytes([3; 32])),
            RegistryName::Repository,
            "reviewer".to_owned(),
            &enrolled,
            "enroll reviewer".to_owned(),
        )
        .unwrap();
        let unregistered = SigningKey::from_bytes(&[14; 32]);
        PendingStore::new(&repository)
            .stage_approval_candidate(request.id(), approval(&request, &unregistered).bytes())
            .unwrap();
        assert!(matches!(
            complete_enrollment(&global, &repository, &request, &enrolled),
            Err(Error::AuthorityNotFound(_))
        ));
    }

    #[test]
    fn enrollment_bundle_commit_is_atomic_and_retryable_at_every_boundary() {
        let stages = [
            EnrollmentPublishStage::FileWritten(0),
            EnrollmentPublishStage::FileWritten(1),
            EnrollmentPublishStage::FileWritten(2),
            EnrollmentPublishStage::FileWritten(3),
            EnrollmentPublishStage::TemporaryDirectorySynced,
            EnrollmentPublishStage::BeforeRename,
            EnrollmentPublishStage::AfterRenameBeforeParentSync,
            EnrollmentPublishStage::BeforeReadback,
        ];
        for (index, fail_at) in stages.into_iter().enumerate() {
            let temp = tempfile::tempdir().unwrap();
            let global = root(&temp.path().join("global"));
            let repository_path = temp.path().join("repository");
            let repository = root(&repository_path);
            let genesis_key = SigningKey::from_bytes(&[41; 32]);
            bootstrap_global(
                &global,
                &credential(&genesis_key),
                "owner".to_owned(),
                BootstrapPresence::HeadlessAsserted,
            )
            .unwrap();
            let enrolled = credential(&SigningKey::from_bytes(&[(index + 51) as u8; 32]));
            let request = stage_enrollment(
                &repository,
                &genesis_key,
                &enrolled,
                RegistryName::Repository,
                "reviewer",
            );
            let mut injected = false;
            let result =
                complete_enrollment_with(&global, &repository, &request, &enrolled, |stage| {
                    if !injected && stage == fail_at {
                        injected = true;
                        return Err(Error::io(
                            "injected enrollment publication failure",
                            std::io::Error::other("injected"),
                        ));
                    }
                    Ok(())
                });
            assert!(matches!(result, Err(Error::Io { .. })));
            assert!(injected);

            let final_directory = repository_path
                .join("enrollments/v1/sha256")
                .join(request.sha256().to_hex());
            if final_directory.exists() {
                let mut names = fs::read_dir(&final_directory)
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name())
                    .collect::<Vec<_>>();
                names.sort();
                assert_eq!(
                    names,
                    [
                        "approval.json",
                        "credential.json",
                        "enrollment.json",
                        "request.json"
                    ]
                    .map(std::ffi::OsString::from)
                );
            }

            complete_enrollment(&global, &repository, &request, &enrolled).unwrap();
            require_bundle_entries(&repository, &enrollment_directory(&request)).unwrap();
            let resolved = Registry::new(&global, &repository)
                .resolve_full("example/project", enrolled.id())
                .unwrap();
            assert_eq!(resolved.principal, "reviewer");
        }
    }

    #[test]
    fn enrollment_ambiguity_is_rejected_before_cross_registry_publication() {
        for winner_registry in [RegistryName::Global, RegistryName::Repository] {
            let temp = tempfile::tempdir().unwrap();
            let global_path = temp.path().join("global");
            let repository_path = temp.path().join("repository");
            let global = root(&global_path);
            let repository = root(&repository_path);
            let genesis_key = SigningKey::from_bytes(&[71; 32]);
            bootstrap_global(
                &global,
                &credential(&genesis_key),
                "owner".to_owned(),
                BootstrapPresence::HeadlessAsserted,
            )
            .unwrap();
            let enrolled = credential(&SigningKey::from_bytes(&[72; 32]));
            let winner = stage_enrollment(
                &repository,
                &genesis_key,
                &enrolled,
                winner_registry,
                "winner",
            );
            complete_enrollment(&global, &repository, &winner, &enrolled).unwrap();

            let loser_registry = match winner_registry {
                RegistryName::Global => RegistryName::Repository,
                RegistryName::Repository => RegistryName::Global,
            };
            let loser = stage_enrollment(
                &repository,
                &genesis_key,
                &enrolled,
                loser_registry,
                "loser",
            );
            assert!(matches!(
                complete_enrollment(&global, &repository, &loser, &enrolled),
                Err(Error::AuthorityConflict(_))
            ));
            let loser_root = match loser_registry {
                RegistryName::Global => &global_path,
                RegistryName::Repository => &repository_path,
            };
            assert!(
                !loser_root
                    .join("enrollments/v1/sha256")
                    .join(loser.sha256().to_hex())
                    .exists()
            );
            if loser_registry != winner_registry {
                assert!(!loser_root.join(credential_path(&enrolled)).exists());
            }
        }
    }

    #[test]
    fn concurrent_conflicting_enrollments_have_one_bundle_winner_without_deadlock() {
        let temp = tempfile::tempdir().unwrap();
        let global_path = temp.path().join("global");
        let repository_path = temp.path().join("repository");
        let global = root(&global_path);
        let repository = root(&repository_path);
        let genesis_key = SigningKey::from_bytes(&[81; 32]);
        bootstrap_global(
            &global,
            &credential(&genesis_key),
            "owner".to_owned(),
            BootstrapPresence::HeadlessAsserted,
        )
        .unwrap();
        let enrolled = Arc::new(credential(&SigningKey::from_bytes(&[82; 32])));
        let first = Arc::new(stage_enrollment(
            &repository,
            &genesis_key,
            &enrolled,
            RegistryName::Repository,
            "first",
        ));
        let second = Arc::new(stage_enrollment(
            &repository,
            &genesis_key,
            &enrolled,
            RegistryName::Repository,
            "second",
        ));
        let barrier = Arc::new(Barrier::new(3));
        let run = |request: Arc<RequestDocument>| {
            let barrier = Arc::clone(&barrier);
            let global_path = global_path.clone();
            let repository_path = repository_path.clone();
            let enrolled = Arc::clone(&enrolled);
            thread::spawn(move || {
                let global = root(&global_path);
                let repository = root(&repository_path);
                barrier.wait();
                complete_enrollment(&global, &repository, &request, &enrolled)
            })
        };
        let first_thread = run(Arc::clone(&first));
        let second_thread = run(Arc::clone(&second));
        barrier.wait();
        let first_result = first_thread.join().unwrap();
        let second_result = second_thread.join().unwrap();
        assert_eq!(first_result.is_ok() as u8 + second_result.is_ok() as u8, 1);
        assert!(first_result.is_ok() || matches!(first_result, Err(Error::AuthorityConflict(_))));
        assert!(second_result.is_ok() || matches!(second_result, Err(Error::AuthorityConflict(_))));
        let first_exists = repository_path.join(enrollment_directory(&first)).exists();
        let second_exists = repository_path.join(enrollment_directory(&second)).exists();
        assert_ne!(first_exists, second_exists);
        let resolved = Registry::new(&global, &repository)
            .resolve_full("example/project", enrolled.id())
            .unwrap();
        assert_eq!(
            resolved.principal,
            if first_exists { "first" } else { "second" }
        );
    }

    #[test]
    fn enrollment_rejects_an_approval_bound_to_another_request() {
        let temp = tempfile::tempdir().unwrap();
        let repository = root(&temp.path().join("repository"));
        let approver = SigningKey::from_bytes(&[83; 32]);
        let enrolled = credential(&SigningKey::from_bytes(&[84; 32]));
        let first = stage_enrollment(
            &repository,
            &approver,
            &enrolled,
            RegistryName::Repository,
            "first",
        );
        let second = stage_enrollment(
            &repository,
            &approver,
            &enrolled,
            RegistryName::Repository,
            "second",
        );

        assert!(matches!(
            Enrollment::from_authority(&first, &approval(&second, &approver), &enrolled),
            Err(Error::UnauthorizedApproval(_))
        ));
    }

    #[test]
    fn duplicate_physical_registry_root_acquires_one_lock() {
        let temp = tempfile::tempdir().unwrap();
        let shared_path = temp.path().join("shared");
        let global = root(&shared_path);
        let repository = root(&shared_path);
        assert!(global.same_root(&repository).unwrap());
        let (global_lock, repository_lock) = lock_registries(&global, &repository).unwrap();
        assert!(repository_lock.is_none());
        drop(global_lock);
    }
}
