//! Push-gate evaluation over one immutable pre-push and remote snapshot.
//!
//! Normative source: SPEC §5.4, §6, and §11.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

use sha2::{Digest as _, Sha256};

use crate::{
    Error, Result,
    authority_file::{PublishOutcome, TrustedRoot},
    extract::{JudgmentUnit, extract_git_object},
    git_traversal::{GitObjectKind, GitRepository, ObjectId},
    ledger::Ledger,
    policy::{PolicyStore, ScopeType},
    registry::Registry,
    wire::{
        Digest32, ObjectFormatName, PUSH_INTENT_MAX_BYTES, PUSH_UPDATE_MAX_COUNT, PushBytes,
        PushIntent, PushIntentDocument, PushIntentId, PushUpdate,
    },
};

const RUN_ATTEMPTS: usize = 1024;

/// One content or state judgment absent from the verified ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushMissingSubject {
    Content(JudgmentUnit),
    State {
        tree_oid: String,
        tree_sha256: Digest32,
    },
}

/// One deterministic missing judgment ordered by scope and subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushMissingJudgment {
    scope: String,
    subject: PushMissingSubject,
}

impl PushMissingJudgment {
    pub fn scope(&self) -> &str {
        &self.scope
    }

    pub fn subject(&self) -> &PushMissingSubject {
        &self.subject
    }
}

/// One scope-local failure retained while the remaining scopes are evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushScopeFailure {
    scope: String,
    error: Error,
}

impl PushScopeFailure {
    pub fn scope(&self) -> &str {
        &self.scope
    }

    pub fn error(&self) -> &Error {
        &self.error
    }
}

/// Complete push-gate result for a single PushIntent snapshot.
#[derive(Debug, Clone)]
pub struct PushGateResult {
    intent: PushIntentDocument,
    missing: Vec<PushMissingJudgment>,
    failures: Vec<PushScopeFailure>,
    missing_remote_tips: Vec<String>,
}

impl PushGateResult {
    pub fn intent_id(&self) -> &PushIntentId {
        self.intent.id()
    }

    pub fn intent(&self) -> &PushIntentDocument {
        &self.intent
    }

    pub fn missing(&self) -> &[PushMissingJudgment] {
        &self.missing
    }

    pub fn failures(&self) -> &[PushScopeFailure] {
        &self.failures
    }

    /// OIDs advertised by the remote whose required local baseline objects
    /// were absent. They are diagnostic only and were deliberately not used
    /// as complete baseline contributions.
    pub fn missing_remote_tips(&self) -> &[String] {
        &self.missing_remote_tips
    }

    pub fn is_clear(&self) -> bool {
        self.missing.is_empty() && self.failures.is_empty()
    }

    pub fn require_clear(&self) -> Result<()> {
        if let Some(failure) = self.failures.first() {
            return Err(failure.error.clone());
        }
        if self.missing.is_empty() {
            Ok(())
        } else {
            Err(Error::JudgmentMissing {
                count: self.missing.len(),
            })
        }
    }
}

/// Read-only push gate bound to one Git repository and its authority roots.
pub struct PushGate<'a> {
    git: GitRepository,
    global: &'a TrustedRoot,
    repository: TrustedRoot,
}

impl<'a> PushGate<'a> {
    pub fn open(working_directory: impl AsRef<Path>, global: &'a TrustedRoot) -> Result<Self> {
        let git = GitRepository::open(working_directory)?;
        let repository = TrustedRoot::open(git.repository_root()?.join(".uchgs"))?;
        Ok(Self {
            git,
            global,
            repository,
        })
    }

    /// Fixes argv/stdin exactly once, durably records that snapshot, and then
    /// evaluates every configured push scope without publishing judgments.
    pub fn evaluate(&self, remote_name: OsString, stdin: Vec<u8>) -> Result<PushGateResult> {
        self.git.validate_remote_name(&remote_name)?;
        let intent = capture_intent(&self.git, &remote_name, &stdin)?;
        persist_intent(&self.repository, &intent)?;

        // No policy/ledger lock is held across remote discovery.
        let remote = self.git.remote_tips(&remote_name)?;
        let snapshot = discover_push(&self.git, intent.value(), &remote.present)?;

        let registry = Registry::new(self.global, &self.repository);
        let policy = PolicyStore::new(&self.repository).load(&registry)?;
        let ledger = Ledger::new(&self.repository);
        let (missing, failures) = evaluate_scopes(&snapshot, policy.config(), &ledger, &registry);
        let missing_remote_tips = remote
            .missing
            .into_iter()
            .chain(snapshot.missing_baseline_tips.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|identifier| identifier.as_str().to_owned())
            .collect();

        Ok(PushGateResult {
            intent,
            missing,
            failures,
            missing_remote_tips,
        })
    }
}

#[derive(Debug)]
/// One successfully peeled §11.4 state target.
struct StateTarget {
    tree_oid: ObjectId,
    tree_sha256: Digest32,
}

#[derive(Debug)]
/// One §11.4 state-only failure deferred for per-scope aggregation.
struct DeferredStateFailure {
    error: Error,
}

#[derive(Debug)]
/// Immutable §11.3–§11.4 discovery result shared by every push scope.
struct PushSnapshot {
    units: Vec<JudgmentUnit>,
    states: Vec<StateTarget>,
    state_failures: Vec<DeferredStateFailure>,
    missing_baseline_tips: Vec<ObjectId>,
}

fn capture_intent(
    git: &GitRepository,
    remote_name: &OsStr,
    stdin: &[u8],
) -> Result<PushIntentDocument> {
    if stdin.len() > PUSH_INTENT_MAX_BYTES {
        return Err(Error::InvalidArguments(format!(
            "pre-push stdin exceeds {PUSH_INTENT_MAX_BYTES} bytes"
        )));
    }
    let remote_name = PushBytes::remote_name(remote_name)?;
    let width = git.object_format().oid_hex_bytes();
    let updates = parse_updates(stdin, width)?;
    PushIntentDocument::encode(PushIntent {
        kind: "push-intent".to_owned(),
        object_format: object_format_name(git.object_format()),
        remote_name,
        schema: 1,
        updates,
    })
}

fn parse_updates(stdin: &[u8], oid_width: usize) -> Result<Vec<PushUpdate>> {
    if stdin.is_empty() {
        return Ok(Vec::new());
    }
    if !stdin.ends_with(b"\n") {
        return Err(Error::InvalidArguments(
            "pre-push stdin must end every update with LF".to_owned(),
        ));
    }
    let mut updates = Vec::new();
    for line in stdin[..stdin.len() - 1].split(|byte| *byte == b'\n') {
        if line.is_empty() || line.contains(&b'\r') || line.contains(&b'\0') {
            return Err(Error::InvalidArguments(
                "pre-push stdin contains an empty or malformed update".to_owned(),
            ));
        }
        let fields: Vec<_> = line.split(|byte| *byte == b' ').collect();
        if fields.len() != 4 || fields.iter().any(|field| field.is_empty()) {
            return Err(Error::InvalidArguments(
                "pre-push update must contain exactly four space-separated fields".to_owned(),
            ));
        }
        if updates.len() == PUSH_UPDATE_MAX_COUNT {
            return Err(Error::InvalidArguments(format!(
                "push update count exceeds {PUSH_UPDATE_MAX_COUNT}"
            )));
        }
        let local_oid = oid_text(fields[1], oid_width, "local_oid")?;
        let remote_oid = oid_text(fields[3], oid_width, "remote_oid")?;
        updates.push(PushUpdate {
            index: updates.len() as u64,
            local_oid,
            local_ref: PushBytes::stdin(fields[0], "local_ref")?,
            remote_oid,
            remote_ref: PushBytes::stdin(fields[2], "remote_ref")?,
        });
    }
    Ok(updates)
}

fn persist_intent(root: &TrustedRoot, intent: &PushIntentDocument) -> Result<PathBuf> {
    for _ in 0..RUN_ATTEMPTS {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|error| Error::Io {
            operation: "allocate push run identifier",
            kind: std::io::ErrorKind::Other,
            message: error.to_string(),
        })?;
        let path = PathBuf::from("runs")
            .join(hex::encode(random))
            .join("push-intent.json");
        match root.publish_file(&path, intent.bytes(), false)? {
            PublishOutcome::Published => return Ok(path),
            PublishOutcome::Existing => continue,
        }
    }
    Err(Error::AuthorityConflict(format!(
        "could not allocate a push run after {RUN_ATTEMPTS} attempts"
    )))
}

fn discover_push(
    git: &GitRepository,
    intent: &PushIntent,
    exclusions: &[ObjectId],
) -> Result<PushSnapshot> {
    let mut identifiers = BTreeSet::new();
    let mut pushed_tips = Vec::new();
    let mut ref_units = Vec::new();

    for update in &intent.updates {
        let local = git.parse_object_id(update.local_oid.as_bytes())?;
        if local.is_zero() {
            continue;
        }
        identifiers.extend(git.pushed_object_difference(&local, exclusions)?);
        pushed_tips.push((update.index as usize, local));
        ref_units.push(JudgmentUnit::ref_name(
            update.remote_ref.decoded("remote_ref.bytes_hex")?,
        )?);
    }

    let identifiers: Vec<_> = identifiers.into_iter().collect();
    let objects = git.read_objects_local_snapshot(&identifiers)?;
    let mut units = Vec::new();
    let mut new_roots = BTreeSet::new();
    for object in &objects {
        units.extend(extract_stored_object(
            git,
            object.identifier(),
            object.kind(),
            &object.framed(),
        )?);
        if object.kind() == GitObjectKind::Commit {
            new_roots.insert(git.commit_tree(object)?);
        }
    }
    units.extend(ref_units);

    // A directly pushed tree or tag-to-tree is a path root even without a
    // commit. A blob or tag-to-blob has no path root, but remains a content
    // target and is deferred as a state-only failure below.
    let mut peeled_tips = Vec::new();
    for (_, tip) in &pushed_tips {
        let tree = peel_push_tree(git, tip)?;
        if let Some(tree) = &tree {
            new_roots.insert(tree.clone());
        }
        peeled_tips.push((tip.clone(), tree));
    }

    let mut baseline_paths = BTreeSet::new();
    let mut missing_baseline_tips = Vec::new();
    for tip in exclusions {
        let tree = match baseline_tree(git, tip)? {
            BaselineAvailability::Available(tree) => tree,
            BaselineAvailability::Missing => {
                missing_baseline_tips.push(tip.clone());
                continue;
            }
        };
        let Some(tree) = tree else {
            continue;
        };
        match baseline_tree_paths(git, &tree)? {
            BaselineAvailability::Available(paths) => baseline_paths.extend(paths),
            BaselineAvailability::Missing => missing_baseline_tips.push(tip.clone()),
        }
    }
    let new_paths = union_paths(git, &new_roots)?;
    for path in new_paths.difference(&baseline_paths) {
        units.push(JudgmentUnit::path(path.clone())?);
    }

    let mut states = BTreeMap::new();
    let mut state_failures = Vec::new();
    for (_, tree) in peeled_tips {
        match tree {
            Some(tree_oid) => match tree_digest(git, &tree_oid) {
                Ok(tree_sha256) => {
                    states.entry(tree_oid.clone()).or_insert(StateTarget {
                        tree_oid,
                        tree_sha256,
                    });
                }
                Err(error) => state_failures.push(DeferredStateFailure { error }),
            },
            None => state_failures.push(DeferredStateFailure {
                error: Error::GitUnavailable(
                    "pushed object does not peel to a tree for state judgment".to_owned(),
                ),
            }),
        }
    }

    Ok(PushSnapshot {
        units: deduplicate(units),
        states: states.into_values().collect(),
        state_failures,
        missing_baseline_tips,
    })
}

fn union_paths(git: &GitRepository, roots: &BTreeSet<ObjectId>) -> Result<BTreeSet<Vec<u8>>> {
    let mut paths = BTreeSet::new();
    for root in roots {
        paths.extend(git.tree_paths_local_snapshot(root)?);
    }
    Ok(paths)
}

/// A §11.3 baseline contribution is either fully available or omitted in the
/// safe direction. No other failure class is represented by `Missing`.
#[derive(Debug, PartialEq, Eq)]
enum BaselineAvailability<T> {
    Available(T),
    Missing,
}

/// Structural outcome of peeling a local Git object graph without invoking
/// revision parsing or allowing a lazy network fetch.
///
/// Normative source: SPEC §3.3 and §11.3–§11.4.
enum StructuralTreePeel {
    Tree(ObjectId),
    NoTree,
    Missing,
}

/// Peels one target-side object graph. Missing objects are required input on
/// this side and therefore remain a typed Git failure.
fn peel_push_tree(git: &GitRepository, tip: &ObjectId) -> Result<Option<ObjectId>> {
    match peel_local_tree(git, tip)? {
        StructuralTreePeel::Tree(tree) => Ok(Some(tree)),
        StructuralTreePeel::NoTree => Ok(None),
        StructuralTreePeel::Missing => Err(Error::GitUnavailable(
            "pushed object peel dependency is unavailable locally".to_owned(),
        )),
    }
}

/// Walks commit/tree/blob/annotated-tag objects by their stored raw bytes.
/// Every hop is validated before its target is trusted. The visited set is
/// the only traversal bound because the authority defines no semantic depth
/// limit for an acyclic annotated-tag chain.
fn peel_local_tree(git: &GitRepository, tip: &ObjectId) -> Result<StructuralTreePeel> {
    let mut current = tip.clone();
    let mut expected_kind = None;
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(current.clone()) {
            return Err(Error::GitUnavailable(
                "annotated-tag chain contains a cycle".to_owned(),
            ));
        }
        let Some(object) = git.read_object_local_snapshot_if_present(&current)? else {
            return Ok(StructuralTreePeel::Missing);
        };
        if expected_kind.is_some_and(|expected| expected != object.kind()) {
            return Err(Error::GitUnavailable(
                "annotated-tag target type does not match the stored object".to_owned(),
            ));
        }
        extract_stored_object(git, object.identifier(), object.kind(), &object.framed())?;
        match object.kind() {
            GitObjectKind::Blob => return Ok(StructuralTreePeel::NoTree),
            GitObjectKind::Tree => return Ok(StructuralTreePeel::Tree(current)),
            GitObjectKind::Commit => {
                current = git.commit_tree(&object)?;
                expected_kind = Some(GitObjectKind::Tree);
            }
            GitObjectKind::Tag => {
                let (target, kind) = tag_target(git, &object)?;
                current = target;
                expected_kind = Some(kind);
            }
        }
    }
}

/// Peels one exclusion tip while classifying only an actually absent object
/// in the peel chain as an unavailable baseline.
fn baseline_tree(
    git: &GitRepository,
    tip: &ObjectId,
) -> Result<BaselineAvailability<Option<ObjectId>>> {
    match peel_local_tree(git, tip)? {
        StructuralTreePeel::Tree(tree) => Ok(BaselineAvailability::Available(Some(tree))),
        StructuralTreePeel::NoTree => Ok(BaselineAvailability::Available(None)),
        StructuralTreePeel::Missing => Ok(BaselineAvailability::Missing),
    }
}

/// Enumerates one baseline root, omitting it only when a required tree object
/// is structurally known to be absent from the local snapshot.
fn baseline_tree_paths(
    git: &GitRepository,
    tree: &ObjectId,
) -> Result<BaselineAvailability<BTreeSet<Vec<u8>>>> {
    if baseline_tree_dependency_missing(git, tree)? {
        return Ok(BaselineAvailability::Missing);
    }
    git.tree_paths_local_snapshot(tree)
        .map(BaselineAvailability::Available)
}

/// Checks exactly the tree objects needed by `ls-tree -r -t`; missing blob
/// bodies do not make path names unavailable because their names live in the
/// containing tree.
fn baseline_tree_dependency_missing(git: &GitRepository, root: &ObjectId) -> Result<bool> {
    let mut pending = vec![root.clone()];
    let mut visited = BTreeSet::new();
    while let Some(tree) = pending.pop() {
        if !visited.insert(tree.clone()) {
            continue;
        }
        let Some(object) = git.read_object_local_snapshot_if_present(&tree)? else {
            return Ok(true);
        };
        if object.kind() != GitObjectKind::Tree {
            return Err(Error::GitUnavailable(
                "baseline tree dependency is not a tree object".to_owned(),
            ));
        }
        extract_stored_object(git, object.identifier(), object.kind(), &object.framed())?;
        pending.extend(tree_children(git, &object)?);
    }
    Ok(false)
}

/// Reads the target OID and declared kind from a tag already validated by the
/// shared §3 parser.
fn tag_target(
    git: &GitRepository,
    object: &crate::git_traversal::GitObject,
) -> Result<(ObjectId, GitObjectKind)> {
    let mut lines = object.body().split(|byte| *byte == b'\n');
    let target = lines
        .next()
        .unwrap_or_default()
        .strip_prefix(b"object ")
        .ok_or_else(|| {
            Error::GitUnavailable("validated tag has no leading object header".to_owned())
        })?;
    let kind = match lines.next().unwrap_or_default().strip_prefix(b"type ") {
        Some(b"blob") => GitObjectKind::Blob,
        Some(b"tree") => GitObjectKind::Tree,
        Some(b"commit") => GitObjectKind::Commit,
        Some(b"tag") => GitObjectKind::Tag,
        _ => {
            return Err(Error::GitUnavailable(
                "validated tag has no supported type header".to_owned(),
            ));
        }
    };
    Ok((git.parse_object_id(target)?, kind))
}

/// Extracts only subtree OIDs from a tree already validated by the shared §3
/// parser; blob availability is irrelevant to path enumeration.
fn tree_children(
    git: &GitRepository,
    object: &crate::git_traversal::GitObject,
) -> Result<Vec<ObjectId>> {
    let body = object.body();
    let oid_bytes = git.object_format().oid_hex_bytes() / 2;
    let mut cursor = 0usize;
    let mut children = Vec::new();
    while cursor < body.len() {
        let mode_end = body[cursor..]
            .iter()
            .position(|byte| *byte == b' ')
            .map(|offset| cursor + offset)
            .ok_or_else(|| Error::GitUnavailable("validated tree lost its mode".to_owned()))?;
        let name_start = mode_end + 1;
        let name_end = body[name_start..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| name_start + offset)
            .ok_or_else(|| Error::GitUnavailable("validated tree lost its name".to_owned()))?;
        let oid_start = name_end + 1;
        let oid_end = oid_start.checked_add(oid_bytes).ok_or_else(|| {
            Error::GitUnavailable("validated tree object length overflowed".to_owned())
        })?;
        if oid_end > body.len() {
            return Err(Error::GitUnavailable(
                "validated tree object identifier is truncated".to_owned(),
            ));
        }
        if &body[cursor..mode_end] == b"40000" {
            children.push(git.parse_object_id(hex::encode(&body[oid_start..oid_end]).as_bytes())?);
        }
        cursor = oid_end;
    }
    Ok(children)
}

fn tree_digest(git: &GitRepository, tree: &ObjectId) -> Result<Digest32> {
    let objects = git.read_objects_local_snapshot(std::slice::from_ref(tree))?;
    let object = &objects[0];
    if object.identifier() != tree || object.kind() != GitObjectKind::Tree {
        return Err(Error::GitUnavailable(
            "peeled state object is not the requested tree".to_owned(),
        ));
    }
    // Validation precedes hashing so corrupt tree bytes never name a state.
    extract_stored_object(git, object.identifier(), object.kind(), &object.framed())?;
    Ok(Digest32::from_bytes(Sha256::digest(object.framed()).into()))
}

/// Validates bytes read from Git's object database while preserving every
/// non-grammar failure class.
fn extract_stored_object(
    git: &GitRepository,
    identifier: &ObjectId,
    kind: GitObjectKind,
    framed: &[u8],
) -> Result<Vec<JudgmentUnit>> {
    extract_git_object(git.object_format(), framed).map_err(|error| match error {
        // The extractor's closed Git wire/structure grammar reports malformed
        // stored objects as InvalidField. Do not widen this arm to substrate or
        // authority failures.
        Error::InvalidField { .. } => Error::GitUnavailable(format!(
            "stored {} object {} is malformed",
            git_object_kind_name(kind),
            identifier.as_str()
        )),
        other => other,
    })
}

fn git_object_kind_name(kind: GitObjectKind) -> &'static str {
    match kind {
        GitObjectKind::Blob => "blob",
        GitObjectKind::Tree => "tree",
        GitObjectKind::Commit => "commit",
        GitObjectKind::Tag => "tag",
    }
}

fn evaluate_scopes(
    snapshot: &PushSnapshot,
    policy: &crate::policy::PolicyConfig,
    ledger: &Ledger<'_>,
    registry: &Registry<'_>,
) -> (Vec<PushMissingJudgment>, Vec<PushScopeFailure>) {
    let mut missing = Vec::new();
    let mut failures = Vec::new();
    for scope in policy.push_requirements() {
        match policy.scope_type(scope) {
            Some(ScopeType::Content) => {
                for unit in &snapshot.units {
                    match ledger.has_unit_scope(unit.id(), scope, registry) {
                        Ok(true) => {}
                        Ok(false) => missing.push(PushMissingJudgment {
                            scope: scope.clone(),
                            subject: PushMissingSubject::Content(unit.clone()),
                        }),
                        Err(error) => failures.push(PushScopeFailure {
                            scope: scope.clone(),
                            error,
                        }),
                    }
                }
            }
            Some(ScopeType::State) => {
                for failure in &snapshot.state_failures {
                    failures.push(PushScopeFailure {
                        scope: scope.clone(),
                        // Preserve the internal §15 type; display context must
                        // never reclassify an underlying substrate failure.
                        error: failure.error.clone(),
                    });
                }
                for state in &snapshot.states {
                    match ledger.has_tree_scope(state.tree_sha256, scope, registry) {
                        Ok(true) => {}
                        Ok(false) => missing.push(PushMissingJudgment {
                            scope: scope.clone(),
                            subject: PushMissingSubject::State {
                                tree_oid: state.tree_oid.as_str().to_owned(),
                                tree_sha256: state.tree_sha256,
                            },
                        }),
                        Err(error) => failures.push(PushScopeFailure {
                            scope: scope.clone(),
                            error,
                        }),
                    }
                }
            }
            None => failures.push(PushScopeFailure {
                scope: scope.clone(),
                error: Error::PolicyInvalid(format!(
                    "push requirement {scope} is not a declared scope"
                )),
            }),
        }
    }
    (missing, failures)
}

fn oid_text(bytes: &[u8], width: usize, field: &'static str) -> Result<String> {
    if bytes.len() != width
        || !bytes.iter().all(u8::is_ascii_hexdigit)
        || bytes.iter().any(u8::is_ascii_uppercase)
    {
        return Err(Error::InvalidArguments(format!(
            "{field} must be {width} lowercase hexadecimal bytes"
        )));
    }
    Ok(std::str::from_utf8(bytes)
        .expect("lowercase hexadecimal is ASCII")
        .to_owned())
}

fn object_format_name(format: crate::extract::ObjectFormat) -> ObjectFormatName {
    match format {
        crate::extract::ObjectFormat::Sha1 => ObjectFormatName::Sha1,
        crate::extract::ObjectFormat::Sha256 => ObjectFormatName::Sha256,
    }
}

fn deduplicate(units: Vec<JudgmentUnit>) -> Vec<JudgmentUnit> {
    units
        .into_iter()
        .map(|unit| (unit.id().to_string(), unit))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{fs, process::Command};

    use tempfile::TempDir;

    use super::*;
    use crate::extract::UnitKind;

    struct RepositoryFixture {
        _directory: TempDir,
        repository: PathBuf,
        remote: PathBuf,
    }

    impl RepositoryFixture {
        fn new(format: &str) -> Self {
            let directory = tempfile::tempdir().expect("temporary repository root");
            let repository = directory.path().join("repo");
            let remote = directory.path().join("remote.git");
            fs::create_dir(&repository).unwrap();
            fs::create_dir(&remote).unwrap();
            let mut init = vec!["init"];
            let mut bare = vec!["init", "--bare"];
            if format == "sha256" {
                init.push("--object-format=sha256");
                bare.push("--object-format=sha256");
            }
            git(&repository, &init);
            git(&remote, &bare);
            let hooks = directory.path().join("empty-hooks");
            fs::create_dir(&hooks).unwrap();
            git_os(
                &repository,
                [
                    OsStr::new("config"),
                    OsStr::new("core.hooksPath"),
                    hooks.as_os_str(),
                ],
            );
            git(&repository, &["config", "user.name", "Push Test"]);
            git(&repository, &["config", "user.email", "push@example.com"]);
            git_os(
                &repository,
                [
                    OsStr::new("remote"),
                    OsStr::new("add"),
                    OsStr::new("origin"),
                    remote.as_os_str(),
                ],
            );
            Self {
                _directory: directory,
                repository,
                remote,
            }
        }

        fn git(&self) -> GitRepository {
            GitRepository::open(&self.repository).unwrap()
        }

        fn commit(&self, path: &str, contents: &[u8], message: &str) -> String {
            let path = self.repository.join(path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, contents).unwrap();
            git(&self.repository, &["add", "-A"]);
            git(&self.repository, &["commit", "-m", message]);
            oid(&self.repository, &["rev-parse", "HEAD"])
        }

        fn push_main(&self) {
            git(
                &self.repository,
                &["push", "origin", "HEAD:refs/heads/main"],
            );
        }

        fn update(&self, local: &str, remote: &str, remote_oid: &str) -> PushIntentDocument {
            let width = self.git().object_format().oid_hex_bytes();
            let line = format!("refs/heads/local {local} {remote} {remote_oid}\n");
            capture_intent(&self.git(), OsStr::new("origin"), line.as_bytes())
                .unwrap_or_else(|error| panic!("capture {width}-digit update: {error}"))
        }

        fn zero(&self) -> String {
            "0".repeat(self.git().object_format().oid_hex_bytes())
        }

        fn literal_object(&self, kind: &str, body: &[u8]) -> String {
            let path = self.repository.join(format!("malformed-{kind}"));
            fs::write(&path, body).unwrap();
            oid(
                &self.repository,
                &[
                    "hash-object",
                    "-t",
                    kind,
                    "--literally",
                    "-w",
                    path.to_str().unwrap(),
                ],
            )
        }
    }

    /// SPEC §16 push gate 01: every currently published tip is excluded.
    #[test]
    fn push_gate_01_excludes_all_published_origin_tips() {
        let fixture = RepositoryFixture::new("sha1");
        let tip = fixture.commit("published", b"already public", "published");
        fixture.push_main();
        git(
            &fixture.repository,
            &["push", "origin", "HEAD:refs/tags/also-public"],
        );
        let git = fixture.git();
        let remote = git.remote_tips(OsStr::new("origin")).unwrap();
        let intent = fixture.update(&tip, "refs/heads/main", &tip);
        let snapshot = discover_push(&git, intent.value(), &remote.present).unwrap();
        assert_eq!(snapshot.units.len(), 1);
        assert_eq!(snapshot.units[0].kind(), UnitKind::Ref);
    }

    /// SPEC §16 push gate 02: a new branch still excludes shared history.
    #[test]
    fn push_gate_02_new_branch_excludes_shared_history() {
        let fixture = RepositoryFixture::new("sha1");
        let shared = fixture.commit("shared", b"shared", "shared");
        fixture.push_main();
        let git = fixture.git();
        let remote = git.remote_tips(OsStr::new("origin")).unwrap();
        let intent = fixture.update(&shared, "refs/heads/new", &fixture.zero());
        let snapshot = discover_push(&git, intent.value(), &remote.present).unwrap();
        assert_eq!(snapshot.units.len(), 1);
        assert_eq!(snapshot.units[0].bytes(), b"refs/heads/new");
    }

    /// SPEC §16 push gate 03: a remote tip absent locally is diagnosed and not excluded.
    #[test]
    fn push_gate_03_missing_local_origin_tip_increases_target() {
        let fixture = RepositoryFixture::new("sha1");
        let base = fixture.commit("base", b"base bytes", "base");
        fixture.push_main();
        let other = fixture._directory.path().join("other");
        git_os(
            fixture._directory.path(),
            [
                OsStr::new("clone"),
                OsStr::new("--branch"),
                OsStr::new("main"),
                fixture.remote.as_os_str(),
                other.as_os_str(),
            ],
        );
        let hooks = fixture._directory.path().join("empty-hooks");
        git_os(
            &other,
            [
                OsStr::new("config"),
                OsStr::new("core.hooksPath"),
                hooks.as_os_str(),
            ],
        );
        git(&other, &["config", "user.name", "Other"]);
        git(&other, &["config", "user.email", "other@example.com"]);
        fs::write(other.join("remote-only"), b"remote only").unwrap();
        git(&other, &["add", "-A"]);
        git(&other, &["commit", "-m", "remote only"]);
        git(&other, &["push", "origin", "HEAD:refs/heads/main"]);

        let local = fixture.commit("local", b"local", "local");
        let git = fixture.git();
        let remote = git.remote_tips(OsStr::new("origin")).unwrap();
        assert_eq!(remote.missing.len(), 1);
        assert!(remote.present.is_empty());
        let intent = fixture.update(&local, "refs/heads/main", &base);
        let snapshot = discover_push(&git, intent.value(), &remote.present).unwrap();
        assert!(
            snapshot
                .units
                .iter()
                .any(|unit| unit.bytes() == b"base bytes")
        );
    }

    /// SPEC §11.2–§11.3: probing a promisor tip is a network-free local
    /// availability check, and a missing tip never becomes an exclusion.
    #[test]
    fn partial_clone_remote_probe_does_not_lazy_fetch_promised_blob() {
        let fixture = RepositoryFixture::new("sha1");
        let local = fixture.commit("local", b"local snapshot bytes", "local");

        fs::write(
            fixture.remote.join("promised-blob"),
            b"promised bytes must remain remote",
        )
        .unwrap();
        let promised = oid(&fixture.remote, &["hash-object", "-w", "promised-blob"]);
        git(
            &fixture.remote,
            &[
                "update-ref",
                "refs/diagnostic/do-not-report-this-ref",
                &promised,
            ],
        );
        git(
            &fixture.repository,
            &["config", "extensions.partialClone", "origin"],
        );
        git(
            &fixture.repository,
            &["config", "remote.origin.promisor", "true"],
        );
        git(
            &fixture.repository,
            &["config", "remote.origin.partialCloneFilter", "blob:none"],
        );

        let object_path = fixture
            .repository
            .join(".git")
            .join("objects")
            .join(&promised[..2])
            .join(&promised[2..]);
        assert!(!object_path.exists());
        let objects_before = object_database_file_count(&fixture.repository.join(".git/objects"));

        let git = fixture.git();
        let remote = git.remote_tips(OsStr::new("origin")).unwrap();
        assert!(remote.present.is_empty());
        assert_eq!(remote.missing.len(), 1);
        assert_eq!(remote.missing[0].as_str(), promised);
        assert!(!object_path.exists());
        assert_eq!(
            object_database_file_count(&fixture.repository.join(".git/objects")),
            objects_before
        );

        let intent = fixture.update(&local, "refs/heads/main", &fixture.zero());
        let snapshot = discover_push(&git, intent.value(), &remote.present).unwrap();
        assert!(
            snapshot
                .units
                .iter()
                .any(|unit| unit.bytes() == b"local snapshot bytes")
        );
        assert!(!object_path.exists());
        assert_eq!(
            object_database_file_count(&fixture.repository.join(".git/objects")),
            objects_before
        );
    }

    /// SPEC §10.1 keeps default tree reads while §11.3 uses a network-free snapshot.
    #[test]
    fn commit_and_push_tree_paths_use_distinct_fetch_modes() {
        let fixture = RepositoryFixture::new("sha1");
        fs::write(fixture.remote.join("promised-tree-file"), b"tree bytes").unwrap();
        let blob = oid(
            &fixture.remote,
            &["hash-object", "-w", "promised-tree-file"],
        );
        let tree_input = format!("100644 blob {blob}\tpath\n");
        let tree = String::from_utf8(git_with_input(
            &fixture.remote,
            &["mktree"],
            tree_input.as_bytes(),
        ))
        .unwrap();
        let tree = tree.trim().to_owned();
        git(
            &fixture.remote,
            &["update-ref", "refs/diagnostic/tree", &tree],
        );
        git(
            &fixture.repository,
            &["config", "extensions.partialClone", "origin"],
        );
        git(
            &fixture.repository,
            &["config", "remote.origin.promisor", "true"],
        );
        git(
            &fixture.repository,
            &["config", "remote.origin.partialCloneFilter", "blob:none"],
        );

        let object_path = fixture
            .repository
            .join(".git")
            .join("objects")
            .join(&tree[..2])
            .join(&tree[2..]);
        assert!(!object_path.exists());
        let objects_before = object_database_file_count(&fixture.repository.join(".git/objects"));

        let git = fixture.git();
        let tree = git.parse_object_id(tree.as_bytes()).unwrap();
        assert!(matches!(
            git.tree_paths_local_snapshot(&tree),
            Err(Error::GitUnavailable(_))
        ));
        assert!(!object_path.exists());
        assert_eq!(
            object_database_file_count(&fixture.repository.join(".git/objects")),
            objects_before
        );

        assert_eq!(
            git.tree_paths(&tree).unwrap(),
            BTreeSet::from([b"path".to_vec()])
        );
        assert!(
            object_database_file_count(&fixture.repository.join(".git/objects")) > objects_before
        );
    }

    /// SPEC §11.3: an unavailable published-side root tree reduces the
    /// baseline instead of hiding new-side paths or fetching lazily.
    #[test]
    fn missing_baseline_tree_increases_required_paths() {
        let fixture = RepositoryFixture::new("sha1");
        let published = fixture.commit("published", b"public bytes", "published");
        fixture.push_main();
        let published_tree = oid(
            &fixture.repository,
            &["rev-parse", &format!("{published}^{{tree}}")],
        );
        let child = fixture.commit("new-child", b"new bytes", "new child");

        git(
            &fixture.repository,
            &["config", "extensions.partialClone", "origin"],
        );
        git(
            &fixture.repository,
            &["config", "remote.origin.promisor", "true"],
        );
        git(
            &fixture.repository,
            &["config", "remote.origin.partialCloneFilter", "blob:none"],
        );
        let published_tree_path = fixture
            .repository
            .join(".git/objects")
            .join(&published_tree[..2])
            .join(&published_tree[2..]);
        #[cfg(windows)]
        {
            let mut permissions = fs::metadata(&published_tree_path).unwrap().permissions();
            // Windows clears FILE_ATTRIBUTE_READONLY here; this cfg block
            // cannot compile into the Unix permission-widening path.
            #[allow(clippy::permissions_set_readonly_false)]
            permissions.set_readonly(false);
            fs::set_permissions(&published_tree_path, permissions).unwrap();
        }
        fs::remove_file(&published_tree_path).unwrap();
        let objects_before = object_database_file_count(&fixture.repository.join(".git/objects"));

        let git = fixture.git();
        let remote = git.remote_tips(OsStr::new("origin")).unwrap();
        assert_eq!(remote.present.len(), 1);
        assert!(remote.missing.is_empty());
        let intent = fixture.update(&child, "refs/heads/main", &published);
        let snapshot = discover_push(&git, intent.value(), &remote.present).unwrap();

        let paths: BTreeSet<_> = snapshot
            .units
            .iter()
            .filter(|unit| unit.kind() == UnitKind::Path)
            .map(|unit| unit.bytes().to_vec())
            .collect();
        assert!(paths.contains(b"published".as_slice()));
        assert!(paths.contains(b"new-child".as_slice()));
        assert_eq!(snapshot.missing_baseline_tips, remote.present);
        assert!(!published_tree_path.exists());
        assert_eq!(
            object_database_file_count(&fixture.repository.join(".git/objects")),
            objects_before
        );
    }

    /// SPEC §11.3 and §15: only structured absence reduces a baseline;
    /// malformed baseline tree bytes remain a Git failure.
    #[test]
    fn malformed_baseline_tree_is_not_treated_as_missing() {
        let fixture = RepositoryFixture::new("sha1");
        let malformed = fixture.literal_object("tree", b"40000 missing-name-and-oid");
        let git = fixture.git();
        let malformed = git.parse_object_id(malformed.as_bytes()).unwrap();
        assert!(matches!(
            baseline_tree(&git, &malformed),
            Err(Error::GitUnavailable(_))
        ));
    }

    /// SPEC §11.2, §15, and §16 push gate 04: credential-aware remote
    /// discovery failures are typed without retaining transport diagnostics.
    #[test]
    fn push_gate_04_ls_remote_failure_fails_gate() {
        let fixture = RepositoryFixture::new("sha1");
        let local = fixture.commit("private.txt", b"private\n", "private");
        let sentinel = "UCHGS_CREDENTIAL_SENTINEL_B5";
        let remote_location = "ssh://credential-like-user@example.invalid/private-location";

        #[cfg(unix)]
        let helper = {
            use std::os::unix::fs::PermissionsExt as _;

            let helper = fixture._directory.path().join("failing-ssh");
            fs::write(
                &helper,
                format!("#!/bin/sh\nprintf '{sentinel}\\377' >&2\nexit 1\n"),
            )
            .unwrap();
            fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
            helper
        };
        #[cfg(windows)]
        let helper = {
            let helper = fixture._directory.path().join("failing-ssh.cmd");
            fs::write(
                &helper,
                format!("@echo off\r\necho {sentinel} 1>&2\r\nexit /b 1\r\n"),
            )
            .unwrap();
            helper
        };

        git_os(
            &fixture.repository,
            [
                OsStr::new("config"),
                OsStr::new("core.sshCommand"),
                helper.as_os_str(),
            ],
        );
        git(
            &fixture.repository,
            &["remote", "set-url", "origin", remote_location],
        );
        fs::create_dir(fixture.repository.join(".uchgs")).unwrap();
        let global_directory = tempfile::tempdir().unwrap();
        let global = TrustedRoot::open(global_directory.path()).unwrap();
        let gate = PushGate::open(&fixture.repository, &global).unwrap();
        let stdin = format!(
            "refs/heads/local {local} refs/heads/main {}\n",
            fixture.zero()
        )
        .into_bytes();

        let error = gate
            .evaluate(OsString::from("origin"), stdin)
            .expect_err("failing credential-aware transport was accepted");
        assert!(matches!(
            &error,
            Error::RemoteUnavailable(message) if message == "git remote discovery failed"
        ));
        for diagnostic in [error.to_string(), format!("{error:?}")] {
            assert!(!diagnostic.contains(sentinel));
            assert!(!diagnostic.contains("credential-like-user"));
            assert!(!diagnostic.contains("private-location"));
        }

        let runs = fixture.repository.join(".uchgs/runs");
        let run = fs::read_dir(&runs)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(run.len(), 1);
        let persisted = fs::read(run[0].join("push-intent.json")).unwrap();
        for secret in [
            sentinel.as_bytes(),
            b"credential-like-user",
            b"private-location",
        ] {
            assert!(
                !persisted
                    .windows(secret.len())
                    .any(|window| window == secret)
            );
        }
    }

    /// SPEC §16 push gate 05: deletion creates neither content nor state targets.
    #[test]
    fn push_gate_05_delete_update_has_no_target() {
        let fixture = RepositoryFixture::new("sha1");
        let zero = fixture.zero();
        let line = format!("(delete) {zero} refs/heads/old {zero}\n");
        let intent = capture_intent(&fixture.git(), OsStr::new("origin"), line.as_bytes()).unwrap();
        let snapshot = discover_push(&fixture.git(), intent.value(), &[]).unwrap();
        assert!(snapshot.units.is_empty());
        assert!(snapshot.states.is_empty());
    }

    /// SPEC §16 push gate 06: every introduced commit root contributes paths.
    #[test]
    fn push_gate_06_paths_use_all_target_commit_root_trees() {
        let fixture = RepositoryFixture::new("sha1");
        let base = fixture.commit("base", b"base", "base");
        fixture.push_main();
        fixture.commit("transient", b"seen only in c1", "add transient");
        fs::remove_file(fixture.repository.join("transient")).unwrap();
        git(&fixture.repository, &["add", "-A"]);
        git(&fixture.repository, &["commit", "-m", "remove transient"]);
        let tip = oid(&fixture.repository, &["rev-parse", "HEAD"]);
        let git = fixture.git();
        let remote = git.remote_tips(OsStr::new("origin")).unwrap();
        let intent = fixture.update(&tip, "refs/heads/main", &base);
        let snapshot = discover_push(&git, intent.value(), &remote.present).unwrap();
        assert!(
            snapshot
                .units
                .iter()
                .any(|unit| { unit.kind() == UnitKind::Path && unit.bytes() == b"transient" })
        );
    }

    /// SPEC §11.3–§11.4 and §16 push gate 07: structural tag chains preserve
    /// content targets while only tree-bearing tips contribute paths/state.
    #[test]
    fn push_gate_07_direct_tree_publication_yields_paths() {
        let fixture = RepositoryFixture::new("sha1");
        let commit = fixture.commit("direct-name", b"blob bytes", "objects");
        let tree = oid(&fixture.repository, &["rev-parse", "HEAD^{tree}"]);
        let blob = oid(&fixture.repository, &["rev-parse", "HEAD:direct-name"]);
        git(
            &fixture.repository,
            &["tag", "-a", "tree-tag", &tree, "-m", "tree tag"],
        );
        let tree_tag = oid(&fixture.repository, &["rev-parse", "refs/tags/tree-tag"]);
        git(
            &fixture.repository,
            &["tag", "-a", "commit-tag", &commit, "-m", "commit tag"],
        );
        let commit_tag = oid(&fixture.repository, &["rev-parse", "refs/tags/commit-tag"]);
        git(
            &fixture.repository,
            &["tag", "-a", "blob-tag", &blob, "-m", "blob tag"],
        );
        let blob_tag = oid(&fixture.repository, &["rev-parse", "refs/tags/blob-tag"]);
        git(
            &fixture.repository,
            &[
                "tag",
                "-a",
                "outer-blob-tag",
                &blob_tag,
                "-m",
                "outer blob tag",
            ],
        );
        let outer_blob_tag = oid(
            &fixture.repository,
            &["rev-parse", "refs/tags/outer-blob-tag"],
        );

        for tip in [&tree, &tree_tag, &commit_tag] {
            let intent = fixture.update(tip, "refs/custom/tree", &fixture.zero());
            let snapshot = discover_push(&fixture.git(), intent.value(), &[]).unwrap();
            assert!(
                snapshot.units.iter().any(|unit| {
                    unit.kind() == UnitKind::Path && unit.bytes() == b"direct-name"
                })
            );
            assert_eq!(snapshot.states.len(), 1);
            assert!(snapshot.state_failures.is_empty());
        }

        for tip in [&blob, &blob_tag, &outer_blob_tag] {
            let intent = fixture.update(tip, "refs/custom/blob", &fixture.zero());
            let snapshot = discover_push(&fixture.git(), intent.value(), &[]).unwrap();
            assert!(
                snapshot
                    .units
                    .iter()
                    .any(|unit| unit.kind() == UnitKind::File)
            );
            assert!(snapshot.units.iter().any(|unit| {
                unit.kind() == UnitKind::Ref && unit.bytes() == b"refs/custom/blob"
            }));
            assert!(
                !snapshot
                    .units
                    .iter()
                    .any(|unit| unit.kind() == UnitKind::Path)
            );
            assert!(snapshot.states.is_empty());
            assert_eq!(snapshot.state_failures.len(), 1);
        }

        let intent = fixture.update(&outer_blob_tag, "refs/custom/blob", &fixture.zero());
        let snapshot = discover_push(&fixture.git(), intent.value(), &[]).unwrap();
        assert!(
            snapshot
                .units
                .iter()
                .any(|unit| unit.kind() == UnitKind::Tag)
        );
        let config = crate::policy::PolicyConfig::parse(
            br#"project = "demo"

[gate.commit]
require = ["content"]

[gate.push]
require = ["content", "state"]

[scope.content]
type = "content"

[scope.state]
type = "state"
"#,
        )
        .unwrap();
        let repository_directory = tempfile::tempdir().unwrap();
        let global_directory = tempfile::tempdir().unwrap();
        let repository = TrustedRoot::open(repository_directory.path()).unwrap();
        let global = TrustedRoot::open(global_directory.path()).unwrap();
        let registry = Registry::new(&global, &repository);
        let ledger = Ledger::new(&repository);
        let (missing, failures) = evaluate_scopes(&snapshot, &config, &ledger, &registry);
        assert!(missing.iter().all(|judgment| judgment.scope() == "content"));
        assert!(
            [UnitKind::Tag, UnitKind::File, UnitKind::Ref]
                .into_iter()
                .all(|kind| missing.iter().any(|judgment| {
                    matches!(
                        judgment.subject(),
                        PushMissingSubject::Content(unit) if unit.kind() == kind
                    )
                }))
        );
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].scope(), "state");
        assert!(matches!(failures[0].error(), Error::GitUnavailable(_)));

        let blob_tag_body = git_bytes(&fixture.repository, &["cat-file", "tag", &blob_tag]);
        let body = String::from_utf8(blob_tag_body).unwrap();
        let missing_target = "f".repeat(fixture.git().object_format().oid_hex_bytes());
        let missing_tag =
            fixture.literal_object("tag", body.replacen(&blob, &missing_target, 1).as_bytes());
        let mismatch_tag =
            fixture.literal_object("tag", body.replacen("type blob", "type tree", 1).as_bytes());
        for tag in [missing_tag, mismatch_tag] {
            let identifier = fixture.git().parse_object_id(tag.as_bytes()).unwrap();
            assert!(matches!(
                peel_push_tree(&fixture.git(), &identifier),
                Err(Error::GitUnavailable(_))
            ));
        }
    }

    /// SPEC §16 push gate 08: unavailable local objects fail with recovery guidance.
    #[test]
    fn push_gate_08_missing_shallow_or_partial_objects_fail_with_recovery() {
        let fixture = RepositoryFixture::new("sha1");
        let missing = "1".repeat(40);
        let intent = fixture.update(&missing, "refs/heads/main", &fixture.zero());
        let error = discover_push(&fixture.git(), intent.value(), &[]).unwrap_err();
        let Error::GitUnavailable(reason) = error else {
            panic!("expected git-unavailable")
        };
        assert!(reason.contains("fetch the remote without --depth"));
        assert!(reason.contains("partial-clone"));
    }

    /// SPEC §16 push gate 09: argv1 must name a configured remote, not a URL.
    #[test]
    fn push_gate_09_rejects_url_instead_of_remote_name() {
        let fixture = RepositoryFixture::new("sha1");
        let local = fixture.commit("private.txt", b"private\n", "private");
        let stdin = format!(
            "refs/heads/local {local} refs/heads/main {}\n",
            fixture.zero()
        )
        .into_bytes();
        fs::create_dir(fixture.repository.join(".uchgs")).unwrap();
        let global_directory = tempfile::tempdir().unwrap();
        let global = TrustedRoot::open(global_directory.path()).unwrap();
        let gate = PushGate::open(&fixture.repository, &global).unwrap();

        for remote in ["https://user:credential@example.com/repo", "not-configured"] {
            let error = match gate.evaluate(OsString::from(remote), stdin.clone()) {
                Ok(_) => panic!("non-remote argv1 was accepted"),
                Err(error) => error,
            };
            assert!(matches!(error, Error::InvalidArguments(_)));
            assert!(!error.to_string().contains("credential"));
            assert!(!fixture.repository.join(".uchgs/runs").exists());
        }
    }

    /// SPEC §16 push gate 10: the canonical intent has no URL field.
    #[test]
    fn push_gate_10_push_intent_omits_connection_url() {
        let fixture = RepositoryFixture::new("sha256");
        let git = fixture.git();
        git.validate_remote_name(OsStr::new("origin")).unwrap();
        let intent = capture_intent(&git, OsStr::new("origin"), b"").unwrap();
        let json: serde_json::Value = serde_json::from_slice(intent.bytes()).unwrap();
        assert_eq!(json["object_format"], "sha256");
        assert!(json.get("url").is_none());

        let authority = tempfile::tempdir().unwrap();
        let root = TrustedRoot::open(authority.path()).unwrap();
        let path = persist_intent(&root, &intent).unwrap();
        assert_eq!(path.parent().unwrap().parent(), Some(Path::new("runs")));
        assert_eq!(path.file_name(), Some(OsStr::new("push-intent.json")));
        assert_eq!(
            root.read_file(&path, PUSH_INTENT_MAX_BYTES).unwrap(),
            intent.bytes()
        );
    }

    /// SPEC §16 push gate 11: state is computed for every ref namespace.
    #[test]
    fn push_gate_11_state_scope_ignores_ref_namespace() {
        let fixture = RepositoryFixture::new("sha1");
        let tip = fixture.commit("note-state", b"state", "state");
        let intent = fixture.update(&tip, "refs/notes/review", &fixture.zero());
        let snapshot = discover_push(&fixture.git(), intent.value(), &[]).unwrap();
        assert_eq!(snapshot.states.len(), 1);
        let tree = oid(&fixture.repository, &["rev-parse", "HEAD^{tree}"]);
        let body = git_bytes(&fixture.repository, &["cat-file", "tree", &tree]);
        let mut framed = format!("tree {}\0", body.len()).into_bytes();
        framed.extend_from_slice(&body);
        assert_eq!(
            snapshot.states[0].tree_sha256,
            Digest32::from_bytes(Sha256::digest(framed).into())
        );
        assert!(
            snapshot.units.iter().any(|unit| {
                unit.kind() == UnitKind::Ref && unit.bytes() == b"refs/notes/review"
            })
        );
    }

    /// SPEC §11.1: stdin ref fields remain byte-exact and are never decoded.
    #[test]
    #[cfg(unix)]
    fn push_intent_preserves_non_utf8_ref_bytes() {
        let mut input = b"refs/heads/raw-".to_vec();
        input.push(0xff);
        input.extend_from_slice(b" 1111111111111111111111111111111111111111 refs/heads/target-");
        input.push(0xfe);
        input.extend_from_slice(b" 0000000000000000000000000000000000000000\n");
        let updates = parse_updates(&input, 40).unwrap();
        assert_eq!(
            updates[0].local_ref.decoded("local_ref").unwrap(),
            b"refs/heads/raw-\xff"
        );
        assert_eq!(
            updates[0].remote_ref.decoded("remote_ref").unwrap(),
            b"refs/heads/target-\xfe"
        );
    }

    /// SPEC §10.2 and §11.3: push extraction uses the stored cleanup result.
    #[test]
    fn commit_gate_05_cleanup_changed_message_is_required_at_push() {
        let fixture = RepositoryFixture::new("sha1");
        fs::write(
            fixture.repository.join("message"),
            b"kept subject\n\n# removed by cleanup\n",
        )
        .unwrap();
        fs::write(fixture.repository.join("content"), b"content").unwrap();
        git(&fixture.repository, &["add", "content"]);
        git(
            &fixture.repository,
            &["commit", "--cleanup=strip", "-F", "message"],
        );
        let tip = oid(&fixture.repository, &["rev-parse", "HEAD"]);
        let intent = fixture.update(&tip, "refs/heads/main", &fixture.zero());
        let snapshot = discover_push(&fixture.git(), intent.value(), &[]).unwrap();
        let commit = snapshot
            .units
            .iter()
            .find(|unit| unit.kind() == UnitKind::Commit)
            .unwrap();
        assert!(commit.bytes().ends_with(b"\n\nkept subject\n"));
        assert!(!commit.bytes().windows(7).any(|bytes| bytes == b"removed"));
    }

    #[test]
    fn force_like_update_uses_snapshot_not_remote_range() {
        let fixture = RepositoryFixture::new("sha1");
        let first = fixture.commit("first", b"first", "first");
        fixture.push_main();
        let second = fixture.commit("second", b"second", "second");
        let intent = fixture.update(&second, "refs/heads/main", &"f".repeat(40));
        let remote = fixture.git().remote_tips(OsStr::new("origin")).unwrap();
        let snapshot = discover_push(&fixture.git(), intent.value(), &remote.present).unwrap();
        assert!(snapshot.units.iter().any(|unit| unit.bytes() == b"second"));
        assert!(!snapshot.units.iter().any(|unit| unit.bytes() == b"first"));
        assert_ne!(first, second);
    }

    /// SPEC §11.3 and §15: malformed stored commits fail as Git substrate,
    /// without exposing their hostile body bytes.
    #[test]
    fn malformed_stored_commit_is_git_unavailable() {
        let fixture = RepositoryFixture::new("sha1");
        fixture.commit("base.txt", b"base\n", "base");
        let tree = oid(&fixture.repository, &["rev-parse", "HEAD^{tree}"]);
        let malformed = fixture.literal_object(
            "commit",
            format!("tree {tree}\n\ncredential-like-hostile-bytes\n").as_bytes(),
        );
        let intent = fixture.update(&malformed, "refs/heads/main", &fixture.zero());

        let error = discover_push(&fixture.git(), intent.value(), &[]).unwrap_err();
        assert!(matches!(error, Error::GitUnavailable(_)));
        let diagnostic = error.to_string();
        assert!(diagnostic.contains(&malformed));
        assert!(diagnostic.contains("stored commit object"));
        assert!(!diagnostic.contains("credential-like-hostile-bytes"));
    }

    /// SPEC §11.3 and §15: a directly pushed malformed annotated tag uses
    /// the same stored-object taxonomy boundary.
    #[test]
    fn malformed_direct_tag_is_git_unavailable() {
        let fixture = RepositoryFixture::new("sha1");
        let commit = fixture.commit("base.txt", b"base\n", "base");
        let malformed = fixture.literal_object(
            "tag",
            format!("object {commit}\ntype commit\ntag malformed\n\nsecret-tag-payload\n")
                .as_bytes(),
        );
        let intent = fixture.update(&malformed, "refs/tags/malformed", &fixture.zero());

        let error = discover_push(&fixture.git(), intent.value(), &[]).unwrap_err();
        assert!(matches!(error, Error::GitUnavailable(_)));
        let diagnostic = error.to_string();
        assert!(diagnostic.contains(&malformed));
        assert!(diagnostic.contains("stored tag object"));
        assert!(!diagnostic.contains("secret-tag-payload"));
    }

    /// SPEC §11.4 and §15: malformed state-tree bytes are rejected before
    /// hashing and are not copied into diagnostics.
    #[test]
    fn malformed_state_tree_is_git_unavailable() {
        let fixture = RepositoryFixture::new("sha1");
        let malformed = fixture.literal_object("tree", b"100644 secret-tree-entry\0");
        let git = fixture.git();
        let identifier = git.parse_object_id(malformed.as_bytes()).unwrap();

        let error = tree_digest(&git, &identifier).unwrap_err();
        assert!(matches!(error, Error::GitUnavailable(_)));
        let diagnostic = error.to_string();
        assert!(diagnostic.contains(&malformed));
        assert!(diagnostic.contains("stored tree object"));
        assert!(!diagnostic.contains("secret-tree-entry"));
    }

    fn git(repository: &Path, arguments: &[&str]) {
        let output = Command::new("git")
            .current_dir(repository)
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {:?}: {}",
            arguments,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git_os<I, S>(repository: &Path, arguments: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = Command::new("git")
            .current_dir(repository)
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git_with_input(repository: &Path, arguments: &[&str], input: &[u8]) -> Vec<u8> {
        use std::io::Write;
        use std::process::Stdio;

        let mut child = Command::new("git")
            .current_dir(repository)
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "git {:?}: {}",
            arguments,
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn oid(repository: &Path, arguments: &[&str]) -> String {
        String::from_utf8(git_bytes(repository, arguments))
            .unwrap()
            .trim()
            .to_owned()
    }

    fn git_bytes(repository: &Path, arguments: &[&str]) -> Vec<u8> {
        let output = Command::new("git")
            .current_dir(repository)
            .args(arguments)
            .output()
            .unwrap();
        assert!(output.status.success());
        output.stdout
    }

    fn object_database_file_count(path: &Path) -> usize {
        fs::read_dir(path)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    object_database_file_count(&entry.path())
                } else {
                    1
                }
            })
            .sum()
    }
}
