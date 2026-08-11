//! Commit-gate evaluation over an immutable Git snapshot and verified authority.
//!
//! Normative source: SPEC §5.4, §6, and §10.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use crate::{
    Error, Result,
    authority_file::TrustedRoot,
    extract::{JudgmentUnit, UnitKind, extract_identity},
    git_traversal::GitRepository,
    ledger::Ledger,
    policy::PolicyStore,
    registry::Registry,
};

const MESSAGE_MAX_BYTES: usize = 16 * 1024 * 1024;

/// One missing content judgment, ordered by policy scope and unit key.
///
/// Normative source: SPEC §10.1–§10.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingJudgment {
    scope: String,
    unit: JudgmentUnit,
}

impl MissingJudgment {
    /// Returns the required content-scope name from SPEC §5.4.
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Returns the exact missing unit from SPEC §3–§4.
    pub fn unit(&self) -> &JudgmentUnit {
        &self.unit
    }
}

/// Deterministic commit-gate result consumed by a later output boundary.
///
/// An empty result passes. A non-empty result is the typed
/// `judgment-missing` condition from SPEC §15; formatting and exit behavior
/// remain the responsibility of the CLI phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitGateResult {
    missing: Vec<MissingJudgment>,
}

impl CommitGateResult {
    /// Reports whether the commit gate has no missing judgments.
    pub fn is_clear(&self) -> bool {
        self.missing.is_empty()
    }

    /// Returns the complete deterministic missing set for §13.2 formatting.
    pub fn missing(&self) -> &[MissingJudgment] {
        &self.missing
    }

    /// Converts the non-empty result into SPEC §15 `judgment-missing`.
    pub fn require_clear(&self) -> Result<()> {
        if self.is_clear() {
            Ok(())
        } else {
            Err(Error::JudgmentMissing {
                count: self.missing.len(),
            })
        }
    }
}

/// Read-only commit gate bound to one Git repository and its authority roots.
///
/// Normative source: SPEC §1, §5.4, §6, §8, and §10.
pub struct CommitGate<'a> {
    git: GitRepository,
    global: &'a TrustedRoot,
    repository: TrustedRoot,
}

impl<'a> CommitGate<'a> {
    /// Opens the repository authority from the parent of its Git common dir.
    pub fn open(working_directory: impl AsRef<Path>, global: &'a TrustedRoot) -> Result<Self> {
        let git = GitRepository::open(working_directory)?;
        let repository = TrustedRoot::open(git.repository_root()?.join(".uchgs"))?;
        Ok(Self {
            git,
            global,
            repository,
        })
    }

    /// Evaluates the exact staged-tree delta without rereading the index after
    /// `git write-tree` fixes the snapshot.
    pub fn pre_commit(&self) -> Result<CommitGateResult> {
        let units = staged_units(&self.git)?;
        self.evaluate(units)
    }

    /// Evaluates the exact, cleanup-before message bytes supplied by Git.
    pub fn commit_message(&self, message_file: impl AsRef<Path>) -> Result<CommitGateResult> {
        let unit = message_unit(&self.git, message_file.as_ref())?;
        self.evaluate(vec![unit])
    }

    fn evaluate(&self, units: Vec<JudgmentUnit>) -> Result<CommitGateResult> {
        let registry = Registry::new(self.global, &self.repository);
        let policy = PolicyStore::new(&self.repository).load(&registry)?;
        let ledger = Ledger::new(&self.repository);
        let missing = missing_for(
            units,
            policy.config().commit_requirements(),
            |unit, scope| ledger.has_unit_scope(unit.id(), scope, &registry),
        )?;
        Ok(CommitGateResult { missing })
    }
}

fn staged_units(git: &GitRepository) -> Result<Vec<JudgmentUnit>> {
    let staged_tree = git.write_tree()?;
    let head_tree = git.head_tree()?;
    let identifiers = git.object_difference(&staged_tree, head_tree.as_ref())?;
    let mut units = git.extracted_objects(&identifiers)?;

    let staged_paths = git.tree_paths(&staged_tree)?;
    let head_paths = match head_tree {
        Some(tree) => git.tree_paths(&tree)?,
        None => Default::default(),
    };
    for path in staged_paths.difference(&head_paths) {
        units.push(JudgmentUnit::path(path.clone())?);
    }
    Ok(deduplicate(units))
}

fn message_unit(git: &GitRepository, message_file: &Path) -> Result<JudgmentUnit> {
    let absolute = if message_file.is_absolute() {
        message_file.to_path_buf()
    } else {
        git.working_directory().join(message_file)
    };
    let (parent, name) = TrustedRoot::open_operator_parent(&absolute)?;
    let message = parent.read_file(PathBuf::from(name), MESSAGE_MAX_BYTES)?;
    let author = git.identity("GIT_AUTHOR_IDENT")?;
    let committer = git.identity("GIT_COMMITTER_IDENT")?;
    synthetic_commit_unit(&author, &committer, &message)
}

/// Assembles the commit unit for a commit object that does not exist yet.
///
/// The layout must reproduce, byte for byte, the form extraction emits for a
/// commit: `author` and `committer` lines whose identities already have the
/// timestamp and zone removed, one blank line, then the message exactly as given.
/// The identities come from the outer commit's own binding. The judgment is keyed
/// on these bytes, so any drift in this layout would stop it from matching the
/// unit the committed object yields where Git's cleanup leaves the message
/// unchanged.
fn synthetic_commit_unit(author: &[u8], committer: &[u8], message: &[u8]) -> Result<JudgmentUnit> {
    let author = extract_identity(author, "author")?;
    let committer = extract_identity(committer, "committer")?;

    let mut bytes = Vec::with_capacity(author.len() + committer.len() + message.len() + 20);
    bytes.extend_from_slice(b"author ");
    bytes.extend_from_slice(author);
    bytes.extend_from_slice(b"\ncommitter ");
    bytes.extend_from_slice(committer);
    bytes.extend_from_slice(b"\n\n");
    bytes.extend_from_slice(message);
    Ok(JudgmentUnit::commit(bytes))
}

fn missing_for(
    units: Vec<JudgmentUnit>,
    scopes: &[String],
    mut has_judgment: impl FnMut(&JudgmentUnit, &str) -> Result<bool>,
) -> Result<Vec<MissingJudgment>> {
    let units = deduplicate(
        units
            .into_iter()
            .filter(|unit| {
                matches!(
                    unit.kind(),
                    UnitKind::File | UnitKind::Path | UnitKind::Commit
                )
            })
            .collect(),
    );
    let mut missing = Vec::new();
    for scope in scopes {
        for unit in &units {
            if !has_judgment(unit, scope)? {
                missing.push(MissingJudgment {
                    scope: scope.clone(),
                    unit: unit.clone(),
                });
            }
        }
    }
    Ok(missing)
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
    use std::{ffi::OsStr, fs, process::Command};

    use tempfile::TempDir;

    use super::*;

    struct RepositoryFixture {
        _directory: TempDir,
        repository: PathBuf,
    }

    impl RepositoryFixture {
        fn new(format: &str) -> Self {
            let directory = tempfile::tempdir().expect("temporary repository");
            let repository = directory.path().join("repo");
            fs::create_dir(&repository).expect("repository directory");
            let repository = fs::canonicalize(repository).expect("canonical repository path");
            let mut arguments = vec!["init"];
            if format == "sha256" {
                arguments.push("--object-format=sha256");
            }
            git(&repository, arguments);
            let hooks = directory.path().join("empty-hooks");
            fs::create_dir(&hooks).expect("empty hooks directory");
            git_os(
                &repository,
                [
                    OsStr::new("config"),
                    OsStr::new("core.hooksPath"),
                    hooks.as_os_str(),
                ],
            );
            git(&repository, ["config", "user.name", "Test User"]);
            git(&repository, ["config", "user.email", "test@example.com"]);
            Self {
                _directory: directory,
                repository,
            }
        }

        fn path(&self) -> &Path {
            &self.repository
        }

        fn write(&self, path: &str, bytes: &[u8]) {
            let path = self.path().join(path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("file parent");
            }
            fs::write(path, bytes).expect("fixture file");
        }

        fn commit_all(&self, message: &str) {
            git(self.path(), ["add", "-A"]);
            git(self.path(), ["commit", "-m", message]);
        }
    }

    /// SPEC §16 commit_gate_01: only units absent from HEAD are required.
    #[test]
    fn commit_gate_01_requires_only_units_absent_from_head() {
        let repository = RepositoryFixture::new("sha1");
        repository.write("same.txt", b"same\n");
        repository.write("changed.txt", b"old\n");
        repository.commit_all("base");
        repository.write("changed.txt", b"new content\n");
        repository.write("new/item.txt", b"new item\n");
        git(repository.path(), ["add", "-A"]);

        let units = staged_units(&GitRepository::open(repository.path()).expect("open git"))
            .expect("staged units");
        assert!(contains(&units, UnitKind::File, b"new content\n"));
        assert!(contains(&units, UnitKind::File, b"new item\n"));
        assert!(contains(&units, UnitKind::Path, b"new"));
        assert!(contains(&units, UnitKind::Path, b"new/item.txt"));
        assert!(!contains(&units, UnitKind::Path, b"changed.txt"));
        assert!(!contains(&units, UnitKind::File, b"same\n"));
    }

    /// SPEC §16 path difference: a content-preserving rename adds only a path.
    #[test]
    fn path_difference_rename_requires_only_the_new_path() {
        let repository = RepositoryFixture::new("sha1");
        repository.write("old", b"unchanged\n");
        repository.commit_all("base");
        fs::rename(repository.path().join("old"), repository.path().join("new"))
            .expect("rename fixture file");
        git(repository.path(), ["add", "-A"]);

        let units = staged_units(&GitRepository::open(repository.path()).expect("open git"))
            .expect("staged units");
        assert!(contains(&units, UnitKind::Path, b"new"));
        assert!(!contains(&units, UnitKind::Path, b"old"));
        assert!(!contains(&units, UnitKind::File, b"unchanged\n"));
    }

    /// SPEC §16 commit_gate_02: an unborn repository requires its whole tree.
    #[test]
    fn commit_gate_02_unborn_repo_requires_full_tree() {
        let repository = RepositoryFixture::new("sha1");
        repository.write("empty", b"");
        repository.write("dir/item", b"x");
        git(repository.path(), ["add", "-A"]);
        let units = staged_units(&GitRepository::open(repository.path()).expect("open git"))
            .expect("staged units");
        assert!(contains(&units, UnitKind::File, b""));
        assert!(contains(&units, UnitKind::File, b"x"));
        assert!(contains(&units, UnitKind::Path, b"empty"));
        assert!(contains(&units, UnitKind::Path, b"dir"));
        assert!(contains(&units, UnitKind::Path, b"dir/item"));
    }

    /// SPEC §16 commit_gate_03: deletion-only creates only the new commit unit.
    #[test]
    fn commit_gate_03_deletion_only_requires_new_commit() {
        let repository = RepositoryFixture::new("sha1");
        repository.write("gone", b"gone\n");
        repository.commit_all("base");
        fs::remove_file(repository.path().join("gone")).expect("remove file");
        git(repository.path(), ["add", "-A"]);
        let git_repository = GitRepository::open(repository.path()).expect("open git");
        assert!(
            staged_units(&git_repository)
                .expect("staged units")
                .is_empty()
        );
        let message = repository.path().join("message");
        fs::write(&message, b"delete gone\n").expect("message");
        assert_eq!(
            message_unit(&git_repository, &message)
                .expect("commit unit")
                .kind(),
            UnitKind::Commit
        );
    }

    /// SPEC §16 commit_gate_04: commit-msg reads all bytes and never rewrites.
    #[test]
    fn commit_gate_04_commit_msg_reads_all_bytes_without_rewrite() {
        let repository = RepositoryFixture::new("sha1");
        let message = repository.path().join("message");
        let exact = b"subject  \n\n# comment\nbody\n";
        fs::write(&message, exact).expect("message");
        let git_repository = GitRepository::open(repository.path()).expect("open git");
        let unit = message_unit(&git_repository, &message).expect("commit unit");
        assert!(unit.bytes().ends_with(exact));
        assert_eq!(fs::read(message).expect("reread message"), exact);
    }

    /// SPEC §16 commit_gate_06: already judged units leave the result empty.
    #[test]
    fn commit_gate_06_already_judged_units_are_not_required() {
        let units = vec![JudgmentUnit::file(b"one"), JudgmentUnit::file(b"two")];
        let scopes = vec!["security".to_owned()];
        assert_eq!(
            missing_for(units.clone(), &scopes, |_, _| Ok(false))
                .expect("missing")
                .len(),
            2
        );
        assert!(
            missing_for(units, &scopes, |_, _| Ok(true))
                .expect("judged")
                .is_empty()
        );
        let result = CommitGateResult {
            missing: vec![MissingJudgment {
                scope: "security".to_owned(),
                unit: JudgmentUnit::file(b"one"),
            }],
        };
        assert!(matches!(
            result.require_clear(),
            Err(Error::JudgmentMissing { count: 1 })
        ));
    }

    /// SPEC §3.1, §10.4, and Appendix A.8 preserve non-UTF-8 identity bytes.
    #[cfg(unix)]
    #[test]
    fn extract_17_commit_gate_accepts_non_utf8_author_identity() {
        use std::os::unix::ffi::OsStrExt as _;

        let repository = RepositoryFixture::new("sha1");
        git_os(
            repository.path(),
            [
                OsStr::new("config"),
                OsStr::new("user.name"),
                OsStr::from_bytes(b"Ren\xe9 Dubois"),
            ],
        );
        git(
            repository.path(),
            ["config", "user.email", "rene@example.com"],
        );
        let git_repository = GitRepository::open(repository.path()).expect("open git");
        let author = git_repository
            .identity("GIT_AUTHOR_IDENT")
            .expect("identity");
        let committer = git_repository
            .identity("GIT_COMMITTER_IDENT")
            .expect("identity");
        assert!(author.contains(&0xe9));
        assert!(
            extract_identity(&author, "author")
                .expect("extract")
                .contains(&0xe9)
        );
        let unit = synthetic_commit_unit(&author, &committer, b"fix encoding\n")
            .expect("synthetic commit");
        assert_eq!(unit.bytes().len(), 93);
        assert_eq!(
            unit.digest().to_string(),
            "3bdc2f5072b618cede691d92d8a955438b0f61c494fba34277e2e6f879d4585e"
        );
    }

    /// SPEC §10.1 and §10.4 bind hook evaluation to the outer commit's
    /// alternate index and temporary identity configuration.
    #[test]
    fn alternate_index_and_temporary_identity_match_the_actual_commit() {
        let repository = RepositoryFixture::new("sha1");
        repository.write("alternate", b"alternate index\n");
        let alternate_index = repository._directory.path().join("alternate-index");
        let probe = repository._directory.path().join("hook-probe");
        let hook = repository._directory.path().join("commit-msg");
        let executable = std::env::current_exe().expect("current test executable");
        let script = format!(
            "#!/bin/sh\nUCHGS_COMMIT_GATE_HOOK_PROBE=1 \\\n+UCHGS_COMMIT_GATE_HOOK_REPOSITORY={} \\\n+UCHGS_COMMIT_GATE_HOOK_MESSAGE=\"$1\" \\\n+UCHGS_COMMIT_GATE_HOOK_OUTPUT={} \\\n+{} --exact commit_gate::tests::hook_probe_helper --nocapture\n",
            shell_quote(repository.path()),
            shell_quote(&probe),
            shell_quote(&executable),
        )
        .replace("\n+", "\n");
        fs::write(&hook, script).expect("commit-msg hook");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).expect("executable hook");
        }
        git_os(
            repository.path(),
            [
                OsStr::new("config"),
                OsStr::new("core.hooksPath"),
                repository._directory.path().as_os_str(),
            ],
        );

        git_with_index(repository.path(), &alternate_index, ["add", "alternate"]);
        let mut commit = fixture_git_command(repository.path());
        commit
            .env("GIT_INDEX_FILE", &alternate_index)
            .env_remove("GIT_AUTHOR_NAME")
            .env_remove("GIT_AUTHOR_EMAIL")
            .env_remove("GIT_AUTHOR_DATE")
            .env_remove("GIT_COMMITTER_NAME")
            .env_remove("GIT_COMMITTER_EMAIL")
            .env_remove("GIT_COMMITTER_DATE")
            .args([
                "-c",
                "user.name=Temporary Identity",
                "-c",
                "user.email=temporary@example.com",
                "commit",
                "-m",
                "temporary identity",
            ]);
        let output = commit.output().expect("outer git commit");
        assert!(
            output.status.success(),
            "git commit failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let probe = fs::read_to_string(probe).expect("hook probe");
        let mut lines = probe.lines();
        let hook_tree = lines.next().expect("hook tree");
        let hook_unit = hex::decode(lines.next().expect("hook unit")).expect("hook unit hex");
        assert!(lines.next().is_none());
        let actual_tree = git_capture(repository.path(), ["rev-parse", "HEAD^{tree}"]);
        assert_eq!(hook_tree.as_bytes(), strip_terminal_lf(&actual_tree));

        let body = git_capture(repository.path(), ["cat-file", "commit", "HEAD"]);
        let mut framed = format!("commit {}\0", body.len()).into_bytes();
        framed.extend_from_slice(&body);
        let actual =
            crate::extract::extract_git_object(crate::extract::ObjectFormat::Sha1, &framed)
                .expect("extract actual commit")
                .into_iter()
                .find(|unit| unit.kind() == UnitKind::Commit)
                .expect("actual commit unit");
        assert_eq!(hook_unit, actual.bytes());
        assert!(
            actual
                .bytes()
                .starts_with(b"author Temporary Identity <temporary@example.com>\n")
        );
        assert!(
            actual
                .bytes()
                .windows(b"\ncommitter Temporary Identity <temporary@example.com>\n\n".len())
                .any(|window| {
                    window == b"\ncommitter Temporary Identity <temporary@example.com>\n\n"
                })
        );
    }

    /// Test-only hook endpoint for the §10.1/§10.4 outer-commit regression.
    #[test]
    fn hook_probe_helper() {
        if std::env::var_os("UCHGS_COMMIT_GATE_HOOK_PROBE").is_none() {
            return;
        }
        let repository = PathBuf::from(
            std::env::var_os("UCHGS_COMMIT_GATE_HOOK_REPOSITORY").expect("hook repository"),
        );
        let message = PathBuf::from(
            std::env::var_os("UCHGS_COMMIT_GATE_HOOK_MESSAGE").expect("hook message"),
        );
        let output =
            PathBuf::from(std::env::var_os("UCHGS_COMMIT_GATE_HOOK_OUTPUT").expect("hook output"));
        let git = GitRepository::open(repository).expect("open hook repository");
        let tree = git.write_tree().expect("hook staged tree");
        let unit = message_unit(&git, &message).expect("hook commit unit");
        fs::write(
            output,
            format!("{}\n{}\n", tree.as_str(), hex::encode(unit.bytes())),
        )
        .expect("write hook probe");
    }

    /// SPEC §2.3 and §10.1 work with both Git object formats.
    #[test]
    fn commit_gate_supports_sha1_and_sha256_repositories() {
        for format in ["sha1", "sha256"] {
            let repository = RepositoryFixture::new(format);
            repository.write("item", b"value\n");
            git(repository.path(), ["add", "-A"]);
            let git_repository = GitRepository::open(repository.path()).expect("open git");
            let units = staged_units(&git_repository).expect("staged units");
            assert!(contains(&units, UnitKind::File, b"value\n"));
            assert!(contains(&units, UnitKind::Path, b"item"));
        }
    }

    /// SPEC §10.1 fails closed when a referenced Git object is unavailable.
    #[test]
    fn missing_git_object_is_git_unavailable() {
        let repository = RepositoryFixture::new("sha1");
        let missing = "1111111111111111111111111111111111111111";
        let cache = format!("100644,{missing},missing");
        git(
            repository.path(),
            [
                "update-index",
                "--add",
                "--info-only",
                "--cacheinfo",
                &cache,
            ],
        );
        assert!(matches!(
            staged_units(&GitRepository::open(repository.path()).expect("open git")),
            Err(Error::GitUnavailable(_))
        ));
    }

    /// SPEC §3.0 and §10.1 preserve non-UTF-8 tree-entry path bytes.
    #[cfg(unix)]
    #[test]
    fn non_utf8_path_is_not_decoded_or_reencoded() {
        let repository = RepositoryFixture::new("sha1");
        let oid = git_input_capture(
            repository.path(),
            ["hash-object", "-w", "--stdin"],
            b"value",
        );
        let mut index = b"100644 blob ".to_vec();
        index.extend_from_slice(String::from_utf8(oid).expect("ASCII OID").trim().as_bytes());
        index.extend_from_slice(b"\traw-\xff\0");
        git_input_capture(
            repository.path(),
            ["update-index", "-z", "--index-info"],
            &index,
        );
        let units = staged_units(&GitRepository::open(repository.path()).expect("open git"))
            .expect("staged units");
        assert!(contains(&units, UnitKind::Path, b"raw-\xff"));
    }

    /// SPEC §3 and §10.1 treat a symlink target as file bytes.
    #[cfg(unix)]
    #[test]
    fn symlink_target_is_file_content() {
        let repository = RepositoryFixture::new("sha1");
        std::os::unix::fs::symlink("destination", repository.path().join("link"))
            .expect("symlink fixture");
        git(repository.path(), ["add", "-A"]);
        let units = staged_units(&GitRepository::open(repository.path()).expect("open git"))
            .expect("staged units");
        assert!(contains(&units, UnitKind::File, b"destination"));
        assert!(contains(&units, UnitKind::Path, b"link"));
    }

    /// SPEC §3 and §10.1 produce only a path for a submodule entry.
    #[test]
    fn submodule_entry_produces_only_a_path() {
        let repository = RepositoryFixture::new("sha1");
        repository.write("base", b"base\n");
        repository.commit_all("base");
        let head = git_capture(repository.path(), ["rev-parse", "HEAD"]);
        let cache = format!(
            "160000,{},submodule",
            String::from_utf8(head).expect("ASCII HEAD").trim()
        );
        git(
            repository.path(),
            ["update-index", "--add", "--cacheinfo", &cache],
        );
        let units = staged_units(&GitRepository::open(repository.path()).expect("open git"))
            .expect("staged units");
        assert!(contains(&units, UnitKind::Path, b"submodule"));
        assert!(!units.iter().any(|unit| unit.kind() == UnitKind::Commit));
    }

    /// SPEC §1 resolves linked worktrees to the main repository authority root.
    #[test]
    fn linked_worktree_uses_the_main_repository_root() {
        let repository = RepositoryFixture::new("sha1");
        repository.write("item", b"value\n");
        repository.commit_all("base");
        let linked = repository._directory.path().join("linked");
        git_os(
            repository.path(),
            [
                OsStr::new("worktree"),
                OsStr::new("add"),
                linked.as_os_str(),
                OsStr::new("-b"),
                OsStr::new("linked"),
            ],
        );
        let root = GitRepository::open(&linked)
            .expect("open linked worktree")
            .repository_root()
            .expect("repository root");
        assert_eq!(
            fs::canonicalize(root).expect("canonical authority root"),
            fs::canonicalize(repository.path()).expect("canonical repository root")
        );
        assert!(!linked.join(".uchgs").exists());
    }

    fn contains(units: &[JudgmentUnit], kind: UnitKind, bytes: &[u8]) -> bool {
        units
            .iter()
            .any(|unit| unit.kind() == kind && unit.bytes() == bytes)
    }

    fn git<I, S>(directory: &Path, arguments: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        git_os(directory, arguments);
    }

    fn fixture_git_command(directory: &Path) -> Command {
        let mut command = Command::new("git");
        command.current_dir(directory);
        for name in crate::git_traversal::ISOLATED_GIT_ENVIRONMENT {
            command.env_remove(name);
        }
        command
    }

    fn git_with_index<I, S>(directory: &Path, index: &Path, arguments: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = fixture_git_command(directory)
            .env("GIT_INDEX_FILE", index)
            .args(arguments)
            .output()
            .expect("run alternate-index git");
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn shell_quote(path: &Path) -> String {
        let path = path.to_string_lossy().replace('\\', "/");
        format!("'{}'", path.replace('\'', "'\\''"))
    }

    fn strip_terminal_lf(bytes: &[u8]) -> &[u8] {
        bytes.strip_suffix(b"\n").unwrap_or(bytes)
    }

    fn git_os<I, S>(directory: &Path, arguments: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = fixture_git_command(directory);
        command.args(arguments);
        let output = command.output().expect("run fixture git");
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git_capture<I, S>(directory: &Path, arguments: I) -> Vec<u8>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = fixture_git_command(directory);
        command.args(arguments);
        let output = command.output().expect("run fixture git");
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    #[cfg(unix)]
    fn git_input_capture<I, S>(directory: &Path, arguments: I, input: &[u8]) -> Vec<u8>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        use std::{io::Write as _, process::Stdio};

        let mut command = fixture_git_command(directory);
        command
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("run fixture git");
        child
            .stdin
            .as_mut()
            .expect("fixture git stdin")
            .write_all(input)
            .expect("write fixture git stdin");
        let output = child.wait_with_output().expect("wait for fixture git");
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }
}
