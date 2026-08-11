//! Byte-preserving Git plumbing shared by the commit and push gates.
//!
//! Normative source: SPEC §1, §3, §10.1, and §10.4.

use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use crate::{
    Error, Result,
    extract::{ObjectFormat, extract_git_object},
};

pub(crate) const ISOLATED_GIT_ENVIRONMENT: [&str; 18] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
    "GIT_SHALLOW_FILE",
    "GIT_GRAFT_FILE",
    "GIT_REPLACE_REF_BASE",
    "GIT_QUARANTINE_PATH",
    "GIT_PREFIX",
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ObjectId(String);

impl ObjectId {
    fn parse(bytes: &[u8], width: usize) -> Result<Self> {
        if bytes.len() != width || !bytes.iter().all(u8::is_ascii_hexdigit) {
            return Err(Error::GitUnavailable(
                "git returned an invalid object identifier".to_owned(),
            ));
        }
        if bytes.iter().any(u8::is_ascii_uppercase) {
            return Err(Error::GitUnavailable(
                "git returned a non-lowercase object identifier".to_owned(),
            ));
        }
        Ok(Self(
            std::str::from_utf8(bytes)
                .map_err(|_| Error::GitUnavailable("object identifier is not ASCII".to_owned()))?
                .to_owned(),
        ))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitRepository {
    working_directory: PathBuf,
    object_format: ObjectFormat,
    index_file: Option<OsString>,
    author_identity: Vec<u8>,
    committer_identity: Vec<u8>,
}

impl GitRepository {
    /// Opens one Git working surface while isolating repository redirects and
    /// retaining the outer commit's exact index selection.
    ///
    /// Author and committer identity variables are intentionally retained:
    /// SPEC §10.4 requires `git var` to observe them.
    pub(crate) fn open(working_directory: impl AsRef<Path>) -> Result<Self> {
        let working_directory = absolute_path(working_directory.as_ref())?;
        let index_file = std::env::var_os("GIT_INDEX_FILE");
        let author_identity = capture_identity(&working_directory, "GIT_AUTHOR_IDENT")?;
        let committer_identity = capture_identity(&working_directory, "GIT_COMMITTER_IDENT")?;
        let mut repository = Self {
            working_directory,
            object_format: ObjectFormat::Sha1,
            index_file,
            author_identity,
            committer_identity,
        };
        let output =
            repository.run([OsStr::new("rev-parse"), OsStr::new("--show-object-format")])?;
        repository.object_format = match strip_one_lf(&output.stdout) {
            b"sha1" => ObjectFormat::Sha1,
            b"sha256" => ObjectFormat::Sha256,
            _ => {
                return Err(Error::GitUnavailable(
                    "git returned an unsupported object format".to_owned(),
                ));
            }
        };
        Ok(repository)
    }

    pub(crate) fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    /// Resolves `<repo>` exactly as the parent of `--git-common-dir`.
    pub(crate) fn repository_root(&self) -> Result<PathBuf> {
        let output = self.run([
            OsStr::new("rev-parse"),
            OsStr::new("--path-format=absolute"),
            OsStr::new("--git-common-dir"),
        ])?;
        let common = bytes_to_path(strip_one_lf(&output.stdout))?;
        if !common.is_absolute() {
            return Err(Error::GitUnavailable(
                "git common directory was not absolute".to_owned(),
            ));
        }
        common
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| Error::GitUnavailable("git common directory has no parent".to_owned()))
    }

    pub(crate) fn write_tree(&self) -> Result<ObjectId> {
        let output = self.run([OsStr::new("write-tree")])?;
        ObjectId::parse(
            strip_one_lf(&output.stdout),
            self.object_format.oid_hex_bytes(),
        )
    }

    pub(crate) fn head_tree(&self) -> Result<Option<ObjectId>> {
        let tree = self.output([
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new("HEAD^{tree}"),
        ])?;
        if tree.status.success() {
            return ObjectId::parse(
                strip_one_lf(&tree.stdout),
                self.object_format.oid_hex_bytes(),
            )
            .map(Some);
        }
        let head = self.output([
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new("HEAD"),
        ])?;
        if !head.status.success() {
            return Ok(None);
        }
        Err(command_failure("rev-parse HEAD^{tree}", &tree.stderr))
    }

    pub(crate) fn object_difference(
        &self,
        included: &ObjectId,
        excluded: Option<&ObjectId>,
    ) -> Result<Vec<ObjectId>> {
        let mut arguments = vec![
            OsString::from("rev-list"),
            OsString::from("--objects"),
            OsString::from(included.as_str()),
        ];
        if let Some(excluded) = excluded {
            arguments.push(OsString::from("--not"));
            arguments.push(OsString::from(excluded.as_str()));
        }
        let output = self.run(arguments.iter().map(OsString::as_os_str))?;
        let width = self.object_format.oid_hex_bytes();
        let mut identifiers = BTreeSet::new();
        for line in output.stdout.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            if line.len() < width || (line.len() > width && line[width] != b' ') {
                return Err(Error::GitUnavailable(
                    "git rev-list returned a malformed object line".to_owned(),
                ));
            }
            identifiers.insert(ObjectId::parse(&line[..width], width)?);
        }
        Ok(identifiers.into_iter().collect())
    }

    pub(crate) fn tree_paths(&self, tree: &ObjectId) -> Result<BTreeSet<Vec<u8>>> {
        let output = self.run([
            OsStr::new("ls-tree"),
            OsStr::new("-r"),
            OsStr::new("-t"),
            OsStr::new("--name-only"),
            OsStr::new("-z"),
            OsStr::new(tree.as_str()),
        ])?;
        if !output.stdout.is_empty() && !output.stdout.ends_with(&[0]) {
            return Err(Error::GitUnavailable(
                "git ls-tree did not terminate its byte paths with NUL".to_owned(),
            ));
        }
        if output.stdout.is_empty() {
            return Ok(BTreeSet::new());
        }
        Ok(output.stdout[..output.stdout.len() - 1]
            .split(|byte| *byte == 0)
            .map(<[u8]>::to_vec)
            .collect())
    }

    pub(crate) fn extracted_objects(
        &self,
        identifiers: &[ObjectId],
    ) -> Result<Vec<crate::extract::JudgmentUnit>> {
        if identifiers.is_empty() {
            return Ok(Vec::new());
        }
        let mut command = self.command();
        command
            .arg("cat-file")
            .arg("--batch")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| Error::GitUnavailable(format!("start git cat-file: {error}")))?;
        let mut requests =
            Vec::with_capacity(identifiers.len() * (self.object_format.oid_hex_bytes() + 1));
        for identifier in identifiers {
            requests.extend_from_slice(identifier.as_str().as_bytes());
            requests.push(b'\n');
        }
        let mut stdin = child.stdin.take().ok_or_else(|| {
            Error::GitUnavailable("git cat-file stdin was unavailable".to_owned())
        })?;
        // Writing and reading must overlap: a large first object can fill
        // stdout before cat-file has consumed a large request list.
        let writer = std::thread::spawn(move || stdin.write_all(&requests));
        let output = child
            .wait_with_output()
            .map_err(|error| Error::GitUnavailable(format!("wait for git cat-file: {error}")))?;
        let write_result = writer.join().map_err(|_| {
            Error::GitUnavailable("git cat-file request writer panicked".to_owned())
        })?;
        if !output.status.success() {
            return Err(command_failure("cat-file --batch", &output.stderr));
        }
        write_result.map_err(|error| {
            Error::GitUnavailable(format!("write git cat-file request: {error}"))
        })?;
        parse_batch(identifiers, &output.stdout, self.object_format)
    }

    pub(crate) fn identity(&self, variable: &'static str) -> Result<Vec<u8>> {
        match variable {
            "GIT_AUTHOR_IDENT" => Ok(self.author_identity.clone()),
            "GIT_COMMITTER_IDENT" => Ok(self.committer_identity.clone()),
            _ => Err(Error::GitUnavailable(format!(
                "unsupported git identity variable {variable}"
            ))),
        }
    }

    fn run<I, S>(&self, arguments: I) -> Result<Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self.output(arguments)?;
        if output.status.success() {
            Ok(output)
        } else {
            Err(command_failure("git plumbing", &output.stderr))
        }
    }

    fn output<I, S>(&self, arguments: I) -> Result<Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = self.command();
        command.args(arguments);
        command
            .output()
            .map_err(|error| Error::GitUnavailable(format!("start git: {error}")))
    }

    fn command(&self) -> Command {
        let mut command = Command::new("git");
        command
            .current_dir(&self.working_directory)
            .arg("--no-replace-objects");
        for name in ISOLATED_GIT_ENVIRONMENT {
            command.env_remove(name);
        }
        if let Some(index_file) = &self.index_file {
            command.env("GIT_INDEX_FILE", index_file);
        }
        command
    }
}

/// Captures one outer identity string before any isolated plumbing runs.
///
/// Unlike `command()`, this deliberately keeps the five `GIT_CONFIG*` variables.
/// The identity recorded here has to be the one the outer invocation would use,
/// so its configuration inputs are not isolated away; everything that redirects
/// the repository or index still is.
fn capture_identity(working_directory: &Path, variable: &'static str) -> Result<Vec<u8>> {
    let mut command = Command::new("git");
    command
        .current_dir(working_directory)
        .arg("--no-replace-objects")
        .arg("var")
        .arg(variable);
    for name in ISOLATED_GIT_ENVIRONMENT {
        if !matches!(
            name,
            "GIT_CONFIG"
                | "GIT_CONFIG_COUNT"
                | "GIT_CONFIG_PARAMETERS"
                | "GIT_CONFIG_GLOBAL"
                | "GIT_CONFIG_SYSTEM"
        ) {
            command.env_remove(name);
        }
    }
    let output = command
        .output()
        .map_err(|error| Error::GitUnavailable(format!("start git var {variable}: {error}")))?;
    if !output.status.success() {
        return Err(command_failure(
            &format!("git var {variable}"),
            &output.stderr,
        ));
    }
    let value = strip_one_lf(&output.stdout);
    if value.is_empty() || value.contains(&b'\n') || value.contains(&b'\r') {
        return Err(Error::GitUnavailable(format!(
            "git var {variable} returned a malformed identity"
        )));
    }
    Ok(value.to_vec())
}

fn parse_batch(
    identifiers: &[ObjectId],
    bytes: &[u8],
    object_format: ObjectFormat,
) -> Result<Vec<crate::extract::JudgmentUnit>> {
    let mut cursor = 0usize;
    let mut units = Vec::new();
    for expected in identifiers {
        let header_end = bytes[cursor..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|offset| cursor + offset)
            .ok_or_else(|| Error::GitUnavailable("truncated git cat-file header".to_owned()))?;
        let header = &bytes[cursor..header_end];
        cursor = header_end + 1;
        let mut fields = header.split(|byte| *byte == b' ');
        let echoed = fields.next().unwrap_or_default();
        let kind = fields.next().unwrap_or_default();
        let length = fields.next().unwrap_or_default();
        if fields.next().is_some() || echoed != expected.as_str().as_bytes() {
            return Err(Error::GitUnavailable(
                "git cat-file response did not match its request".to_owned(),
            ));
        }
        if kind == b"missing" || length.is_empty() {
            return Err(Error::GitUnavailable(format!(
                "git object {} is unavailable",
                expected.as_str()
            )));
        }
        if kind != b"blob" && kind != b"tree" && kind != b"commit" && kind != b"tag" {
            return Err(Error::GitUnavailable(
                "git cat-file returned an unsupported object type".to_owned(),
            ));
        }
        let length = parse_size(length)?;
        let body_end = cursor
            .checked_add(length)
            .ok_or_else(|| Error::GitUnavailable("git object length overflowed".to_owned()))?;
        if body_end >= bytes.len() || bytes[body_end] != b'\n' {
            return Err(Error::GitUnavailable(
                "git cat-file returned a truncated object".to_owned(),
            ));
        }
        let mut framed = Vec::with_capacity(kind.len() + length + 32);
        framed.extend_from_slice(kind);
        framed.push(b' ');
        framed.extend_from_slice(length.to_string().as_bytes());
        framed.push(0);
        framed.extend_from_slice(&bytes[cursor..body_end]);
        units.extend(extract_git_object(object_format, &framed)?);
        cursor = body_end + 1;
    }
    if cursor != bytes.len() {
        return Err(Error::GitUnavailable(
            "git cat-file returned trailing bytes".to_owned(),
        ));
    }
    Ok(units)
}

fn parse_size(bytes: &[u8]) -> Result<usize> {
    if bytes.is_empty()
        || (bytes.len() > 1 && bytes[0] == b'0')
        || !bytes.iter().all(u8::is_ascii_digit)
    {
        return Err(Error::GitUnavailable(
            "git cat-file returned a noncanonical size".to_owned(),
        ));
    }
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| Error::GitUnavailable("git object size is out of range".to_owned()))
}

fn strip_one_lf(bytes: &[u8]) -> &[u8] {
    bytes.strip_suffix(b"\n").unwrap_or(bytes)
}

fn command_failure(operation: &str, stderr: &[u8]) -> Error {
    let detail = String::from_utf8_lossy(stderr);
    Error::GitUnavailable(format!("{operation}: {}", detail.trim()))
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    std::env::current_dir()
        .map(|current| current.join(path))
        .map_err(|error| Error::io("resolve Git working directory", error))
}

#[cfg(unix)]
fn bytes_to_path(bytes: &[u8]) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt as _;
    Ok(PathBuf::from(OsString::from_vec(bytes.to_vec())))
}

#[cfg(windows)]
fn bytes_to_path(bytes: &[u8]) -> Result<PathBuf> {
    String::from_utf8(bytes.to_vec())
        .map(PathBuf::from)
        .map_err(|_| Error::GitUnavailable("git returned a non-UTF-8 Windows path".to_owned()))
}

#[cfg(not(any(unix, windows)))]
fn bytes_to_path(_bytes: &[u8]) -> Result<PathBuf> {
    Err(Error::UnsupportedPlatform(
        "Git path decoding is unsupported on this platform".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SPEC §10.4 keeps identity environment while isolating repository/index state.
    #[test]
    fn command_environment_isolates_repository_but_preserves_identity() {
        let repository = GitRepository {
            working_directory: PathBuf::from("."),
            object_format: ObjectFormat::Sha1,
            index_file: Some(OsString::from("alternate-index")),
            author_identity: b"Author <author@example.com> 1 +0000".to_vec(),
            committer_identity: b"Committer <committer@example.com> 1 +0000".to_vec(),
        };
        let command = repository.command();
        let changes: std::collections::BTreeMap<_, _> = command
            .get_envs()
            .map(|(name, value)| (name.to_owned(), value.map(OsStr::to_owned)))
            .collect();
        for name in ISOLATED_GIT_ENVIRONMENT {
            if name == "GIT_INDEX_FILE" {
                assert_eq!(
                    changes.get(OsStr::new(name)),
                    Some(&Some(OsString::from("alternate-index")))
                );
            } else {
                assert_eq!(changes.get(OsStr::new(name)), Some(&None));
            }
        }
        assert!(!changes.contains_key(OsStr::new("GIT_AUTHOR_NAME")));
        assert!(!changes.contains_key(OsStr::new("GIT_COMMITTER_NAME")));
    }
}
