use std::{
    ffi::{OsStr, OsString},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _};
#[cfg(not(windows))]
use cap_std::fs::File;
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use fs2::FileExt as _;

use crate::{Error, Result};

const TEMPORARY_ATTEMPTS: u64 = 1024;
static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Identifies the shared §14.2 temporary-name namespace.
///
/// One recognizer decides both what the cleanup paths may delete and what directory
/// scans skip, so the set of names this module may remove is exactly the set it
/// ignores. It accepts only what `authority_temporary_name` produces; a broader
/// prefix match would let an unrelated `.tmp-*` file be deleted, or be skipped as
/// though it were our own leftover.
pub(crate) fn is_authority_temporary_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(fields) = name.strip_prefix(".tmp-authority-") else {
        return false;
    };
    let mut fields = fields.splitn(3, '-');
    let (Some(pid), Some(sequence), Some(final_name)) =
        (fields.next(), fields.next(), fields.next())
    else {
        return false;
    };
    let mut components = Path::new(final_name).components();
    let valid_final_name =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    matches!(
        parse_canonical_decimal(pid),
        Some(pid) if pid != 0 && pid <= u64::from(u32::MAX)
    ) && parse_canonical_decimal(sequence).is_some()
        && valid_final_name
}

fn parse_canonical_decimal(value: &str) -> Option<u64> {
    let parsed = value.parse::<u64>().ok()?;
    (parsed.to_string() == value).then_some(parsed)
}

fn authority_temporary_name(final_name: &OsStr, counter: u64) -> OsString {
    OsString::from(format!(
        ".tmp-authority-{}-{counter}-{}",
        std::process::id(),
        final_name.to_string_lossy()
    ))
}

/// Outcome of a no-replace authority publication.
///
/// Normative source: SPEC §14.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublishOutcome {
    Published,
    Existing,
}

/// Caller-selected authority root opened as a capability.
///
/// This type deliberately has no global/repository path policy. A later
/// platform layer must choose and pass the physical root.
pub struct TrustedRoot {
    dir: Dir,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PrivateFileSnapshot {
    len: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
    #[cfg(windows)]
    attributes: u32,
    #[cfg(windows)]
    creation_time: u64,
    #[cfg(windows)]
    last_write_time: u64,
}

#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsAuthorityCapability {
    LocalNtfs,
    Remote,
    Other,
    Unknown,
}

#[cfg(any(windows, test))]
fn validate_windows_authority_capability(capability: WindowsAuthorityCapability) -> Result<()> {
    match capability {
        WindowsAuthorityCapability::LocalNtfs => Ok(()),
        WindowsAuthorityCapability::Remote => Err(Error::UnsupportedPlatform(
            "requires a local NTFS authority root; remote filesystems are unsupported".to_owned(),
        )),
        WindowsAuthorityCapability::Other => Err(Error::UnsupportedPlatform(
            "requires a local NTFS authority root; this filesystem is unsupported".to_owned(),
        )),
        WindowsAuthorityCapability::Unknown => Err(Error::UnsupportedPlatform(
            "requires a proven local NTFS authority root".to_owned(),
        )),
    }
}

impl TrustedRoot {
    /// Opens the exact caller-supplied directory as the authority boundary.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(Error::field("trusted_root", "must be an absolute path"));
        }
        let dir = Dir::open_ambient_dir(path, ambient_authority())
            .map_err(|error| Error::io("open trusted root", error))?;
        let metadata = dir
            .dir_metadata()
            .map_err(|error| Error::io("stat trusted root", error))?;
        if !metadata.is_dir() {
            return Err(Error::field(
                "trusted_root",
                "must be an ordinary directory",
            ));
        }
        Ok(Self { dir })
    }

    /// Opens an operator-selected absolute file path as a validated parent
    /// capability plus one direct-child name.
    ///
    /// Normative source: SPEC §14.1–§14.2.
    pub(crate) fn open_operator_parent(path: &Path) -> Result<(Self, OsString)> {
        if !path.is_absolute() {
            return Err(Error::field(
                "operator_path",
                "must be an absolute file path",
            ));
        }
        let final_name = path
            .file_name()
            .ok_or_else(|| Error::field("operator_path", "must name one file"))?
            .to_os_string();
        let mut final_components = Path::new(&final_name).components();
        if !matches!(final_components.next(), Some(Component::Normal(_)))
            || final_components.next().is_some()
        {
            return Err(Error::field(
                "operator_path",
                "final component must be one ordinary name",
            ));
        }
        let parent = path
            .parent()
            .ok_or_else(|| Error::field("operator_path", "must have an absolute parent"))?;
        let root_path = parent
            .ancestors()
            .last()
            .ok_or_else(|| Error::field("operator_path", "must have an absolute root"))?;
        if !root_path.is_absolute() {
            return Err(Error::field("operator_path", "must have an absolute root"));
        }
        let relative_parent = parent
            .strip_prefix(root_path)
            .map_err(|_| Error::field("operator_path", "parent escaped its absolute root"))?;
        let mut current = Dir::open_ambient_dir(root_path, ambient_authority())
            .map_err(|error| Error::io("open operator filesystem root", error))?;
        for component in relative_parent.components() {
            let Component::Normal(name) = component else {
                return Err(Error::field(
                    "operator_path",
                    "parent contains a namespace escape",
                ));
            };
            current = current
                .open_dir_nofollow(name)
                .map_err(|error| Error::io("open operator parent component", error))?;
        }
        Ok((Self { dir: current }, final_name))
    }

    /// Reads one bounded ordinary file through the same opened handle.
    pub fn read_file(&self, relative: impl AsRef<Path>, maximum: usize) -> Result<Vec<u8>> {
        self.read_file_with_hook(relative.as_ref(), maximum, || {})
    }

    /// Reads one protected operator file through its validated parent handle.
    ///
    /// Normative source: SPEC §8.6 and §14.1.
    pub(crate) fn read_private_file(&self, name: &Path, maximum: usize) -> Result<Vec<u8>> {
        self.read_private_file_with_hook(name, maximum, || {})
    }

    fn read_private_file_with_hook(
        &self,
        name: &Path,
        maximum: usize,
        after_initial_stat: impl FnOnce(),
    ) -> Result<Vec<u8>> {
        self.require_writable_authority_filesystem()?;
        Self::read_private_dir_file_with_hook(&self.dir, name, maximum, after_initial_stat)
    }

    fn read_private_dir_file(dir: &Dir, name: &Path, maximum: usize) -> Result<Vec<u8>> {
        Self::read_private_dir_file_with_hook(dir, name, maximum, || {})
    }

    fn read_private_dir_file_with_hook(
        dir: &Dir,
        name: &Path,
        maximum: usize,
        after_initial_stat: impl FnOnce(),
    ) -> Result<Vec<u8>> {
        let (parent, name) = split_file_path(name)?;
        if !parent.as_os_str().is_empty() {
            return Err(Error::field(
                "operator_path",
                "private file must be a direct child of the opened parent",
            ));
        }

        #[cfg(not(windows))]
        let file = {
            let mut options = OpenOptions::new();
            options.read(true);
            options.follow(FollowSymlinks::No);
            use cap_std::fs::OpenOptionsExt as _;
            options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
            dir.open_with(Path::new(&name), &options)
                .map_err(|error| Error::io("open private operator file", error))?
                .into_std()
        };
        #[cfg(windows)]
        let file = {
            let parent = dir
                .try_clone()
                .map_err(|error| Error::io("clone private-file parent", error))?
                .into_std_file();
            let opened = uchgs_windows_fs::open_regular(&parent, &name)
                .map_err(|error| Error::io("open private operator file", error))?;
            opened
                .try_clone_file()
                .map_err(|error| Error::io("retain private operator file handle", error))?
        };
        Self::read_private_std_file_with_hook(file, maximum, after_initial_stat)
    }

    fn read_private_std_file_with_hook(
        mut file: std::fs::File,
        maximum: usize,
        after_initial_stat: impl FnOnce(),
    ) -> Result<Vec<u8>> {
        uchgs_custody_platform::verify_private_file(&file).map_err(|error| {
            Error::io(
                "verify private operator file",
                std::io::Error::other(error.to_string()),
            )
        })?;
        let identity = file
            .try_clone()
            .map_err(|error| Error::io("retain private-file identity", error))?;
        let before = private_file_snapshot(&file)?;
        if before.len > maximum as u64 {
            return Err(Error::EncodedLengthExceeded {
                maximum,
                actual: usize::try_from(before.len).unwrap_or(usize::MAX),
            });
        }
        after_initial_stat();
        let limit = maximum
            .checked_add(1)
            .ok_or_else(|| Error::field("operator_path", "maximum is too large"))?;
        let capacity = usize::try_from(before.len)
            .map_err(|_| Error::field("operator_path", "file length does not fit in memory"))?;
        let mut bytes = Vec::with_capacity(capacity);
        Read::take(&mut file, limit as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| Error::io("read private operator file", error))?;
        if bytes.len() > maximum {
            return Err(Error::EncodedLengthExceeded {
                maximum,
                actual: bytes.len(),
            });
        }
        let after = private_file_snapshot(&file)?;
        let same_identity = private_file_identity_matches(&identity, &file)?;
        uchgs_custody_platform::verify_private_file(&file).map_err(|error| {
            Error::io(
                "reverify private operator file",
                std::io::Error::other(error.to_string()),
            )
        })?;
        if !same_identity || before != after || after.len != bytes.len() as u64 {
            return Err(Error::AuthorityConflict(
                "private operator file changed while being read".to_owned(),
            ));
        }
        Ok(bytes)
    }

    fn read_file_with_hook(
        &self,
        relative: &Path,
        maximum: usize,
        after_initial_stat: impl FnOnce(),
    ) -> Result<Vec<u8>> {
        let (parent, name) = split_file_path(relative)?;
        let dir = self.open_dir(&parent)?;
        Self::read_dir_file_with_hook(&dir, Path::new(&name), maximum, after_initial_stat)
    }

    /// Reads one bounded ordinary direct child through an already-opened
    /// directory handle.
    pub(crate) fn read_dir_file(dir: &Dir, name: &Path, maximum: usize) -> Result<Vec<u8>> {
        Self::read_dir_file_with_hook(dir, name, maximum, || {})
    }

    fn read_dir_file_with_hook(
        dir: &Dir,
        name: &Path,
        maximum: usize,
        after_initial_stat: impl FnOnce(),
    ) -> Result<Vec<u8>> {
        let (parent, name) = split_file_path(name)?;
        if !parent.as_os_str().is_empty() {
            return Err(Error::field(
                "authority_file",
                "must be a direct child of the opened directory",
            ));
        }
        let mut options = OpenOptions::new();
        options.read(true);
        options.follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
        }
        let mut file = dir
            .open_with(Path::new(&name), &options)
            .map_err(|error| Error::io("open authority file", error))?;
        let before = file
            .metadata()
            .map_err(|error| Error::io("stat authority file", error))?;
        if !before.is_file() {
            return Err(Error::field(
                "authority_file",
                "must be an ordinary disk file",
            ));
        }
        let before_len = usize::try_from(before.len())
            .map_err(|_| Error::field("authority_file", "encoded length does not fit in memory"))?;
        if before_len > maximum {
            return Err(Error::EncodedLengthExceeded {
                maximum,
                actual: before_len,
            });
        }
        after_initial_stat();
        let limit = maximum
            .checked_add(1)
            .ok_or_else(|| Error::field("authority_file", "maximum is too large"))?;
        let mut bytes = Vec::with_capacity(before_len);
        Read::take(&mut file, limit as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| Error::io("read authority file", error))?;
        if bytes.len() > maximum {
            return Err(Error::EncodedLengthExceeded {
                maximum,
                actual: bytes.len(),
            });
        }
        // Re-stat through the same already-opened handle and compare against the
        // pre-read stat. A length or type change mid-read means the already-open
        // file was mutated concurrently during the read, so the bytes we hold are
        // not a trustworthy authority snapshot and must be rejected. The
        // `take(maximum + 1)` above ensures an over-cap file surfaces as an
        // overflow rather than a silent truncation.
        let after = file
            .metadata()
            .map_err(|error| Error::io("restat authority file", error))?;
        if !after.is_file() || after.len() != bytes.len() as u64 || before.len() != after.len() {
            return Err(Error::field(
                "authority_file",
                "file changed length while being read",
            ));
        }
        Ok(bytes)
    }

    pub(crate) fn open_dir(&self, relative: &Path) -> Result<Dir> {
        validate_relative(relative, true)?;
        let mut current = self
            .dir
            .try_clone()
            .map_err(|error| Error::io("clone directory handle", error))?;
        for component in relative.components() {
            let Component::Normal(name) = component else {
                unreachable!("validated relative path");
            };
            current = current
                .open_dir_nofollow(name)
                .map_err(|error| Error::io("open authority directory", error))?;
        }
        Ok(current)
    }

    pub(crate) fn ensure_dir(&self, relative: &Path) -> Result<Dir> {
        self.require_writable_authority_filesystem()?;
        validate_relative(relative, true)?;
        let mut current = self
            .dir
            .try_clone()
            .map_err(|error| Error::io("clone directory handle", error))?;
        for component in relative.components() {
            let Component::Normal(name) = component else {
                unreachable!("validated relative path");
            };
            match current.create_dir(name) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(Error::io("create authority directory", error)),
            }
            current = current
                .open_dir_nofollow(name)
                .map_err(|error| Error::io("open authority directory", error))?;
        }
        Ok(current)
    }

    pub(crate) fn entries(&self, relative: &Path) -> Result<Vec<OsString>> {
        let dir = self.open_dir(relative)?;
        let mut names = Vec::new();
        for entry in dir
            .entries()
            .map_err(|error| Error::io("list authority directory", error))?
        {
            let entry =
                entry.map_err(|error| Error::io("read authority directory entry", error))?;
            names.push(entry.file_name());
        }
        names.sort_by_key(native_name_bytes);
        Ok(names)
    }

    /// Publishes one complete authority file through a same-directory temporary
    /// file. `replace` is reserved for the ledger append exception in §6.4.
    ///
    /// Normative source: SPEC §6.4 and §14.2.
    pub(crate) fn publish_file(
        &self,
        relative: &Path,
        bytes: &[u8],
        replace: bool,
    ) -> Result<PublishOutcome> {
        self.publish_file_internal(relative, bytes, replace, false)
    }

    /// Publishes one protected operator-selected file without replacing an
    /// existing winner.
    ///
    /// Staging protects and re-verifies the file while it is still empty, and only
    /// then writes the bytes, so the content is never on disk ahead of the
    /// protection that guards it.
    ///
    /// Normative source: SPEC §8.6 and §14.2.
    pub(crate) fn publish_private_file(&self, name: &Path, bytes: &[u8]) -> Result<PublishOutcome> {
        self.publish_file_internal(name, bytes, false, true)
    }

    fn publish_file_internal(
        &self,
        relative: &Path,
        bytes: &[u8],
        replace: bool,
        private: bool,
    ) -> Result<PublishOutcome> {
        self.require_writable_authority_filesystem()?;
        let (parent_path, final_name) = split_file_path(relative)?;
        let parent = self.ensure_dir(&parent_path)?;
        self.cleanup_foreign_temporaries(&parent)?;

        for _ in 0..TEMPORARY_ATTEMPTS {
            let counter = TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let temporary_name = authority_temporary_name(&final_name, counter);
            let temporary_path = Path::new(&temporary_name);
            let mut staged = match if private {
                Self::create_private_staged_file(&parent, temporary_path)
            } else {
                Self::write_new_file(&parent, temporary_path, bytes)
            } {
                Ok(staged) => staged,
                Err(Error::Io {
                    kind: std::io::ErrorKind::AlreadyExists,
                    ..
                }) => continue,
                Err(error) => return Err(error),
            };
            if private {
                if let Err(error) = Self::write_private_staged_file(&mut staged, bytes) {
                    Self::remove_staged_file(&parent, temporary_path, &staged);
                    return Err(error);
                }
            }
            if let Err(error) = Self::reverify_staged_file(&mut staged, bytes) {
                Self::remove_staged_file(&parent, temporary_path, &staged);
                return Err(error);
            }

            let outcome = Self::rename_staged_file(
                &parent,
                temporary_path,
                &staged,
                Path::new(&final_name),
                replace,
            );
            match outcome {
                Ok(PublishOutcome::Published) => {
                    #[cfg(not(windows))]
                    Self::sync_dir(&parent)?;
                    let committed = if private {
                        Self::read_private_dir_file(&parent, Path::new(&final_name), bytes.len())?
                    } else {
                        Self::read_dir_file(&parent, Path::new(&final_name), bytes.len())?
                    };
                    if committed != bytes {
                        return Err(Error::AuthorityConflict(format!(
                            "published authority file {} does not match the committed bytes",
                            relative.display()
                        )));
                    }
                    return Ok(PublishOutcome::Published);
                }
                Ok(PublishOutcome::Existing) => {
                    Self::remove_staged_file(&parent, temporary_path, &staged);
                    return Ok(PublishOutcome::Existing);
                }
                Err(error) => {
                    Self::remove_staged_file(&parent, temporary_path, &staged);
                    return Err(error);
                }
            }
        }
        Err(Error::AuthorityConflict(format!(
            "could not allocate a temporary authority name after {TEMPORARY_ATTEMPTS} attempts"
        )))
    }

    /// Removes one direct authority file through its validated parent.
    ///
    /// Normative source: SPEC §7.5 and §14.2.
    pub(crate) fn remove_file(&self, relative: &Path) -> Result<()> {
        self.require_writable_authority_filesystem()?;
        let (parent_path, name) = split_file_path(relative)?;
        let parent = self.open_dir(&parent_path)?;
        parent
            .remove_file(Path::new(&name))
            .map_err(|error| Error::io("remove authority file", error))?;
        #[cfg(not(windows))]
        Self::sync_dir(&parent)?;
        Ok(())
    }

    /// Moves one completed authority directory to a final name without
    /// replacing an existing winner.
    ///
    /// Normative source: SPEC §7.5, §7.6, and §14.2.
    pub(crate) fn rename_directory_no_replace(
        &self,
        source: &Path,
        destination: &Path,
    ) -> Result<PublishOutcome> {
        self.rename_directory_no_replace_with(source, destination, || Ok(()))
    }

    pub(crate) fn rename_directory_no_replace_with(
        &self,
        source: &Path,
        destination: &Path,
        after_rename: impl FnOnce() -> Result<()>,
    ) -> Result<PublishOutcome> {
        self.require_writable_authority_filesystem()?;
        let (source_parent_path, source_name) = split_file_path(source)?;
        let (destination_parent_path, destination_name) = split_file_path(destination)?;
        let source_parent = self.open_dir(&source_parent_path)?;
        let destination_parent = self.ensure_dir(&destination_parent_path)?;

        #[cfg(not(windows))]
        let outcome = rename_no_replace(
            &source_parent,
            Path::new(&source_name),
            &destination_parent,
            Path::new(&destination_name),
        )?;

        #[cfg(windows)]
        let outcome = {
            let source_parent_file = source_parent
                .try_clone()
                .map_err(|error| Error::io("clone authority source parent", error))?
                .into_std_file();
            let destination_parent_file = destination_parent
                .try_clone()
                .map_err(|error| Error::io("clone authority destination parent", error))?
                .into_std_file();
            let source = uchgs_windows_fs::open_directory(&source_parent_file, &source_name)
                .map_err(|error| Error::io("open authority directory for rename", error))?;
            match uchgs_windows_fs::rename_to(
                &source,
                &destination_parent_file,
                &destination_name,
                false,
            ) {
                Ok(uchgs_windows_fs::RenameOutcome::Renamed) => PublishOutcome::Published,
                Ok(uchgs_windows_fs::RenameOutcome::Existing) => PublishOutcome::Existing,
                Err(error) => {
                    return Err(Error::io(
                        "rename authority directory",
                        error.into_io_error(),
                    ));
                }
            }
        };

        if outcome == PublishOutcome::Published {
            after_rename()?;
            Self::sync_dir(&source_parent)?;
            if source_parent_path != destination_parent_path {
                Self::sync_dir(&destination_parent)?;
            }
        }
        Ok(outcome)
    }

    pub(crate) fn create_temporary_directory(
        &self,
        parent_path: &Path,
        final_name: &OsStr,
    ) -> Result<PathBuf> {
        self.require_writable_authority_filesystem()?;
        validate_relative(parent_path, true)?;
        validate_relative(Path::new(final_name), false)?;
        if Path::new(final_name).components().count() != 1 {
            return Err(Error::field(
                "authority_path",
                "temporary directory target must be one path component",
            ));
        }
        let parent = self.ensure_dir(parent_path)?;
        self.cleanup_foreign_temporaries(&parent)?;
        for _ in 0..TEMPORARY_ATTEMPTS {
            let counter = TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let temporary_name = authority_temporary_name(final_name, counter);
            #[cfg(not(windows))]
            let creation = parent.create_dir(Path::new(&temporary_name));
            #[cfg(windows)]
            let creation = {
                let parent_file = parent
                    .try_clone()
                    .map_err(|error| Error::io("clone staged directory parent", error))?
                    .into_std_file();
                uchgs_windows_fs::create_directory(&parent_file, &temporary_name).map(drop)
            };
            match creation {
                Ok(()) => {
                    parent
                        .open_dir_nofollow(Path::new(&temporary_name))
                        .map_err(|error| Error::io("open staged authority directory", error))?;
                    return Ok(parent_path.join(temporary_name));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(Error::io("create staged authority directory", error));
                }
            }
        }
        Err(Error::AuthorityConflict(format!(
            "could not allocate a temporary authority name after {TEMPORARY_ATTEMPTS} attempts"
        )))
    }

    pub(crate) fn sync_directory(&self, relative: &Path) -> Result<()> {
        self.require_writable_authority_filesystem()?;
        let directory = self.open_dir(relative)?;
        Self::sync_dir(&directory)
    }

    pub(crate) fn same_root(&self, other: &Self) -> Result<bool> {
        let this = self
            .dir
            .try_clone()
            .map_err(|error| Error::io("clone first authority root identity", error))?
            .into_std_file();
        let other = other
            .dir
            .try_clone()
            .map_err(|error| Error::io("clone second authority root identity", error))?
            .into_std_file();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;

            let this = this
                .metadata()
                .map_err(|error| Error::io("stat first authority root identity", error))?;
            let other = other
                .metadata()
                .map_err(|error| Error::io("stat second authority root identity", error))?;
            Ok(this.dev() == other.dev() && this.ino() == other.ino())
        }
        #[cfg(windows)]
        {
            uchgs_windows_fs::same_file_identity(&this, &other)
                .map_err(|error| Error::io("compare authority root identity", error))
        }
    }

    fn cleanup_foreign_temporaries(&self, parent: &Dir) -> Result<()> {
        let own_prefix = format!(".tmp-authority-{}-", std::process::id());
        let entries = parent
            .entries()
            .map_err(|error| Error::io("list authority temporary files", error))?;
        for entry in entries {
            let Ok(entry) = entry else { continue };
            let name = entry.file_name();
            let display = name.to_string_lossy();
            if is_authority_temporary_name(&name)
                && !display.starts_with(&own_prefix)
                && parent.remove_file(Path::new(&name)).is_err()
            {
                let _ = parent.remove_dir_all(Path::new(&name));
            }
        }
        Ok(())
    }

    pub(crate) fn lock(&self, name: &'static str) -> Result<AuthorityLock> {
        self.require_writable_authority_filesystem()?;
        let path = Path::new(name);
        validate_relative(path, false)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        options.follow(FollowSymlinks::No);
        let mut attempts = 0;
        let file = loop {
            match self.dir.open_with(path, &options) {
                Ok(file) => break file,
                // A simultaneous create/open can transiently lose the name
                // between the no-follow resolution steps. Retrying preserves
                // the single named lock without introducing another namespace.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && attempts < 16 => {
                    attempts += 1;
                    std::thread::yield_now();
                }
                Err(error) => return Err(Error::io("open authority lock", error)),
            }
        };
        let metadata = file
            .metadata()
            .map_err(|error| Error::io("stat authority lock", error))?;
        if !metadata.is_file() {
            return Err(Error::field(
                "authority_lock",
                "must be an ordinary disk file",
            ));
        }
        let file = file.into_std();
        file.lock_exclusive()
            .map_err(|error| Error::io("lock authority root", error))?;
        Ok(AuthorityLock { file })
    }

    #[cfg(not(windows))]
    pub(crate) fn write_new_file(dir: &Dir, name: &Path, bytes: &[u8]) -> Result<File> {
        validate_relative(name, false)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        options.follow(FollowSymlinks::No);
        let mut file = dir
            .open_with(name, &options)
            .map_err(|error| Error::io("create staged authority file", error))?;
        file.write_all(bytes)
            .map_err(|error| Error::io("write staged authority file", error))?;
        file.sync_all()
            .map_err(|error| Error::io("sync staged authority file", error))?;
        Ok(file)
    }

    #[cfg(not(windows))]
    fn create_private_staged_file(dir: &Dir, name: &Path) -> Result<File> {
        validate_relative(name, false)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        options.follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        #[cfg(not(unix))]
        return Err(Error::UnsupportedPlatform(
            "private staging requires Unix creation modes or Windows protected handles".into(),
        ));

        let mut file = dir
            .open_with(name, &options)
            .map_err(|error| Error::io("create staged private file", error))?;
        let prepared = Self::protect_staged_private_file(&file)
            .and_then(|()| Self::reverify_staged_file(&mut file, b""));
        if let Err(error) = prepared {
            let _ = dir.remove_file(name);
            return Err(error);
        }
        Ok(file)
    }

    #[cfg(windows)]
    pub(crate) fn write_new_file(
        dir: &Dir,
        name: &Path,
        bytes: &[u8],
    ) -> Result<uchgs_windows_fs::OpenedObject> {
        validate_relative(name, false)?;
        if name.components().count() != 1 {
            return Err(Error::field(
                "authority_path",
                "staged authority files must be direct children",
            ));
        }
        let parent = dir
            .try_clone()
            .map_err(|error| Error::io("clone staged authority parent", error))?
            .into_std_file();
        let mut opened = uchgs_windows_fs::create_regular(&parent, name.as_os_str())
            .map_err(|error| Error::io("create staged authority file", error))?;
        opened
            .file_mut()
            .write_all(bytes)
            .map_err(|error| Error::io("write staged authority file", error))?;
        opened
            .file()
            .sync_all()
            .map_err(|error| Error::io("sync staged authority file", error))?;
        Ok(opened)
    }

    #[cfg(windows)]
    fn create_private_staged_file(
        dir: &Dir,
        name: &Path,
    ) -> Result<uchgs_windows_fs::OpenedObject> {
        validate_relative(name, false)?;
        if name.components().count() != 1 {
            return Err(Error::field(
                "authority_path",
                "staged private files must be direct children",
            ));
        }
        let parent = dir
            .try_clone()
            .map_err(|error| Error::io("clone staged private parent", error))?
            .into_std_file();
        let descriptor =
            uchgs_custody_platform::private_file_security_descriptor().map_err(|error| {
                Error::io(
                    "build staged private-file protection",
                    std::io::Error::other(error.to_string()),
                )
            })?;
        let mut opened = unsafe {
            // The descriptor owns its allocation through this synchronous
            // handle-relative create call.
            uchgs_windows_fs::create_regular_with_security_descriptor(
                &parent,
                name.as_os_str(),
                descriptor.as_ptr(),
            )
        }
        .map_err(|error| Error::io("create staged private file", error))?;
        Self::verify_staged_private_file(&opened)?;
        Self::reverify_staged_file(&mut opened, b"")?;
        Ok(opened)
    }

    #[cfg(not(windows))]
    fn write_private_staged_file(file: &mut File, bytes: &[u8]) -> Result<()> {
        file.write_all(bytes)
            .map_err(|error| Error::io("write staged private file", error))?;
        file.sync_all()
            .map_err(|error| Error::io("sync staged private file", error))?;
        Self::reverify_staged_file(file, bytes)?;
        Self::verify_staged_private_file(file)
    }

    #[cfg(windows)]
    fn write_private_staged_file(
        file: &mut uchgs_windows_fs::OpenedObject,
        bytes: &[u8],
    ) -> Result<()> {
        file.file_mut()
            .write_all(bytes)
            .map_err(|error| Error::io("write staged private file", error))?;
        file.file()
            .sync_all()
            .map_err(|error| Error::io("sync staged private file", error))?;
        Self::reverify_staged_file(file, bytes)?;
        Self::verify_staged_private_file(file)
    }

    #[cfg(not(windows))]
    fn protect_staged_private_file(file: &File) -> Result<()> {
        let file = file
            .try_clone()
            .map_err(|error| Error::io("clone staged private file", error))?
            .into_std();
        uchgs_custody_platform::protect_private_file(&file).map_err(|error| {
            Error::io(
                "protect staged private file",
                std::io::Error::other(error.to_string()),
            )
        })?;
        file.sync_all()
            .map_err(|error| Error::io("sync staged private-file protection", error))?;
        uchgs_custody_platform::verify_private_file(&file).map_err(|error| {
            Error::io(
                "verify staged private file",
                std::io::Error::other(error.to_string()),
            )
        })
    }

    #[cfg(not(windows))]
    fn verify_staged_private_file(file: &File) -> Result<()> {
        let file = file
            .try_clone()
            .map_err(|error| Error::io("clone staged private file", error))?
            .into_std();
        uchgs_custody_platform::verify_private_file(&file).map_err(|error| {
            Error::io(
                "verify staged private file",
                std::io::Error::other(error.to_string()),
            )
        })
    }

    #[cfg(not(windows))]
    pub(crate) fn reverify_staged_file(file: &mut File, expected: &[u8]) -> Result<()> {
        let before = file
            .metadata()
            .map_err(|error| Error::io("stat staged authority file", error))?;
        if !before.is_file() || before.len() != expected.len() as u64 {
            return Err(Error::field(
                "staged_authority_file",
                "must remain the exact expected ordinary file",
            ));
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|error| Error::io("rewind staged authority file", error))?;
        let limit = expected
            .len()
            .checked_add(1)
            .ok_or_else(|| Error::field("staged_authority_file", "length overflow"))?;
        let mut actual = Vec::with_capacity(expected.len());
        Read::take(&mut *file, limit as u64)
            .read_to_end(&mut actual)
            .map_err(|error| Error::io("re-read staged authority file", error))?;
        let after = file
            .metadata()
            .map_err(|error| Error::io("restat staged authority file", error))?;
        if actual != expected
            || !after.is_file()
            || after.len() != expected.len() as u64
            || before.len() != after.len()
        {
            return Err(Error::field(
                "staged_authority_file",
                "changed before the authority commit point",
            ));
        }
        Ok(())
    }

    #[cfg(not(windows))]
    fn rename_staged_file(
        parent: &Dir,
        temporary_name: &Path,
        _staged: &File,
        final_name: &Path,
        replace: bool,
    ) -> Result<PublishOutcome> {
        if replace {
            parent
                .rename(temporary_name, parent, final_name)
                .map_err(|error| Error::io("replace authority file", error))?;
            return Ok(PublishOutcome::Published);
        }
        rename_no_replace(parent, temporary_name, parent, final_name)
    }

    #[cfg(not(windows))]
    fn remove_staged_file(parent: &Dir, temporary_name: &Path, _staged: &File) {
        let _ = parent.remove_file(temporary_name);
    }

    #[cfg(windows)]
    fn protect_staged_private_file(file: &uchgs_windows_fs::OpenedObject) -> Result<()> {
        uchgs_custody_platform::protect_private_file(file.file()).map_err(|error| {
            Error::io(
                "protect staged private file",
                std::io::Error::other(error.to_string()),
            )
        })?;
        file.file()
            .sync_all()
            .map_err(|error| Error::io("sync staged private-file protection", error))?;
        uchgs_custody_platform::verify_private_file(file.file()).map_err(|error| {
            Error::io(
                "verify staged private file",
                std::io::Error::other(error.to_string()),
            )
        })
    }

    #[cfg(windows)]
    fn verify_staged_private_file(file: &uchgs_windows_fs::OpenedObject) -> Result<()> {
        uchgs_custody_platform::verify_private_file(file.file()).map_err(|error| {
            Error::io(
                "verify staged private file",
                std::io::Error::other(error.to_string()),
            )
        })
    }

    #[cfg(windows)]
    pub(crate) fn reverify_staged_file(
        file: &mut uchgs_windows_fs::OpenedObject,
        expected: &[u8],
    ) -> Result<()> {
        let before = file
            .file()
            .metadata()
            .map_err(|error| Error::io("stat staged authority file", error))?;
        if !before.is_file() || before.len() != expected.len() as u64 {
            return Err(Error::field(
                "staged_authority_file",
                "must remain the exact expected ordinary file",
            ));
        }
        file.file_mut()
            .seek(SeekFrom::Start(0))
            .map_err(|error| Error::io("rewind staged authority file", error))?;
        let limit = expected
            .len()
            .checked_add(1)
            .ok_or_else(|| Error::field("staged_authority_file", "length overflow"))?;
        let mut actual = Vec::with_capacity(expected.len());
        Read::take(file.file_mut(), limit as u64)
            .read_to_end(&mut actual)
            .map_err(|error| Error::io("re-read staged authority file", error))?;
        let after = file
            .file()
            .metadata()
            .map_err(|error| Error::io("restat staged authority file", error))?;
        if actual != expected
            || !after.is_file()
            || after.len() != expected.len() as u64
            || before.len() != after.len()
        {
            return Err(Error::field(
                "staged_authority_file",
                "changed before the authority commit point",
            ));
        }
        Ok(())
    }

    #[cfg(windows)]
    fn rename_staged_file(
        parent: &Dir,
        _temporary_name: &Path,
        staged: &uchgs_windows_fs::OpenedObject,
        final_name: &Path,
        replace: bool,
    ) -> Result<PublishOutcome> {
        let parent = parent
            .try_clone()
            .map_err(|error| Error::io("clone authority publication parent", error))?
            .into_std_file();
        match uchgs_windows_fs::rename_to(staged, &parent, final_name.as_os_str(), replace) {
            Ok(uchgs_windows_fs::RenameOutcome::Renamed) => Ok(PublishOutcome::Published),
            Ok(uchgs_windows_fs::RenameOutcome::Existing) => Ok(PublishOutcome::Existing),
            Err(error) => Err(Error::io("publish authority file", error.into_io_error())),
        }
    }

    #[cfg(windows)]
    fn remove_staged_file(
        _parent: &Dir,
        _temporary_name: &Path,
        staged: &uchgs_windows_fs::OpenedObject,
    ) {
        let _ = uchgs_windows_fs::delete_opened_regular(staged);
    }

    pub(crate) fn require_writable_authority_filesystem(&self) -> Result<()> {
        #[cfg(windows)]
        {
            let root = self
                .dir
                .try_clone()
                .map_err(|error| Error::io("clone authority root for volume query", error))?
                .into_std_file();
            let capability = match uchgs_windows_fs::volume_capability(&root) {
                Ok(uchgs_windows_fs::VolumeCapability::LocalNtfs) => {
                    WindowsAuthorityCapability::LocalNtfs
                }
                Ok(uchgs_windows_fs::VolumeCapability::Remote) => {
                    WindowsAuthorityCapability::Remote
                }
                Ok(uchgs_windows_fs::VolumeCapability::Other) => WindowsAuthorityCapability::Other,
                Err(_) => WindowsAuthorityCapability::Unknown,
            };
            validate_windows_authority_capability(capability)
        }
        #[cfg(not(windows))]
        {
            Ok(())
        }
    }

    #[cfg(not(windows))]
    pub(crate) fn sync_dir(dir: &Dir) -> Result<()> {
        // A capability `Dir` may hold an O_PATH descriptor on Linux, which
        // cannot be fsynced. Reopen `.` through that validated handle to obtain
        // an fsync-capable descriptor without resolving an ambient pathname.
        dir.open(".")
            .map_err(|error| Error::io("open directory for sync", error))?
            .sync_all()
            .map_err(|error| Error::io("sync authority directory", error))
    }

    #[cfg(windows)]
    pub(crate) fn sync_dir(dir: &Dir) -> Result<()> {
        // Windows does not provide a directory-fsync operation equivalent to
        // Unix. Every authority child create and rename is issued through a
        // retained handle opened with FILE_WRITE_THROUGH; validating the
        // directory's local-NTFS capability here closes that durability
        // contract without retrying through an ambient pathname.
        let handle = dir
            .try_clone()
            .map_err(|error| Error::io("clone directory for sync", error))?
            .into_std_file();
        let capability = match uchgs_windows_fs::volume_capability(&handle)
            .map_err(|error| Error::io("query authority directory volume", error))?
        {
            uchgs_windows_fs::VolumeCapability::LocalNtfs => WindowsAuthorityCapability::LocalNtfs,
            uchgs_windows_fs::VolumeCapability::Remote => WindowsAuthorityCapability::Remote,
            uchgs_windows_fs::VolumeCapability::Other => WindowsAuthorityCapability::Other,
        };
        validate_windows_authority_capability(capability)
    }
}

pub(crate) struct AuthorityLock {
    file: std::fs::File,
}

impl Drop for AuthorityLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

#[cfg(unix)]
fn private_file_snapshot(file: &std::fs::File) -> Result<PrivateFileSnapshot> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|error| Error::io("stat private operator file", error))?;
    if !metadata.is_file() {
        return Err(Error::field(
            "operator_path",
            "must identify one ordinary disk file",
        ));
    }
    Ok(PrivateFileSnapshot {
        len: metadata.len(),
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

#[cfg(windows)]
fn private_file_snapshot(file: &std::fs::File) -> Result<PrivateFileSnapshot> {
    use std::os::windows::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|error| Error::io("stat private operator file", error))?;
    if !metadata.is_file() {
        return Err(Error::field(
            "operator_path",
            "must identify one ordinary disk file",
        ));
    }
    Ok(PrivateFileSnapshot {
        len: metadata.file_size(),
        attributes: metadata.file_attributes(),
        creation_time: metadata.creation_time(),
        last_write_time: metadata.last_write_time(),
    })
}

#[cfg(unix)]
fn private_file_identity_matches(
    expected: &std::fs::File,
    observed: &std::fs::File,
) -> Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    let expected = expected
        .metadata()
        .map_err(|error| Error::io("stat retained private-file identity", error))?;
    let observed = observed
        .metadata()
        .map_err(|error| Error::io("restat private-file identity", error))?;
    Ok(expected.dev() == observed.dev() && expected.ino() == observed.ino())
}

#[cfg(windows)]
fn private_file_identity_matches(
    expected: &std::fs::File,
    observed: &std::fs::File,
) -> Result<bool> {
    uchgs_windows_fs::same_file_identity(expected, observed)
        .map_err(|error| Error::io("compare private-file identity", error))
}

fn split_file_path(path: &Path) -> Result<(PathBuf, OsString)> {
    validate_relative(path, false)?;
    let name = path
        .file_name()
        .ok_or_else(|| Error::field("authority_path", "must name a file"))?
        .to_owned();
    Ok((
        path.parent().unwrap_or_else(|| Path::new("")).to_owned(),
        name,
    ))
}

fn validate_relative(path: &Path, allow_empty: bool) -> Result<()> {
    if path.as_os_str().is_empty() {
        return if allow_empty {
            Ok(())
        } else {
            Err(Error::field("authority_path", "must not be empty"))
        };
    }
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Error::field(
            "authority_path",
            "must contain only relative normal components",
        ));
    }
    Ok(())
}

#[cfg(all(
    unix,
    any(target_os = "linux", target_os = "android", target_vendor = "apple")
))]
fn rename_no_replace(
    source_parent: &Dir,
    source_name: &Path,
    destination_parent: &Dir,
    destination_name: &Path,
) -> Result<PublishOutcome> {
    use rustix::fs::{RenameFlags, renameat_with};
    match renameat_with(
        source_parent,
        source_name,
        destination_parent,
        destination_name,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => Ok(PublishOutcome::Published),
        Err(error) if error == rustix::io::Errno::EXIST => Ok(PublishOutcome::Existing),
        Err(error) => Err(map_no_replace_error(error)),
    }
}

#[cfg(all(
    unix,
    any(target_os = "linux", target_os = "android", target_vendor = "apple")
))]
fn map_no_replace_error(error: rustix::io::Errno) -> Error {
    if no_replace_is_unsupported(error) {
        Error::UnsupportedPlatform(
            "atomic no-replace rename is unavailable on this kernel or filesystem".to_owned(),
        )
    } else {
        Error::io(
            "publish authority name",
            std::io::Error::from_raw_os_error(error.raw_os_error()),
        )
    }
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
fn no_replace_is_unsupported(error: rustix::io::Errno) -> bool {
    // renameat2(2) assigns EINVAL to an unsupported flag on the target
    // filesystem. This call supplies the sole valid NOREPLACE flag and all
    // path components were validated before reaching this boundary.
    matches!(error, rustix::io::Errno::NOSYS | rustix::io::Errno::INVAL)
}

#[cfg(all(unix, target_vendor = "apple"))]
fn no_replace_is_unsupported(error: rustix::io::Errno) -> bool {
    // renameatx_np(2) uses ENOTSUP for a filesystem that cannot honor the
    // requested flag; EINVAL has broader meanings and deliberately stays I/O.
    matches!(error, rustix::io::Errno::NOSYS | rustix::io::Errno::NOTSUP)
}

#[cfg(all(unix, target_os = "freebsd"))]
fn rename_no_replace(
    source_parent: &Dir,
    source_name: &Path,
    destination_parent: &Dir,
    destination_name: &Path,
) -> Result<PublishOutcome> {
    use std::{
        ffi::CString,
        os::{fd::AsRawFd as _, unix::ffi::OsStrExt as _},
    };

    unsafe extern "C" {
        fn renameat2(
            fromfd: std::ffi::c_int,
            from: *const std::ffi::c_char,
            tofd: std::ffi::c_int,
            to: *const std::ffi::c_char,
            flags: std::ffi::c_uint,
        ) -> std::ffi::c_int;
    }

    const RENAME_NOREPLACE: std::ffi::c_uint = 1;
    let source = CString::new(source_name.as_os_str().as_bytes())
        .map_err(|_| Error::field("authority_path", "contains NUL"))?;
    let destination = CString::new(destination_name.as_os_str().as_bytes())
        .map_err(|_| Error::field("authority_path", "contains NUL"))?;
    // SAFETY: both C strings are NUL-terminated and remain live for the call;
    // both descriptors are retained validated directory capabilities.
    let result = unsafe {
        renameat2(
            source_parent.as_raw_fd(),
            source.as_ptr(),
            destination_parent.as_raw_fd(),
            destination.as_ptr(),
            RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        return Ok(PublishOutcome::Published);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        Ok(PublishOutcome::Existing)
    } else {
        Err(map_freebsd_no_replace_error(error))
    }
}

#[cfg(all(unix, target_os = "freebsd"))]
fn map_freebsd_no_replace_error(error: std::io::Error) -> Error {
    let unsupported = [rustix::io::Errno::NOTSUP, rustix::io::Errno::NOSYS]
        .into_iter()
        .any(|errno| error.raw_os_error() == Some(errno.raw_os_error()));
    if unsupported {
        Error::UnsupportedPlatform(
            "atomic no-replace rename is unavailable on this kernel or filesystem".to_owned(),
        )
    } else {
        Error::io("publish authority name", error)
    }
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd"
    ))
))]
fn rename_no_replace(
    _source_parent: &Dir,
    _source_name: &Path,
    _destination_parent: &Dir,
    _destination_name: &Path,
) -> Result<PublishOutcome> {
    Err(Error::UnsupportedPlatform(
        "no atomic no-replace rename is available on this Unix platform".to_owned(),
    ))
}

#[cfg(unix)]
fn native_name_bytes(value: &OsString) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt as _;
    value.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn native_name_bytes(value: &OsString) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt as _;
    value
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    #[test]
    fn temporary_name_recognizer_matches_only_generated_grammar() {
        for final_name in [
            OsStr::new("record.json"),
            OsStr::new("record-with-hyphen.json"),
        ] {
            let generated = authority_temporary_name(final_name, 7);
            assert!(is_authority_temporary_name(&generated));
        }

        for invalid in [
            ".tmp-garbage",
            ".tmp-unknown",
            ".tmp-authority",
            ".tmp-authority--1-record.json",
            ".tmp-authority-0-1-record.json",
            ".tmp-authority-01-1-record.json",
            ".tmp-authority-1--record.json",
            ".tmp-authority-1-01-record.json",
            ".tmp-authority-1-1-",
            ".tmp-authority-1-1-.",
            ".tmp-authority-1-1-..",
            ".tmp-authority-1-1-dir/record.json",
            ".tmp-policy-1-1-record.json",
            ".tmpx-authority-1-1-record.json",
        ] {
            assert!(
                !is_authority_temporary_name(OsStr::new(invalid)),
                "unexpected temporary name: {invalid}"
            );
        }
    }

    #[test]
    fn temporary_directory_creation_cleans_only_foreign_generated_residue() {
        let temp = tempfile::tempdir().unwrap();
        let root = TrustedRoot::open(temp.path()).unwrap();
        let parent = temp.path().join("bundles");
        std::fs::create_dir_all(&parent).unwrap();
        let foreign_pid = if std::process::id() == u32::MAX {
            1
        } else {
            std::process::id() + 1
        };
        let foreign = format!(".tmp-authority-{foreign_pid}-1-stale");
        std::fs::create_dir(parent.join(&foreign)).unwrap();
        std::fs::write(parent.join(&foreign).join("partial"), b"partial").unwrap();
        std::fs::create_dir(parent.join(".tmp-garbage")).unwrap();

        let staged = root
            .create_temporary_directory(Path::new("bundles"), OsStr::new("final"))
            .unwrap();
        assert!(!parent.join(foreign).exists());
        assert!(parent.join(".tmp-garbage").exists());
        assert!(temp.path().join(&staged).is_dir());
        assert!(is_authority_temporary_name(
            staged.file_name().expect("staged directory has a name")
        ));
    }

    #[test]
    fn growth_after_initial_stat_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("growing");
        std::fs::write(&path, vec![0_u8; 4096]).unwrap();
        let root = TrustedRoot::open(temp.path()).unwrap();

        let error = root
            .read_file_with_hook(Path::new("growing"), 8192, || {
                let mut file = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap();
                file.write_all(&vec![1_u8; 8192]).unwrap();
                file.sync_all().unwrap();
            })
            .unwrap_err();
        assert!(matches!(error, Error::EncodedLengthExceeded { .. }));
    }

    #[test]
    fn private_file_size_change_during_same_handle_read_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let root = TrustedRoot::open(temp.path()).unwrap();
        assert_eq!(
            root.publish_private_file(Path::new("operator.key"), b"secret"),
            Ok(PublishOutcome::Published)
        );

        let result = root.read_private_file_with_hook(Path::new("operator.key"), 7, || {
            std::fs::write(temp.path().join("operator.key"), b"changed").unwrap();
        });
        assert!(matches!(result, Err(Error::AuthorityConflict(_))));
    }

    #[test]
    fn private_staging_residues_are_protected_before_and_after_write() {
        let temp = tempfile::tempdir().unwrap();
        let root = TrustedRoot::open(temp.path()).unwrap();
        let parent = root.ensure_dir(Path::new("")).unwrap();

        let mut empty =
            TrustedRoot::create_private_staged_file(&parent, Path::new("empty.tmp")).unwrap();
        TrustedRoot::reverify_staged_file(&mut empty, b"").unwrap();
        TrustedRoot::verify_staged_private_file(&empty).unwrap();
        drop(empty);
        let empty = std::fs::File::open(temp.path().join("empty.tmp")).unwrap();
        uchgs_custody_platform::verify_private_file(&empty).unwrap();
        assert_eq!(empty.metadata().unwrap().len(), 0);

        let mut written =
            TrustedRoot::create_private_staged_file(&parent, Path::new("written.tmp")).unwrap();
        TrustedRoot::write_private_staged_file(&mut written, b"private bytes").unwrap();
        drop(written);
        let written = std::fs::File::open(temp.path().join("written.tmp")).unwrap();
        uchgs_custody_platform::verify_private_file(&written).unwrap();
        assert_eq!(
            std::fs::read(temp.path().join("written.tmp")).unwrap(),
            b"private bytes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_staging_creation_mode_is_independent_of_umask() {
        const CHILD: &str = "UCHGS_PRIVATE_STAGING_UMASK_CHILD";
        const TEST: &str =
            "authority_file::tests::private_staging_creation_mode_is_independent_of_umask";

        if std::env::var_os(CHILD).is_some() {
            use std::os::unix::fs::PermissionsExt as _;

            let temp = tempfile::tempdir().unwrap();
            let root = TrustedRoot::open(temp.path()).unwrap();
            let parent = root.ensure_dir(Path::new("")).unwrap();
            let staged =
                TrustedRoot::create_private_staged_file(&parent, Path::new("private.tmp")).unwrap();
            let metadata = staged.try_clone().unwrap().into_std().metadata().unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            return;
        }

        let test_binary = std::env::current_exe().unwrap();
        for mask in ["000", "022", "077"] {
            let status = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg("umask \"$1\"; shift; exec \"$@\"")
                .arg("sh")
                .arg(mask)
                .arg(&test_binary)
                .arg("--exact")
                .arg(TEST)
                .arg("--nocapture")
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(
                status.success(),
                "private staging failed under umask {mask}"
            );
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn directory_sync_succeeds_for_staging_and_parent_handles() {
        let temp = tempfile::tempdir().unwrap();
        let root = TrustedRoot::open(temp.path()).unwrap();
        let parent = root.ensure_dir(Path::new("bundles")).unwrap();
        parent.create_dir("staging").unwrap();
        let staging = parent.open_dir("staging").unwrap();

        TrustedRoot::sync_dir(&staging).unwrap();
        TrustedRoot::sync_dir(&parent).unwrap();
    }

    #[cfg(all(
        unix,
        any(target_os = "linux", target_os = "android", target_vendor = "apple")
    ))]
    #[test]
    fn unavailable_atomic_no_replace_has_a_typed_platform_error() {
        assert!(matches!(
            map_no_replace_error(rustix::io::Errno::NOSYS),
            Error::UnsupportedPlatform(_)
        ));
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert!(matches!(
            map_no_replace_error(rustix::io::Errno::INVAL),
            Error::UnsupportedPlatform(_)
        ));
        #[cfg(target_vendor = "apple")]
        assert!(matches!(
            map_no_replace_error(rustix::io::Errno::NOTSUP),
            Error::UnsupportedPlatform(_)
        ));
        assert!(matches!(
            map_no_replace_error(rustix::io::Errno::IO),
            Error::Io { .. }
        ));
    }

    #[cfg(all(unix, target_os = "freebsd"))]
    #[test]
    fn freebsd_unsupported_no_replace_has_a_typed_platform_error() {
        assert!(matches!(
            map_freebsd_no_replace_error(std::io::Error::from_raw_os_error(
                rustix::io::Errno::NOTSUP.raw_os_error()
            )),
            Error::UnsupportedPlatform(_)
        ));
        assert!(matches!(
            map_freebsd_no_replace_error(std::io::Error::from_raw_os_error(
                rustix::io::Errno::NOSYS.raw_os_error()
            )),
            Error::UnsupportedPlatform(_)
        ));
        assert!(matches!(
            map_freebsd_no_replace_error(std::io::Error::from_raw_os_error(
                rustix::io::Errno::IO.raw_os_error()
            )),
            Error::Io { .. }
        ));
    }

    #[test]
    fn windows_capability_policy_is_path_independent_and_fail_closed() {
        validate_windows_authority_capability(WindowsAuthorityCapability::LocalNtfs).unwrap();
        for capability in [
            WindowsAuthorityCapability::Remote,
            WindowsAuthorityCapability::Other,
            WindowsAuthorityCapability::Unknown,
        ] {
            assert!(matches!(
                validate_windows_authority_capability(capability).unwrap_err(),
                Error::UnsupportedPlatform(_)
            ));
        }
    }
}
