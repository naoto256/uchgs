use std::{
    ffi::OsString,
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
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

/// Caller-selected authority root opened as a capability.
///
/// This type deliberately has no global/repository path policy. A later
/// platform layer must choose and pass the physical root.
pub struct TrustedRoot {
    dir: Dir,
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
        WindowsAuthorityCapability::Remote => Err(Error::field(
            "authority_publication",
            "requires a local NTFS authority root; remote filesystems are unsupported",
        )),
        WindowsAuthorityCapability::Other => Err(Error::field(
            "authority_publication",
            "requires a local NTFS authority root; this filesystem is unsupported",
        )),
        WindowsAuthorityCapability::Unknown => Err(Error::field(
            "authority_publication",
            "requires a proven local NTFS authority root",
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

    /// Reads one bounded ordinary file through the same opened handle.
    pub fn read_file(&self, relative: impl AsRef<Path>, maximum: usize) -> Result<Vec<u8>> {
        self.read_file_with_hook(relative.as_ref(), maximum, || {})
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

    pub(crate) fn lock(&self, name: &'static str) -> Result<AuthorityLock> {
        self.require_writable_authority_filesystem()?;
        let path = Path::new(name);
        validate_relative(path, false)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        options.follow(FollowSymlinks::No);
        let file = self
            .dir
            .open_with(path, &options)
            .map_err(|error| Error::io("open authority lock", error))?;
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
}

pub(crate) struct AuthorityLock {
    file: std::fs::File,
}

impl Drop for AuthorityLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
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
                Error::InvalidField {
                    field: "authority_publication",
                    ..
                }
            ));
        }
    }
}
