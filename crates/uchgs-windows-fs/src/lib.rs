#![cfg(windows)]

use std::{
    ffi::OsStr,
    io,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt as _,
        io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle, RawHandle},
    },
    ptr,
};

use windows_sys::Wdk::{
    Foundation::OBJECT_ATTRIBUTES,
    Storage::FileSystem::{
        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
        FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
        FILE_WRITE_THROUGH, FileFsDeviceInformation, FileRenameInformation, NtCreateFile,
        NtQueryVolumeInformationFile, NtSetInformationFile,
    },
    System::SystemServices::{FILE_FS_DEVICE_INFORMATION, FILE_REMOTE_DEVICE},
};
use windows_sys::Win32::{
    Foundation::{
        HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError,
        STATUS_OBJECT_NAME_COLLISION, UNICODE_STRING,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ACCESS_RIGHTS, FILE_ADD_FILE,
        FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO, FILE_LIST_DIRECTORY,
        FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FileDispositionInfo, GetFileInformationByHandle,
        GetVolumeInformationByHandleW, SYNCHRONIZE, SetFileInformationByHandle,
    },
    System::IO::IO_STATUS_BLOCK,
};

const FILE_CREATED_INFORMATION: usize = 2;
const FILE_OPENED_INFORMATION: usize = 1;
const MAX_DIRECT_CHILD_UTF16_UNITS: usize = 255;
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelativeOpenKind {
    NewRegular,
    ExistingRegular,
    NewDirectory,
    ExistingDirectory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OpenSpec {
    desired_access: FILE_ACCESS_RIGHTS,
    file_attributes: u32,
    create_disposition: u32,
    create_options: u32,
    expected_information: usize,
    expected_directory: bool,
}

impl RelativeOpenKind {
    fn spec(self) -> OpenSpec {
        match self {
            Self::NewRegular => OpenSpec {
                desired_access: FILE_READ_DATA
                    | FILE_WRITE_DATA
                    | FILE_READ_ATTRIBUTES
                    | FILE_WRITE_ATTRIBUTES
                    | DELETE
                    | SYNCHRONIZE,
                file_attributes: FILE_ATTRIBUTE_NORMAL,
                create_disposition: FILE_CREATE,
                create_options: FILE_NON_DIRECTORY_FILE
                    | FILE_OPEN_REPARSE_POINT
                    | FILE_WRITE_THROUGH
                    | FILE_SYNCHRONOUS_IO_NONALERT,
                expected_information: FILE_CREATED_INFORMATION,
                expected_directory: false,
            },
            Self::ExistingRegular => OpenSpec {
                desired_access: FILE_READ_DATA | FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE,
                file_attributes: FILE_ATTRIBUTE_NORMAL,
                create_disposition: FILE_OPEN,
                create_options: FILE_NON_DIRECTORY_FILE
                    | FILE_OPEN_REPARSE_POINT
                    | FILE_WRITE_THROUGH
                    | FILE_SYNCHRONOUS_IO_NONALERT,
                expected_information: FILE_OPENED_INFORMATION,
                expected_directory: false,
            },
            Self::NewDirectory => OpenSpec {
                desired_access: FILE_LIST_DIRECTORY
                    | FILE_ADD_FILE
                    | FILE_ADD_SUBDIRECTORY
                    | FILE_READ_ATTRIBUTES
                    | FILE_WRITE_ATTRIBUTES
                    | DELETE
                    | SYNCHRONIZE,
                file_attributes: FILE_ATTRIBUTE_DIRECTORY,
                create_disposition: FILE_CREATE,
                create_options: FILE_DIRECTORY_FILE
                    | FILE_WRITE_THROUGH
                    | FILE_SYNCHRONOUS_IO_NONALERT,
                expected_information: FILE_CREATED_INFORMATION,
                expected_directory: true,
            },
            Self::ExistingDirectory => OpenSpec {
                desired_access: FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE,
                file_attributes: FILE_ATTRIBUTE_NORMAL,
                create_disposition: FILE_OPEN,
                // Deliberately omit FILE_DIRECTORY_FILE: the already-opened
                // handle is classified after open, including reparse rejection.
                create_options: FILE_OPEN_REPARSE_POINT
                    | FILE_WRITE_THROUGH
                    | FILE_SYNCHRONOUS_IO_NONALERT,
                expected_information: FILE_OPENED_INFORMATION,
                expected_directory: true,
            },
        }
    }
}

#[derive(Debug)]
pub struct OpenedObject {
    file: std::fs::File,
    kind: RelativeOpenKind,
}

impl OpenedObject {
    pub fn file(&self) -> &std::fs::File {
        &self.file
    }

    pub fn file_mut(&mut self) -> &mut std::fs::File {
        &mut self.file
    }

    pub fn try_clone_file(&self) -> io::Result<std::fs::File> {
        self.file.try_clone()
    }

    pub fn kind(&self) -> RelativeOpenKind {
        self.kind
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenameOutcome {
    Renamed,
    Existing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenameStage {
    ValidateDestination,
    VerifySource,
    VerifyDestinationParent,
    Rename,
}

#[derive(Debug)]
pub struct RenameError {
    stage: RenameStage,
    source: io::Error,
}

impl RenameError {
    pub fn stage(&self) -> RenameStage {
        self.stage
    }

    pub fn into_io_error(self) -> io::Error {
        self.source
    }
}

impl std::fmt::Display for RenameError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:?}: {}", self.stage, self.source)
    }
}

impl std::error::Error for RenameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeCapability {
    LocalNtfs,
    Remote,
    Other,
}

fn rename_error(stage: RenameStage, source: io::Error) -> RenameError {
    RenameError { stage, source }
}

fn direct_child_utf16(name: &OsStr) -> io::Result<Vec<u16>> {
    let units = name.encode_wide().collect::<Vec<_>>();
    if units.is_empty()
        || units.len() > MAX_DIRECT_CHILD_UTF16_UNITS
        || units.iter().any(|unit| {
            *unit == 0
                || *unit == u16::from(b'/')
                || *unit == u16::from(b'\\')
                || *unit == u16::from(b':')
        })
        || units == [u16::from(b'.')]
        || units == [u16::from(b'.'), u16::from(b'.')]
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "name must be one nonempty Windows path component",
        ));
    }
    let byte_length = units
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "name is too long"))?;
    u16::try_from(byte_length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name is too long"))?;
    Ok(units)
}

fn handle_information(handle: HANDLE) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let result = unsafe {
        GetFileInformationByHandle(handle, &mut information as *mut BY_HANDLE_FILE_INFORMATION)
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(information)
}

fn handle_identity(handle: HANDLE) -> io::Result<(u32, u32, u32)> {
    let information = handle_information(handle)?;
    Ok((
        information.dwVolumeSerialNumber,
        information.nFileIndexHigh,
        information.nFileIndexLow,
    ))
}

fn validate_opened_type(file: &std::fs::File, spec: OpenSpec) -> io::Result<()> {
    let information = handle_information(file.as_raw_handle() as HANDLE)?;
    let is_directory = information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    let is_reparse = information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    if is_reparse || is_directory != spec.expected_directory {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "opened object has the wrong type or is a reparse point",
        ));
    }
    Ok(())
}

fn require_local_ntfs(handle: &std::fs::File) -> io::Result<()> {
    match volume_capability(handle)? {
        VolumeCapability::LocalNtfs => Ok(()),
        VolumeCapability::Remote => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "authority publication requires local NTFS, not a remote filesystem",
        )),
        VolumeCapability::Other => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "authority publication requires local NTFS",
        )),
    }
}

fn open_relative(
    parent: &std::fs::File,
    name: &OsStr,
    kind: RelativeOpenKind,
) -> io::Result<OpenedObject> {
    let mut name = direct_child_utf16(name)?;
    require_local_ntfs(parent)?;
    let spec = kind.spec();
    let name_bytes = u16::try_from(
        name.len()
            .checked_mul(size_of::<u16>())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "name is too long"))?,
    )
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name is too long"))?;
    let unicode = UNICODE_STRING {
        Length: name_bytes,
        MaximumLength: name_bytes,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>())
            .expect("fixed Windows structure fits u32"),
        RootDirectory: parent.as_raw_handle() as HANDLE,
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut status = IO_STATUS_BLOCK::default();
    let mut handle: HANDLE = ptr::null_mut();
    let ntstatus = unsafe {
        NtCreateFile(
            &mut handle,
            spec.desired_access,
            &attributes,
            &mut status,
            ptr::null(),
            spec.file_attributes,
            SHARE_ALL,
            spec.create_disposition,
            spec.create_options,
            ptr::null(),
            0,
        )
    };
    if ntstatus < 0 {
        let code = unsafe { RtlNtStatusToDosError(ntstatus) };
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::other(
            "NtCreateFile succeeded without a valid handle",
        ));
    }
    let handle = unsafe {
        // NtCreateFile returned a fresh owned kernel handle.
        OwnedHandle::from_raw_handle(handle as RawHandle)
    };
    let file = std::fs::File::from(handle);
    if status.Information != spec.expected_information {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NtCreateFile returned an unexpected create/open disposition",
        ));
    }
    validate_opened_type(&file, spec)?;
    Ok(OpenedObject { file, kind })
}

pub fn create_regular(parent: &std::fs::File, name: &OsStr) -> io::Result<OpenedObject> {
    open_relative(parent, name, RelativeOpenKind::NewRegular)
}

pub fn open_regular(parent: &std::fs::File, name: &OsStr) -> io::Result<OpenedObject> {
    open_relative(parent, name, RelativeOpenKind::ExistingRegular)
}

pub fn create_directory(parent: &std::fs::File, name: &OsStr) -> io::Result<OpenedObject> {
    open_relative(parent, name, RelativeOpenKind::NewDirectory)
}

pub fn open_directory(parent: &std::fs::File, name: &OsStr) -> io::Result<OpenedObject> {
    open_relative(parent, name, RelativeOpenKind::ExistingDirectory)
}

/// Compares two already-opened handles without resolving either pathname.
pub fn same_file_identity(left: &std::fs::File, right: &std::fs::File) -> io::Result<bool> {
    Ok(handle_identity(left.as_raw_handle() as HANDLE)?
        == handle_identity(right.as_raw_handle() as HANDLE)?)
}

pub fn same_object_identity(left: &OpenedObject, right: &OpenedObject) -> io::Result<bool> {
    same_file_identity(left.file(), right.file())
}

/// Marks the exact already-opened regular file for deletion.
///
/// The handle was acquired with `DELETE` and share-all at first open, so this
/// never resolves an ambient pathname or risks deleting a same-name winner.
pub fn delete_opened_regular(file: &OpenedObject) -> io::Result<()> {
    match file.kind() {
        RelativeOpenKind::NewRegular | RelativeOpenKind::ExistingRegular => {}
        RelativeOpenKind::NewDirectory | RelativeOpenKind::ExistingDirectory => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "only an opened regular file can be deleted",
            ));
        }
    }
    require_local_ntfs(file.file())?;
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    let result = unsafe {
        SetFileInformationByHandle(
            file.file().as_raw_handle() as HANDLE,
            FileDispositionInfo,
            (&raw const disposition).cast(),
            u32::try_from(size_of::<FILE_DISPOSITION_INFO>())
                .expect("FILE_DISPOSITION_INFO fits in u32"),
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Classifies the filesystem behind an already-validated handle.
///
/// The remote bit and filesystem name are queried from the opened object
/// itself; no drive letter, UNC path, current directory, or environment value
/// participates in the decision.
pub fn volume_capability(handle: &std::fs::File) -> io::Result<VolumeCapability> {
    let mut status_block = IO_STATUS_BLOCK::default();
    let mut device = FILE_FS_DEVICE_INFORMATION::default();
    let status = unsafe {
        NtQueryVolumeInformationFile(
            handle.as_raw_handle() as HANDLE,
            &mut status_block,
            (&mut device as *mut FILE_FS_DEVICE_INFORMATION).cast(),
            u32::try_from(size_of::<FILE_FS_DEVICE_INFORMATION>())
                .expect("fixed Windows structure fits u32"),
            FileFsDeviceInformation,
        )
    };
    if status < 0 {
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    if device.Characteristics & FILE_REMOTE_DEVICE != 0 {
        return Ok(VolumeCapability::Remote);
    }

    let mut filesystem_name = [0_u16; 32];
    let result = unsafe {
        GetVolumeInformationByHandleW(
            handle.as_raw_handle() as HANDLE,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            filesystem_name.as_mut_ptr(),
            u32::try_from(filesystem_name.len()).expect("fixed buffer fits u32"),
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    let length = filesystem_name
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| io::Error::other("filesystem name was not NUL-terminated"))?;
    if filesystem_name[..length] == [b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16] {
        Ok(VolumeCapability::LocalNtfs)
    } else {
        Ok(VolumeCapability::Other)
    }
}

fn rename_info_buffer_bytes(name_bytes: usize) -> io::Result<usize> {
    size_of::<FILE_RENAME_INFORMATION>()
        .checked_add(name_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "destination is too long"))
}

fn ntstatus_error(status: i32) -> io::Error {
    let code = unsafe { RtlNtStatusToDosError(status) };
    io::Error::from_raw_os_error(code as i32)
}

/// Renames a source whose access/share/write-through contract was acquired by
/// this crate at its first create/open. The destination is resolved only as a
/// direct child of the caller's already-validated parent handle.
pub fn rename_to(
    source: &OpenedObject,
    destination_parent: &std::fs::File,
    destination_name: &OsStr,
    replace: bool,
) -> Result<RenameOutcome, RenameError> {
    let destination = direct_child_utf16(destination_name)
        .map_err(|error| rename_error(RenameStage::ValidateDestination, error))?;
    require_local_ntfs(source.file())
        .map_err(|error| rename_error(RenameStage::VerifySource, error))?;
    require_local_ntfs(destination_parent)
        .map_err(|error| rename_error(RenameStage::VerifyDestinationParent, error))?;
    let source_identity = handle_identity(source.file().as_raw_handle() as HANDLE)
        .map_err(|error| rename_error(RenameStage::VerifySource, error))?;
    let parent_identity = handle_identity(destination_parent.as_raw_handle() as HANDLE)
        .map_err(|error| rename_error(RenameStage::VerifyDestinationParent, error))?;
    if source_identity.0 != parent_identity.0 {
        return Err(rename_error(
            RenameStage::VerifyDestinationParent,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "source and destination parent are on different volumes",
            ),
        ));
    }

    let name_bytes = destination
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or_else(|| {
            rename_error(
                RenameStage::ValidateDestination,
                io::Error::new(io::ErrorKind::InvalidInput, "destination is too long"),
            )
        })?;
    // FileRenameInformation consumes the native FILE_RENAME_INFORMATION
    // layout. Microsoft requires the complete fixed structure plus every
    // FileNameLength byte even though FileName begins inside that structure.
    let buffer_bytes = rename_info_buffer_bytes(name_bytes)
        .map_err(|error| rename_error(RenameStage::ValidateDestination, error))?;
    let buffer_size = u32::try_from(buffer_bytes).map_err(|_| {
        rename_error(
            RenameStage::ValidateDestination,
            io::Error::new(io::ErrorKind::InvalidInput, "destination is too long"),
        )
    })?;
    let word_count = buffer_bytes.div_ceil(size_of::<usize>());
    let mut storage = vec![0usize; word_count];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();

    unsafe {
        // `storage` is usize-aligned and sized for the fixed header plus every
        // UTF-16 code unit. NtSetInformationFile consumes the bytes
        // synchronously because the source was opened for synchronous I/O.
        (*info).Anonymous.ReplaceIfExists = replace;
        (*info).RootDirectory = destination_parent.as_raw_handle() as HANDLE;
        (*info).FileNameLength = u32::try_from(name_bytes).expect("bounded above");
        ptr::copy_nonoverlapping(
            destination.as_ptr(),
            (*info).FileName.as_mut_ptr(),
            destination.len(),
        );
    }

    let mut io_status = IO_STATUS_BLOCK::default();
    let ntstatus = unsafe {
        NtSetInformationFile(
            source.file().as_raw_handle() as HANDLE,
            &mut io_status,
            info.cast(),
            buffer_size,
            FileRenameInformation,
        )
    };
    let completion_status = unsafe { io_status.Anonymous.Status };
    if ntstatus == 0 && completion_status == 0 {
        return Ok(RenameOutcome::Renamed);
    }
    let failure = if ntstatus != 0 {
        ntstatus
    } else {
        completion_status
    };
    match failure {
        STATUS_OBJECT_NAME_COLLISION if !replace => Ok(RenameOutcome::Existing),
        _ => Err(rename_error(RenameStage::Rename, ntstatus_error(failure))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::OsString,
        io::{Read as _, Seek as _, SeekFrom, Write as _},
        os::windows::ffi::OsStringExt as _,
        os::windows::fs::OpenOptionsExt as _,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

    fn test_root(name: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "uchgs-windows-fs-{name}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        root
    }

    fn open_root(root: &std::path::Path) -> std::fs::File {
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(SHARE_ALL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(root)
            .unwrap()
    }

    #[test]
    fn sealed_open_matrix_is_exact() {
        let new_regular = RelativeOpenKind::NewRegular.spec();
        assert_eq!(
            new_regular.desired_access,
            FILE_READ_DATA
                | FILE_WRITE_DATA
                | FILE_READ_ATTRIBUTES
                | FILE_WRITE_ATTRIBUTES
                | DELETE
                | SYNCHRONIZE
        );
        assert_eq!(new_regular.create_disposition, FILE_CREATE);
        assert_eq!(new_regular.expected_information, FILE_CREATED_INFORMATION);
        assert!(new_regular.create_options & FILE_NON_DIRECTORY_FILE != 0);
        assert!(new_regular.create_options & FILE_OPEN_REPARSE_POINT != 0);
        assert!(new_regular.desired_access & DELETE != 0);

        let existing_regular = RelativeOpenKind::ExistingRegular.spec();
        assert_eq!(
            existing_regular.desired_access,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE
        );
        assert_eq!(existing_regular.create_disposition, FILE_OPEN);
        assert_eq!(
            existing_regular.expected_information,
            FILE_OPENED_INFORMATION
        );
        assert_eq!(existing_regular.desired_access & FILE_WRITE_DATA, 0);

        let new_directory = RelativeOpenKind::NewDirectory.spec();
        assert_eq!(
            new_directory.desired_access,
            FILE_LIST_DIRECTORY
                | FILE_ADD_FILE
                | FILE_ADD_SUBDIRECTORY
                | FILE_READ_ATTRIBUTES
                | FILE_WRITE_ATTRIBUTES
                | DELETE
                | SYNCHRONIZE
        );
        assert!(new_directory.create_options & FILE_DIRECTORY_FILE != 0);
        assert_eq!(new_directory.create_options & FILE_OPEN_REPARSE_POINT, 0);

        let existing_directory = RelativeOpenKind::ExistingDirectory.spec();
        assert_eq!(
            existing_directory.desired_access,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE
        );
        assert_eq!(existing_directory.create_options & FILE_DIRECTORY_FILE, 0);
        assert!(existing_directory.create_options & FILE_OPEN_REPARSE_POINT != 0);
        for spec in [
            new_regular,
            existing_regular,
            new_directory,
            existing_directory,
        ] {
            assert!(spec.create_options & FILE_WRITE_THROUGH != 0);
            assert!(spec.create_options & FILE_SYNCHRONOUS_IO_NONALERT != 0);
        }
        assert_eq!(
            SHARE_ALL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        );
    }

    #[test]
    fn native_rename_information_layout_and_buffer_length_are_exact() {
        assert_eq!(FileRenameInformation, 10);
        assert_eq!(
            rename_info_buffer_bytes(0).unwrap(),
            size_of::<FILE_RENAME_INFORMATION>()
        );
        assert_eq!(
            rename_info_buffer_bytes(6).unwrap(),
            size_of::<FILE_RENAME_INFORMATION>() + 6
        );
        assert!(
            rename_info_buffer_bytes(6).unwrap()
                > std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName) + 6
        );
    }

    #[test]
    fn direct_child_utf16_bounds_are_exact_and_lossless() {
        let at_limit = OsString::from_wide(&vec![u16::from(b'a'); 255]);
        assert_eq!(
            direct_child_utf16(&at_limit).unwrap(),
            vec![u16::from(b'a'); 255]
        );
        let above_limit = OsString::from_wide(&vec![u16::from(b'a'); 256]);
        assert_eq!(
            direct_child_utf16(&above_limit).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let unpaired_surrogate = OsString::from_wide(&[0xd800]);
        assert_eq!(direct_child_utf16(&unpaired_surrogate).unwrap(), [0xd800]);
        let embedded_nul = OsString::from_wide(&[u16::from(b'a'), 0, u16::from(b'b')]);
        assert_eq!(
            direct_child_utf16(&embedded_nul).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn direct_child_validation_precedes_handle_use() {
        let executable = std::env::current_exe().unwrap();
        let placeholder = std::fs::File::open(executable).unwrap();
        for name in [
            OsStr::new(""),
            OsStr::new("."),
            OsStr::new(".."),
            OsStr::new("child/nested"),
            OsStr::new(r"child\nested"),
            OsStr::new(r"C:child"),
            OsStr::new("child:stream"),
        ] {
            assert_eq!(
                create_regular(&placeholder, name).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            let source = OpenedObject {
                file: placeholder.try_clone().unwrap(),
                kind: RelativeOpenKind::NewRegular,
            };
            let error = rename_to(&source, &placeholder, name, false).unwrap_err();
            assert_eq!(error.stage(), RenameStage::ValidateDestination);
        }
    }

    #[test]
    fn first_open_regular_rename_is_handle_relative_and_no_replace() {
        let root_path = test_root("regular-rename");
        let parent = open_root(&root_path);
        let mut source = create_regular(&parent, OsStr::new("source")).unwrap();
        source.file_mut().write_all(b"exact").unwrap();
        source.file().sync_all().unwrap();
        source.file_mut().seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        source.file_mut().read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"exact");

        assert_eq!(
            rename_to(&source, &parent, OsStr::new("destination"), false).unwrap(),
            RenameOutcome::Renamed
        );
        let destination = open_regular(&parent, OsStr::new("destination")).unwrap();
        assert!(same_object_identity(&source, &destination).unwrap());

        let mut loser = create_regular(&parent, OsStr::new("loser")).unwrap();
        loser.file_mut().write_all(b"other").unwrap();
        loser.file().sync_all().unwrap();
        assert_eq!(
            rename_to(&loser, &parent, OsStr::new("destination"), false).unwrap(),
            RenameOutcome::Existing
        );
        drop(destination);
        drop(loser);
        drop(source);
        drop(parent);
        assert_eq!(
            std::fs::read(root_path.join("destination")).unwrap(),
            b"exact"
        );
        std::fs::remove_dir_all(root_path).unwrap();
    }

    #[test]
    fn opened_regular_delete_targets_the_exact_renamed_object() {
        let root_path = test_root("regular-delete");
        let parent = open_root(&root_path);
        let mut source = create_regular(&parent, OsStr::new("source")).unwrap();
        source.file_mut().write_all(b"exact").unwrap();
        source.file().sync_all().unwrap();
        assert_eq!(
            rename_to(&source, &parent, OsStr::new("destination"), false).unwrap(),
            RenameOutcome::Renamed
        );
        delete_opened_regular(&source).unwrap();
        drop(source);
        drop(parent);
        assert!(!root_path.join("destination").exists());
        std::fs::remove_dir_all(root_path).unwrap();
    }

    #[test]
    fn complete_directory_is_built_and_renamed_through_retained_handles() {
        let root_path = test_root("directory-rename");
        let parent = open_root(&root_path);
        let staging = create_directory(&parent, OsStr::new("staging")).unwrap();
        let mut record = create_regular(staging.file(), OsStr::new("record")).unwrap();
        record.file_mut().write_all(b"complete").unwrap();
        record.file().sync_all().unwrap();
        drop(record);

        assert_eq!(
            rename_to(&staging, &parent, OsStr::new("final"), false).unwrap(),
            RenameOutcome::Renamed
        );
        let final_directory = open_directory(&parent, OsStr::new("final")).unwrap();
        assert!(same_object_identity(&staging, &final_directory).unwrap());
        drop(final_directory);
        drop(staging);
        drop(parent);
        assert_eq!(
            std::fs::read(root_path.join("final/record")).unwrap(),
            b"complete"
        );
        std::fs::remove_dir_all(root_path).unwrap();
    }

    #[test]
    fn post_open_name_swap_is_detected_by_identity() {
        let root_path = test_root("identity-swap");
        let parent = open_root(&root_path);
        let original = create_regular(&parent, OsStr::new("source")).unwrap();
        std::fs::rename(root_path.join("source"), root_path.join("displaced")).unwrap();
        std::fs::write(root_path.join("source"), b"replacement").unwrap();
        let replacement = open_regular(&parent, OsStr::new("source")).unwrap();
        assert!(!same_object_identity(&original, &replacement).unwrap());
        drop(replacement);
        drop(original);
        drop(parent);
        std::fs::remove_dir_all(root_path).unwrap();
    }

    #[test]
    fn existing_directory_open_rejects_regular_and_reparse_types() {
        let root_path = test_root("type-check");
        let parent = open_root(&root_path);
        std::fs::write(root_path.join("regular"), b"file").unwrap();
        assert_eq!(
            open_directory(&parent, OsStr::new("regular"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        drop(parent);
        std::fs::remove_dir_all(root_path).unwrap();
    }
}
