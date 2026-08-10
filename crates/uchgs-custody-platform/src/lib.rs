//! Small safe facade over terminal echo and private-file ACL primitives.

use std::{fs, io::Write as _};

use zeroize::{Zeroize, Zeroizing};

const SECRET_INPUT_CHUNK_UNITS: usize = 128;

struct SecretInput<T>
where
    T: Copy + Default + Zeroize,
{
    chunks: Vec<Zeroizing<Box<[T]>>>,
    len: usize,
}

impl<T> SecretInput<T>
where
    T: Copy + Default + Zeroize,
{
    fn new() -> Self {
        Self {
            chunks: Vec::new(),
            len: 0,
        }
    }

    fn push(&mut self, value: T) {
        let chunk_index = self.len / SECRET_INPUT_CHUNK_UNITS;
        let unit_index = self.len % SECRET_INPUT_CHUNK_UNITS;
        if chunk_index == self.chunks.len() {
            self.chunks.push(Zeroizing::new(
                vec![T::default(); SECRET_INPUT_CHUNK_UNITS].into_boxed_slice(),
            ));
        }
        self.chunks[chunk_index][unit_index] = value;
        self.len += 1;
    }

    fn last(&self) -> Option<T> {
        self.len.checked_sub(1).map(|index| {
            self.chunks[index / SECRET_INPUT_CHUNK_UNITS][index % SECRET_INPUT_CHUNK_UNITS]
        })
    }

    fn pop(&mut self) -> Option<T> {
        let index = self.len.checked_sub(1)?;
        let value = self.chunks[index / SECRET_INPUT_CHUNK_UNITS][index % SECRET_INPUT_CHUNK_UNITS];
        self.chunks[index / SECRET_INPUT_CHUNK_UNITS][index % SECRET_INPUT_CHUNK_UNITS].zeroize();
        self.len = index;
        Some(value)
    }

    fn into_vec(self) -> Zeroizing<Vec<T>> {
        let mut output = Zeroizing::new(Vec::with_capacity(self.len));
        for (index, chunk) in self.chunks.iter().enumerate() {
            let remaining = self.len.saturating_sub(index * SECRET_INPUT_CHUNK_UNITS);
            let used = remaining.min(SECRET_INPUT_CHUNK_UNITS);
            output.extend_from_slice(&chunk[..used]);
        }
        output
    }
}

#[cfg(any(windows, test))]
fn utf16_hidden_string(units: &[u16]) -> Result<Zeroizing<String>, Error> {
    let mut bytes = SecretInput::new();
    for decoded in char::decode_utf16(units.iter().copied()) {
        let character = decoded.map_err(|_| {
            Error::invariant("read terminal passphrase", "input must be valid UTF-16")
        })?;
        let mut encoded = Zeroizing::new([0_u8; 4]);
        for byte in character.encode_utf8(&mut *encoded).as_bytes() {
            bytes.push(*byte);
        }
    }
    let mut bytes = bytes.into_vec();
    let value = String::from_utf8(std::mem::take(&mut *bytes)).map_err(|error| {
        let _bytes = Zeroizing::new(error.into_bytes());
        Error::invariant(
            "read terminal passphrase",
            "UTF-16 input changed after UTF-8 encoding",
        )
    })?;
    Ok(Zeroizing::new(value))
}

#[derive(Debug)]
pub struct Error {
    operation: &'static str,
    message: String,
}

impl Error {
    fn io(operation: &'static str, error: std::io::Error) -> Self {
        Self {
            operation,
            message: error.to_string(),
        }
    }

    fn invariant(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            operation,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.operation, self.message)
    }
}

impl std::error::Error for Error {}

#[cfg(any(unix, test))]
fn read_hidden_line(reader: &mut impl std::io::Read) -> Result<Zeroizing<String>, Error> {
    let mut value = SecretInput::new();
    loop {
        let mut byte = Zeroizing::new([0_u8; 1]);
        match reader.read(&mut *byte) {
            Ok(0) => {
                return Err(Error::invariant(
                    "read terminal passphrase",
                    "controlling terminal closed before line ending",
                ));
            }
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                value.push(byte[0]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Error::io("read terminal passphrase", error)),
        }
    }
    if value.last() == Some(b'\r') {
        value.pop();
    }
    let mut bytes = value.into_vec();
    if std::str::from_utf8(&bytes).is_err() {
        return Err(Error::invariant(
            "read terminal passphrase",
            "input must be valid UTF-8",
        ));
    }
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(value) => Ok(Zeroizing::new(value)),
        Err(error) => {
            let _bytes = Zeroizing::new(error.into_bytes());
            Err(Error::invariant(
                "read terminal passphrase",
                "input changed after UTF-8 validation",
            ))
        }
    }
}

/// Reads one line from the controlling terminal with echo disabled.
pub fn prompt_hidden(prompt: &str) -> Result<Zeroizing<String>, Error> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        let terminal = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|error| Error::io("open controlling terminal", error))?;
        let fd = terminal.as_raw_fd();
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
            return Err(Error::io(
                "read terminal mode",
                std::io::Error::last_os_error(),
            ));
        }
        let original = unsafe { original.assume_init() };
        let mut hidden = original;
        hidden.c_lflag &= !libc::ECHO;
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
            return Err(Error::io(
                "disable terminal echo",
                std::io::Error::last_os_error(),
            ));
        }
        let guard = UnixEchoGuard { fd, original };
        let mut output = &terminal;
        output
            .write_all(prompt.as_bytes())
            .and_then(|_| output.flush())
            .map_err(|error| Error::io("write terminal prompt", error))?;
        let mut input = &terminal;
        let value = read_hidden_line(&mut input)?;
        drop(guard);
        output
            .write_all(b"\n")
            .map_err(|error| Error::io("finish terminal prompt", error))?;
        Ok(value)
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::System::Console::{
            ENABLE_ECHO_INPUT, GetConsoleMode, ReadConsoleW, SetConsoleMode,
        };
        let input = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("CONIN$")
            .map_err(|error| Error::io("open controlling terminal input", error))?;
        let mut output = fs::OpenOptions::new()
            .write(true)
            .open("CONOUT$")
            .map_err(|error| Error::io("open controlling terminal output", error))?;
        let handle = input.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
        let mut original = 0_u32;
        if unsafe { GetConsoleMode(handle, &mut original) } == 0 {
            return Err(Error::io(
                "read terminal mode",
                std::io::Error::last_os_error(),
            ));
        }
        if unsafe { SetConsoleMode(handle, original & !ENABLE_ECHO_INPUT) } == 0 {
            return Err(Error::io(
                "disable terminal echo",
                std::io::Error::last_os_error(),
            ));
        }
        let guard = WindowsEchoGuard { handle, original };
        output
            .write_all(prompt.as_bytes())
            .and_then(|_| output.flush())
            .map_err(|error| Error::io("write terminal prompt", error))?;
        let mut units = SecretInput::new();
        loop {
            let mut unit = Zeroizing::new([0_u16; 1]);
            let mut read = 0_u32;
            if unsafe {
                ReadConsoleW(
                    handle,
                    unit.as_mut_ptr().cast(),
                    1,
                    &mut read,
                    std::ptr::null(),
                )
            } == 0
            {
                return Err(Error::io(
                    "read terminal passphrase",
                    std::io::Error::last_os_error(),
                ));
            }
            if read == 0 {
                return Err(Error::invariant(
                    "read terminal passphrase",
                    "controlling terminal closed before line ending",
                ));
            }
            if read != 1 {
                return Err(Error::invariant(
                    "read terminal passphrase",
                    "console returned an unexpected UTF-16 unit count",
                ));
            }
            if unit[0] == b'\n'.into() {
                break;
            }
            units.push(unit[0]);
        }
        if units.last() == Some(u16::from(b'\r')) {
            units.pop();
        }
        let units = units.into_vec();
        let value = utf16_hidden_string(&units)?;
        drop(guard);
        output
            .write_all(b"\r\n")
            .map_err(|error| Error::io("finish terminal prompt", error))?;
        Ok(value)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = prompt;
        Err(Error::invariant(
            "prompt for passphrase",
            "unsupported platform",
        ))
    }
}

/// Applies the frozen platform-private protection through the already-opened file.
///
/// Taking the handle instead of a path is the authority boundary: a pathname can be
/// renamed or replaced between creation and protection, so protecting by name may
/// harden a replacement while leaving the real key readable. The handle designates
/// the exact file object, so the protection cannot be redirected to another file.
/// On Windows the handle must grant `WRITE_DAC`; callers obtain that right when the
/// private file is first created rather than reopening it by name.
pub fn protect_private_file(file: &fs::File) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| Error::io("protect private key", error))
    }
    #[cfg(windows)]
    {
        windows_private_file::protect(file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Err(Error::invariant(
            "protect private key",
            "unsupported platform",
        ))
    }
}

/// Owns the exact protected DACL used when Windows creates a private file.
///
/// Keeping construction beside `protect_private_file` prevents create-time and
/// post-create protection from drifting into two different policies.
#[cfg(windows)]
pub struct PrivateFileSecurityDescriptor(windows_private_file::OwnedSecurityDescriptor);

#[cfg(windows)]
impl PrivateFileSecurityDescriptor {
    pub fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.0.as_ptr()
    }
}

/// Builds the same protected current-user DACL that `protect_private_file`
/// applies to an already-opened Windows file.
#[cfg(windows)]
pub fn private_file_security_descriptor() -> Result<PrivateFileSecurityDescriptor, Error> {
    windows_private_file::security_descriptor().map(PrivateFileSecurityDescriptor)
}

/// Verifies protection on the same already-opened private file.
///
/// Verification has to observe the object the caller already holds; re-resolving the
/// pathname could confirm a different file than the one that will actually be read.
/// On Windows the handle must grant `READ_CONTROL` so its DACL can be inspected.
pub fn verify_private_file(file: &fs::File) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = file
            .metadata()
            .map_err(|error| Error::io("inspect private key", error))?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o600 {
            Err(Error::invariant(
                "verify private key",
                "mode must be exactly 0600",
            ))
        } else {
            Ok(())
        }
    }
    #[cfg(windows)]
    {
        windows_private_file::verify(file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Err(Error::invariant(
            "verify private key",
            "unsupported platform",
        ))
    }
}

#[cfg(unix)]
struct UnixEchoGuard {
    fd: std::os::fd::RawFd,
    original: libc::termios,
}

#[cfg(unix)]
impl Drop for UnixEchoGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
        }
    }
}

#[cfg(windows)]
struct WindowsEchoGuard {
    handle: windows_sys::Win32::Foundation::HANDLE,
    original: u32,
}

#[cfg(windows)]
impl Drop for WindowsEchoGuard {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::System::Console::SetConsoleMode(self.handle, self.original);
        }
    }
}

#[cfg(windows)]
mod windows_private_file {
    use super::*;
    use std::{ffi::c_void, os::windows::io::AsRawHandle as _, ptr};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, LocalFree},
        Security::{
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            },
            DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
            GetKernelObjectSecurity, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
            GetTokenInformation, INHERITED_ACE, PROTECTED_DACL_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SetKernelObjectSecurity, TOKEN_QUERY,
            TOKEN_USER, TokenUser,
        },
        Storage::FileSystem::FILE_ALL_ACCESS,
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    pub(super) struct OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl OwnedSecurityDescriptor {
        pub(super) fn as_ptr(&self) -> *mut c_void {
            self.0.cast()
        }
    }

    impl Drop for OwnedSecurityDescriptor {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0.cast());
            }
        }
    }

    fn current_user_token() -> Result<(OwnedHandle, Vec<usize>), Error> {
        let mut handle = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } == 0 {
            return Err(Error::io(
                "open current process token",
                std::io::Error::last_os_error(),
            ));
        }
        let handle = OwnedHandle(handle);
        let mut needed = 0;
        unsafe {
            GetTokenInformation(handle.0, TokenUser, ptr::null_mut(), 0, &mut needed);
        }
        if needed < std::mem::size_of::<TOKEN_USER>() as u32 {
            return Err(Error::invariant(
                "read Windows token",
                "buffer is truncated",
            ));
        }
        let mut words = vec![0_usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                handle.0,
                TokenUser,
                words.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(Error::io(
                "read current process token",
                std::io::Error::last_os_error(),
            ));
        }
        Ok((handle, words))
    }

    struct TokenSid<'token> {
        raw: PSID,
        _token: std::marker::PhantomData<&'token [usize]>,
    }

    impl TokenSid<'_> {
        fn as_raw(&self) -> PSID {
            self.raw
        }
    }

    fn token_sid(words: &[usize]) -> Result<TokenSid<'_>, Error> {
        let user = unsafe { &*words.as_ptr().cast::<TOKEN_USER>() };
        if user.User.Sid.is_null() {
            Err(Error::invariant("read Windows token", "user SID is null"))
        } else {
            Ok(TokenSid {
                raw: user.User.Sid,
                _token: std::marker::PhantomData,
            })
        }
    }

    pub(super) fn security_descriptor() -> Result<OwnedSecurityDescriptor, Error> {
        let (_handle, token) = current_user_token()?;
        let sid = token_sid(&token)?;
        let mut sid_text = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid.as_raw(), &mut sid_text) } == 0 {
            return Err(Error::io(
                "format current user SID",
                std::io::Error::last_os_error(),
            ));
        }
        let sid_string = unsafe {
            let mut length = 0_usize;
            while *sid_text.add(length) != 0 {
                length += 1;
                if length > 256 {
                    LocalFree(sid_text.cast());
                    return Err(Error::invariant("format Windows SID", "text is oversized"));
                }
            }
            let value = String::from_utf16_lossy(std::slice::from_raw_parts(sid_text, length));
            LocalFree(sid_text.cast());
            value
        };
        let sddl = format!("D:P(A;;FA;;;{sid_string})")
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SECURITY_DESCRIPTOR_REVISION,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(Error::io(
                "build private key DACL",
                std::io::Error::last_os_error(),
            ));
        }
        Ok(OwnedSecurityDescriptor(descriptor))
    }

    pub(super) fn protect(file: &fs::File) -> Result<(), Error> {
        let descriptor = security_descriptor()?;
        let result = unsafe {
            SetKernelObjectSecurity(
                file.as_raw_handle() as HANDLE,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor.0,
            )
        };
        if result == 0 {
            return Err(Error::io(
                "protect private key DACL",
                std::io::Error::last_os_error(),
            ));
        }
        verify(file)
    }

    pub(super) fn verify(file: &fs::File) -> Result<(), Error> {
        let (_handle, token) = current_user_token()?;
        let expected_sid = token_sid(&token)?;
        let mut needed = 0;
        unsafe {
            GetKernelObjectSecurity(
                file.as_raw_handle() as HANDLE,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                0,
                &mut needed,
            );
        }
        if needed == 0 || needed > 64 * 1024 {
            return Err(Error::invariant("read private key DACL", "size is invalid"));
        }
        let word_bytes = std::mem::size_of::<usize>();
        let mut descriptor = vec![0_usize; (needed as usize).div_ceil(word_bytes)];
        if unsafe {
            GetKernelObjectSecurity(
                file.as_raw_handle() as HANDLE,
                DACL_SECURITY_INFORMATION,
                descriptor.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(Error::io(
                "read private key DACL",
                std::io::Error::last_os_error(),
            ));
        }
        let security_descriptor = descriptor.as_mut_ptr().cast::<c_void>();
        let mut control = 0_u16;
        let mut revision = 0_u32;
        if unsafe { GetSecurityDescriptorControl(security_descriptor, &mut control, &mut revision) }
            == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return Err(Error::invariant(
                "verify private key DACL",
                "DACL must be protected",
            ));
        }
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl: *mut ACL = ptr::null_mut();
        if unsafe {
            GetSecurityDescriptorDacl(security_descriptor, &mut present, &mut acl, &mut defaulted)
        } == 0
            || present == 0
            || acl.is_null()
        {
            return Err(Error::invariant(
                "verify private key DACL",
                "DACL must be explicit",
            ));
        }
        let mut info = ACL_SIZE_INFORMATION::default();
        if unsafe {
            GetAclInformation(
                acl,
                (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
            || info.AceCount != 1
        {
            return Err(Error::invariant(
                "verify private key DACL",
                "must contain exactly one ACE",
            ));
        }
        let mut ace: *mut c_void = ptr::null_mut();
        if unsafe { GetAce(acl, 0, &mut ace) } == 0 || ace.is_null() {
            return Err(Error::io(
                "read private key DACL ACE",
                std::io::Error::last_os_error(),
            ));
        }
        let header = unsafe { ptr::read_unaligned(ace.cast::<ACE_HEADER>()) };
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE
            || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(Error::invariant(
                "verify private key DACL",
                "must contain one full access-allowed ACE",
            ));
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = ptr::addr_of!(allowed.SidStart).cast_mut().cast();
        if (header.AceFlags as u32) & INHERITED_ACE != 0
            || allowed.Mask != FILE_ALL_ACCESS
            || unsafe { EqualSid(sid, expected_sid.as_raw()) } == 0
        {
            return Err(Error::invariant(
                "verify private key DACL",
                "must grant only the current user full access",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod input_tests {
    use super::*;

    #[test]
    fn hidden_input_requires_a_terminal_line_ending_without_an_extra_length_policy() {
        let mut unix = std::io::Cursor::new(b"secret\n".as_slice());
        assert_eq!(read_hidden_line(&mut unix).unwrap().as_str(), "secret");

        let mut windows = std::io::Cursor::new(b"secret\r\n".as_slice());
        assert_eq!(read_hidden_line(&mut windows).unwrap().as_str(), "secret");

        let mut closed = std::io::Cursor::new(b"secret".as_slice());
        assert!(
            read_hidden_line(&mut closed)
                .unwrap_err()
                .to_string()
                .contains("controlling terminal closed")
        );

        let mut invalid_utf8 = std::io::Cursor::new([0xff, b'\n']);
        assert!(
            read_hidden_line(&mut invalid_utf8)
                .unwrap_err()
                .to_string()
                .contains("valid UTF-8")
        );

        assert_eq!(
            utf16_hidden_string(&[b's'.into(), 0xd83d, 0xdd10])
                .unwrap()
                .as_str(),
            "s🔐"
        );
        assert!(utf16_hidden_string(&[0xd800]).is_err());

        let long = vec![b'x'; 4097]
            .into_iter()
            .chain(*b"\n")
            .collect::<Vec<_>>();
        assert_eq!(
            read_hidden_line(&mut std::io::Cursor::new(long))
                .unwrap()
                .len(),
            4097
        );
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn private_file_mode_is_exact() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory =
            std::env::temp_dir().join(format!("uchgs-custody-platform-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("key");
        let moved = directory.join("opened-key");
        fs::write(&path, b"secret").unwrap();
        let file = fs::File::open(&path).unwrap();
        fs::rename(&path, &moved).unwrap();
        fs::write(&path, b"replacement").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        protect_private_file(&file).unwrap();
        assert_eq!(
            fs::metadata(&moved).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_ne!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        verify_private_file(&file).unwrap();
        drop(file);
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(moved);
        let _ = fs::remove_dir(directory);
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn private_file_dacl_is_exactly_the_protected_operator_ace() {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::{
            Foundation::{GENERIC_READ, GENERIC_WRITE},
            Storage::FileSystem::{READ_CONTROL, WRITE_DAC},
        };

        let directory =
            std::env::temp_dir().join(format!("uchgs-custody-platform-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("key");
        let moved = directory.join("opened-key");
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .access_mode(GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
            .open(&path)
            .unwrap();
        fs::rename(&path, &moved).unwrap();
        fs::write(&path, b"replacement").unwrap();
        protect_private_file(&file).unwrap();
        verify_private_file(&file).unwrap();
        let replacement = fs::OpenOptions::new()
            .read(true)
            .access_mode(GENERIC_READ | READ_CONTROL)
            .open(&path)
            .unwrap();
        assert!(verify_private_file(&replacement).is_err());
        drop(replacement);
        drop(file);
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(moved);
        let _ = fs::remove_dir(directory);
    }
}
