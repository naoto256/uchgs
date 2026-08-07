#![forbid(unsafe_op_in_unsafe_fn)]
#![cfg(unix)]

use std::{
    ffi::OsString, io, mem::MaybeUninit, os::unix::ffi::OsStringExt as _, path::PathBuf, ptr,
};

const FALLBACK_BUFFER_BYTES: usize = 16 * 1024;
const MAX_BUFFER_BYTES: usize = 1024 * 1024;

/// Resolves the effective account's home from the operating-system account
/// database. Environment variables and the current directory are not inputs.
pub fn effective_account_home() -> io::Result<PathBuf> {
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buffer_bytes = if suggested > 0 {
        usize::try_from(suggested).map_err(|_| invalid_account_home())?
    } else {
        FALLBACK_BUFFER_BYTES
    };
    if buffer_bytes > MAX_BUFFER_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "account database buffer requirement exceeds the fixed bound",
        ));
    }
    buffer_bytes = buffer_bytes.max(1);
    let uid = unsafe { libc::geteuid() };

    loop {
        let mut record = MaybeUninit::<libc::passwd>::uninit();
        let mut result = ptr::null_mut();
        let mut buffer = vec![0_u8; buffer_bytes];
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                record.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE {
            buffer_bytes = buffer_bytes
                .checked_mul(2)
                .filter(|size| *size <= MAX_BUFFER_BYTES)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "account database entry exceeds the fixed bound",
                    )
                })?;
            continue;
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        if result.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "effective account is absent from the operating-system database",
            ));
        }
        if result != record.as_mut_ptr() {
            return Err(invalid_account_home());
        }
        let record = unsafe { record.assume_init() };
        let directory = bounded_c_string(&buffer, record.pw_dir.cast())?;
        if directory.is_empty() {
            return Err(invalid_account_home());
        }
        let path = PathBuf::from(OsString::from_vec(directory.to_vec()));
        if !path.is_absolute() {
            return Err(invalid_account_home());
        }
        return Ok(path);
    }
}

fn bounded_c_string(buffer: &[u8], pointer: *const u8) -> io::Result<&[u8]> {
    if pointer.is_null() {
        return Err(invalid_account_home());
    }
    let start = buffer.as_ptr() as usize;
    let end = start
        .checked_add(buffer.len())
        .ok_or_else(invalid_account_home)?;
    let address = pointer as usize;
    if !(start..end).contains(&address) {
        return Err(invalid_account_home());
    }
    let offset = address - start;
    let bytes = &buffer[offset..];
    let nul = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(invalid_account_home)?;
    Ok(&bytes[..nul])
}

fn invalid_account_home() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "operating-system account home is invalid",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_home_is_absolute_and_nonempty() {
        let home = effective_account_home().unwrap();
        assert!(home.is_absolute());
        assert!(!home.as_os_str().is_empty());
    }

    #[test]
    fn bounded_account_directory_rejects_outside_and_unterminated_pointers() {
        let buffer = b"/home/test\0";
        assert_eq!(
            bounded_c_string(buffer, buffer.as_ptr()).unwrap(),
            b"/home/test"
        );
        assert!(bounded_c_string(buffer, ptr::null()).is_err());
        assert!(bounded_c_string(&buffer[..buffer.len() - 1], buffer.as_ptr()).is_err());
    }
}
