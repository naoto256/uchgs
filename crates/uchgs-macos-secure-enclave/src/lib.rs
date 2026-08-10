//! Narrow safe boundary for 0.1.0 Secure Enclave custody.
//!
//! The root crate forbids unsafe code. CoreFoundation and Security.framework
//! FFI is isolated here and exposed only as key-id-bound create/sign/delete
//! operations.

#![cfg(target_os = "macos")]

use std::{ffi::c_void, ptr};

use p256::ecdsa::{
    Signature, VerifyingKey,
    signature::{Verifier as _, hazmat::PrehashVerifier as _},
};
use security_framework_sys::{
    access_control::{
        SecAccessControlCreateWithFlags, kSecAccessControlBiometryCurrentSet,
        kSecAccessControlPrivateKeyUsage, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    },
    base::{SecKeyRef, errSecItemNotFound, errSecSuccess},
    item::{
        kSecAttrAccessControl, kSecAttrIsPermanent, kSecAttrKeyClass, kSecAttrKeyClassPrivate,
        kSecAttrKeySizeInBits, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID,
        kSecAttrTokenIDSecureEnclave, kSecClass, kSecClassKey, kSecMatchLimit, kSecMatchLimitAll,
        kSecPrivateKeyAttrs, kSecReturnRef, kSecUseDataProtectionKeychain, kSecValueRef,
    },
    key::{
        Algorithm, SecKeyCopyExternalRepresentation, SecKeyCopyPublicKey, SecKeyCreateRandomKey,
        SecKeyCreateSignature, SecKeyGetTypeID,
    },
    keychain_item::{SecItemCopyMatching, SecItemDelete},
};
use sha2::{Digest as _, Sha256};

const APPLICATION_TAG_DOMAIN: &[u8] = b"uchgs.secure-enclave.application-tag";
const APPLICATION_TAG_VERSION: u32 = 1;
const POSSESSION_DOMAIN: &[u8] = b"uchgs.secure-enclave.possession";
const POSSESSION_VERSION: u32 = 1;
const P256_UNCOMPRESSED_PUBLIC_LEN: usize = 65;
const MAX_PROVIDER_DER_SIGNATURE_LEN: usize = 1024;
const MAX_KEY_ID_BYTES: usize = 128;

type CfTypeRef = *const c_void;
type CfMutableDictionaryRef = *mut c_void;
type CfDataRef = *const c_void;
type CfErrorRef = *mut c_void;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFTypeDictionaryKeyCallBacks: u8;
    static kCFTypeDictionaryValueCallBacks: u8;
    static kCFBooleanTrue: CfTypeRef;

    fn CFArrayGetCount(array: CfTypeRef) -> isize;
    fn CFArrayGetTypeID() -> usize;
    fn CFArrayGetValueAtIndex(array: CfTypeRef, index: isize) -> CfTypeRef;
    fn CFDataCreate(allocator: CfTypeRef, bytes: *const u8, length: isize) -> CfDataRef;
    fn CFDataGetBytePtr(data: CfDataRef) -> *const u8;
    fn CFDataGetLength(data: CfDataRef) -> isize;
    fn CFDataGetTypeID() -> usize;
    fn CFDictionaryCreateMutable(
        allocator: CfTypeRef,
        capacity: isize,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> CfMutableDictionaryRef;
    fn CFDictionarySetValue(dictionary: CfMutableDictionaryRef, key: CfTypeRef, value: CfTypeRef);
    fn CFErrorGetCode(error: CfErrorRef) -> isize;
    fn CFGetTypeID(value: CfTypeRef) -> usize;
    fn CFNumberCreate(allocator: CfTypeRef, number_type: isize, value: *const c_void) -> CfTypeRef;
    fn CFRelease(value: CfTypeRef);
    fn CFRetain(value: CfTypeRef) -> CfTypeRef;
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecAttrApplicationTag: CfTypeRef;
}

#[cfg(test)]
static CREATE_FAILURE_STAGE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Error from the narrow platform boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(String);

impl Error {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// A newly persisted key armed for exact rollback until public publication.
pub struct Creation {
    key: Option<OwnedSecKey>,
    key_id: String,
    public_key_x963: [u8; P256_UNCOMPRESSED_PUBLIC_LEN],
}

impl Creation {
    pub fn public_key_x963(&self) -> &[u8; P256_UNCOMPRESSED_PUBLIC_LEN] {
        &self.public_key_x963
    }

    /// Transfers responsibility for the now-published public credential.
    pub fn disarm(mut self) {
        self.key.take();
    }
}

impl Drop for Creation {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            if let Err(error) = delete_exact_key(&key) {
                eprintln!(
                    "uchgs: warning: Secure Enclave rollback for key {:?} failed before credential publication: {error}",
                    self.key_id
                );
            }
        }
    }
}

/// Creates one exact, non-replacing, Touch-ID-bound P-256 key.
pub fn create(key_id: &str) -> Result<Creation, Error> {
    validate_key_id(key_id)?;
    let tag = application_tag(key_id);
    if lookup_key(&tag, key_id)?.is_some() {
        return Err(Error::new(format!(
            "Secure Enclave key {key_id:?} already exists under the exact uchgs application tag"
        )));
    }
    let key = create_key(&tag)?;
    let mut creation = Creation {
        key: Some(key),
        key_id: key_id.to_owned(),
        public_key_x963: [0; P256_UNCOMPRESSED_PUBLIC_LEN],
    };
    #[cfg(test)]
    if CREATE_FAILURE_STAGE
        .compare_exchange(
            1,
            0,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        )
        .is_ok()
    {
        return Err(Error::new("injected public-key export failure"));
    }
    creation.public_key_x963 = export_public(
        creation
            .key
            .as_ref()
            .expect("new Secure Enclave key remains rollback-armed"),
    )?;
    #[cfg(test)]
    if CREATE_FAILURE_STAGE
        .compare_exchange(
            2,
            0,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        )
        .is_ok()
    {
        return Err(Error::new("injected possession-proof failure"));
    }
    prove_possession(
        creation
            .key
            .as_ref()
            .expect("new Secure Enclave key remains rollback-armed"),
        &tag,
        &creation.public_key_x963,
        key_id,
    )?;
    Ok(creation)
}

/// Signs one already-framed 32-byte approval challenge with Touch ID.
pub fn sign_prehash(
    key_id: &str,
    expected_public_x963: &[u8; P256_UNCOMPRESSED_PUBLIC_LEN],
    challenge: &[u8; 32],
) -> Result<[u8; 64], Error> {
    validate_key_id(key_id)?;
    let tag = application_tag(key_id);
    let key = lookup_key(&tag, key_id)?.ok_or_else(|| {
        Error::new(format!(
            "Secure Enclave key {key_id:?} was not found under its exact uchgs application tag"
        ))
    })?;
    let actual = export_public(&key)?;
    if actual != *expected_public_x963 {
        return Err(Error::new(format!(
            "Secure Enclave key {key_id:?} has a different public key; refusing to sign"
        )));
    }
    sign_and_verify_prehash(&key, expected_public_x963, challenge, key_id)
}

/// Returns the exact public key for one existing application-tagged key.
pub fn public_key(key_id: &str) -> Result<[u8; P256_UNCOMPRESSED_PUBLIC_LEN], Error> {
    validate_key_id(key_id)?;
    let tag = application_tag(key_id);
    let key = lookup_key(&tag, key_id)?.ok_or_else(|| {
        Error::new(format!(
            "Secure Enclave key {key_id:?} was not found under its exact uchgs application tag"
        ))
    })?;
    export_public(&key)
}

fn create_key(tag: &[u8; 32]) -> Result<OwnedSecKey, Error> {
    let mut access_error: CfErrorRef = ptr::null_mut();
    let access = unsafe {
        SecAccessControlCreateWithFlags(
            ptr::null(),
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly.cast(),
            kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet,
            (&mut access_error as *mut CfErrorRef).cast(),
        )
    };
    if access.is_null() {
        return Err(cf_error(
            "create one-shot Touch ID access policy",
            access_error,
        ));
    }
    let access = OwnedCf::new(access.cast(), "Touch ID access policy")?;
    let tag = OwnedCf::data(tag)?;
    let size = OwnedCf::number_i32(256)?;
    let private = OwnedCf::dictionary()?;
    private.set(unsafe { kSecAttrIsPermanent.cast() }, cf_true())?;
    private.set(application_tag_key(), tag.as_ptr())?;
    private.set(unsafe { kSecAttrAccessControl.cast() }, access.as_ptr())?;

    let parameters = OwnedCf::dictionary()?;
    parameters.set(unsafe { kSecAttrKeyType.cast() }, unsafe {
        kSecAttrKeyTypeECSECPrimeRandom.cast()
    })?;
    parameters.set(unsafe { kSecAttrKeySizeInBits.cast() }, size.as_ptr())?;
    parameters.set(unsafe { kSecAttrTokenID.cast() }, unsafe {
        kSecAttrTokenIDSecureEnclave.cast()
    })?;
    parameters.set(unsafe { kSecUseDataProtectionKeychain.cast() }, cf_true())?;
    parameters.set(unsafe { kSecPrivateKeyAttrs.cast() }, private.as_ptr())?;

    let mut error: CfErrorRef = ptr::null_mut();
    let key = unsafe {
        SecKeyCreateRandomKey(
            parameters.as_ptr().cast(),
            (&mut error as *mut CfErrorRef).cast(),
        )
    };
    if key.is_null() {
        return Err(cf_error("create Secure Enclave key", error));
    }
    OwnedSecKey::from_create(key)
}

fn lookup_key(tag: &[u8; 32], key_id: &str) -> Result<Option<OwnedSecKey>, Error> {
    let tag = OwnedCf::data(tag)?;
    let query = exact_key_query(tag.as_ptr())?;
    query.set(unsafe { kSecReturnRef.cast() }, cf_true())?;
    query.set(unsafe { kSecMatchLimit.cast() }, unsafe {
        kSecMatchLimitAll.cast()
    })?;

    let mut result: CfTypeRef = ptr::null();
    let status = unsafe {
        SecItemCopyMatching(
            query.as_ptr().cast(),
            (&mut result as *mut CfTypeRef).cast(),
        )
    };
    if status == errSecItemNotFound {
        return Ok(None);
    }
    if status != errSecSuccess {
        return Err(Error::new(format!(
            "Secure Enclave lookup for key {key_id:?} failed with Security.framework status {status}"
        )));
    }
    if result.is_null() {
        return Err(Error::new("Secure Enclave lookup returned a null result"));
    }
    let result = OwnedCf::new(result, "Secure Enclave lookup result")?;
    let result_type = unsafe { CFGetTypeID(result.as_ptr()) };
    if result_type == unsafe { SecKeyGetTypeID() } {
        return Ok(Some(OwnedSecKey::retain(result.as_ptr() as SecKeyRef)?));
    }
    if result_type != unsafe { CFArrayGetTypeID() } {
        return Err(Error::new(
            "Secure Enclave lookup returned a non-key object",
        ));
    }
    let count = unsafe { CFArrayGetCount(result.as_ptr()) };
    if count == 0 {
        return Ok(None);
    }
    if count != 1 {
        return Err(Error::new(format!(
            "Secure Enclave lookup for key {key_id:?} is ambiguous: {count} exact matches"
        )));
    }
    let value = unsafe { CFArrayGetValueAtIndex(result.as_ptr(), 0) };
    if value.is_null() || unsafe { CFGetTypeID(value) } != unsafe { SecKeyGetTypeID() } {
        return Err(Error::new(
            "Secure Enclave lookup returned a non-key result",
        ));
    }
    Ok(Some(OwnedSecKey::retain(value as SecKeyRef)?))
}

fn exact_key_query(tag: CfTypeRef) -> Result<OwnedCf, Error> {
    let query = OwnedCf::dictionary()?;
    query.set(unsafe { kSecClass.cast() }, unsafe { kSecClassKey.cast() })?;
    query.set(unsafe { kSecAttrKeyClass.cast() }, unsafe {
        kSecAttrKeyClassPrivate.cast()
    })?;
    query.set(unsafe { kSecAttrKeyType.cast() }, unsafe {
        kSecAttrKeyTypeECSECPrimeRandom.cast()
    })?;
    query.set(unsafe { kSecAttrTokenID.cast() }, unsafe {
        kSecAttrTokenIDSecureEnclave.cast()
    })?;
    query.set(unsafe { kSecUseDataProtectionKeychain.cast() }, cf_true())?;
    query.set(application_tag_key(), tag)?;
    Ok(query)
}

fn export_public(key: &OwnedSecKey) -> Result<[u8; P256_UNCOMPRESSED_PUBLIC_LEN], Error> {
    let public = unsafe { SecKeyCopyPublicKey(key.as_ptr()) };
    let public = OwnedSecKey::from_create(public)?;
    let mut error: CfErrorRef = ptr::null_mut();
    let bytes = unsafe {
        SecKeyCopyExternalRepresentation(public.as_ptr(), (&mut error as *mut CfErrorRef).cast())
    };
    if bytes.is_null() {
        return Err(cf_error("export Secure Enclave public key", error));
    }
    let bytes = OwnedCf::new(bytes.cast(), "Secure Enclave public key")?;
    bytes.data_exact("Secure Enclave public key", P256_UNCOMPRESSED_PUBLIC_LEN)
}

fn sign_and_verify_prehash(
    key: &OwnedSecKey,
    expected_public: &[u8; P256_UNCOMPRESSED_PUBLIC_LEN],
    challenge: &[u8; 32],
    key_id: &str,
) -> Result<[u8; 64], Error> {
    let digest = OwnedCf::data(challenge)?;
    let mut error: CfErrorRef = ptr::null_mut();
    let signature = unsafe {
        SecKeyCreateSignature(
            key.as_ptr(),
            Algorithm::ECDSASignatureDigestX962SHA256.into(),
            digest.as_ptr().cast(),
            (&mut error as *mut CfErrorRef).cast(),
        )
    };
    if signature.is_null() {
        return Err(Error::new(format!(
            "Touch ID did not authorize Secure Enclave key {key_id:?}: {}",
            cf_error("authorize Secure Enclave signature", error)
        )));
    }
    let signature = OwnedCf::new(signature.cast(), "Secure Enclave provider signature")?;
    let der = signature.data_bounded(
        "Secure Enclave provider DER signature",
        1,
        MAX_PROVIDER_DER_SIGNATURE_LEN,
    )?;
    let parsed = Signature::from_der(&der)
        .map_err(|_| Error::new("Secure Enclave returned an invalid DER signature"))?;
    let normalized = parsed.normalize_s().unwrap_or(parsed);
    let verifier = VerifyingKey::from_sec1_bytes(expected_public)
        .map_err(|_| Error::new("Secure Enclave public key is not valid P-256 X9.63"))?;
    verifier
        .verify_prehash(challenge, &normalized)
        .map_err(|_| Error::new("Secure Enclave signature failed portable verification"))?;
    Ok(normalized.to_bytes().into())
}

fn prove_possession(
    key: &OwnedSecKey,
    tag: &[u8; 32],
    public: &[u8; P256_UNCOMPRESSED_PUBLIC_LEN],
    key_id: &str,
) -> Result<(), Error> {
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random)
        .map_err(|error| Error::new(format!("generate possession challenge: {error}")))?;
    let mut payload = Vec::with_capacity(
        POSSESSION_DOMAIN.len() + 1 + 4 + tag.len() + public.len() + random.len(),
    );
    payload.extend_from_slice(POSSESSION_DOMAIN);
    payload.push(0);
    payload.extend_from_slice(&POSSESSION_VERSION.to_be_bytes());
    payload.extend_from_slice(tag);
    payload.extend_from_slice(public);
    payload.extend_from_slice(&random);

    let message = OwnedCf::data(&payload)?;
    let mut error: CfErrorRef = ptr::null_mut();
    let signature = unsafe {
        SecKeyCreateSignature(
            key.as_ptr(),
            Algorithm::ECDSASignatureMessageX962SHA256.into(),
            message.as_ptr().cast(),
            (&mut error as *mut CfErrorRef).cast(),
        )
    };
    if signature.is_null() {
        return Err(Error::new(format!(
            "Touch ID did not authorize Secure Enclave key {key_id:?} possession proof: {}",
            cf_error("authorize Secure Enclave possession proof", error)
        )));
    }
    let signature = OwnedCf::new(signature.cast(), "Secure Enclave possession signature")?;
    let der = signature.data_bounded(
        "Secure Enclave possession DER signature",
        1,
        MAX_PROVIDER_DER_SIGNATURE_LEN,
    )?;
    let parsed = Signature::from_der(&der)
        .map_err(|_| Error::new("Secure Enclave returned an invalid possession signature"))?;
    let normalized = parsed.normalize_s().unwrap_or(parsed);
    let verifier = VerifyingKey::from_sec1_bytes(public)
        .map_err(|_| Error::new("Secure Enclave public key is not valid P-256 X9.63"))?;
    verifier
        .verify(&payload, &normalized)
        .map_err(|_| Error::new("Secure Enclave possession proof failed portable verification"))?;
    Ok(())
}

fn delete_exact_key(key: &OwnedSecKey) -> Result<(), Error> {
    let query = OwnedCf::dictionary()?;
    query.set(unsafe { kSecClass.cast() }, unsafe { kSecClassKey.cast() })?;
    query.set(
        unsafe { kSecValueRef.cast() },
        key.as_ptr().cast_const().cast(),
    )?;
    query.set(unsafe { kSecUseDataProtectionKeychain.cast() }, cf_true())?;
    let status = unsafe { SecItemDelete(query.as_ptr().cast()) };
    if status == errSecSuccess || status == errSecItemNotFound {
        Ok(())
    } else {
        Err(Error::new(format!(
            "delete exact Secure Enclave key failed with status {status}"
        )))
    }
}

fn validate_key_id(key_id: &str) -> Result<(), Error> {
    let bytes = key_id.as_bytes();
    if !(1..=MAX_KEY_ID_BYTES).contains(&bytes.len())
        || bytes.first() == Some(&b'.')
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Err(Error::new(format!(
            "Secure Enclave key id must contain 1..={MAX_KEY_ID_BYTES} ASCII bytes from [A-Za-z0-9._-] and must not start with '.'"
        )))
    } else {
        Ok(())
    }
}

fn application_tag(key_id: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(APPLICATION_TAG_DOMAIN);
    hash.update([0]);
    hash.update(APPLICATION_TAG_VERSION.to_be_bytes());
    hash.update((key_id.len() as u64).to_be_bytes());
    hash.update(key_id.as_bytes());
    hash.finalize().into()
}

fn application_tag_key() -> CfTypeRef {
    unsafe { kSecAttrApplicationTag }
}

fn cf_true() -> CfTypeRef {
    unsafe { kCFBooleanTrue }
}

fn cf_error(operation: &str, error: CfErrorRef) -> Error {
    if error.is_null() {
        return Error::new(format!("{operation}: no Security.framework error detail"));
    }
    let code = unsafe { CFErrorGetCode(error) };
    unsafe { CFRelease(error.cast()) };
    Error::new(format!("{operation}: Security.framework error {code}"))
}

struct OwnedCf(CfTypeRef);

impl OwnedCf {
    fn new(value: CfTypeRef, label: &str) -> Result<Self, Error> {
        if value.is_null() {
            Err(Error::new(format!("allocate {label}: returned null")))
        } else {
            Ok(Self(value))
        }
    }

    fn dictionary() -> Result<Self, Error> {
        let value = unsafe {
            CFDictionaryCreateMutable(
                ptr::null(),
                0,
                ptr::addr_of!(kCFTypeDictionaryKeyCallBacks).cast(),
                ptr::addr_of!(kCFTypeDictionaryValueCallBacks).cast(),
            )
        };
        Self::new(value.cast(), "CoreFoundation dictionary")
    }

    fn data(bytes: &[u8]) -> Result<Self, Error> {
        let value = unsafe { CFDataCreate(ptr::null(), bytes.as_ptr(), bytes.len() as isize) };
        Self::new(value.cast(), "CoreFoundation data")
    }

    fn number_i32(value: i32) -> Result<Self, Error> {
        let value =
            unsafe { CFNumberCreate(ptr::null(), 3, (&value as *const i32).cast::<c_void>()) };
        Self::new(value, "CoreFoundation number")
    }

    fn as_ptr(&self) -> CfTypeRef {
        self.0
    }

    fn set(&self, key: CfTypeRef, value: CfTypeRef) -> Result<(), Error> {
        if key.is_null() || value.is_null() {
            return Err(Error::new("CoreFoundation dictionary received null"));
        }
        unsafe { CFDictionarySetValue(self.0.cast_mut(), key, value) };
        Ok(())
    }

    fn data_exact<const N: usize>(&self, label: &str, expected: usize) -> Result<[u8; N], Error> {
        let bytes = self.data_bounded(label, expected, expected)?;
        bytes
            .try_into()
            .map_err(|_| Error::new(format!("{label} has the wrong length")))
    }

    fn data_bounded(&self, label: &str, minimum: usize, maximum: usize) -> Result<Vec<u8>, Error> {
        if unsafe { CFGetTypeID(self.0) } != unsafe { CFDataGetTypeID() } {
            return Err(Error::new(format!("{label} is not CFData")));
        }
        let raw = unsafe { CFDataGetLength(self.0.cast()) };
        let length = usize::try_from(raw)
            .map_err(|_| Error::new(format!("{label} has a negative length")))?;
        if !(minimum..=maximum).contains(&length) {
            return Err(Error::new(format!(
                "{label} must contain {minimum}..={maximum} bytes; got {length}"
            )));
        }
        let pointer = unsafe { CFDataGetBytePtr(self.0.cast()) };
        if pointer.is_null() {
            return Err(Error::new(format!("{label} returned a null pointer")));
        }
        Ok(unsafe { std::slice::from_raw_parts(pointer, length) }.to_vec())
    }
}

impl Drop for OwnedCf {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0) };
    }
}

struct OwnedSecKey(SecKeyRef);

impl OwnedSecKey {
    fn from_create(key: SecKeyRef) -> Result<Self, Error> {
        if key.is_null() {
            Err(Error::new("Security.framework returned a null key"))
        } else {
            Ok(Self(key))
        }
    }

    fn retain(key: SecKeyRef) -> Result<Self, Error> {
        if key.is_null() {
            return Err(Error::new("Security.framework returned a null key"));
        }
        unsafe { CFRetain(key.cast()) };
        Ok(Self(key))
    }

    fn as_ptr(&self) -> SecKeyRef {
        self.0
    }
}

impl Drop for OwnedSecKey {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0.cast()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static SECURE_ENCLAVE_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct FailureStageReset;

    impl Drop for FailureStageReset {
        fn drop(&mut self) {
            CREATE_FAILURE_STAGE.store(0, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn application_tag_is_versioned_and_key_bound() {
        assert_eq!(application_tag("alpha"), application_tag("alpha"));
        assert_ne!(application_tag("alpha"), application_tag("beta"));
    }

    #[test]
    fn key_id_validation_is_closed() {
        assert!(validate_key_id("operator").is_ok());
        assert!(validate_key_id("operator.key_1-2").is_ok());
        assert!(validate_key_id(&"a".repeat(MAX_KEY_ID_BYTES)).is_ok());
        assert!(validate_key_id("").is_err());
        assert!(validate_key_id(".hidden").is_err());
        assert!(validate_key_id("a b").is_err());
        assert!(validate_key_id("a/b").is_err());
        assert!(validate_key_id("鍵").is_err());
        assert!(validate_key_id("line\nbreak").is_err());
        assert!(validate_key_id(&"a".repeat(MAX_KEY_ID_BYTES + 1)).is_err());
    }

    #[test]
    #[ignore = "requires an operator-present Secure Enclave and Touch ID"]
    fn secure_enclave_touch_id_ceremony() {
        let _serial = SECURE_ENCLAVE_TEST.lock().unwrap();
        let mut suffix = [0_u8; 8];
        getrandom::fill(&mut suffix).unwrap();
        let key_id = format!("uchgs-item10-{:016x}", u64::from_be_bytes(suffix));
        let creation = create(&key_id).expect("create and prove possession");
        let public = *creation.public_key_x963();
        creation.disarm();
        let challenge = Sha256::digest(b"independent sign-time challenge").into();
        sign_prehash(&key_id, &public, &challenge).expect("Touch ID sign");
        let key = lookup_key(&application_tag(&key_id), &key_id)
            .expect("lookup")
            .expect("key exists");
        delete_exact_key(&key).expect("delete exact drill key");
        delete_exact_key(&key).expect("repeat exact delete is idempotent");
        assert!(
            lookup_key(&application_tag(&key_id), &key_id)
                .expect("post-delete lookup")
                .is_none()
        );

        let rollback_id = format!("{key_id}-rollback");
        let rollback = create(&rollback_id).expect("create rollback drill key");
        drop(rollback);
        assert!(
            lookup_key(&application_tag(&rollback_id), &rollback_id)
                .expect("post-rollback lookup")
                .is_none()
        );
    }

    #[test]
    #[ignore = "requires an operator-present signed Secure Enclave host"]
    fn creation_failures_rollback_before_retry() {
        let _serial = SECURE_ENCLAVE_TEST.lock().unwrap();
        for (stage, label) in [(1, "export"), (2, "proof")] {
            let mut suffix = [0_u8; 8];
            getrandom::fill(&mut suffix).unwrap();
            let key_id = format!(
                "uchgs-item10-{label}-rollback-{:016x}",
                u64::from_be_bytes(suffix)
            );
            CREATE_FAILURE_STAGE.store(stage, std::sync::atomic::Ordering::SeqCst);
            let _reset_stage = FailureStageReset;
            assert!(create(&key_id).is_err());
            assert!(
                lookup_key(&application_tag(&key_id), &key_id)
                    .expect("post-failure lookup")
                    .is_none()
            );

            let retry = create(&key_id).expect("retry after exact rollback");
            drop(retry);
            assert!(
                lookup_key(&application_tag(&key_id), &key_id)
                    .expect("post-retry rollback lookup")
                    .is_none()
            );
        }
    }
}
