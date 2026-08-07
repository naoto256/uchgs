mod canonical;
mod credential;
mod id;

pub use canonical::{ExactJson, WireValidate};
pub use credential::{
    PublicCredential, PublicCredentialDocument, SecureEnclaveP256Credential,
    SoftwareEd25519Credential,
};
pub use id::{CredentialId, Digest32};

pub const CREDENTIAL_MAX_BYTES: usize = 1024 * 1024;
