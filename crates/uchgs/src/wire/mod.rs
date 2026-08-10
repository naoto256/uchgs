mod approval;
mod canonical;
mod credential;
mod id;
mod request;
pub(crate) mod validation;

pub use approval::{
    Approval, ApprovalDocument, ApprovalMaterial, CredentialResolver, DelegationEvidence,
};
pub use canonical::{ExactJson, WireValidate};
pub use credential::{
    PublicCredential, PublicCredentialDocument, SecureEnclaveP256Credential,
    SoftwareEd25519Credential,
};
pub use id::{CredentialId, Digest32, GenesisId, PolicyId, PushIntentId, RequestId};
pub use request::{
    Action, AttestContentAction, AttestTreeAction, DelegationGrantAction, ObjectFormatName,
    PolicyUpdateAction, RegistryName, Request, RequestDocument, SignerEnrollAction, SourceName,
    UnitDescriptor,
};

pub const CREDENTIAL_MAX_BYTES: usize = 1024 * 1024;
pub const REQUEST_MAX_BYTES: usize = 16 * 1024 * 1024;
pub const APPROVAL_MAX_BYTES: usize = 1024 * 1024;
