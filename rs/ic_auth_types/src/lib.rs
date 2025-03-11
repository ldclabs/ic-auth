use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// A delegation from one key to another.
///
/// If key A signs a delegation containing key B, then key B may be used to
/// authenticate as key A's corresponding principal(s).
#[derive(CandidType, Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct Delegation {
    /// The delegated-to key.
    pub pubkey: ByteBuf,
    /// A nanosecond timestamp after which this delegation is no longer valid.
    pub expiration: u64,
    /// If present, this delegation only applies to requests sent to one of these canisters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<Principal>>,
}

/// A [`Delegation`] that has been signed by an [`Identity`](https://docs.rs/ic-agent/latest/ic_agent/trait.Identity.html).
#[derive(CandidType, Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct SignedDelegation {
    /// The signed delegation.
    pub delegation: Delegation,
    /// The signature for the delegation.
    pub signature: ByteBuf,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct SignInResponse {
    /// The session expiration time in nanoseconds since the UNIX epoch. This is the time at which
    /// the delegation will no longer be valid.
    pub expiration: u64,
    /// The user canister public key. This key is used to derive the user principal.
    pub user_key: ByteBuf,
    /// seed is a part of the user_key
    pub seed: ByteBuf,
}
