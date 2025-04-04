use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};

mod bytes;
mod xid;

pub use bytes::*;
pub use xid::*;

/// A delegation from one key to another.
///
/// If key A signs a delegation containing key B, then key B may be used to
/// authenticate as key A's corresponding principal(s).
#[derive(CandidType, Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct Delegation {
    /// The delegated-to key.
    pub pubkey: ByteBufB64,
    /// A nanosecond timestamp after which this delegation is no longer valid.
    pub expiration: u64,
    /// If present, this delegation only applies to requests sent to one of these canisters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<Principal>>,
}

/// SignedDelegation is a [`Delegation`] that has been signed by an [`Identity`](https://docs.rs/ic-agent/latest/ic_agent/trait.Identity.html).
#[derive(CandidType, Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct SignedDelegation {
    /// The signed delegation.
    pub delegation: Delegation,
    /// The signature for the delegation.
    pub signature: ByteBufB64,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct SignInResponse {
    /// The session expiration time in nanoseconds since the UNIX epoch. This is the time at which
    /// the delegation will no longer be valid.
    pub expiration: u64,
    /// The user canister public key. This key is used to derive the user principal.
    pub user_key: ByteBufB64,
    /// seed is a part of the user_key
    pub seed: ByteBufB64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delegation_formart() {
        let d = Delegation {
            pubkey: ByteBufB64(vec![1, 2, 3, 4]),
            expiration: 99,
            targets: Some(vec![Principal::management_canister()]),
        };

        let data = serde_json::to_string(&d).unwrap();
        println!("{}", data);
        assert_eq!(
            data,
            r#"{"pubkey":"AQIDBA==","expiration":99,"targets":["aaaaa-aa"]}"#
        );
        let d1: Delegation = serde_json::from_str(&data).unwrap();
        assert_eq!(d, d1);

        let mut data = Vec::new();
        ciborium::into_writer(&d, &mut data).unwrap();
        println!("{}", const_hex::encode(&data));
        assert_eq!(
            data,
            const_hex::decode(
                "a3667075626b657944010203046a65787069726174696f6e186367746172676574738140"
            )
            .unwrap()
        );
        let d1: Delegation = ciborium::from_reader(&data[..]).unwrap();
        assert_eq!(d, d1);
    }
}
