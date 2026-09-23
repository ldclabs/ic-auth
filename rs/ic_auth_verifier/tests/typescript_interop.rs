#![cfg(feature = "envelope")]

use candid::Principal;
use ic_auth_types::{
    DelegationCompact, DelegationPermissions, SignedDelegationCompact, cbor_from_slice,
    deterministic_cbor_into_vec,
};
use ic_auth_verifier::{SignedEnvelope, deeplink::SignInResponse, sha3_256};
use serde::Serialize;

#[derive(Serialize)]
struct Message<'a> {
    amount: f64,
    challenge: &'a str,
}

#[test]
fn verifies_typescript_delegation_with_targets_and_a_structured_digest() {
    let message = deterministic_cbor_into_vec(&Message {
        amount: 1.5,
        challenge: "login",
    })
    .unwrap();
    assert_eq!(
        hex::encode(&message),
        include_str!("fixtures/message.hex").trim()
    );
    let digest = sha3_256(&message);
    assert_eq!(
        hex::encode(digest),
        include_str!("fixtures/message-digest.hex").trim()
    );

    let encoded = hex::decode(include_str!("fixtures/delegated-envelope.hex").trim()).unwrap();
    let envelope = SignedEnvelope::from_bytes(&encoded).unwrap();
    assert_eq!(envelope.to_bytes(), encoded);
    // Fixed time keeps the fixture valid independently of the test execution date.
    envelope
        .verify(
            1_800_000_000_000,
            Some(Principal::anonymous()),
            Some(&digest),
        )
        .unwrap();
    assert!(
        envelope
            .verify(
                1_800_000_000_000,
                Some(Principal::management_canister()),
                Some(&digest)
            )
            .is_err()
    );
}

#[test]
fn produces_the_compact_sign_in_response_consumed_by_typescript() {
    // Tests the wire shape; these placeholder keys/signature are not credentials.
    let response = SignInResponse {
        user_pubkey: vec![1, 2, 3].into(),
        delegations: vec![SignedDelegationCompact {
            delegation: DelegationCompact {
                pubkey: vec![4, 5, 6].into(),
                expiration: 123,
                targets: Some(vec![Principal::anonymous()]),
                permissions: Some(DelegationPermissions::Queries),
            },
            signature: vec![7, 8, 9].into(),
        }],
        authn_method: "passkey".into(),
        origin: "https://example.com".into(),
    };
    let encoded = deterministic_cbor_into_vec(&response).unwrap();
    assert_eq!(
        hex::encode(&encoded),
        include_str!("fixtures/sign-in-response.hex").trim()
    );
    let decoded: SignInResponse = cbor_from_slice(&encoded).unwrap();
    assert_eq!(decoded.delegations, response.delegations);
}
