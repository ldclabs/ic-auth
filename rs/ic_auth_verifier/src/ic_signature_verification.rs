use candid::Principal;
use ic_canister_sig_creation::CanisterSigPublicKey;
use ic_certification::{Certificate, HashTree, SubtreeLookupResult, leaf};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{
    certificate_verification::{
        parse_certificate_cbor, verify_certificate, verify_certificate_time,
    },
    sha256,
    signature_cache::SignatureCache,
};

/// Default freshness window applied to a canister signature's certificate.
///
/// [`verify_canister_sig`] uses this when the caller passes `None`, accepting a
/// certificate whose `/time` is within 47 days of `current_time_ns` in either
/// direction. That is far more permissive than the 5 minutes the reference
/// implementation of [`verify_certificate`](crate::verify_certificate) uses in
/// its own tests: it lets a captured certificate keep verifying for weeks, so
/// the delegation `expiration` — not certificate freshness — is what bounds
/// the replay window. Pass an explicit `allowed_certificate_time_offset_ns` to
/// tighten it.
pub const MAX_CERT_TIME_OFFSET_NS: u128 = 47 * 24 * 3600 * 1_000_000_000; // 47 days

/// Separates cache entries for whole canister signatures from BLS entries.
const CANISTER_SIG_CACHE_DOMAIN: &[u8] = b"ic-auth-canister-sig";

/// Verifies that `signature` is a valid canister signature on `message`.
/// <https://internetcomputer.org/docs/current/references/ic-interface-spec#canister-signatures>
///
/// `ic_root_public_key_der` is the DER-encoded IC root public key, such as
/// [`IC_ROOT_PK_DER`](ic_canister_sig_creation::IC_ROOT_PK_DER).
///
/// A session presents the same canister signature on every request. Apart
/// from the certificate's `/time`, the outcome depends only on the arguments,
/// so a signature that verified before is accepted after re-checking
/// certificate freshness alone.
pub fn verify_canister_sig(
    message: &[u8],
    signature_cbor: &[u8],
    public_key_der: &[u8],
    ic_root_public_key_der: &[u8],
    current_time_ns: u128,
    allowed_certificate_time_offset_ns: Option<u128>,
) -> Result<(), String> {
    let allowed_offset_ns = allowed_certificate_time_offset_ns.unwrap_or(MAX_CERT_TIME_OFFSET_NS);
    let signature = parse_signature_cbor(signature_cbor)?;
    let certificate = parse_certificate_cbor(&signature.certificate)?;

    let entry = SignatureCache::entry(&[
        CANISTER_SIG_CACHE_DOMAIN,
        ic_root_public_key_der,
        public_key_der,
        signature_cbor,
        message,
    ]);
    if SignatureCache::global().contains(&entry) {
        return verify_certificate_time(&certificate, current_time_ns, allowed_offset_ns);
    }

    let public_key = CanisterSigPublicKey::try_from(public_key_der)
        .map_err(|e| format!("failed to parse canister sig public key: {e}"))?;
    check_sig_path(&signature, &public_key, message)?;
    check_certified_data(&signature, &certificate, &public_key.canister_id)?;
    verify_certificate(
        &certificate,
        public_key.canister_id.as_slice(),
        ic_root_public_key_der,
        current_time_ns,
        allowed_offset_ns,
    )?;

    SignatureCache::global().insert(entry);
    Ok(())
}

// Check that the certificate's tree contains for the canister identified by
// signing_canister_id an entry for certified_data that matches signature.tree.digest.
fn check_certified_data(
    signature: &CanisterSignature,
    certificate: &Certificate,
    signing_canister_id: &Principal,
) -> Result<(), String> {
    let cert_data_path = [
        "canister".as_bytes(),
        signing_canister_id.as_slice(),
        "certified_data".as_bytes(),
    ];
    let SubtreeLookupResult::Found(cert_data_leaf) =
        certificate.tree.lookup_subtree(&cert_data_path)
    else {
        return Err("certified_data entry not found".to_string());
    };
    if cert_data_leaf != leaf(signature.tree.digest()) {
        return Err("certified_data doesn't match sig tree digest".to_string());
    }
    Ok(())
}

// Check that signature.tree contains an empty leaf at correct "sig"-path,
// where the path is determined by hashes of canister_sig_pk.seed and msg.
fn check_sig_path(
    signature: &CanisterSignature,
    canister_sig_pk: &CanisterSigPublicKey,
    msg: &[u8],
) -> Result<(), String> {
    let seed_hash = sha256(&canister_sig_pk.seed);
    let msg_hash = sha256(msg);
    let sig_path = ["sig".as_bytes(), &seed_hash, &msg_hash];
    let SubtreeLookupResult::Found(sig_leaf) = signature.tree.lookup_subtree(&sig_path) else {
        return Err("signature entry not found".to_string());
    };
    if sig_leaf != leaf(b"") {
        return Err("signature entry is not an empty leaf".to_string());
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct CanisterSignature {
    pub certificate: ByteBuf,
    pub tree: HashTree,
}

fn parse_signature_cbor(signature_cbor: &[u8]) -> Result<CanisterSignature, String> {
    // 0xd9d9f7 (cf. https://tools.ietf.org/html/rfc7049#section-2.4.5) is the
    // self-describing CBOR tag required to be present by the interface spec.
    if signature_cbor.len() < 3 || signature_cbor[0..3] != [0xd9, 0xd9, 0xf7] {
        return Err("signature CBOR doesn't have a self-describing tag".to_string());
    }
    serde_cbor::from_slice::<CanisterSignature>(signature_cbor)
        .map_err(|e| format!("failed to parse signature CBOR: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_certification::{empty, labeled};

    fn canister_public_key() -> CanisterSigPublicKey {
        let pk_der =
            hex::decode("303c300c060a2b0601040183b8430102032c000a000000000000000101011f809d0136deeed8e0187447d20ac0e13e0201e1dede8c437eada3e8dc349f85")
                .unwrap();
        CanisterSigPublicKey::try_from(pk_der.as_slice()).unwrap()
    }

    #[test]
    fn test_parse_cbor_helpers_reject_missing_or_invalid_tags() {
        assert_eq!(
            parse_signature_cbor(&[]).unwrap_err(),
            "signature CBOR doesn't have a self-describing tag"
        );
        assert!(
            parse_signature_cbor(&[0xd9, 0xd9, 0xf7, 0xff])
                .unwrap_err()
                .contains("failed to parse signature CBOR")
        );

        assert_eq!(
            parse_certificate_cbor(&[]).unwrap_err(),
            "certificate CBOR doesn't have a self-describing tag"
        );
        assert!(
            parse_certificate_cbor(&[0xd9, 0xd9, 0xf7, 0xff])
                .unwrap_err()
                .contains("failed to parse certificate CBOR")
        );
    }

    #[test]
    fn test_check_sig_path_errors() {
        let public_key = canister_public_key();
        let signature = CanisterSignature {
            certificate: ByteBuf::from(vec![]),
            tree: empty(),
        };
        assert_eq!(
            check_sig_path(&signature, &public_key, b"message").unwrap_err(),
            "signature entry not found"
        );

        let seed_hash = sha256(&public_key.seed);
        let msg_hash = sha256(b"message");
        let signature = CanisterSignature {
            certificate: ByteBuf::from(vec![]),
            tree: labeled(
                b"sig".to_vec(),
                labeled(
                    seed_hash.to_vec(),
                    labeled(msg_hash.to_vec(), leaf(b"not-empty")),
                ),
            ),
        };
        assert_eq!(
            check_sig_path(&signature, &public_key, b"message").unwrap_err(),
            "signature entry is not an empty leaf"
        );
    }

    #[test]
    fn test_check_certified_data_errors() {
        let public_key = canister_public_key();
        let signature = CanisterSignature {
            certificate: ByteBuf::new(),
            tree: empty(),
        };
        let certificate = Certificate {
            tree: empty(),
            signature: vec![],
            delegation: None,
        };
        assert_eq!(
            check_certified_data(&signature, &certificate, &public_key.canister_id).unwrap_err(),
            "certified_data entry not found"
        );

        let certificate = Certificate {
            tree: labeled(
                b"canister".to_vec(),
                labeled(
                    public_key.canister_id.as_slice().to_vec(),
                    labeled(b"certified_data".to_vec(), leaf(b"mismatch")),
                ),
            ),
            signature: vec![],
            delegation: None,
        };
        assert_eq!(
            check_certified_data(&signature, &certificate, &public_key.canister_id).unwrap_err(),
            "certified_data doesn't match sig tree digest"
        );
    }

    #[test]
    fn a_repeat_verification_skips_everything_but_the_time_check() {
        // A canister signature on a local replica whose certificate `/time` is
        // 1_234_567 ns, so it is fresh at `current_time_ns = 0`.
        let message =
            hex::decode("086c81b03b34184d2365b88a7d94ad9cc0f4e98970b6c10068aae4e407333339")
                .unwrap();
        let signature = hex::decode("d9d9f7a26b636572746966696361746558a1d9d9f7a26474726565830183024863616e697374657283024a0000000000000001010183024e6365727469666965645f646174618203582053e3b19ab292296b52b451b0662af2d86ac707569b39825fc31f62aca41406d483024474696d6582034387ad4b697369676e61747572655830a95766af95898e1c8492de7b7d9e6c601ea9d9958113f6c0491ef044ed5ebb03d31983abfa40ebbef7068ebaf7e66f05647472656583024373696783025820591047009df12cb39741d672f270045fd15beec2b0b84c1d71bda98b758726cd83025820d37372239856cdf2ae158e5ac365f15501a9e5612a970ddd7b3199c522b54194820340").unwrap();
        let public_key = hex::decode("303c300c060a2b0601040183b8430102032c000a000000000000000101011f809d0136deeed8e0187447d20ac0e13e0201e1dede8c437eada3e8dc349f85").unwrap();
        let root = hex::decode("308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100b90210504fe157d1df412e500ced967ef794dc7aa88c84d764b74b6bc2cf0e575d79f331927df062240c88a28e1802c60b407c7bce541b50310d775919bcd0f799222c3738bc3bcc8bf05af5f52ee2afec54c460bda35c6c379267924db2d374").unwrap();
        let entry = |message: &[u8]| {
            SignatureCache::entry(&[
                CANISTER_SIG_CACHE_DOMAIN,
                &root,
                &public_key,
                &signature,
                message,
            ])
        };
        let verify = |message: &[u8], now: u128| {
            verify_canister_sig(message, &signature, &public_key, &root, now, None)
        };

        verify(&message, 0).unwrap();
        assert!(SignatureCache::global().contains(&entry(&message)));
        verify(&message, 0).unwrap();

        // The signature does not cover this message, so it fails in full...
        let unsigned = b"not the signed message";
        assert_eq!(
            verify(unsigned, 0).unwrap_err(),
            "signature entry not found"
        );
        // ...and a recorded entry is what lets it through, proving that a hit
        // bypasses the signature checks.
        SignatureCache::global().insert(entry(unsigned));
        verify(unsigned, 0).unwrap();

        // Certificate freshness is still enforced on a hit.
        let stale = MAX_CERT_TIME_OFFSET_NS + 1_000_000_000;
        for message in [message.as_slice(), unsigned] {
            let err = verify(message, stale).unwrap_err();
            assert!(err.contains("too far in the past"), "{err}");
        }
    }

    #[test]
    fn test_hash_sha256_vector() {
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
