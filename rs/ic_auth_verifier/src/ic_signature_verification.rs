use candid::Principal;
use ic_certificate_verification::VerifyCertificate;
use ic_certification::{Certificate, HashTree, SubtreeLookupResult, leaf};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};

pub const IC_STATE_ROOT_DOMAIN_SEPARATOR: &[u8; 14] = b"\x0Dic-state-root";
pub const MAX_CERT_TIME_OFFSET_NS: u128 = 47 * 24 * 3600 * 1_000_000_000; // 47 days

use ic_canister_sig_creation::CanisterSigPublicKey;

/// Verifies that `signature` is a valid canister signature on `message`.
/// https://internetcomputer.org/docs/current/references/ic-interface-spec#canister-signatures
pub fn verify_canister_sig(
    message: &[u8],
    signature_cbor: &[u8],
    public_key_der: &[u8],
    ic_root_public_key_raw: &[u8],
    current_time_ns: &u128,
    allowed_certificate_time_offset_ns: Option<u128>,
) -> Result<(), String> {
    let signature = parse_signature_cbor(signature_cbor)?;
    let public_key = CanisterSigPublicKey::try_from(public_key_der)
        .map_err(|e| format!("failed to parse canister sig public key: {e}"))?;
    check_sig_path(&signature, &public_key, message)?;
    let certificate =
        check_certified_data_and_get_certificate(&signature, &public_key.canister_id)?;

    certificate
        .verify(
            public_key.canister_id.as_slice(),
            ic_root_public_key_raw,
            current_time_ns,
            &allowed_certificate_time_offset_ns.unwrap_or(MAX_CERT_TIME_OFFSET_NS),
        )
        .map_err(|err| format!("{err:?}"))?;
    Ok(())
}

// Check that signature.certificate's tree contains for the canister identified by
// signing_canister_id an entry for certified_data that matches signature.tree.digest.
fn check_certified_data_and_get_certificate(
    signature: &CanisterSignature,
    signing_canister_id: &Principal,
) -> Result<Certificate, String> {
    let certificate = parse_certificate_cbor(&signature.certificate)?;
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
    Ok(certificate)
}

// Check that signature.tree contains an empty leaf at correct "sig"-path,
// where the path is determined by hashes of canister_sig_pk.seed and msg.
fn check_sig_path(
    signature: &CanisterSignature,
    canister_sig_pk: &CanisterSigPublicKey,
    msg: &[u8],
) -> Result<(), String> {
    let seed_hash = hash_sha256(&canister_sig_pk.seed);
    let msg_hash = hash_sha256(msg);
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

fn parse_certificate_cbor(certificate_cbor: &[u8]) -> Result<Certificate, String> {
    // 0xd9d9f7 (cf. https://tools.ietf.org/html/rfc7049#section-2.4.5) is the
    // self-describing CBOR tag required to be present by the interface spec.
    if certificate_cbor.len() < 3 || certificate_cbor[0..3] != [0xd9, 0xd9, 0xf7] {
        return Err("certificate CBOR doesn't have a self-describing tag".to_string());
    }
    serde_cbor::from_slice::<Certificate>(certificate_cbor)
        .map_err(|e| format!("failed to parse certificate CBOR: {e}"))
}

const SHA256_DIGEST_LEN: usize = 32;
fn hash_sha256(data: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    let mut hash = Sha256::default();
    hash.update(data);
    <[u8; SHA256_DIGEST_LEN]>::from(hash.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_certification::{empty, labeled};

    fn tagged_cbor<T: Serialize>(value: &T) -> Vec<u8> {
        let mut out = vec![0xd9, 0xd9, 0xf7];
        out.extend(serde_cbor::to_vec(value).unwrap());
        out
    }

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

        let seed_hash = hash_sha256(&public_key.seed);
        let msg_hash = hash_sha256(b"message");
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
        let certificate = Certificate {
            tree: empty(),
            signature: vec![],
            delegation: None,
        };
        let signature = CanisterSignature {
            certificate: ByteBuf::from(tagged_cbor(&certificate)),
            tree: empty(),
        };
        assert_eq!(
            check_certified_data_and_get_certificate(&signature, &public_key.canister_id)
                .unwrap_err(),
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
        let signature = CanisterSignature {
            certificate: ByteBuf::from(tagged_cbor(&certificate)),
            tree: empty(),
        };
        assert_eq!(
            check_certified_data_and_get_certificate(&signature, &public_key.canister_id)
                .unwrap_err(),
            "certified_data doesn't match sig tree digest"
        );
    }

    #[test]
    fn test_hash_sha256_vector() {
        assert_eq!(
            hex::encode(hash_sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
