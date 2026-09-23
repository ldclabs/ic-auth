//! Verification and signing utilities for IC-Auth.
//!
//! The base crate verifies raw signatures for the public key formats used by
//! Internet Computer identities: Ed25519, ECDSA P-256, ECDSA secp256k1, and IC
//! canister signatures. Optional features add higher-level protocol surfaces:
//!
//! - `envelope`: [`SignedEnvelope`] parsing, verification, HTTP headers, and
//!   deep-link payload helpers.
//! - `identity`: `ic-agent` identity helpers for clients and services that
//!   need to sign envelopes. This feature is intended for native/server
//!   targets, not canisters.
//!
//! # Examples
//!
//! ```
//! use ic_auth_verifier::{Algorithm, sha256, verify_basic_sig};
//!
//! let digest = sha256(b"message");
//! assert_eq!(digest.len(), 32);
//!
//! let err = verify_basic_sig(Algorithm::IcCanisterSignature, &[], b"message", &[])
//!     .unwrap_err();
//! assert!(err.contains("not supported"));
//! ```

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use sha3::Digest;

mod asn1;

#[cfg(feature = "envelope")]
pub mod envelope;

#[cfg(feature = "envelope")]
pub mod deeplink;

#[cfg(feature = "envelope")]
pub mod certificate_verification;

#[cfg(feature = "envelope")]
mod signature_cache;

#[cfg(feature = "envelope")]
mod ic_signature_verification;

#[cfg(feature = "identity")]
pub mod identity;

pub use asn1::*;
pub use ic_canister_sig_creation::CanisterSigPublicKey;

#[cfg(feature = "envelope")]
pub use certificate_verification::*;

#[cfg(feature = "envelope")]
pub use ic_signature_verification::*;

#[cfg(feature = "envelope")]
pub use envelope::*;

#[cfg(feature = "envelope")]
pub use deeplink::*;

#[cfg(feature = "identity")]
pub use identity::*;

/// Verifies a raw signature for non-canister public keys.
///
/// `public_key` must be the algorithm-specific raw public key bytes returned by
/// [`user_public_key_from_der`], not the DER SubjectPublicKeyInfo wrapper. For
/// ECDSA variants the function hashes `msg` with SHA-256 and verifies the
/// resulting prehash, matching `ic-agent` arbitrary-message signatures.
///
/// IC canister signatures require certificate verification and should be
/// handled with `verify_sig` or `verify_sig_with_rootkey` from the `envelope`
/// feature instead.
pub fn verify_basic_sig(
    algorithm_id: Algorithm,
    public_key: &[u8],
    msg: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    match algorithm_id {
        Algorithm::Ed25519 => {
            let public_key = public_key
                .try_into()
                .map_err(|_| "Ed25519 public key must be 32 bytes long".to_string())?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
                .map_err(|err| format!("{err:?}"))?;
            let sig = ed25519_dalek::Signature::from_slice(signature)
                .map_err(|err| format!("{err:?}"))?;
            key.verify_strict(msg, &sig)
                .map_err(|_| "Ed25519 signature verification failed".to_string())
        }
        Algorithm::EcdsaP256 => {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|err| format!("{err:?}"))?;
            let sig =
                p256::ecdsa::Signature::try_from(signature).map_err(|err| format!("{err:?}"))?;

            let msg_hash = sha256(msg);
            key.verify_prehash(&msg_hash, &sig)
                .map_err(|_| "ECDSA P256 signature verification failed".to_string())
        }
        Algorithm::EcdsaSecp256k1 => {
            let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|err| err.to_string())?;
            let sig =
                k256::ecdsa::Signature::try_from(signature).map_err(|err| format!("{err:?}"))?;

            let msg_hash = sha256(msg);
            key.verify_prehash(&msg_hash, &sig)
                .map_err(|_| "ECDSA Secp256k1 signature verification failed".to_string())
        }
        algorithm => Err(format!(
            "{algorithm:?} is not supported for basic signature verification"
        )),
    }
}

/// Computes SHA-256 for `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes SHA3-256 for `data`.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes Keccak-256 for `data`.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha3::Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(feature = "identity")]
/// Returns `N` cryptographically random bytes.
pub fn rand_bytes<const N: usize>() -> [u8; N] {
    use rand::Rng;

    let mut rng = rand::rng();
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_agent::{
        Identity,
        identity::{BasicIdentity, Prime256v1Identity, Secp256k1Identity},
    };
    use rand::{Rng, rng};

    const MESSAGE: &[u8] = b"some message";
    const P256_IDENTITY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvXJuZvDH64piyxw5
ly/vUyYqGs2p88/SR7W6cRPkBjihRANCAARRttlXg16tlM9Z9tDvj38Y0u7xNofw
FRL8jv/6Kmy74w/LB+cEUhlKSzjEZsD9ltrOysyXi/jjpTlQhXEIYZor
-----END PRIVATE KEY-----
";
    const SECP256K1_IDENTITY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgCDLudkRxUeRDhnUp2pvL
xLDICLIoNCa1sQdMgz5Y14GhRANCAASA7zusnWjPN0y8nJlD4YAEOpTEYu+CcCdO
VwidXc26G4+/g7dUbMwbN4E3d3bpxHEP31M+2by6jY67MqFKKroR
-----END PRIVATE KEY-----
";

    fn rand_bytes<const N: usize>() -> [u8; N] {
        let mut rng = rng();
        let mut bytes = [0u8; N];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    fn p256_identity() -> Prime256v1Identity {
        Prime256v1Identity::from_pem(P256_IDENTITY_PEM).unwrap()
    }

    fn secp256k1_identity() -> Secp256k1Identity {
        Secp256k1Identity::from_pem(SECP256K1_IDENTITY_PEM).unwrap()
    }

    #[test]
    fn should_work_with_ed25519() {
        let sk: [u8; 32] = rand_bytes();
        let id = BasicIdentity::from_raw_key(&sk);
        let sig = id.sign_arbitrary(MESSAGE).unwrap();
        let pk_der = id.public_key().unwrap();
        let (alg, pk) = user_public_key_from_der(&pk_der).unwrap();
        assert_eq!(alg, Algorithm::Ed25519);
        assert!(verify_basic_sig(alg, &pk, MESSAGE, &sig.signature.unwrap()).is_ok());
    }

    #[test]
    fn should_work_with_ecdsa_secp256k1() {
        let pk_der = hex::decode("3056301006072a8648ce3d020106052b8104000a034200047060f720298ffa0f48d9606abdb013bc82f4ff269f9adc3e7226391af3fad8b30fd6a30deb81d5b4f9e142971085d0ae15b8e222d85af1e17438e630d09b7ef4").unwrap();
        let (alg, pk) = user_public_key_from_der(&pk_der).unwrap();
        assert_eq!(alg, Algorithm::EcdsaSecp256k1);
        assert!(k256::ecdsa::VerifyingKey::from_sec1_bytes(&pk).is_ok());

        let id = secp256k1_identity();
        let sig = id.sign_arbitrary(MESSAGE).unwrap();
        let pk_der = id.public_key().unwrap();
        let (alg, pk) = user_public_key_from_der(&pk_der).unwrap();
        assert_eq!(alg, Algorithm::EcdsaSecp256k1);
        assert!(verify_basic_sig(alg, &pk, MESSAGE, &sig.signature.unwrap()).is_ok());
    }

    #[test]
    fn should_work_with_ecdsa_p256() {
        let pk_der = hex::decode("3059301306072a8648ce3d020106082a8648ce3d03010703420004485c32997ce7c6d38ca82c821185c689d424fac7c9695bb97786c4248aab6428949bcd163e2bcf3eeeac4f200b38fbd053f82c4e1776dc9c6dc8db9b7c35e06f").unwrap();
        let (alg, pk) = user_public_key_from_der(&pk_der).unwrap();
        assert_eq!(alg, Algorithm::EcdsaP256);
        assert!(p256::ecdsa::VerifyingKey::from_sec1_bytes(&pk).is_ok());

        let id = p256_identity();
        let sig = id.sign_arbitrary(MESSAGE).unwrap();
        let pk_der = id.public_key().unwrap();
        let (alg, pk) = user_public_key_from_der(&pk_der).unwrap();
        assert_eq!(alg, Algorithm::EcdsaP256);
        assert!(verify_basic_sig(alg, &pk, MESSAGE, &sig.signature.unwrap()).is_ok());
    }

    #[test]
    fn should_work_with_iccsa_pubkey() {
        let pk_der =
            hex::decode("301b300c060a2b0601040183b8430102030b007075626c6963206b6579").unwrap();
        let (alg, _pk) = user_public_key_from_der(&pk_der).unwrap();
        assert_eq!(alg, Algorithm::IcCanisterSignature);
    }

    #[test]
    fn hash_helpers_match_known_vectors() {
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex::encode(sha3_256(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        assert_eq!(
            hex::encode(keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    #[test]
    fn verify_basic_sig_rejects_invalid_inputs() {
        assert_eq!(
            verify_basic_sig(Algorithm::IcCanisterSignature, &[], MESSAGE, &[]).unwrap_err(),
            "IcCanisterSignature is not supported for basic signature verification"
        );

        assert_eq!(
            verify_basic_sig(Algorithm::Ed25519, &[0; 31], MESSAGE, &[]).unwrap_err(),
            "Ed25519 public key must be 32 bytes long"
        );

        let id = BasicIdentity::from_raw_key(&[8u8; 32]);
        let sig = id.sign_arbitrary(MESSAGE).unwrap();
        let pk_der = id.public_key().unwrap();
        let (alg, pk) = user_public_key_from_der(&pk_der).unwrap();
        assert!(verify_basic_sig(alg, &pk, MESSAGE, &[]).is_err());
        assert_eq!(
            verify_basic_sig(alg, &pk, b"tampered", &sig.signature.unwrap()).unwrap_err(),
            "Ed25519 signature verification failed"
        );

        let id = p256_identity();
        let pk_der = id.public_key().unwrap();
        let (alg, pk) = user_public_key_from_der(&pk_der).unwrap();
        assert!(verify_basic_sig(alg, &pk, MESSAGE, &[]).is_err());

        let id = secp256k1_identity();
        let pk_der = id.public_key().unwrap();
        let (alg, pk) = user_public_key_from_der(&pk_der).unwrap();
        assert!(verify_basic_sig(alg, &pk, MESSAGE, &[]).is_err());

        assert!(verify_basic_sig(Algorithm::EcdsaP256, &[0], MESSAGE, &[]).is_err());
        assert!(verify_basic_sig(Algorithm::EcdsaSecp256k1, &[0], MESSAGE, &[]).is_err());
    }
}
