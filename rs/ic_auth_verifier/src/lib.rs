use k256::ecdsa::signature::hazmat::PrehashVerifier;
use sha3::Digest;

mod asn1;

#[cfg(feature = "envelope")]
pub mod envelope;

#[cfg(feature = "envelope")]
pub mod deeplink;

#[cfg(feature = "identity")]
pub mod identity;

pub use asn1::*;
pub use ic_canister_sig_creation::CanisterSigPublicKey;

#[cfg(feature = "envelope")]
pub use envelope::*;

#[cfg(feature = "envelope")]
pub use deeplink::*;

#[cfg(feature = "identity")]
pub use identity::*;

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

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha3::Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(feature = "identity")]
pub fn rand_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;

    let mut rng = rand::rng();
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_consensus::SigningKey as Ed25519SigningKey;
    use ic_agent::{
        Identity,
        identity::{BasicIdentity, Prime256v1Identity, Secp256k1Identity},
    };
    use rand::{RngCore, rng};

    const MESSAGE: &[u8] = b"some message";

    fn rand_bytes<const N: usize>() -> [u8; N] {
        let mut rng = rng();
        let mut bytes = [0u8; N];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    #[test]
    fn should_work_with_ed25519() {
        let sk: [u8; 32] = rand_bytes();
        let sk = Ed25519SigningKey::from(sk);
        let id = BasicIdentity::from_signing_key(sk);
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

        let sk: [u8; 32] = rand_bytes();
        let sk = k256::ecdsa::SigningKey::from_bytes(&sk.into()).unwrap();
        let id = Secp256k1Identity::from_private_key(sk.into());
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

        let sk: [u8; 32] = rand_bytes();
        let sk = p256::ecdsa::SigningKey::from_bytes(&sk.into()).unwrap();
        let id = Prime256v1Identity::from_private_key(sk.into());
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
}
