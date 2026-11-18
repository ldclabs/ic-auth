use serde::{Deserialize, Serialize};
use spki::{ObjectIdentifier, SubjectPublicKeyInfoRef, der::Decode};

const IC_CANISTER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.56387.1.2");
const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const SECP256K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// Public-key algorithms recognized in IC identity DER public keys.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    /// Internet Computer canister signature public key.
    IcCanisterSignature,
    /// Ed25519 public key.
    Ed25519,
    /// ECDSA over the NIST P-256 curve, also known as secp256r1.
    EcdsaP256,
    /// ECDSA over the secp256k1 curve.
    EcdsaSecp256k1,
}

/// Parses a DER SubjectPublicKeyInfo public key.
///
/// For basic signatures, pass the returned raw bytes to [`crate::verify_basic_sig`].
/// The public canister signature verifier accepts the original DER key.
pub fn user_public_key_from_der(data: &[u8]) -> Result<(Algorithm, Vec<u8>), String> {
    let (algorithm, key) = parse_public_key(data)?;
    Ok((algorithm, key.to_vec()))
}

pub(crate) fn parse_public_key(data: &[u8]) -> Result<(Algorithm, &[u8]), String> {
    let spki = SubjectPublicKeyInfoRef::from_der(data)
        .map_err(|err| format!("Error in DER encoding: {err}"))?;
    let identifier = spki.algorithm;
    let algorithm = match (identifier.oid, identifier.parameters) {
        (IC_CANISTER, None) => Algorithm::IcCanisterSignature,
        (ED25519, None) => Algorithm::Ed25519,
        (EC_PUBLIC_KEY, Some(curve)) => match curve.decode_as::<ObjectIdentifier>() {
            Ok(SECP256K1) => Algorithm::EcdsaSecp256k1,
            Ok(SECP256R1) => Algorithm::EcdsaP256,
            _ => return Err("Unsupported EC curve".into()),
        },
        _ => return Err(format!("Unsupported algorithm: {}", identifier.oid)),
    };
    let key = spki
        .subject_public_key
        .as_bytes()
        .ok_or("Inconsistent key length")?;
    Ok((algorithm, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_public_key_from_der() {
        let data = hex::decode("303C300C060A2B0601040183B8430102032C000A0000000000000007010116FB513D360579FA1102D36E3BC8D53FB966F3AC9F717842B2B54C227582D786").unwrap();
        let (algo, pk) = user_public_key_from_der(&data).unwrap();
        println!("Algorithm: {algo:?}");
        assert_eq!(algo, Algorithm::IcCanisterSignature);
        assert_eq!(pk.len(), 43);

        let data = hex::decode("302A300506032B65700321004258A79844B5BC3089D6467A2CA67DA33EAB4A96ADCD93E72349B75C0A4C5219").unwrap();
        let (algo, pk) = user_public_key_from_der(&data).unwrap();
        println!("Algorithm: {algo:?}");
        assert_eq!(algo, Algorithm::Ed25519);
        assert_eq!(pk.len(), 32);
    }

    #[test]
    fn test_user_public_key_from_der_rejects_malformed_data() {
        for (case, encoded) in [
            ("truncated DER", "ff"),
            ("top-level integer", "020100"),
            ("two top-level items", "020100020101"),
            ("empty sequence", "3000"),
            ("missing key", "3003020100"),
            ("missing algorithm sequence", "3006020100030100"),
            ("integer algorithm identifier", "30083003020100030100"),
            (
                "extra algorithm parameter",
                "300e300906032b657005000500030100",
            ),
            ("key is not a bit string", "3009300506032b65700500"),
            ("trailing data", "300a300506032b657003010000"),
        ] {
            assert!(
                user_public_key_from_der(&hex::decode(encoded).unwrap()).is_err(),
                "{case}"
            );
        }
    }

    #[test]
    fn test_user_public_key_from_der_rejects_unsupported_algorithm() {
        let unsupported_key_info = hex::decode("300e300906052b0e03021a0500030100").unwrap();
        assert!(
            user_public_key_from_der(&unsupported_key_info)
                .unwrap_err()
                .contains("Unsupported algorithm")
        );
    }

    #[test]
    fn algorithms_require_matching_parameters_and_byte_aligned_keys() {
        // Ed25519 with explicit NULL and EC without a named curve are unsupported.
        for encoded in [
            "300c300706032b65700500030100",
            "300e300906072a8648ce3d0201030100",
        ] {
            assert!(user_public_key_from_der(&hex::decode(encoded).unwrap()).is_err());
        }
        let unaligned = hex::decode("300b300506032b657003020100").unwrap();
        assert_eq!(
            user_public_key_from_der(&unaligned).unwrap_err(),
            "Inconsistent key length"
        );
    }
}
