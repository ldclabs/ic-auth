/// Lite version of `ic-crypto-standalone-sig-verifier`
/// Original source: https://github.com/dfinity/ic/blob/master/rs/crypto/standalone-sig-verifier/src/sign_utils.rs
use serde::{Deserialize, Serialize};
use simple_asn1::{ASN1Block, OID, from_der, oid};

#[allow(non_camel_case_types)]
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    IcCanisterSignature,
    Ed25519,
    EcdsaP256,
    EcdsaSecp256k1,
}

/// Parses the given `data` as a DER-encoded public key
pub fn user_public_key_from_der(data: &[u8]) -> Result<(Algorithm, Vec<u8>), String> {
    let mut parts = from_der(data).map_err(|err| format!("Error in DER encoding: {err}"))?;
    if parts.len() != 1 {
        return Err("Expected exactly one ASN.1 block".to_string());
    }
    let mut key_seq = if let ASN1Block::Sequence(_offset, part) = parts.remove(0) {
        part
    } else {
        return Err("Expected an ASN.1 sequence".to_string());
    };

    if key_seq.len() != 2 {
        return Err("Expected exactly two ASN.1 blocks".to_string());
    }

    let pk_bytes = public_key_bytes(key_seq.pop().unwrap())?;
    let algo_id = algorithm_identifier(key_seq.pop().unwrap())?;
    if algo_id == PkixAlgorithmIdentifier::iccsa() {
        return Ok((Algorithm::IcCanisterSignature, pk_bytes));
    } else if algo_id == PkixAlgorithmIdentifier::ed25519() {
        return Ok((Algorithm::Ed25519, pk_bytes));
    } else if algo_id == PkixAlgorithmIdentifier::ecdsa_secp256k1() {
        return Ok((Algorithm::EcdsaSecp256k1, pk_bytes));
    } else if algo_id == PkixAlgorithmIdentifier::ecdsa_secp256r1() {
        return Ok((Algorithm::EcdsaP256, pk_bytes));
    }

    Err(format!("Unsupported algorithm: {algo_id:?}"))
}

/// An AlgorithmIdentifier as described in RFC 5480
#[derive(Clone, Eq, PartialEq, Debug)]
struct PkixAlgorithmIdentifier {
    pub oid: OID,
    pub params: Option<PkixAlgorithmParameters>,
}

impl PkixAlgorithmIdentifier {
    fn iccsa() -> Self {
        Self {
            oid: oid!(1, 3, 6, 1, 4, 1, 56387, 1, 2),
            params: None,
        }
    }

    fn ed25519() -> Self {
        Self {
            oid: oid!(1, 3, 101, 112),
            params: None,
        }
    }

    fn ecdsa_secp256k1() -> Self {
        Self {
            oid: oid!(1, 2, 840, 10045, 2, 1),
            params: Some(PkixAlgorithmParameters::ObjectIdentifier(oid!(
                1, 3, 132, 0, 10
            ))),
        }
    }

    fn ecdsa_secp256r1() -> Self {
        Self {
            oid: oid!(1, 2, 840, 10045, 2, 1),
            params: Some(PkixAlgorithmParameters::ObjectIdentifier(oid!(
                1, 2, 840, 10045, 3, 1, 7
            ))),
        }
    }
}

/// The parameters of an AlgorithmIdentifier as described in RFC 5480
///
/// This enum can be extended to support alternate types as required
/// when different algorithms are implemented
#[derive(Clone, Eq, PartialEq, Debug)]
enum PkixAlgorithmParameters {
    /// An ASN.1 object identifier
    ObjectIdentifier(OID),
    /// An ASN.1 explicit NULL
    Null,
}

/// Retrieves PkixAlgorithmIdentifier from the given ASN1Block.
fn algorithm_identifier(oid_seq: ASN1Block) -> Result<PkixAlgorithmIdentifier, String> {
    // PkixAlgorithmIdentifier is a pair of an OID plus anything (or nothing)
    // whose type depends on the leading OID. However in our current usage
    // the second parameter is always either absent or a second OID
    if let ASN1Block::Sequence(_offset_oid, oid_parts) = oid_seq {
        if oid_parts.len() == 1 || oid_parts.len() == 2 {
            let algo_oid = oid_parts
                .first()
                .expect("Missing OID from algorithm identifier");
            let algo_params = oid_parts.get(1);

            match (algo_oid, algo_params) {
                (ASN1Block::ObjectIdentifier(_, algo_oid), Some(ASN1Block::Null(_))) => {
                    Ok(PkixAlgorithmIdentifier {
                        oid: algo_oid.clone(),
                        params: Some(PkixAlgorithmParameters::Null),
                    })
                }
                (
                    ASN1Block::ObjectIdentifier(_, algo_oid),
                    Some(ASN1Block::ObjectIdentifier(_, algo_params)),
                ) => Ok(PkixAlgorithmIdentifier {
                    oid: algo_oid.clone(),
                    params: Some(PkixAlgorithmParameters::ObjectIdentifier(
                        algo_params.clone(),
                    )),
                }),
                (ASN1Block::ObjectIdentifier(_, algo_oid), None) => Ok(PkixAlgorithmIdentifier {
                    oid: algo_oid.clone(),
                    params: None,
                }),
                (_, _) => Err("Algorithm identifier has unexpected type".to_string()),
            }
        } else {
            Err("Algorithm identifier has unexpected size".to_string())
        }
    } else {
        Err("Expected algorithm identifier".to_string())
    }
}

/// Retrieves raw public key bytes from the given ASN1Block.
fn public_key_bytes(key_part: ASN1Block) -> Result<Vec<u8>, String> {
    if let ASN1Block::BitString(_offset, bits_count, key_bytes) = key_part {
        if bits_count != key_bytes.len() * 8 {
            return Err("Inconsistent key length".to_string());
        }
        Ok(key_bytes)
    } else {
        Err(format!("Expected BitString, got {:?}", key_part))
    }
}
