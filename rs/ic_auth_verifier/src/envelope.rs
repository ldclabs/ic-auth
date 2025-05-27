use base64::{
    Engine,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use candid::{CandidType, Principal};
use ciborium::{from_reader, into_writer};
use http::header::{AUTHORIZATION, HeaderMap, HeaderName};
use ic_auth_types::{ByteBufB64, DelegationCompact, SignedDelegation, SignedDelegationCompact};
use ic_canister_sig_creation::delegation_signature_msg;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "sign")]
use ic_agent::Identity;

use crate::{Algorithm, sha3_256, user_public_key_from_der, verify_basic_sig};

pub use ic_signature_verification::verify_canister_sig;

/// The Internet Computer's anonymous principal identifier.
/// This is used when no authenticated identity is provided.
pub const ANONYMOUS_PRINCIPAL: Principal = Principal::anonymous();

/// Maximum allowed time drift in milliseconds for delegation verification.
/// This prevents replay attacks while allowing for reasonable clock differences.
pub const PERMITTED_DRIFT_MS: u64 = 60 * 1000;

/// The IC root public key used when verifying canister signatures.
/// This is the official Internet Computer root public key used to verify the authenticity
/// of canister signatures across the IC network.
/// For more information, see:
/// https://internetcomputer.org/docs/current/developer-docs/web-apps/obtain-verify-ic-pubkey
pub const IC_ROOT_PUBLIC_KEY_RAW: &[u8; 96] = &[
    129, 76, 14, 110, 199, 31, 171, 88, 59, 8, 189, 129, 55, 60, 37, 92, 60, 55, 27, 46, 132, 134,
    60, 152, 164, 241, 224, 139, 116, 35, 93, 20, 251, 93, 156, 12, 213, 70, 217, 104, 95, 145, 58,
    12, 11, 44, 197, 52, 21, 131, 191, 75, 67, 146, 228, 103, 219, 150, 214, 91, 155, 180, 203,
    113, 113, 18, 248, 71, 46, 13, 90, 77, 20, 80, 95, 253, 116, 132, 176, 18, 145, 9, 28, 95, 135,
    185, 136, 131, 70, 63, 152, 9, 26, 11, 170, 174,
];

/// HTTP header for the caller's public key used in authentication.
/// This header contains the base64url-encoded public key of the caller.
pub static HEADER_IC_AUTH_PUBKEY: HeaderName = HeaderName::from_static("ic-auth-pubkey");

/// HTTP header for the request content hash.
/// This header contains a base64url-encoded hash of the request content,
/// which can be customized based on business logic requirements.
pub static HEADER_IC_AUTH_CONTENT_DIGEST: HeaderName =
    HeaderName::from_static("ic-auth-content-digest");

/// HTTP header for the signature of the content digest.
/// This header contains a base64url-encoded cryptographic signature
/// that proves the authenticity of the content digest.
pub static HEADER_IC_AUTH_SIGNATURE: HeaderName = HeaderName::from_static("ic-auth-signature");

/// HTTP header for the delegation chain used in authentication.
/// This header contains a base64url-encoded CBOR representation of the delegation chain
/// that connects the public key to the signature.
pub static HEADER_IC_AUTH_DELEGATION: HeaderName = HeaderName::from_static("ic-auth-delegation");

/// HTTP header for the authenticated user principal.
/// This header contains the textual representation of the authenticated user's principal ID,
/// or the anonymous principal if authentication fails or is not provided.
pub static HEADER_IC_AUTH_USER: HeaderName = HeaderName::from_static("ic-auth-user");

/// Verifies a signature using the public key and the mainnet IC root public key.
///
/// # Arguments
/// * `public_key` - The DER-encoded public key to verify against
/// * `msg` - The message that was signed
/// * `signature` - The signature to verify
///
/// # Returns
/// * `Ok(())` if the signature is valid
/// * `Err(String)` with an error message if verification fails
pub fn verify_sig(public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<(), String> {
    verify_sig_with_rootkey(IC_ROOT_PUBLIC_KEY_RAW, public_key, msg, signature)
}

/// Verifies a signature using the public key and a specified IC root public key.
/// This function allows verification against different IC networks by providing
/// a custom root public key.
///
/// # Arguments
/// * `ic_root_public_key_raw` - The raw IC root public key to use for verification
/// * `public_key` - The DER-encoded public key to verify against
/// * `msg` - The message that was signed
/// * `signature` - The signature to verify
///
/// # Returns
/// * `Ok(())` if the signature is valid
/// * `Err(String)` with an error message if verification fails
pub fn verify_sig_with_rootkey(
    ic_root_public_key_raw: &[u8],
    public_key: &[u8],
    msg: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let (alg, pk) = user_public_key_from_der(public_key)?;
    match alg {
        Algorithm::IcCanisterSignature => {
            verify_canister_sig(msg, signature, public_key, ic_root_public_key_raw)
        }
        _ => verify_basic_sig(alg, &pk, msg, signature),
    }
}

/// The authentication envelope for Internet Computer authentication.
///
/// This structure encapsulates all the necessary components for authenticating
/// a request to an Internet Computer service. It includes the public key of the
/// sender, the signature, the content digest, and an optional delegation chain.
///
/// The envelope can be serialized to and from various formats, including bytes,
/// base64 strings, and HTTP headers, making it versatile for different transport
/// mechanisms.
#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct SignedEnvelope {
    /// The public key of the self-authenticating principal this request is from.
    /// This is the head of the delegation chain (if any) and is used to derive
    /// the principal ID of the sender.
    #[serde(rename = "p", alias = "pubkey")]
    pub pubkey: ByteBufB64,

    /// A cryptographic signature authorizing the request.
    /// When delegations are involved, this is the signature from the tail of the
    /// delegation chain, not necessarily made by the owner of `pubkey`.
    #[serde(rename = "s", alias = "signature")]
    pub signature: ByteBufB64,

    /// The request content's hash digest that was signed by the sender.
    /// This is typically a SHA-256 or SHA3-256 hash of the request content.
    #[serde(rename = "h", alias = "digest")]
    pub digest: ByteBufB64,

    /// The chain of delegations connecting `pubkey` to `signature`, in order.
    /// Each delegation authorizes the next entity in the chain to sign on behalf
    /// of the previous entity, forming a chain of trust from the original identity
    /// to the actual signer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "d", alias = "delegation")]
    pub delegation: Option<Vec<SignedDelegationCompact>>,
}

impl SignedEnvelope {
    /// Returns the sender's principal ID derived from the public key.
    ///
    /// This computes a self-authenticating principal ID based on the public key
    /// in the envelope, which uniquely identifies the sender.
    ///
    /// # Returns
    /// * `Principal` - The principal ID of the sender
    pub fn sender(&self) -> Principal {
        Principal::self_authenticating(&self.pubkey)
    }

    /// Encodes the SignedEnvelope into a binary representation.
    ///
    /// # Returns
    /// * `Vec<u8>` - The CBOR-encoded binary representation of the envelope
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        into_writer(self, &mut buf).expect("failed to encode SignedEnvelope");
        buf
    }

    /// Decodes a SignedEnvelope from its binary representation.
    ///
    /// # Arguments
    /// * `bytes` - The CBOR-encoded binary representation of the envelope
    ///
    /// # Returns
    /// * `Result<Self, String>` - The decoded envelope or an error message
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        from_reader(bytes).map_err(|err| format!("failed to decode SignedEnvelope data: {err:?}"))
    }

    /// Encodes the SignedEnvelope into a base64url string.
    ///
    /// # Returns
    /// * `String` - The base64url-encoded representation of the envelope
    pub fn to_base64(&self) -> String {
        URL_SAFE.encode(self.to_bytes())
    }

    /// Decodes a SignedEnvelope from a base64url string.
    ///
    /// # Arguments
    /// * `s` - The base64url-encoded string representation of the envelope
    ///
    /// # Returns
    /// * `Result<Self, String>` - The decoded envelope or an error message
    pub fn from_base64(s: &str) -> Result<Self, String> {
        decode_base64(s).and_then(|data| Self::from_bytes(&data))
    }

    /// Creates a SignedEnvelope by signing a message with the provided identity.
    ///
    /// This computes the SHA3-256 hash of the message and signs it with the identity.
    ///
    /// # Arguments
    /// * `identity` - The identity to sign with, implementing the `Identity` trait
    /// * `message` - The message to sign
    ///
    /// # Returns
    /// * `Result<Self, String>` - The signed envelope or an error message
    #[cfg(feature = "sign")]
    pub fn sign_message(identity: &impl Identity, message: &[u8]) -> Result<Self, String> {
        Self::sign_digest(identity, sha3_256(message).into())
    }

    /// Creates a SignedEnvelope by signing a pre-computed digest with the provided identity.
    ///
    /// # Arguments
    /// * `identity` - The identity to sign with, implementing the `Identity` trait
    /// * `digest` - The pre-computed digest to sign
    ///
    /// # Returns
    /// * `Result<Self, String>` - The signed envelope or an error message
    #[cfg(feature = "sign")]
    pub fn sign_digest(identity: &impl Identity, digest: Vec<u8>) -> Result<Self, String> {
        let sig = identity
            .sign_arbitrary(&digest)
            .map_err(|err| format!("{:?}", err))?;
        let envelope = Self {
            pubkey: sig
                .public_key
                .ok_or_else(|| "missing public_key".to_string())?
                .into(),
            signature: sig
                .signature
                .ok_or_else(|| "missing signature".to_string())?
                .into(),
            digest: digest.into(),
            delegation: sig.delegations.map(|delegations| {
                delegations
                    .into_iter()
                    .map(|d| SignedDelegationCompact {
                        delegation: DelegationCompact {
                            pubkey: d.delegation.pubkey.into(),
                            expiration: d.delegation.expiration,
                            targets: d.delegation.targets,
                        },
                        signature: d.signature.into(),
                    })
                    .collect::<Vec<_>>()
            }),
        };
        Ok(envelope)
    }

    /// Verifies the SignedEnvelope according to the Internet Computer authentication rules.
    ///
    /// Verification rules:
    /// - Delegation chain length must not exceed 5
    /// - Delegations must not be expired (considering the permitted time drift)
    /// - Each signature in the chain must verify against the corresponding public key
    /// - If delegation targets are specified, the expected target must be included
    /// - The content digest must match the expected digest (if provided)
    ///
    /// # Arguments
    /// * `now_ms` - The current time in milliseconds since the Unix epoch
    /// * `expect_target` - Optional canister ID that should be in the delegation targets
    /// * `expect_digest` - Optional expected content digest to verify against
    ///
    /// # Returns
    /// * `Ok(())` if verification succeeds
    /// * `Err(String)` with a detailed error message if verification fails
    pub fn verify(
        &self,
        now_ms: u64,
        expect_target: Option<Principal>,
        expect_digest: Option<&[u8]>,
    ) -> Result<(), String> {
        if let Some(expect_digest) = expect_digest {
            if self.digest.as_ref() != expect_digest {
                return Err("Content digest does not match".to_string());
            }
        }

        let mut last_verified = &self.pubkey;
        if let Some(delegation) = &self.delegation {
            if delegation.is_empty() {
                return Err("Delegation chain is empty".to_string());
            }
            if delegation.len() > 5 {
                return Err(format!(
                    "Delegation chain length exceeds the limit 5: {}",
                    delegation.len()
                ));
            }

            for d in delegation {
                if d.delegation.expiration / 1_000_000 < now_ms - PERMITTED_DRIFT_MS {
                    return Err(format!(
                        "Delegation has expired:\n\
                         Provided expiry:    {}\n\
                         Local replica timestamp: {}",
                        d.delegation.expiration,
                        now_ms * 1_000_000,
                    ));
                }

                let targets = match &d.delegation.targets {
                    Some(targets) => {
                        if let Some(target) = &expect_target {
                            // Should check if the expected target is in the delegation targets
                            if !targets.contains(target) {
                                return Err(format!(
                                    "Expected target canister ID '{expect_target:?}' is not in the delegation targets: {:?}",
                                    targets
                                ));
                            }
                        }
                        Some(
                            targets
                                .iter()
                                .map(|p| p.as_slice().to_vec())
                                .collect::<Vec<Vec<u8>>>(),
                        )
                    }
                    None => None,
                };

                let msg = delegation_signature_msg(
                    d.delegation.pubkey.as_slice(),
                    d.delegation.expiration,
                    targets.as_ref(),
                );
                verify_sig(last_verified, &msg, &d.signature)?;

                last_verified = &d.delegation.pubkey;
            }
        }

        verify_sig(last_verified, &self.digest, &self.signature)
    }

    /// Extracts a SignedEnvelope from the Authorization header.
    ///
    /// This looks for an "ICP" authentication scheme in the Authorization header
    /// and decodes the associated token as a SignedEnvelope.
    ///
    /// # Arguments
    /// * `headers` - The HTTP headers to extract from
    ///
    /// # Returns
    /// * `Option<Self>` - The extracted envelope, or None if not found or invalid
    pub fn from_authorization(headers: &HeaderMap) -> Option<Self> {
        if let Some(token) = headers.get(AUTHORIZATION) {
            if let Ok(token) = token.to_str() {
                if let Some(token) = token.strip_prefix("ICP ") {
                    if let Ok(envelope) = Self::from_base64(token) {
                        return Some(envelope);
                    }
                }
            }
        }
        None
    }

    /// Adds the SignedEnvelope to the Authorization header.
    ///
    /// This encodes the envelope as a base64url string and adds it to the
    /// Authorization header with the "ICP" authentication scheme.
    ///
    /// # Arguments
    /// * `headers` - The HTTP headers to add to
    ///
    /// # Returns
    /// * `Result<(), String>` - Success or an error message if adding fails
    pub fn to_authorization(&self, headers: &mut HeaderMap) -> Result<(), String> {
        headers.insert(
            AUTHORIZATION,
            format!("ICP {}", self.to_base64())
                .parse()
                .map_err(|err| format!("insert {AUTHORIZATION} header failed: {err}"))?,
        );
        Ok(())
    }

    /// Extracts a SignedEnvelope from the IC-Auth-* HTTP headers.
    ///
    /// This looks for the individual components of the envelope in separate headers
    /// and reconstructs the envelope from them.
    ///
    /// # Arguments
    /// * `headers` - The HTTP headers to extract from
    ///
    /// # Returns
    /// * `Option<Self>` - The extracted envelope, or None if not found or invalid
    pub fn from_headers(headers: &HeaderMap) -> Option<Self> {
        if let Some(pubkey) = extract_data(headers, &HEADER_IC_AUTH_PUBKEY) {
            if let Some(digest) = extract_data(headers, &HEADER_IC_AUTH_CONTENT_DIGEST) {
                if let Some(signature) = extract_data(headers, &HEADER_IC_AUTH_SIGNATURE) {
                    let mut envelope = Self {
                        pubkey: pubkey.into(),
                        signature: signature.into(),
                        digest: digest.into(),
                        delegation: None,
                    };
                    match extract_data(headers, &HEADER_IC_AUTH_DELEGATION) {
                        Some(data) => {
                            if let Ok(delegation) = from_reader(&data[..]) {
                                envelope.delegation = Some(delegation);
                                return Some(envelope);
                            }
                        }
                        None => return Some(envelope),
                    }
                }
            }
        }

        None
    }

    /// Adds the SignedEnvelope components to the IC-Auth-* HTTP headers.
    ///
    /// This breaks down the envelope into its components and adds each one
    /// to a separate HTTP header.
    ///
    /// # Arguments
    /// * `headers` - The HTTP headers to add to
    ///
    /// # Returns
    /// * `Result<(), String>` - Success or an error message
    pub fn to_headers(&self, headers: &mut HeaderMap) -> Result<(), String> {
        headers.insert(
            &HEADER_IC_AUTH_PUBKEY,
            URL_SAFE_NO_PAD
                .encode(&self.pubkey)
                .parse()
                .map_err(|err| format!("insert {HEADER_IC_AUTH_PUBKEY} header failed: {err}"))?,
        );
        headers.insert(
            &HEADER_IC_AUTH_CONTENT_DIGEST,
            URL_SAFE_NO_PAD
                .encode(&self.digest)
                .parse()
                .map_err(|err| {
                    format!("insert {HEADER_IC_AUTH_CONTENT_DIGEST} header failed: {err}")
                })?,
        );
        headers.insert(
            &HEADER_IC_AUTH_SIGNATURE,
            URL_SAFE_NO_PAD
                .encode(&self.signature)
                .parse()
                .map_err(|err| format!("insert {HEADER_IC_AUTH_SIGNATURE} header failed: {err}"))?,
        );
        if let Some(delegations) = &self.delegation {
            headers.insert(
                &HEADER_IC_AUTH_DELEGATION,
                URL_SAFE_NO_PAD
                    .encode(to_cbor_bytes(&delegations))
                    .parse()
                    .map_err(|err| {
                        format!("insert {HEADER_IC_AUTH_DELEGATION} header failed: {err}")
                    })?,
            );
        }
        Ok(())
    }
}

/// Verifies a delegation chain.
///
/// This function checks the validity of a chain of signed delegations,
/// ensuring that each delegation is not expired, and that the signatures
/// are valid according to the provided IC root public key.
///
/// # Arguments
/// * `user_pubkey` - The der public key of the user to sign the delegation chain
/// * `session_pubkey` - The public key of the session to verify against
/// * `delegations` - The chain of signed delegations to verify
/// * `now_ms` - The current time in milliseconds since the Unix epoch
/// * `ic_root_public_key_raw` - Optional raw IC root public key for signature verification
pub fn verify_delegation_chain(
    user_pubkey: &[u8],
    session_pubkey: &[u8],
    delegations: &[SignedDelegationCompact],
    now_ms: u64,
    ic_root_public_key_raw: Option<&[u8]>,
) -> Result<(), String> {
    if delegations.is_empty() {
        return Err("Delegation chain is empty".to_string());
    }

    let ic_root_public_key_raw = ic_root_public_key_raw.unwrap_or(IC_ROOT_PUBLIC_KEY_RAW);
    let mut last_verified = user_pubkey;
    for d in delegations {
        if d.delegation.expiration / 1_000_000 < now_ms - PERMITTED_DRIFT_MS {
            return Err(format!(
                "Delegation has expired:\n\
                         Provided expiry:    {}\n\
                         Local replica timestamp: {}",
                d.delegation.expiration,
                now_ms * 1_000_000,
            ));
        }

        let msg = delegation_signature_msg(
            d.delegation.pubkey.as_slice(),
            d.delegation.expiration,
            d.delegation
                .targets
                .as_ref()
                .map(|targets| {
                    targets
                        .iter()
                        .map(|p| p.as_slice().to_vec())
                        .collect::<Vec<Vec<u8>>>()
                })
                .as_ref(),
        );

        verify_sig_with_rootkey(ic_root_public_key_raw, last_verified, &msg, &d.signature)?;

        last_verified = &d.delegation.pubkey;
    }
    if last_verified != session_pubkey {
        return Err(format!(
            "Last verified public key does not match session public key:\n\
             Last verified: {}\n\
             Session public key: {}",
            const_hex::encode(last_verified),
            const_hex::encode(session_pubkey)
        ));
    }

    Ok(())
}

/// Extracts base64url-encoded data from an HTTP header.
///
/// # Arguments
/// * `headers` - The HTTP headers to extract from
/// * `key` - The name of the header to extract
///
/// # Returns
/// * `Option<Vec<u8>>` - The decoded data, or None if not found or invalid
pub fn extract_data(headers: &HeaderMap, key: &HeaderName) -> Option<Vec<u8>> {
    if let Some(val) = headers.get(key) {
        if let Ok(val) = val.to_str() {
            if let Ok(data) = decode_base64(val) {
                return Some(data);
            }
        }
    }
    None
}

/// Extracts the authenticated user principal from the HTTP headers.
///
/// This looks for the IC-Auth-User header and parses it as a Principal.
/// If the header is not found or invalid, it returns the anonymous principal.
///
/// # Arguments
/// * `headers` - The HTTP headers to extract from
///
/// # Returns
/// * `Principal` - The authenticated user principal or anonymous principal
pub fn extract_user(headers: &HeaderMap) -> Principal {
    if let Some(caller) = headers.get(&HEADER_IC_AUTH_USER) {
        if let Ok(caller) = Principal::from_text(caller.to_str().unwrap_or_default()) {
            caller
        } else {
            ANONYMOUS_PRINCIPAL
        }
    } else {
        ANONYMOUS_PRINCIPAL
    }
}

/// Encodes an object into CBOR binary format.
///
/// # Arguments
/// * `obj` - The object to encode, which must implement the Serialize trait
///
/// # Returns
/// * `Vec<u8>` - The CBOR-encoded binary representation of the object
///
/// # Panics
/// * If encoding fails
pub fn to_cbor_bytes(obj: &impl Serialize) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    into_writer(obj, &mut buf).expect("failed to encode in CBOR format");
    buf
}

/// Decodes base64url-encoded data.
///
/// This function handles both padded and unpadded base64url data.
///
/// # Arguments
/// * `data` - The base64url-encoded string to decode
///
/// # Returns
/// * `Result<Vec<u8>, String>` - The decoded data or an error message
pub fn decode_base64(data: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(data.trim().trim_end_matches('='))
        .map_err(|err| format!("failed to decode base64 data: {err}"))
}

/// SignedEnvelopeFull is a full representation of the SignedEnvelope.
/// It includes the full field names for serialization and deserialization.
#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct SignedEnvelopeFull {
    #[serde(alias = "p")]
    pub pubkey: ByteBufB64,

    #[serde(alias = "s")]
    pub signature: ByteBufB64,

    #[serde(alias = "h")]
    pub digest: ByteBufB64,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(alias = "d")]
    pub delegation: Option<Vec<SignedDelegation>>,
}

impl From<SignedEnvelope> for SignedEnvelopeFull {
    fn from(envelope: SignedEnvelope) -> Self {
        Self {
            pubkey: envelope.pubkey,
            signature: envelope.signature,
            digest: envelope.digest,
            delegation: envelope
                .delegation
                .map(|delegations| delegations.into_iter().map(Into::into).collect()),
        }
    }
}

impl From<SignedEnvelopeFull> for SignedEnvelope {
    fn from(envelope: SignedEnvelopeFull) -> Self {
        Self {
            pubkey: envelope.pubkey,
            signature: envelope.signature,
            digest: envelope.digest,
            delegation: envelope
                .delegation
                .map(|delegations| delegations.into_iter().map(Into::into).collect()),
        }
    }
}

/// Returns the current Unix timestamp in milliseconds.
///
/// # Returns
/// * `u64` - The number of milliseconds since the Unix epoch
///
/// # Panics
/// * If the system time is before the Unix epoch
#[inline]
pub fn unix_ms() -> u64 {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch");
    ts.as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_consensus::SigningKey;
    use ic_agent::{Identity, identity::BasicIdentity};
    use ic_canister_sig_creation::CanisterSigPublicKey;

    #[test]
    fn test_envelope_with_ed25519() {
        let secret = [8u8; 32];
        let sk = SigningKey::from(secret);
        let id = BasicIdentity::from_signing_key(sk);
        println!("id: {:?}", id.sender().unwrap().to_text());
        // jjn6g-sh75l-r3cxb-wxrkl-frqld-6p6qq-d4ato-wske5-op7s5-n566f-bqe

        let msg = b"hello world";
        let mut headers = HeaderMap::new();
        let se = SignedEnvelope::sign_message(&id, msg).unwrap();
        se.to_headers(&mut headers).unwrap();

        let mut se2 = SignedEnvelope::from_headers(&headers).unwrap();
        assert!(se2.verify(unix_ms(), None, None).is_ok());

        se2.digest = sha3_256(b"hello world 2").to_vec().into();
        assert!(se2.verify(unix_ms(), None, None).is_err());
    }

    #[test]
    fn test_envelope_with_iccsa() {
        let msg =
            const_hex::decode("086c81b03b34184d2365b88a7d94ad9cc0f4e98970b6c10068aae4e407333339")
                .unwrap();
        let sig =
            const_hex::decode("d9d9f7a26b636572746966696361746558a1d9d9f7a26474726565830183024863616e697374657283024a0000000000000001010183024e6365727469666965645f646174618203582053e3b19ab292296b52b451b0662af2d86ac707569b39825fc31f62aca41406d483024474696d6582034387ad4b697369676e61747572655830a95766af95898e1c8492de7b7d9e6c601ea9d9958113f6c0491ef044ed5ebb03d31983abfa40ebbef7068ebaf7e66f05647472656583024373696783025820591047009df12cb39741d672f270045fd15beec2b0b84c1d71bda98b758726cd83025820d37372239856cdf2ae158e5ac365f15501a9e5612a970ddd7b3199c522b54194820340")
                .unwrap();
        let pk_der =
            const_hex::decode("303c300c060a2b0601040183b8430102032c000a000000000000000101011f809d0136deeed8e0187447d20ac0e13e0201e1dede8c437eada3e8dc349f85")
                .unwrap();
        let root =
            const_hex::decode("b90210504fe157d1df412e500ced967ef794dc7aa88c84d764b74b6bc2cf0e575d79f331927df062240c88a28e1802c60b407c7bce541b50310d775919bcd0f799222c3738bc3bcc8bf05af5f52ee2afec54c460bda35c6c379267924db2d374")
                .unwrap();
        let (alg, _pk) = user_public_key_from_der(&pk_der).unwrap();
        assert_eq!(alg, Algorithm::IcCanisterSignature);

        let cspk = CanisterSigPublicKey::try_from(pk_der.as_slice()).unwrap();
        println!("canister_id: {}", cspk.canister_id.to_text());
        // canister_id: rrkah-fqaaa-aaaaa-aaaaq-cai

        let res = verify_sig_with_rootkey(&root, &pk_der, &msg, &sig);
        assert!(res.is_ok());
    }
}
