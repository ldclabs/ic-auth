use base64::{
    Engine,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use candid::{CandidType, Principal};
use ciborium::from_reader;
use http::header::{AUTHORIZATION, HeaderMap, HeaderName};
use ic_auth_types::{
    ByteBufB64, DelegationCompact, SignedDelegation, SignedDelegationCompact,
    canonical_cbor_into_vec,
};
use ic_canister_sig_creation::delegation_signature_msg;
use serde::{Deserialize, Serialize};

#[cfg(feature = "identity")]
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

pub const IC_REQUEST_AUTH_DELEGATION_DOMAIN_SEPARATOR: &[u8] = b"\x1Aic-request-auth-delegation";

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
        canonical_cbor_into_vec(&self).expect("failed to encode SignedEnvelope")
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
    #[cfg(feature = "identity")]
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
    #[cfg(feature = "identity")]
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
                let mut message = Vec::with_capacity(
                    IC_REQUEST_AUTH_DELEGATION_DOMAIN_SEPARATOR.len() + msg.len(),
                );
                message.extend_from_slice(IC_REQUEST_AUTH_DELEGATION_DOMAIN_SEPARATOR);
                message.extend(msg);
                verify_sig(last_verified, &message, &d.signature)?;

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
                    .encode(canonical_cbor_into_vec(&delegations)?)
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
        let mut message =
            Vec::with_capacity(IC_REQUEST_AUTH_DELEGATION_DOMAIN_SEPARATOR.len() + msg.len());
        message.extend_from_slice(IC_REQUEST_AUTH_DELEGATION_DOMAIN_SEPARATOR);
        message.extend(msg);
        verify_sig_with_rootkey(
            ic_root_public_key_raw,
            last_verified,
            &message,
            &d.signature,
        )?;

        last_verified = &d.delegation.pubkey;
    }
    if last_verified != session_pubkey {
        return Err(format!(
            "Last verified public key does not match session public key:\n\
             Last verified: {}\n\
             Session public key: {}",
            hex::encode(last_verified),
            hex::encode(session_pubkey)
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_consensus::SigningKey;
    use ic_agent::{Identity, identity::BasicIdentity};
    use ic_canister_sig_creation::CanisterSigPublicKey;

    use crate::unix_timestamp;

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
        assert!(
            se2.verify(unix_timestamp().as_millis() as u64, None, None)
                .is_ok()
        );

        se2.digest = sha3_256(b"hello world 2").to_vec().into();
        assert!(
            se2.verify(unix_timestamp().as_millis() as u64, None, None)
                .is_err()
        );
    }

    #[test]
    fn test_envelope_with_iccsa() {
        let msg = hex::decode("086c81b03b34184d2365b88a7d94ad9cc0f4e98970b6c10068aae4e407333339")
            .unwrap();
        let sig =
            hex::decode("d9d9f7a26b636572746966696361746558a1d9d9f7a26474726565830183024863616e697374657283024a0000000000000001010183024e6365727469666965645f646174618203582053e3b19ab292296b52b451b0662af2d86ac707569b39825fc31f62aca41406d483024474696d6582034387ad4b697369676e61747572655830a95766af95898e1c8492de7b7d9e6c601ea9d9958113f6c0491ef044ed5ebb03d31983abfa40ebbef7068ebaf7e66f05647472656583024373696783025820591047009df12cb39741d672f270045fd15beec2b0b84c1d71bda98b758726cd83025820d37372239856cdf2ae158e5ac365f15501a9e5612a970ddd7b3199c522b54194820340")
                .unwrap();
        let pk_der =
            hex::decode("303c300c060a2b0601040183b8430102032c000a000000000000000101011f809d0136deeed8e0187447d20ac0e13e0201e1dede8c437eada3e8dc349f85")
                .unwrap();
        let root =
            hex::decode("b90210504fe157d1df412e500ced967ef794dc7aa88c84d764b74b6bc2cf0e575d79f331927df062240c88a28e1802c60b407c7bce541b50310d775919bcd0f799222c3738bc3bcc8bf05af5f52ee2afec54c460bda35c6c379267924db2d374")
                .unwrap();
        let (alg, _pk) = user_public_key_from_der(&pk_der).unwrap();
        assert_eq!(alg, Algorithm::IcCanisterSignature);

        let cspk = CanisterSigPublicKey::try_from(pk_der.as_slice()).unwrap();
        println!("canister_id: {}", cspk.canister_id.to_text());
        // canister_id: rrkah-fqaaa-aaaaa-aaaaq-cai

        let res = verify_sig_with_rootkey(&root, &pk_der, &msg, &sig);
        assert!(res.is_ok());
    }

    #[test]
    fn test_verify_delegation_chain() {
        let user_pubkey = hex::decode(
            "303C300C060A2B0601040183B8430102032C000A0000000000000007010116FB513D360579FA1102D36E3BC8D53FB966F3AC9F717842B2B54C227582D786",
        ).unwrap();
        let session_pubkey = hex::decode(
            "302A300506032B6570032100C6C020379C06F82F81111E1DA776F143C4F532EBE2D9FB16461F1243B5A92BAA",
        ).unwrap();
        let delegations = vec![
            SignedDelegationCompact {
                delegation: DelegationCompact {
                    pubkey: hex::decode(
                        "302A300506032B65700321005EC6DE6BD72919EA56CCA4E8E7124CEF75807DC212F1AE1FC3BA58903FC8795A",
                    ).unwrap().into(),
                    expiration: 1748957411593484684,
                    targets: None,
                },
                signature: hex::decode(
                    "D9D9F7A26B63657274696669636174655904AFD9D9F7A36474726565830183018301820458207F795EAF211FB3DA321D2291429BAD43A869A1CCFD761FF5A35F1A362322A1F483024863616E697374657283018301830183024A000000000000000701018301830183024E6365727469666965645F64617461820358201BD26E2A134BB173ACE579802B2BD138D28B3307CE5415BAD1304EDC8EB6A5E182045820D8F64F7AFCA6A55D4EE6DED9B0200BAC6651CAF4C7A1920212B5A03C9BF1DF3682045820F5ECD4D3EDCD85DE4C3B07B8A8D77F69DEFCB5BD652071FFD46B2A6604029112820458205085E5811DEACD817B4FF38A37C93B8421B7DDC92E5489FDF0D3F5CF36E320728204582032698C8D6A87E6831B3E8AA11641F27E77B692C6F866FD3D9D3E917EA570515682045820F7C9916E3BDEB2AC59E18441EBEFDDA60B801A91F8508B4F1B2ADA5B7F62AAA682045820989249384F8855B851E3F07C55E66DEFA4719612B1D9565E4C2B47918F902240830182045820FBF74833516364406FEC8290DFB4593E369120B408F757754CF11E96DF87AA8D83024474696D658203498CF3BBB0EDC2959E18697369676E61747572655830AF6204D323E367981055D0FB24E03070BDD6EC0D1BFABE2E3408B9C4792F1D4C44FE49A3AE9FD6ABD53D53DCF38E0E0E6A64656C65676174696F6EA2697375626E65745F6964581D43DCAF1180DB82FDA708CE3AC7A03A6060ABDE13E9546C60E8CCE65D026B6365727469666963617465590294D9D9F7A264747265658301820458200E077A1AA8E3A69E473446FB605EF74212198EC90D4D0010B3DC091AE3F01B798301830182045820954285DD391C0258F30BD79123B51AB939B93982F24426FE94E376FC13F5D3D38302467375626E6574830183018301820458200985315BBE905B7F9336D7064793905B005689F3C9C2A21AD9A31FBE6CDD5599830182045820466A70286CF9ACE9801CA53E22AF6EE059A094FD60498606D484B6854058307D83018301820458208B2F6C15078AE4D3B93470915CA53E373327F37EA74BA1B8177D986BB79B31AE8302581D43DCAF1180DB82FDA708CE3AC7A03A6060ABDE13E9546C60E8CCE65D02830183024F63616E69737465725F72616E67657382035832D9D9F782824A000000000000000701014A00000000000000070101824A000000000210000001014A00000000021FFFFF010183024A7075626C69635F6B657982035885308182301D060D2B0601040182DC7C0503010201060C2B0601040182DC7C050302010361008819AAA868DA353E3451BB97675FFFAA711E3C1C1230E39E1FEEB0AF9FE03E67C9393F08D796C1E42B528ABB5FCB4159199284B00096F6DAFA93B4711F1AC65F594B67CE2C0B35710E0391C5424CB754779A1C6084F6E77B584E7C8CF7FE9D89820458202C51DB7B5650B7A3DBBB8530A7449CC6F90144778B62F20F3C26D72E95E50698820458206961EF137C2AEE0B0467082EF6D3C12C03E93013B602A4CB6214270E484863F182045820EA6D87F551BD7F433852FA3F8697E653676C2DA59615618B39C50D74069123C983024474696D65820349A0BFA380BAC2959E18697369676E61747572655830B82F7761EC5C9A30672188D7A5F7EE82B540E51A86239C5A2A8E51DA6CB19CA3980DD8125440EC49C54865CED7EAA10F6474726565830182045820ECF5038E1037F1181243DAABBD82BE6045A5B0B9F1025C905FA339E2C1305608830243736967830183018204582029D9F6DAFC4411D79A0B7A64FCFF42FCE426974773A4178BA421DF59165D9E32830182045820ABD07F88910310B251F025105AEA620A46984E3D677A54EEC324134F6ED4DDD783018204582055D9BE42D0A247D96B4C67822E937EAD71567B5BE0A4965150F01D2AB51AC971830182045820CCB0E0C4819032E6C3C7B0E359F8A7297EED11A484FD7D8081CCA2461371E0328301830258206BB18EF359E4DBB2372D7C255BA9351BC862ACF06D9D2B14CDB1271EEFAA597E8302582015451785051A113622599AD74E94CC066EEF4BAC88AC36A42403C65CEDFFE8E0820340820458203A229EE09D8AC3B9C0540F596654FED78B3D5ABDD03657F66AD3240856214167820458206C0048C242D41CF83B77D782F6733B95B7AA137736741D05DACA0385D79BF466").unwrap().into()
                }, SignedDelegationCompact{
                    delegation: DelegationCompact {
                    pubkey: hex::decode(
                        "302A300506032B6570032100C6C020379C06F82F81111E1DA776F143C4F532EBE2D9FB16461F1243B5A92BAA",
                    ).unwrap().into(),
                    expiration: 1750784792831000000,
                    targets: None,
                },
                signature: hex::decode("18397232DD4AE43103E1884E956F91B44188E40A288DBCB73BF99DC27DBFAB1E1F0FAB76C44E0A0206F34887D5197B46C2D57876B0DB4C28E97967FDA8807908").unwrap().into(),
                }];
        let rt = verify_delegation_chain(
            &user_pubkey,
            &session_pubkey,
            &delegations,
            1748957411500,
            None,
        );
        assert!(rt.is_ok(), "Delegation chain verification failed: {:?}", rt);
    }
}
