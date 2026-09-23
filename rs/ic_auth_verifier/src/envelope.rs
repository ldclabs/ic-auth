use base64::{
    Engine,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use candid::{CandidType, Principal};
use http::header::{AUTHORIZATION, HeaderMap, HeaderName};
use ic_auth_types::{
    ByteBufB64, DelegationCompact, DelegationPermissions, SignedDelegation,
    SignedDelegationCompact, cbor_from_slice, deterministic_cbor_into_vec,
};
use ic_representation_independent_hash::{Value as HashValue, representation_independent_hash};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[cfg(feature = "identity")]
use ic_agent::{Identity, Signature};

use ic_canister_sig_creation::IC_ROOT_PK_DER;

#[cfg(feature = "identity")]
use crate::sha3_256;
use crate::{Algorithm, user_public_key_from_der, verify_basic_sig, verify_canister_sig};

/// The Internet Computer's anonymous principal identifier.
/// This is used when no authenticated identity is provided.
pub const ANONYMOUS_PRINCIPAL: Principal = Principal::anonymous();

/// Maximum allowed time drift in milliseconds for delegation verification.
/// This prevents replay attacks while allowing for reasonable clock differences.
pub const PERMITTED_DRIFT_MS: u64 = 300 * 1000;

/// Maximum allowed delegation chain length.
pub const MAX_DELEGATION_CHAIN_LENGTH: usize = 5;

/// Domain separator for delegation signature messages.
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
/// * `current_time_ns` - The current time in nanoseconds since the Unix epoch, used for validating canister signatures with time-based constraints
///
/// # Returns
/// * `Ok(())` if the signature is valid
/// * `Err(String)` with an error message if verification fails
pub fn verify_sig(
    public_key: &[u8],
    msg: &[u8],
    signature: &[u8],
    current_time_ns: u128,
) -> Result<(), String> {
    verify_sig_with_rootkey(IC_ROOT_PK_DER, public_key, msg, signature, current_time_ns)
}

/// Verifies a signature using the public key and a specified IC root public key.
/// This function allows verification against different IC networks by providing
/// a custom root public key.
///
/// # Arguments
/// * `ic_root_public_key_der` - The DER-encoded IC root public key to use for
///   verification, such as [`IC_ROOT_PK_DER`]
/// * `public_key` - The DER-encoded public key to verify against
/// * `msg` - The message that was signed
/// * `signature` - The signature to verify
/// * `current_time_ns` - The current time in nanoseconds since the Unix epoch, used for validating canister signatures with time-based constraints
///
/// # Returns
/// * `Ok(())` if the signature is valid
/// * `Err(String)` with an error message if verification fails
pub fn verify_sig_with_rootkey(
    ic_root_public_key_der: &[u8],
    public_key: &[u8],
    msg: &[u8],
    signature: &[u8],
    current_time_ns: u128,
) -> Result<(), String> {
    let (alg, pk) = user_public_key_from_der(public_key)?;
    match alg {
        Algorithm::IcCanisterSignature => verify_canister_sig(
            msg,
            signature,
            public_key,
            ic_root_public_key_der,
            current_time_ns,
            None,
        ),
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
    #[serde(rename = "p", alias = "pubkey", alias = "public_key")]
    pub pubkey: ByteBufB64,

    /// A cryptographic signature authorizing the request.
    /// When delegations are involved, this is the signature from the tail of the
    /// delegation chain, not necessarily made by the owner of `pubkey`.
    #[serde(rename = "s", alias = "signature")]
    pub signature: ByteBufB64,

    /// The request content's hash digest that was signed by the sender.
    /// This is typically a SHA-256 or SHA3-256 hash of the request content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "h", alias = "digest")]
    pub digest: Option<ByteBufB64>,

    /// The chain of delegations connecting `pubkey` to `signature`, in order.
    /// Each delegation authorizes the next entity in the chain to sign on behalf
    /// of the previous entity, forming a chain of trust from the original identity
    /// to the actual signer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "d", alias = "delegation")]
    pub delegation: Option<Vec<SignedDelegationCompact>>,
}

#[cfg(feature = "identity")]
impl TryFrom<Signature> for SignedEnvelope {
    type Error = String;
    fn try_from(sig: Signature) -> Result<Self, Self::Error> {
        Ok(Self {
            pubkey: sig
                .public_key
                .ok_or_else(|| "missing public_key".to_string())?
                .into(),
            signature: sig
                .signature
                .ok_or_else(|| "missing signature".to_string())?
                .into(),
            digest: None,
            delegation: sig.delegations.map(|delegations| {
                delegations
                    .into_iter()
                    .map(|d| SignedDelegationCompact {
                        delegation: DelegationCompact {
                            pubkey: d.delegation.pubkey.into(),
                            expiration: d.delegation.expiration,
                            targets: d.delegation.targets,
                            permissions: d.delegation.permissions.map(|p| match p {
                                ic_agent::identity::DelegationPermissions::Queries => {
                                    ic_auth_types::DelegationPermissions::Queries
                                }
                                ic_agent::identity::DelegationPermissions::All => {
                                    ic_auth_types::DelegationPermissions::All
                                }
                            }),
                        },
                        signature: d.signature.into(),
                    })
                    .collect::<Vec<_>>()
            }),
        })
    }
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
        deterministic_cbor_into_vec(&self).expect("failed to encode SignedEnvelope")
    }

    /// Decodes a SignedEnvelope from its binary representation.
    ///
    /// # Arguments
    /// * `bytes` - The CBOR-encoded binary representation of the envelope
    ///
    /// # Returns
    /// * `Result<Self, String>` - The decoded envelope or an error message
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        cbor_from_slice(bytes).map_err(|err| format!("failed to decode SignedEnvelope data: {err}"))
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
            .map_err(|err| format!("{err:?}"))?;
        let mut envelope: Self = sig.try_into()?;
        envelope.digest = Some(digest.into());
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
        let current_time_ns = now_ms as u128 * 1_000_000;
        let digest = match (self.digest.as_ref(), expect_digest) {
            (Some(digest), Some(expect_digest)) => {
                if digest.as_slice() != expect_digest {
                    return Err("Content digest does not match".to_string());
                }
                digest
            }
            (Some(digest), None) => digest.as_slice(),
            (None, Some(expect_digest)) => expect_digest,
            (None, None) => {
                return Err("No content digest provided for verification".to_string());
            }
        };

        let last_verified = verify_delegations(
            &self.pubkey,
            self.delegation.as_deref().unwrap_or_default(),
            now_ms,
            expect_target,
            IC_ROOT_PK_DER,
        )?;

        verify_sig(last_verified, digest, &self.signature, current_time_ns)
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
        if let Some(token) = headers.get(AUTHORIZATION)
            && let Ok(token) = token.to_str()
            && let Some((scheme, token)) = token.split_once(' ')
            && scheme.eq_ignore_ascii_case("ICP")
            && let Ok(envelope) = Self::from_base64(token)
        {
            return Some(envelope);
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
    /// * `Option<Self>` - The extracted envelope, or None if not found or invalid.
    ///   A delegation header that is present but malformed invalidates the whole envelope.
    pub fn from_headers(headers: &HeaderMap) -> Option<Self> {
        let pubkey = extract_data(headers, &HEADER_IC_AUTH_PUBKEY)?;
        let digest = extract_data(headers, &HEADER_IC_AUTH_CONTENT_DIGEST)?;
        let signature = extract_data(headers, &HEADER_IC_AUTH_SIGNATURE)?;
        let delegation = match headers.get(&HEADER_IC_AUTH_DELEGATION) {
            Some(value) => {
                let data = decode_base64(value.to_str().ok()?).ok()?;
                Some(cbor_from_slice(&data).ok()?)
            }
            None => None,
        };

        Some(Self {
            pubkey: pubkey.into(),
            signature: signature.into(),
            digest: Some(digest.into()),
            delegation,
        })
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
        // The optional headers are cleared when absent from this envelope.
        // `insert` alone would leave a previous envelope's digest or delegation
        // behind when the caller reuses a `HeaderMap`, pairing them with the new
        // public key and signature.
        match &self.digest {
            Some(digest) => {
                headers.insert(
                    &HEADER_IC_AUTH_CONTENT_DIGEST,
                    URL_SAFE_NO_PAD.encode(digest).parse().map_err(|err| {
                        format!("insert {HEADER_IC_AUTH_CONTENT_DIGEST} header failed: {err}")
                    })?,
                );
            }
            None => {
                headers.remove(&HEADER_IC_AUTH_CONTENT_DIGEST);
            }
        }
        headers.insert(
            &HEADER_IC_AUTH_SIGNATURE,
            URL_SAFE_NO_PAD
                .encode(&self.signature)
                .parse()
                .map_err(|err| format!("insert {HEADER_IC_AUTH_SIGNATURE} header failed: {err}"))?,
        );
        match &self.delegation {
            Some(delegations) => {
                headers.insert(
                    &HEADER_IC_AUTH_DELEGATION,
                    URL_SAFE_NO_PAD
                        .encode(deterministic_cbor_into_vec(&delegations)?)
                        .parse()
                        .map_err(|err| {
                            format!("insert {HEADER_IC_AUTH_DELEGATION} header failed: {err}")
                        })?,
                );
            }
            None => {
                headers.remove(&HEADER_IC_AUTH_DELEGATION);
            }
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
/// * `ic_root_public_key_der` - Optional DER-encoded IC root public key for
///   canister signatures; defaults to the mainnet key
pub fn verify_delegation_chain(
    user_pubkey: &[u8],
    session_pubkey: &[u8],
    delegations: &[SignedDelegationCompact],
    now_ms: u64,
    ic_root_public_key_der: Option<&[u8]>,
) -> Result<(), String> {
    if delegations.is_empty() {
        return Err("Delegation chain is empty".to_string());
    }

    let last_verified = verify_delegations(
        user_pubkey,
        delegations,
        now_ms,
        None,
        ic_root_public_key_der.unwrap_or(IC_ROOT_PK_DER),
    )?;
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

/// Verifies each link and returns the key authorized by the chain. An empty
/// chain leaves the original key authorized, as required by plain envelopes.
fn verify_delegations<'a>(
    user_pubkey: &'a [u8],
    delegations: &'a [SignedDelegationCompact],
    now_ms: u64,
    expect_target: Option<Principal>,
    ic_root_public_key_der: &[u8],
) -> Result<&'a [u8], String> {
    if delegations.len() > MAX_DELEGATION_CHAIN_LENGTH {
        return Err(format!(
            "Delegation chain length exceeds the limit {}: {}",
            MAX_DELEGATION_CHAIN_LENGTH,
            delegations.len()
        ));
    }

    let current_time_ns = now_ms as u128 * 1_000_000;
    let mut last_verified = user_pubkey;
    for d in delegations {
        check_delegation_expiration(d.delegation.expiration, now_ms)?;
        if let (Some(targets), Some(target)) = (&d.delegation.targets, &expect_target)
            && !targets.contains(target)
        {
            return Err(format!(
                "Expected target canister ID '{expect_target:?}' is not in the delegation targets: {targets:?}"
            ));
        }

        let message = delegation_signed_message(&d.delegation);
        verify_sig_with_rootkey(
            ic_root_public_key_der,
            last_verified,
            &message,
            &d.signature,
            current_time_ns,
        )?;

        last_verified = &d.delegation.pubkey;
    }
    Ok(last_verified)
}

fn is_delegation_expired(expiration_ns: u64, now_ms: u64) -> bool {
    let earliest_valid_ms = now_ms.saturating_sub(PERMITTED_DRIFT_MS);
    expiration_ns / 1_000_000 < earliest_valid_ms
}

fn check_delegation_expiration(expiration_ns: u64, now_ms: u64) -> Result<(), String> {
    if is_delegation_expired(expiration_ns, now_ms) {
        return Err(format!(
            "Delegation has expired:\n\
             Provided expiry:    {}\n\
             Local replica timestamp: {}",
            expiration_ns,
            now_ms as u128 * 1_000_000,
        ));
    }
    Ok(())
}

/// Builds the domain-separated message whose signature authorizes the delegation.
///
/// The hashed map must contain every field the signer put in the delegation,
/// including `permissions`. `delegation_signature_msg` predates that field and
/// cannot hash it, so the map is built here to stay byte-identical to
/// `ic_agent::identity::Delegation::signable`. Leaving `permissions` out would
/// make it unauthenticated: a `Queries`-only delegation could be rewritten to
/// `All` without breaking the signature.
fn delegation_signed_message(delegation: &DelegationCompact) -> Vec<u8> {
    let mut map: Vec<(String, HashValue)> = Vec::with_capacity(4);
    map.push((
        "pubkey".to_string(),
        HashValue::Bytes(delegation.pubkey.to_vec()),
    ));
    map.push((
        "expiration".to_string(),
        HashValue::Number(delegation.expiration),
    ));
    if let Some(targets) = &delegation.targets {
        map.push((
            "targets".to_string(),
            HashValue::Array(
                targets
                    .iter()
                    .map(|p| HashValue::Bytes(p.as_slice().to_vec()))
                    .collect(),
            ),
        ));
    }
    if let Some(permissions) = &delegation.permissions {
        // The variant names match the `#[serde(rename = ...)]` on
        // `DelegationPermissions`, which is what the signer serializes.
        let permissions = match permissions {
            DelegationPermissions::Queries => "queries",
            DelegationPermissions::All => "all",
        };
        map.push((
            "permissions".to_string(),
            HashValue::String(permissions.to_string()),
        ));
    }

    let msg = representation_independent_hash(&map);
    let mut message =
        Vec::with_capacity(IC_REQUEST_AUTH_DELEGATION_DOMAIN_SEPARATOR.len() + msg.len());
    message.extend_from_slice(IC_REQUEST_AUTH_DELEGATION_DOMAIN_SEPARATOR);
    message.extend_from_slice(&msg);
    message
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
    decode_base64(headers.get(key)?.to_str().ok()?).ok()
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
    headers
        .get(&HEADER_IC_AUTH_USER)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| Principal::from_text(text).ok())
        .unwrap_or(ANONYMOUS_PRINCIPAL)
}

/// Decodes base64-encoded data.
///
/// Accepts exactly what [`ByteBufB64`] parses: the base64url or the standard
/// alphabet, padded or not, with an optional `b64:` prefix. Padding must be
/// well formed, so a run of `=` is rejected rather than decoded to nothing.
/// Surrounding whitespace is ignored.
///
/// # Arguments
/// * `data` - The base64-encoded string to decode
///
/// # Returns
/// * `Result<Vec<u8>, String>` - The decoded data or an error message
pub fn decode_base64(data: &str) -> Result<Vec<u8>, String> {
    ByteBufB64::from_str(data.trim())
        .map(ByteBufB64::into_vec)
        .map_err(|err| format!("failed to decode base64 data: {err}"))
}

/// Full-name representation of [`SignedEnvelope`].
///
/// `SignedEnvelope` serializes with compact field names (`p`, `s`, `h`, `d`)
/// for transport. This companion type is useful when an API boundary wants
/// descriptive names while retaining aliases for compact payloads.
#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct SignedEnvelopeFull {
    /// The DER public key of the user identity.
    #[serde(alias = "p")]
    pub pubkey: ByteBufB64,

    /// The signature over the envelope digest.
    #[serde(alias = "s")]
    pub signature: ByteBufB64,

    /// Optional digest that was signed by `signature`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(alias = "h")]
    pub digest: Option<ByteBufB64>,

    /// Optional full-name delegation chain.
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
    #[cfg(feature = "identity")]
    use crate::unix_timestamp;
    #[cfg(feature = "identity")]
    use cbor2::Value;
    #[cfg(feature = "identity")]
    use ic_agent::{
        Identity,
        identity::{
            BasicIdentity, DelegatedIdentity, Delegation as AgentDelegation,
            SignedDelegation as AgentSignedDelegation,
        },
    };
    use ic_auth_types::DelegationCompact;
    use ic_canister_sig_creation::CanisterSigPublicKey;
    #[cfg(feature = "identity")]
    use std::time::Duration;

    fn sample_envelope() -> SignedEnvelope {
        SignedEnvelope {
            pubkey: vec![1, 2, 3].into(),
            signature: vec![4, 5, 6].into(),
            digest: Some(vec![7, 8, 9].into()),
            delegation: None,
        }
    }

    #[cfg(feature = "identity")]
    #[test]
    fn test_envelope_with_ed25519() {
        let secret = [8u8; 32];
        let id = BasicIdentity::from_raw_key(&secret);
        println!("id: {:?}", id.sender().unwrap().to_text());
        // jjn6g-sh75l-r3cxb-wxrkl-frqld-6p6qq-d4ato-wske5-op7s5-n566f-bqe

        let msg = b"hello world";
        let mut headers = HeaderMap::new();
        let se = SignedEnvelope::sign_message(&id, msg).unwrap();
        assert_eq!(se.sender(), id.sender().unwrap());
        se.to_headers(&mut headers).unwrap();

        let mut se2 = SignedEnvelope::from_headers(&headers).unwrap();
        assert!(
            se2.verify(unix_timestamp().as_millis() as u64, None, None)
                .is_ok()
        );

        se2.digest = Some(sha3_256(b"hello world 2").to_vec().into());
        assert!(
            se2.verify(unix_timestamp().as_millis() as u64, None, None)
                .is_err()
        );

        let digest = sha3_256(msg);
        let sig = id.sign_arbitrary(digest.as_slice()).unwrap();
        let se: SignedEnvelope = sig.try_into().unwrap();
        assert!(
            se.verify(
                unix_timestamp().as_millis() as u64,
                None,
                Some(digest.as_slice())
            )
            .is_ok()
        );

        let delegated = crate::delegated_basic_identity(&id, 3600 * 1000);
        let se = SignedEnvelope::sign_message(&delegated, msg).unwrap();
        assert_eq!(se.delegation.as_ref().unwrap().len(), 1);
        assert!(
            se.verify(unix_timestamp().as_millis() as u64, None, None)
                .is_ok()
        );

        let sig = delegated.sign_arbitrary(digest.as_slice()).unwrap();
        let se: SignedEnvelope = sig.try_into().unwrap();
        assert_eq!(se.delegation.as_ref().unwrap().len(), 1);
        assert!(
            se.verify(
                unix_timestamp().as_millis() as u64,
                None,
                Some(digest.as_slice())
            )
            .is_ok()
        );
    }

    #[cfg(feature = "identity")]
    #[test]
    fn test_envelope_with_ed25519_2() {
        // test data from ts/ic-auth/src/identity.test.ts
        let secret = [8u8; 32];
        let id = BasicIdentity::from_raw_key(&secret);

        let msg = "pGFk92FoWCDy_PBrUtbrh328ZTWvrZnuiE2EMKHfMz_1M6f3JN1nq2FwWCwwKjAFBgMrZXADIQATmPYsbRpFfFG6aktfPb0vafypMhYhjciZfkFr0X2TymFzWEAzEYt2uq3q2BiMmgz91CLI6Sj0Vs90pE-bTd37h35FpBOonchIBqXyjtBpnfguDbZkKzy_VWbs9bDx29_5lqwD";
        let se = SignedEnvelope::from_base64(msg).unwrap();
        assert_eq!(id.public_key().unwrap(), se.pubkey.as_slice());
        assert_eq!(
            se.digest.as_ref().unwrap().as_slice(),
            hex::decode("f2fcf06b52d6eb877dbc6535afad99ee884d8430a1df333ff533a7f724dd67ab")
                .unwrap()
                .as_slice()
        );

        assert!(
            se.verify(unix_timestamp().as_millis() as u64, None, None)
                .is_ok()
        );

        let msg = "o2Fk92FwWCwwKjAFBgMrZXADIQATmPYsbRpFfFG6aktfPb0vafypMhYhjciZfkFr0X2TymFzWEAzEYt2uq3q2BiMmgz91CLI6Sj0Vs90pE-bTd37h35FpBOonchIBqXyjtBpnfguDbZkKzy_VWbs9bDx29_5lqwD";
        let se = SignedEnvelope::from_base64(msg).unwrap();
        assert_eq!(id.public_key().unwrap(), se.pubkey.as_slice());
        assert_eq!(se.digest, None);

        assert!(
            se.verify(unix_timestamp().as_millis() as u64, None, None)
                .is_err()
        );

        let obj = vec![
            (Value::from("z"), Value::from("z")),     // 0x617a
            (Value::from("aa"), Value::from("aa")),   // 0x626161
            (Value::from(10), Value::from(10)),       // 0x0a
            (Value::from(100), Value::from(100)),     // 0x1864
            (Value::from(-1), Value::from(-1)),       // 0x20
            (Value::from(false), Value::from(false)), // 0xf4
        ];

        let data = deterministic_cbor_into_vec(&Value::Map(obj)).unwrap();
        let digest = sha3_256(&data);
        assert!(
            se.verify(
                unix_timestamp().as_millis() as u64,
                None,
                Some(digest.as_slice())
            )
            .is_ok()
        );

        // generated by ic-certification 2.6
        let msg = "pGFkgaJhZKJhZRsYojcfvOoZmmFwWCwwKjAFBgMrZXADIQBoGlRAsc_ADaKVxzccHBGsazda-ERmveqkjSZFbiY2nmFzWQZu2dn3omtjZXJ0aWZpY2F0ZVkE1dnZ96NkdHJlZYMBgwGDAYIEWCD_2rktIbM7CQPjMFxdtgoXDsQBe6ZnfYHz_VEkO7uCtYMCSGNhbmlzdGVygwGDAYMBgwJKAAAAAAAAAAcBAYMBgwGDAk5jZXJ0aWZpZWRfZGF0YYIDWCBWgGiPBtG2u85cDRFAPYs7vLdc6Grw571wSc0RMCI6EYIEWCDY9k96_KalXU7m3tmwIAusZlHK9MehkgIStaA8m_HfNoIEWCBOYkQtPpTRBP_gYe1cnFAcC8xgoKTJJTJlEp9i4bgOfoIEWCBthgttL0RxWKx9zQUzB1VVoDJfNVBABnygDRTTlPpcd4IEWCAfyKogUeU4zw3Pa2EBGB5VcNaukbds8ZT7AbSR6GX-gYIEWCDm4cUcLUxvcw_J2442dS94YI_tAHxqDsyTEqltTeRe4IIEWCBODzfzIXgSp1yunK4EJegz62agSuPIA2wlNiYf8RilioMBggRYICnLk_WKVCD1pHHANP7Kh0HvezdFZ1X21aGEwGM67W9ggwGCBFggfbVemnKYEja9TKRlj9yBlXGcvPfICHl9a299larerwSDAkR0aW1lggNJmrOgreu2wMwYaXNpZ25hdHVyZVgwqclPwHXkj30JDkbDXJZG5gddlh7PgmYEy5XS41RLyngn4KATI205Wt1cee-lKHXoamRlbGVnYXRpb26iaXN1Ym5ldF9pZFgdQ9yvEYDbgv2nCM46x6A6YGCr3hPpVGxg6MzmXQJrY2VydGlmaWNhdGVZApTZ2feiZHRyZWWDAYIEWCDtgh8WsbKpiZoLi5XYylCxX__YyZPUZsIk0PXjz1lzvYMBggRYIFunwSpsZKpJ5QG34-6Hdf5fiGjJrkCJRjDPdKogQZzlgwGDAkZzdWJuZXSDAYMBggRYIH78fWQs2KX21INhFAUooPeg_qG9FaEZ-FnJvQByCxnYgwGDAYMBgwGDAlgdQ9yvEYDbgv2nCM46x6A6YGCr3hPpVGxg6MzmXQKDAYMCT2NhbmlzdGVyX3Jhbmdlc4IDWDLZ2feCgkoAAAAAAAAABwEBSgAAAAAAAAAHAQGCSgAAAAACEAAAAQFKAAAAAAIf__8BAYMCSnB1YmxpY19rZXmCA1iFMIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhALiJ5Njs3jKCWgg15m1SnjGedDTM6N_jrO8RBSZZl13LZLkUsrJ-jXTvit3bHngQtgBp9qUJUzy8-XCxJo82dQVlV5gl1xnyg-ykrW4rt26B_Up2EY9NOZnuKxOqWdH8aYIEWCDNNRYZFlJHwcKUuJIXQK9JIA0pKYarBTb9K3DDUzpPD4IEWCCcu0ovvg1X5FqsJC-HA-rJOFf6CdjDxCqs4Ii-cSOwS4IEWCANOW8zq66lZnKBOKlXR-J03L7dcvb1a5pIDj7u4eHu54IEWCAmUyo7WsE_oDGyz13rElnLdnC06YydNtMc98fxHuNuDIIEWCB2Q0u6125BV4e6HKAOUmknD4_423JMC2hEXc2mwamhSoMCRHRpbWWCA0nPvfXihLHAzBhpc2lnbmF0dXJlWDCulZzovZrP2dWIIMhEBaSh5XU9J_aMKtKUW6JgNpzOTHAYDTCa1XyOdPpZ00e6ix9kdHJlZYMBggRYIHYbG1hqqpq8_WWQRV3C6xttakOgXO079nv_qXI6sETrgwJDc2lngwGCBFggqSaSUsJM66WL_J9fC3tzQBJsHddRM7iKFSHNW_dnjzuDAYIEWCCwKoJHyzof_3-jNNjHETV_ezpXKqNRTc76XGllr_3zHoMBggRYIJJpmDUOjCZuLgTeQwfKb0B7aJCbce1Nkt6svPUVwhpngwGCBFggRAxMN7esuXj82dGA0oo0jQFZL_E9_NIW3QZuNI8Zwx-DAYMBggRYIMGyphmMiwQtCOVs7007IKrTQdJMcTbReVp1F_LuJHxsgwGCBFggdHEIJNsCUNILPOaPC72zPGcDzhAPP3QeFCJHEo4C52yDAlgg5P8-40zMpjFL_rEmGbtJM39mBn6oASZiC_1kSmOgrEWDAlggJ8HNs_IqkCfk2fuw-rIgFqkpkSqPIxHFoVgIw4ysbaqCA0CCBFggwy969dGj_RU_qiA4zFkKgMgkmTw6Dg_uzIICxJCXkoFhaFggrQaFGeXvwG47mPtg184iJUpbfwDtMVhSJQinJDD7c6lhcFg-MDwwDAYKKwYBBAGDuEMBAgMsAAoAAAAAAAAABwEB4tq0V5C7RTXNzCnXExRTjoLBLwxA2yf_dlWf5jo_uFRhc1hAfcBZym1voNCADrdalYEZAWT_d_zlMVQG7X_X4lR9zTqvHxj-iwT0XBIN3nvHJIBx8wnxOOW2sOOu0hSpiYKgDQ";

        let se = SignedEnvelope::from_base64(msg).unwrap();
        println!("SignedEnvelope: {:?}", se);
        let rt = se.verify(1772449812590u64, None, None);
        println!("Verification result: {:?}", rt);
        assert!(rt.is_ok());

        // generated by ic-certification 3.1
        let msg = "pGFkgaJhZKJhZRsYprjiTQ1kp2FwWCwwKjAFBgMrZXADIQCA6d4AfqWkdFNu5tbaLp7r9jDxilfJvcLWRdIYzSior2FzWQc02dn3omtjZXJ0aWZpY2F0ZVkGWdnZ96NkdHJlZYMBgwGDAYIEWCD_2rktIbM7CQPjMFxdtgoXDsQBe6ZnfYHz_VEkO7uCtYMCSGNhbmlzdGVygwGDAYMBgwJKAAAAAAAAAAcBAYMBgwGDAk5jZXJ0aWZpZWRfZGF0YYIDWCB2gerHLFm4j1TskyiMYwuJVjti6AkhLhUkmf3yVzgt44IEWCDY9k96_KalXU7m3tmwIAusZlHK9MehkgIStaA8m_HfNoIEWCClii6jhbz6sPHd0uk34rJi6t4x2zU7ap7pu2pHQee1S4IEWCBthgttL0RxWKx9zQUzB1VVoDJfNVBABnygDRTTlPpcd4IEWCA7n254mzmU7xueyXf_BwN4PmMyXI3ZkEy2ep_1MtzWEYIEWCDSHJjM3167Pm98kHUeDMXaLF_cPTiJsu1zlQKZG7gnQoIEWCBZMddBC0-Quz23yaa-wGXhf4sJJ0CMVlNApcf6P0M2toMBggRYIIRNgDlknNZ00VrpChW1u2EkiJpLHm16Aaw9s81wxyw9gwGCBFggMm2roqFHTU5jlTeTnwz61Y9afsoeE1dBam7LurSMO1mDAkR0aW1lggNJp8mtrpTv4M4YaXNpZ25hdHVyZVgwsUfGmq1hpWv0RXnDU4isnnsrytYCYohlaDj8KpVrF95OaVWcsgyBWomgsYtLoxPqamRlbGVnYXRpb26iaXN1Ym5ldF9pZFgdQ9yvEYDbgv2nCM46x6A6YGCr3hPpVGxg6MzmXQJrY2VydGlmaWNhdGVZBBjZ2feiZHRyZWWDAYMBggRYIK3tAhG-5CMHRe6B6HYrumYzszgynK2_Cyk3lgxiz-VegwGDAk9jYW5pc3Rlcl9yYW5nZXODAYMBggRYIPWzPdcCUOwykUxZYJMI-zG0o1JPBtxcycR-ltOoWzQKgwGDAYMBgwGDAlgdQ9yvEYDbgv2nCM46x6A6YGCr3hPpVGxg6MzmXQKDAkoAAAAAAAAABwEBggNYMtnZ94KCSgAAAAAAAAAHAQFKAAAAAAAAAAcBAYJKAAAAAAIQAAABAUoAAAAAAh___wEBggRYIJ2wKoflpjM_8kD8PoQJl7Pvux0kvc21FZQlcEpPjebeggRYIGBtpBoQkI8sWSD0kMaU5qqTdy-kUVf1tmSbla42it92ggRYIOyolKEQ1iwzQOQhsmpRZ-DqycNrnX_QlOFSvAY74bT8ggRYIKvGtteIKoBa9myTiVb5LgymcFkhzR8PhHkWmb9ddOKMggRYIHddYNv5vlTceU_HgpFF5d20rbT5bWhGm-sx-i-4LQsLggRYIAH0KcEdL8U24W7AywFr3_rR_1KtobDR9S_4zxJRVn0UgwGCBFggeePKvLIybJiV9N45REvhjwjws9fpaA2eiaYKSPqhZ_yDAYMCRnN1Ym5ldIMBgwGCBFggiISkVrMM0Rk0jF71z1nHVHXloWSxxt03W_wPRhKANMKDAYMBgwGDAYMCWB1D3K8RgNuC_acIzjrHoDpgYKveE-lUbGDozOZdAoMBgwGCBFggUIlMwLMiEhS4oN4qyA9F8qOf6QkRzQ0IjhmShRyLJ-mDAkpwdWJsaWNfa2V5ggNYhTCBgjAdBg0rBgEEAYLcfAUDAQIBBgwrBgEEAYLcfAUDAgEDYQC4ieTY7N4ygloINeZtUp4xnnQ0zOjf46zvEQUmWZddy2S5FLKyfo1074rd2x54ELYAafalCVM8vPlwsSaPNnUFZVeYJdcZ8oPspK1uK7dugf1KdhGPTTmZ7isTqlnR_GmCBFggOtxzXIoxJu5vYSDBubz8MoJVDYZct-cjWYzLeTdyU5KCBFggNgnQcvmXshXCdPo1-Q72q0aowcpaEHxogyGI4WwCWPKCBFggj4x3eo7K7qsgb-JEuWw_9DcMe2RulRtusZKIgE7JCAyCBFgg2cEDpvexMjtphCR0PV8O8jGeRQXzwnGxohAmgy9KAbKCBFggYOlh9AO7NO3rkGDg86e0FJjFS5hp97IJEtK2fTj5Fo2CBFggOv_0dwIPh6D4tdK_kb9vQEszT-3myESFPY98--7BKfWDAkR0aW1lggNJo8Kk9ent4M4YaXNpZ25hdHVyZVgwhYPOO9jW_tQ5NAMfHRb2rICF9TnGmipUNRTkhaIOvsiy_VkrpQJGtSA7noPJuKEEZHRyZWWDAYIEWCAd1PxBigg-1t83kV57jr2buakKUEVB_liWTXLdBoAtOIMCQ3NpZ4MBgwGDAlggBYX1pW_0nbODY6WVI_XoWnz46JsL1yG2omXetIl1irWDAlggkxDcFnea8djFW-ISPfIwEdE-KvsXYYMq6_WnceSpqhmCA0CCBFggv3BAqPUThOCNdaS-f7TRhEu6A1izhQIvkbUeggveE7OCBFggRpEubsoN-OjKpzy8IAo9jGIQFCCVntAMhOVobFPyHJVhaFggrQaFGeXvwG47mPtg184iJUpbfwDtMVhSJQinJDD7c6lhcFg-MDwwDAYKKwYBBAGDuEMBAgMsAAoAAAAAAAAABwEBkVc8F_k6Ukkl1TQM_crFVBrhBzqDMR65DDzNGLoK-E5hc1hAsLo4H4SdoWumrYdekdP1oBIeOE-W5G8BanUak3w7TPCSZv1IBRu0iMW9x1AoA3EftD9ckUM_54hG21KCEknWCA";

        let se = SignedEnvelope::from_base64(msg).unwrap();
        println!("SignedEnvelope: {:?}", se);
        let rt = se.verify(1773718385139u64, None, None);
        println!("Verification result: {:?}", rt);
        assert!(rt.is_ok());
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
            hex::decode("308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100b90210504fe157d1df412e500ced967ef794dc7aa88c84d764b74b6bc2cf0e575d79f331927df062240c88a28e1802c60b407c7bce541b50310d775919bcd0f799222c3738bc3bcc8bf05af5f52ee2afec54c460bda35c6c379267924db2d374")
                .unwrap();
        let (alg, _pk) = user_public_key_from_der(&pk_der).unwrap();
        assert_eq!(alg, Algorithm::IcCanisterSignature);

        let cspk = CanisterSigPublicKey::try_from(pk_der.as_slice()).unwrap();
        println!("canister_id: {}", cspk.canister_id.to_text());
        // canister_id: rrkah-fqaaa-aaaaa-aaaaq-cai

        let res = verify_sig_with_rootkey(&root, &pk_der, &msg, &sig, 0);
        println!("Verification result: {:?}", res);
        assert!(res.is_ok());
    }

    #[test]
    fn test_delegation_expiration_check_saturates_drift() {
        assert!(!is_delegation_expired(0, 0));
        assert!(!is_delegation_expired(0, PERMITTED_DRIFT_MS - 1));
        assert!(is_delegation_expired(0, PERMITTED_DRIFT_MS + 1));
    }

    #[test]
    fn test_base64_and_header_helpers_reject_invalid_input() {
        assert!(decode_base64("%%%").is_err());
        // both base64 alphabets are accepted, padded or not, with or without
        // the `b64:` prefix that `ByteBufB64` writes
        assert_eq!(decode_base64("-__v").unwrap(), vec![251, 255, 239]);
        assert_eq!(decode_base64("+//v").unwrap(), vec![251, 255, 239]);
        assert_eq!(decode_base64("b64:-__v").unwrap(), vec![251, 255, 239]);
        assert_eq!(decode_base64("+/8=").unwrap(), vec![251, 255]);
        assert_eq!(decode_base64("-_8").unwrap(), vec![251, 255]);
        assert_eq!(decode_base64(" AQID ").unwrap(), vec![1, 2, 3]);
        // padding after a complete quantum is not padding
        assert!(decode_base64("+//v==").is_err());
        assert!(decode_base64("AQID=").is_err());

        let mut headers = HeaderMap::new();
        headers.insert(&HEADER_IC_AUTH_PUBKEY, "%%%".parse().unwrap());
        assert_eq!(extract_data(&headers, &HEADER_IC_AUTH_PUBKEY), None);
        assert!(SignedEnvelope::from_headers(&headers).is_none());
        assert!(SignedEnvelope::from_authorization(&headers).is_none());

        headers.insert(AUTHORIZATION, "Bearer token".parse().unwrap());
        assert!(SignedEnvelope::from_authorization(&headers).is_none());
        headers.insert(AUTHORIZATION, "ICP invalid".parse().unwrap());
        assert!(SignedEnvelope::from_authorization(&headers).is_none());
    }

    #[test]
    fn test_envelope_roundtrips_authorization_and_component_headers() {
        let envelope = sample_envelope();
        let bytes = envelope.to_bytes();

        let decoded = SignedEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.pubkey, envelope.pubkey);
        assert_eq!(decoded.signature, envelope.signature);
        assert_eq!(decoded.digest, envelope.digest);
        assert!(SignedEnvelope::from_bytes(&[0xff]).is_err());

        let encoded = envelope.to_base64();
        let decoded = SignedEnvelope::from_base64(&encoded).unwrap();
        assert_eq!(decoded.pubkey, envelope.pubkey);

        let mut headers = HeaderMap::new();
        envelope.to_authorization(&mut headers).unwrap();
        let decoded = SignedEnvelope::from_authorization(&headers).unwrap();
        assert_eq!(decoded.signature, envelope.signature);

        let mut headers = HeaderMap::new();
        envelope.to_headers(&mut headers).unwrap();
        let decoded = SignedEnvelope::from_headers(&headers).unwrap();
        assert_eq!(decoded.pubkey, envelope.pubkey);
        assert_eq!(decoded.digest, envelope.digest);

        headers.remove(&HEADER_IC_AUTH_CONTENT_DIGEST);
        assert!(SignedEnvelope::from_headers(&headers).is_none());
    }

    #[test]
    fn test_envelope_headers_with_delegation_roundtrip() {
        let mut envelope = sample_envelope();
        envelope.delegation = Some(vec![SignedDelegationCompact {
            delegation: DelegationCompact {
                pubkey: vec![9, 8, 7].into(),
                expiration: u64::MAX,
                targets: Some(vec![Principal::management_canister()]),
                permissions: None,
            },
            signature: vec![6, 5, 4].into(),
        }]);

        let mut headers = HeaderMap::new();
        envelope.to_headers(&mut headers).unwrap();
        let decoded = SignedEnvelope::from_headers(&headers).unwrap();

        assert_eq!(decoded.delegation.unwrap().len(), 1);

        // a present but malformed delegation header invalidates the whole envelope
        headers.insert(&HEADER_IC_AUTH_DELEGATION, "%%%".parse().unwrap());
        assert!(SignedEnvelope::from_headers(&headers).is_none());

        // valid base64 but invalid CBOR is also rejected
        headers.insert(&HEADER_IC_AUTH_DELEGATION, "_w".parse().unwrap());
        assert!(SignedEnvelope::from_headers(&headers).is_none());
    }

    #[test]
    fn test_full_envelope_conversions_roundtrip() {
        let full = SignedEnvelopeFull {
            pubkey: vec![1, 2, 3].into(),
            signature: vec![4, 5, 6].into(),
            digest: Some(vec![7, 8, 9].into()),
            delegation: Some(vec![SignedDelegation {
                delegation: ic_auth_types::Delegation {
                    pubkey: vec![10, 11, 12].into(),
                    expiration: 123,
                    targets: Some(vec![Principal::management_canister()]),
                    permissions: None,
                },
                signature: vec![13, 14, 15].into(),
            }]),
        };

        let compact: SignedEnvelope = full.clone().into();
        assert_eq!(compact.pubkey, full.pubkey);
        assert_eq!(compact.signature, full.signature);
        assert_eq!(compact.digest, full.digest);
        assert_eq!(compact.delegation.as_ref().unwrap().len(), 1);

        let full_again: SignedEnvelopeFull = compact.into();
        assert_eq!(full_again.pubkey, full.pubkey);
        assert_eq!(full_again.signature, full.signature);
        assert_eq!(full_again.digest, full.digest);
        assert_eq!(full_again.delegation.unwrap().len(), 1);
    }

    #[cfg(feature = "identity")]
    #[test]
    fn test_targeted_delegation_verification_paths() {
        let user = BasicIdentity::from_raw_key(&[8u8; 32]);
        let session = BasicIdentity::from_raw_key(&[9u8; 32]);
        let target = Principal::management_canister();
        let expiration = unix_timestamp()
            .saturating_add(Duration::from_secs(3600))
            .as_nanos() as u64;
        let delegation = AgentDelegation {
            pubkey: session.public_key().unwrap(),
            expiration,
            targets: Some(vec![target]),
            permissions: None,
        };
        let signature = user
            .sign_delegation(&delegation)
            .unwrap()
            .signature
            .unwrap();
        let compact = SignedDelegationCompact {
            delegation: DelegationCompact {
                pubkey: delegation.pubkey.clone().into(),
                expiration: delegation.expiration,
                targets: delegation.targets.clone(),
                permissions: None,
            },
            signature: signature.clone().into(),
        };

        let user_pubkey = user.public_key().unwrap();
        let session_pubkey = session.public_key().unwrap();
        let now_ms = unix_timestamp().as_millis() as u64;
        verify_delegation_chain(
            &user_pubkey,
            &session_pubkey,
            std::slice::from_ref(&compact),
            now_ms,
            None,
        )
        .unwrap();
        let err = verify_delegation_chain(
            &user_pubkey,
            b"wrong-session",
            std::slice::from_ref(&compact),
            now_ms,
            None,
        )
        .unwrap_err();
        assert!(err.contains("Last verified public key does not match session public key"));

        let delegated = DelegatedIdentity::new_unchecked(
            user_pubkey.clone(),
            Box::new(session),
            vec![AgentSignedDelegation {
                delegation,
                signature,
            }],
        );
        let digest = sha3_256(b"targeted message");
        let envelope = SignedEnvelope::sign_digest(&delegated, digest.to_vec()).unwrap();
        envelope
            .verify(now_ms, Some(target), Some(&digest))
            .unwrap();
    }

    #[test]
    fn test_signed_envelope_rejects_delegation_length_and_expiration() {
        let delegation = SignedDelegationCompact {
            delegation: DelegationCompact {
                pubkey: vec![1, 2, 3].into(),
                expiration: u64::MAX,
                targets: None,
                permissions: None,
            },
            signature: vec![4, 5, 6].into(),
        };
        let envelope = SignedEnvelope {
            pubkey: vec![7, 8, 9].into(),
            signature: vec![10, 11, 12].into(),
            digest: Some(vec![13, 14, 15].into()),
            delegation: Some(vec![delegation; MAX_DELEGATION_CHAIN_LENGTH + 1]),
        };
        assert!(envelope.verify(0, None, Some(&[13, 14, 15])).is_err());
        let err = envelope.verify(0, None, None).unwrap_err();
        assert!(err.contains("Delegation chain length exceeds the limit"));

        let envelope = SignedEnvelope {
            pubkey: vec![7, 8, 9].into(),
            signature: vec![10, 11, 12].into(),
            digest: Some(vec![13, 14, 15].into()),
            delegation: Some(vec![SignedDelegationCompact {
                delegation: DelegationCompact {
                    pubkey: vec![1, 2, 3].into(),
                    expiration: 0,
                    targets: None,
                    permissions: None,
                },
                signature: vec![4, 5, 6].into(),
            }]),
        };
        let err = envelope
            .verify(PERMITTED_DRIFT_MS + 1, None, None)
            .unwrap_err();
        assert!(err.contains("Delegation has expired"));
    }

    #[cfg(feature = "identity")]
    #[test]
    fn test_delegation_permissions_are_covered_by_the_signature() {
        use ic_agent::identity::DelegationPermissions as AgentPerms;

        let user = BasicIdentity::from_raw_key(&[8u8; 32]);
        let session = BasicIdentity::from_raw_key(&[9u8; 32]);
        let expiration = unix_timestamp()
            .saturating_add(Duration::from_secs(3600))
            .as_nanos() as u64;

        let cases = [
            (None, None),
            (
                Some(AgentPerms::Queries),
                Some(ic_auth_types::DelegationPermissions::Queries),
            ),
            (
                Some(AgentPerms::All),
                Some(ic_auth_types::DelegationPermissions::All),
            ),
        ];

        let mut messages = Vec::new();
        for (agent_perms, our_perms) in cases {
            let agent = AgentDelegation {
                pubkey: session.public_key().unwrap(),
                expiration,
                targets: None,
                permissions: agent_perms,
            };
            let compact = DelegationCompact {
                pubkey: agent.pubkey.clone().into(),
                expiration: agent.expiration,
                targets: agent.targets.clone(),
                permissions: our_perms,
            };

            // The message this crate recomputes must be exactly what the signer
            // signed, or a delegation carrying `permissions` never verifies.
            assert_eq!(
                delegation_signed_message(&compact),
                agent.signable(),
                "recomputed message diverges from ic-agent for {:?}",
                compact.permissions
            );
            messages.push(delegation_signed_message(&compact));
        }

        // ...and each permission value must produce a distinct message, so that
        // `permissions` cannot be rewritten without breaking the signature.
        assert_ne!(messages[0], messages[1]);
        assert_ne!(messages[0], messages[2]);
        assert_ne!(messages[1], messages[2]);

        // End to end: tampering with `permissions` invalidates the chain.
        let agent = AgentDelegation {
            pubkey: session.public_key().unwrap(),
            expiration,
            targets: None,
            permissions: Some(AgentPerms::Queries),
        };
        let signature = user.sign_delegation(&agent).unwrap().signature.unwrap();
        let signed = SignedDelegationCompact {
            delegation: DelegationCompact {
                pubkey: agent.pubkey.clone().into(),
                expiration: agent.expiration,
                targets: None,
                permissions: Some(ic_auth_types::DelegationPermissions::Queries),
            },
            signature: signature.into(),
        };
        let user_pubkey = user.public_key().unwrap();
        let session_pubkey = session.public_key().unwrap();
        let now_ms = unix_timestamp().as_millis() as u64;
        verify_delegation_chain(
            &user_pubkey,
            &session_pubkey,
            std::slice::from_ref(&signed),
            now_ms,
            None,
        )
        .unwrap();

        for tampered in [None, Some(ic_auth_types::DelegationPermissions::All)] {
            let mut forged = signed.clone();
            forged.delegation.permissions = tampered;
            assert!(
                verify_delegation_chain(
                    &user_pubkey,
                    &session_pubkey,
                    std::slice::from_ref(&forged),
                    now_ms,
                    None,
                )
                .is_err(),
                "rewriting permissions must invalidate the delegation"
            );
        }
    }

    #[test]
    fn test_to_headers_clears_stale_optional_headers() {
        let full = SignedEnvelope {
            pubkey: vec![1].into(),
            signature: vec![2].into(),
            digest: Some(vec![3].into()),
            delegation: Some(vec![SignedDelegationCompact {
                delegation: DelegationCompact {
                    pubkey: vec![4].into(),
                    expiration: 9,
                    targets: None,
                    permissions: None,
                },
                signature: vec![5].into(),
            }]),
        };
        let bare = SignedEnvelope {
            pubkey: vec![9].into(),
            signature: vec![8].into(),
            digest: None,
            delegation: None,
        };

        // Writing `bare` over a reused map must not leave `full`'s digest and
        // delegation behind to be paired with the new key and signature.
        let mut headers = HeaderMap::new();
        full.to_headers(&mut headers).unwrap();
        bare.to_headers(&mut headers).unwrap();

        assert!(headers.get(&HEADER_IC_AUTH_CONTENT_DIGEST).is_none());
        assert!(headers.get(&HEADER_IC_AUTH_DELEGATION).is_none());
        // No digest header means the envelope is no longer reconstructable.
        assert!(SignedEnvelope::from_headers(&headers).is_none());
    }

    #[test]
    fn test_decode_base64_rejects_overlong_padding() {
        // Optional padding, in either alphabet, still decodes.
        assert_eq!(decode_base64("AQID").unwrap(), vec![1, 2, 3]);
        assert_eq!(decode_base64("AQIDBA==").unwrap(), vec![1, 2, 3, 4]);
        assert!(decode_base64("").unwrap().is_empty());

        // A run of `=` is not data: these used to decode instead of failing.
        for malformed in ["====", "AQID====", "AQIDBA======"] {
            assert!(
                decode_base64(malformed).is_err(),
                "expected {malformed:?} to be rejected"
            );
        }

        // ...so a garbage header no longer yields an empty key.
        let mut headers = HeaderMap::new();
        headers.insert(&HEADER_IC_AUTH_PUBKEY, "====".parse().unwrap());
        assert_eq!(extract_data(&headers, &HEADER_IC_AUTH_PUBKEY), None);
    }

    #[test]
    fn test_extract_user_defaults_to_anonymous() {
        let mut headers = HeaderMap::new();
        assert_eq!(extract_user(&headers), ANONYMOUS_PRINCIPAL);

        headers.insert(
            &HEADER_IC_AUTH_USER,
            Principal::management_canister().to_text().parse().unwrap(),
        );
        assert_eq!(extract_user(&headers), Principal::management_canister());

        headers.insert(&HEADER_IC_AUTH_USER, "not-a-principal".parse().unwrap());
        assert_eq!(extract_user(&headers), ANONYMOUS_PRINCIPAL);
    }

    #[test]
    fn test_verify_rejects_missing_and_mismatched_digest_before_signature() {
        let envelope = SignedEnvelope {
            pubkey: vec![1, 2, 3].into(),
            signature: vec![4, 5, 6].into(),
            digest: None,
            delegation: None,
        };

        assert_eq!(
            envelope.verify(0, None, None).unwrap_err(),
            "No content digest provided for verification"
        );

        let mut envelope = sample_envelope();
        let err = envelope.verify(0, None, Some(&[0])).unwrap_err();
        assert_eq!(err, "Content digest does not match");

        envelope.digest = None;
        let err = envelope.verify(0, None, Some(&[7, 8, 9])).unwrap_err();
        assert!(err.contains("DER encoding") || err.contains("ASN.1"));
    }

    #[test]
    fn test_verify_rejects_delegation_target_mismatch() {
        let envelope = SignedEnvelope {
            pubkey: vec![1, 2, 3].into(),
            signature: vec![4, 5, 6].into(),
            digest: Some(vec![7, 8, 9].into()),
            delegation: Some(vec![SignedDelegationCompact {
                delegation: DelegationCompact {
                    pubkey: vec![9, 8, 7].into(),
                    expiration: u64::MAX,
                    targets: Some(vec![Principal::management_canister()]),
                    permissions: None,
                },
                signature: vec![6, 5, 4].into(),
            }]),
        };

        let other = Principal::from_slice(&[1, 2, 3]);
        let err = envelope.verify(0, Some(other), None).unwrap_err();
        assert!(err.contains("is not in the delegation targets"));
    }

    #[test]
    fn test_verify_delegation_chain_rejects_empty_and_invalid_chain() {
        assert_eq!(
            verify_delegation_chain(&[], &[], &[], 0, None).unwrap_err(),
            "Delegation chain is empty"
        );

        let delegation = SignedDelegationCompact {
            delegation: DelegationCompact {
                pubkey: vec![1, 2, 3].into(),
                expiration: u64::MAX,
                targets: None,
                permissions: None,
            },
            signature: vec![4, 5, 6].into(),
        };
        let err = verify_delegation_chain(&[], &[9], &[delegation], 0, Some(&[])).unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn test_verify_delegation_chain_rejects_expired_delegation() {
        let delegation = SignedDelegationCompact {
            delegation: DelegationCompact {
                pubkey: vec![1, 2, 3].into(),
                expiration: 0,
                targets: None,
                permissions: None,
            },
            signature: vec![4, 5, 6].into(),
        };
        let err =
            verify_delegation_chain(&[], &[1, 2, 3], &[delegation], PERMITTED_DRIFT_MS + 1, None)
                .unwrap_err();
        assert!(err.contains("Delegation has expired"));
    }

    #[test]
    fn test_verify_delegation_chain_rejects_too_many_delegations() {
        let delegation = SignedDelegationCompact {
            delegation: DelegationCompact {
                pubkey: ByteBufB64::new(),
                expiration: u64::MAX,
                targets: None,
                permissions: None,
            },
            signature: ByteBufB64::new(),
        };
        let delegations = vec![delegation; MAX_DELEGATION_CHAIN_LENGTH + 1];

        let err = verify_delegation_chain(&[], &[], &delegations, 0, None).unwrap_err();
        assert!(err.contains("Delegation chain length exceeds the limit"));
    }

    #[test]
    fn test_verify_delegation_chain() {
        use crate::{IC_STATE_ROOT_DOMAIN_SEPARATOR, sha256};
        use ic_agent::{Identity, identity::BasicIdentity};
        use ic_certification::{Certificate, fork, labeled, leaf};
        use ic_verify_bls_signature::PrivateKey;

        fn tagged<T: Serialize>(value: &T) -> Vec<u8> {
            let mut bytes = vec![0xd9, 0xd9, 0xf7];
            bytes.extend(serde_cbor::to_vec(value).unwrap());
            bytes
        }

        let now_ms = 1_700_000_000_000;
        let expiration = (now_ms + 600_000) * 1_000_000;
        let middle = BasicIdentity::from_raw_key(&[8; 32]);
        let session = BasicIdentity::from_raw_key(&[9; 32]);
        let canister_key = CanisterSigPublicKey::new(Principal::from_slice(&[1]), vec![7; 32]);
        let first = DelegationCompact {
            pubkey: middle.public_key().unwrap().into(),
            expiration,
            targets: None,
            permissions: None,
        };
        let sig_tree = labeled(
            b"sig".to_vec(),
            labeled(
                sha256(&canister_key.seed).to_vec(),
                labeled(
                    sha256(&delegation_signed_message(&first)).to_vec(),
                    leaf(Vec::<u8>::new()),
                ),
            ),
        );
        let mut time = now_ms * 1_000_000;
        let mut encoded_time = Vec::new();
        loop {
            let byte = (time & 0x7f) as u8;
            time >>= 7;
            encoded_time.push(if time == 0 { byte } else { byte | 0x80 });
            if time == 0 {
                break;
            }
        }
        let cert_tree = fork(
            labeled(
                b"canister".to_vec(),
                labeled(
                    canister_key.canister_id.as_slice().to_vec(),
                    labeled(b"certified_data".to_vec(), leaf(sig_tree.digest().to_vec())),
                ),
            ),
            labeled(b"time".to_vec(), leaf(encoded_time)),
        );
        let mut key_bytes = [0; 32];
        key_bytes[31] = 1;
        let root = PrivateKey::deserialize(&key_bytes).unwrap();
        let mut root_der = IC_ROOT_PK_DER[..37].to_vec();
        root_der.extend_from_slice(&root.public_key().serialize());
        let mut message = IC_STATE_ROOT_DOMAIN_SEPARATOR.to_vec();
        message.extend_from_slice(&cert_tree.digest());
        let certificate = Certificate {
            tree: cert_tree,
            signature: root.sign(&message).serialize().to_vec(),
            delegation: None,
        };
        #[derive(Serialize)]
        struct CanisterSignature {
            certificate: serde_bytes::ByteBuf,
            tree: ic_certification::HashTree,
        }
        let first_signature = tagged(&CanisterSignature {
            certificate: tagged(&certificate).into(),
            tree: sig_tree,
        });
        let second = DelegationCompact {
            pubkey: session.public_key().unwrap().into(),
            expiration,
            targets: None,
            permissions: None,
        };
        let second_signature = middle
            .sign_arbitrary(&delegation_signed_message(&second))
            .unwrap()
            .signature
            .unwrap();
        let mut delegations = vec![
            SignedDelegationCompact {
                delegation: first,
                signature: first_signature.into(),
            },
            SignedDelegationCompact {
                delegation: second,
                signature: second_signature.into(),
            },
        ];
        let user_pubkey = canister_key.to_der();
        let session_pubkey = session.public_key().unwrap();
        verify_delegation_chain(
            &user_pubkey,
            &session_pubkey,
            &delegations,
            now_ms,
            Some(&root_der),
        )
        .unwrap();
        let err = verify_delegation_chain(
            &user_pubkey,
            b"wrong-session",
            &delegations,
            now_ms,
            Some(&root_der),
        )
        .unwrap_err();
        assert!(err.contains("Last verified public key does not match session public key"));
        delegations[0].delegation.expiration += 1;
        assert!(
            verify_delegation_chain(
                &user_pubkey,
                &session_pubkey,
                &delegations,
                now_ms,
                Some(&root_der)
            )
            .is_err()
        );
    }

    #[test]
    fn authorization_scheme_is_case_insensitive() {
        let envelope = sample_envelope();
        for scheme in ["ICP", "icp", "IcP"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                AUTHORIZATION,
                format!("{scheme} {}", envelope.to_base64())
                    .parse()
                    .unwrap(),
            );
            let parsed = SignedEnvelope::from_authorization(&headers).unwrap();
            assert_eq!(parsed.to_bytes(), envelope.to_bytes());
        }
    }
}
