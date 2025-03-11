use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use candid::Principal;
use ciborium::{from_reader, into_writer};
use http::header::{HeaderMap, HeaderName};
use ic_agent::Identity;
use ic_auth_types::{Delegation, SignedDelegation};
use ic_canister_sig_creation::delegation_signature_msg;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Algorithm, sha3_256, user_public_key_from_der, verify_basic_sig};

pub use ic_signature_verification::verify_canister_sig;

pub const ANONYMOUS_PRINCIPAL: Principal = Principal::anonymous();
pub const PERMITTED_DRIFT_MS: u64 = 60 * 1000;

/// The IC root public key used when verifying canister signatures.
/// https://internetcomputer.org/docs/current/developer-docs/web-apps/obtain-verify-ic-pubkey
pub const IC_ROOT_PUBLIC_KEY_RAW: &[u8; 96] = &[
    129, 76, 14, 110, 199, 31, 171, 88, 59, 8, 189, 129, 55, 60, 37, 92, 60, 55, 27, 46, 132, 134,
    60, 152, 164, 241, 224, 139, 116, 35, 93, 20, 251, 93, 156, 12, 213, 70, 217, 104, 95, 145, 58,
    12, 11, 44, 197, 52, 21, 131, 191, 75, 67, 146, 228, 103, 219, 150, 214, 91, 155, 180, 203,
    113, 113, 18, 248, 71, 46, 13, 90, 77, 20, 80, 95, 253, 116, 132, 176, 18, 145, 9, 28, 95, 135,
    185, 136, 131, 70, 63, 152, 9, 26, 11, 170, 174,
];

/// Caller's public key for authentication
pub static HEADER_IC_AUTH_PUBKEY: HeaderName = HeaderName::from_static("ic-auth-pubkey");

/// Request content hash (customizable by business logic)
pub static HEADER_IC_AUTH_CONTENT_DIGEST: HeaderName =
    HeaderName::from_static("ic-auth-content-digest");

/// Signature of the content digest
pub static HEADER_IC_AUTH_SIGNATURE: HeaderName = HeaderName::from_static("ic-auth-signature");

/// Delegation chain for authentication
pub static HEADER_IC_AUTH_DELEGATION: HeaderName = HeaderName::from_static("ic-auth-delegation");

/// Authenticated user principal (or anonymous principal)
pub static HEADER_IC_AUTH_USER: HeaderName = HeaderName::from_static("ic-auth-user");

/// Verify the signature of the message with the public key and the mainnet IC root public key
pub fn verify_sig(public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<(), String> {
    verify_sig_with_rootkey(IC_ROOT_PUBLIC_KEY_RAW, public_key, msg, signature)
}

/// Verify the signature of the message with the public key and given IC root public key
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

/// The authentication envelope, which is signed by the sender, and can be verified by `ic_auth_verifier`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignedEnvelope {
    /// The public key of the self-signing principal this request is from.
    pub pubkey: ByteBuf,
    /// A cryptographic signature authorizing the request. Not necessarily made by `sender_pubkey`; when delegations are involved,
    /// `sender_sig` is the tail of the delegation chain, and `sender_pubkey` is the head.
    pub signature: ByteBuf,
    /// the request content's hash digest to sign by sender
    pub digest: ByteBuf,
    /// The chain of delegations connecting `pubkey` to `signature`, and in that order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<Vec<SignedDelegation>>,
}

impl SignedEnvelope {
    /// The sender's principal ID
    pub fn sender(&self) -> Principal {
        Principal::self_authenticating(&self.pubkey)
    }

    /// Encode the SignedEnvelope into bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        into_writer(self, &mut buf).expect("failed to encode SignedEnvelope");
        buf
    }

    /// Decode the SignedEnvelope from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        from_reader(bytes).map_err(|err| format!("failed to decode SignedEnvelope data: {err:?}"))
    }

    /// Encode the SignedEnvelope into base64_url string
    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.to_bytes())
    }

    /// Decode the SignedEnvelope from base64_url string
    pub fn from_base64(s: &str) -> Result<Self, String> {
        decode_base64(s).and_then(|data| Self::from_bytes(&data))
    }

    /// Sign the message with the Identity
    pub fn sign_message(identity: impl Identity, message: &[u8]) -> Result<Self, String> {
        Self::sign_digest(identity, sha3_256(message).into())
    }

    /// Sign the message digest with the Identity
    pub fn sign_digest(identity: impl Identity, digest: Vec<u8>) -> Result<Self, String> {
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
                    .map(|d| SignedDelegation {
                        delegation: Delegation {
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

    /// Verify the SignedEnvelope, rules:
    /// - Delegation chain length ≤ 5
    /// - Delegations must not be expired
    /// - Signature must verify against the public key
    /// - Canister must be in delegation targets (if specified)
    pub fn verify(
        &self,
        now_ms: u64,
        expect_target: Option<Principal>,
        expect_digest: Option<&[u8]>,
    ) -> Result<(), String> {
        if let Some(expect_digest) = expect_digest {
            if self.digest != expect_digest {
                return Err("Content digest does not match".to_string());
            }
        }

        let mut has_targets = false;
        let mut in_targets = false;
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
                        has_targets = true;
                        in_targets = in_targets
                            || if let Some(target) = &expect_target {
                                targets.contains(target)
                            } else {
                                false
                            };
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

        if has_targets && !in_targets {
            return Err(format!(
                "Canister '{expect_target:?}' is not one of the delegation targets.",
            ));
        }

        verify_sig(last_verified, &self.digest, &self.signature)
    }

    /// Try to extract the SignedEnvelope from the http headers
    pub fn try_from(headers: &HeaderMap) -> Option<Self> {
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

    /// Insert the SignedEnvelope into the http headers
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

/// Extracts the base64-encoded data from the headers
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

/// Extracts the user principal from the headers
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

/// Encode object into CBOR bytes
pub fn to_cbor_bytes(obj: &impl Serialize) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    into_writer(obj, &mut buf).expect("failed to encode in CBOR format");
    buf
}

/// Decode base64_url data
pub fn decode_base64(data: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(data.trim().trim_end_matches('='))
        .map_err(|err| format!("failed to decode base64 data: {err}"))
}

/// Returns the current unix timestamp in milliseconds.
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
        let se = SignedEnvelope::sign_message(id, msg).unwrap();
        se.to_headers(&mut headers).unwrap();

        let mut se2 = SignedEnvelope::try_from(&headers).unwrap();
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
