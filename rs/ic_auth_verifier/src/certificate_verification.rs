//! Verification of Internet Computer state-tree certificates.
//!
//! This mirrors the `ic-certificate-verification` crate, which this crate used
//! until it became unusable for canisters: that crate depends on `cached`,
//! which depends unconditionally on `web-time`, which reads the browser clock
//! through `js-sys` on `wasm32-unknown-unknown`. The resulting
//! `__wbindgen_placeholder__` imports are not exported by the IC runtime, so
//! any canister linking it is rejected at installation with
//!
//! ```text
//! Wasm module has an invalid import section. Module imports function
//! '__wbindgen_describe' from '__wbindgen_placeholder__' that is not exported
//! by the runtime.
//! ```
//!
//! Verifying canister signatures is precisely what a canister needs from this
//! crate, so gating the dependency behind a feature would not have helped.
//!
//! <https://internetcomputer.org/docs/current/references/ic-interface-spec#certification>

use candid::Principal;
use ic_certification::{Certificate, Delegation, LookupResult, SubtreeLookupResult};
use serde_bytes::ByteBuf;

use crate::signature_cache::SignatureCache;

pub const IC_STATE_ROOT_DOMAIN_SEPARATOR: &[u8; 14] = b"\x0Dic-state-root";

const DER_PREFIX: &[u8; 37] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00";
const KEY_LENGTH: usize = 96;

/// Verifies a certificate against `root_public_key`.
///
/// Checks, in order, that the certificate's `/time` is within
/// `allowed_certificate_time_offset_ns` of `current_time_ns`, that any subnet
/// delegation is itself signed by the root key and covers `canister_id`, and
/// that the certificate's BLS signature verifies under the resulting key.
pub fn verify_certificate(
    certificate: &Certificate,
    canister_id: &[u8],
    root_public_key: &[u8],
    current_time_ns: u128,
    allowed_certificate_time_offset_ns: u128,
) -> Result<(), String> {
    verify_certificate_time(
        certificate,
        current_time_ns,
        allowed_certificate_time_offset_ns,
    )?;

    let der_key = match &certificate.delegation {
        Some(delegation) => verify_delegation(delegation, canister_id, root_public_key)?,
        None => root_public_key.to_vec(),
    };
    verify_certificate_signature(certificate, &der_key)
}

/// Verifies the delegation certificate and returns the DER-encoded subnet key
/// that the delegating certificate must be signed with.
fn verify_delegation(
    delegation: &Delegation,
    canister_id: &[u8],
    root_public_key: &[u8],
) -> Result<Vec<u8>, String> {
    let cert = parse_certificate_cbor(&delegation.certificate)?;

    // A delegation may not itself be delegated: the chain is exactly one hop.
    if cert.delegation.is_some() {
        return Err("certificate has too many delegations".to_string());
    }

    // Only the signature is checked here. A subnet delegation is not reissued
    // on a regular basis, so its `/time` says nothing about freshness.
    verify_certificate_signature(&cert, root_public_key)?;

    let canister_id = Principal::try_from_slice(canister_id)
        .map_err(|err| format!("invalid canister id: {err}"))?;

    // Current layout: /canister_ranges/<subnet_id>/<range_key>, which splits
    // one subnet's ranges over several leaves.
    let canister_ranges_path = ["canister_ranges".as_bytes(), delegation.subnet_id.as_ref()];
    let canister_ranges: Vec<(Principal, Principal)> =
        match cert.tree.lookup_subtree(&canister_ranges_path) {
            SubtreeLookupResult::Found(subnet_tree) => {
                let mut ranges = Vec::new();
                for range_key_path in subnet_tree.list_paths() {
                    let Some(range_key) = range_key_path.first() else {
                        continue;
                    };
                    if let LookupResult::Found(range_data) =
                        subnet_tree.lookup_path([range_key.as_bytes()])
                    {
                        ranges.extend(parse_canister_ranges(range_data)?);
                    }
                }
                ranges
            }
            SubtreeLookupResult::Absent | SubtreeLookupResult::Unknown => {
                // Legacy layout: /subnet/<subnet_id>/canister_ranges.
                let legacy_path = [
                    "subnet".as_bytes(),
                    delegation.subnet_id.as_ref(),
                    "canister_ranges".as_bytes(),
                ];
                match cert.tree.lookup_path(&legacy_path) {
                    LookupResult::Found(range_data) => parse_canister_ranges(range_data)?,
                    _ => {
                        return Err(
                            "subnet canister id ranges not found in delegation certificate"
                                .to_string(),
                        );
                    }
                }
            }
        };

    if !principal_is_within_ranges(&canister_id, &canister_ranges) {
        // This subnet is not authorized to answer for this canister.
        return Err(format!(
            "canister {canister_id} is not in the delegated subnet's canister ranges"
        ));
    }

    let public_key_path = [
        "subnet".as_bytes(),
        delegation.subnet_id.as_ref(),
        "public_key".as_bytes(),
    ];
    let LookupResult::Found(subnet_public_key) = cert.tree.lookup_path(&public_key_path) else {
        return Err("subnet public key not found in delegation certificate".to_string());
    };

    Ok(subnet_public_key.to_vec())
}

fn verify_certificate_time(
    certificate: &Certificate,
    current_time_ns: u128,
    allowed_certificate_time_offset_ns: u128,
) -> Result<(), String> {
    let LookupResult::Found(encoded_certificate_time) =
        certificate.tree.lookup_path(["time".as_bytes()])
    else {
        return Err("missing time path in certificate tree".to_string());
    };

    let certificate_time = decode_leb128_u128(encoded_certificate_time)
        .map_err(|err| format!("failed to decode certificate time: {err}"))?;
    let max_certificate_time = current_time_ns.saturating_add(allowed_certificate_time_offset_ns);
    let min_certificate_time = current_time_ns.saturating_sub(allowed_certificate_time_offset_ns);

    if certificate_time > max_certificate_time {
        return Err(format!(
            "certificate time {certificate_time} is too far in the future, max: {max_certificate_time}"
        ));
    }
    if certificate_time < min_certificate_time {
        return Err(format!(
            "certificate time {certificate_time} is too far in the past, min: {min_certificate_time}"
        ));
    }
    Ok(())
}

fn verify_certificate_signature(certificate: &Certificate, der_key: &[u8]) -> Result<(), String> {
    let mut msg = Vec::with_capacity(IC_STATE_ROOT_DOMAIN_SEPARATOR.len() + 32);
    msg.extend_from_slice(IC_STATE_ROOT_DOMAIN_SEPARATOR);
    msg.extend_from_slice(&certificate.tree.digest());

    let public_key = extract_der(der_key)?;
    verify_bls_signature_cached(public_key, &certificate.signature, &msg)
}

/// Verifies a BLS signature, short-circuiting on a previously verified triple.
///
/// A subnet delegation certificate is stable for long stretches, so the same
/// signature is re-verified on request after request. Caching the successful
/// verifications keeps that off the hot path; see [`SignatureCache`].
fn verify_bls_signature_cached(
    public_key: &[u8],
    signature: &[u8],
    msg: &[u8],
) -> Result<(), String> {
    let entry = SignatureCache::entry(public_key, signature, msg);
    if SignatureCache::global().contains(&entry) {
        return Ok(());
    }

    ic_verify_bls_signature::verify_bls_signature(signature, msg, public_key)
        .map_err(|_| "certificate signature verification failed".to_string())?;

    SignatureCache::global().insert(entry);
    Ok(())
}

/// Strips the DER prefix from a BLS public key.
fn extract_der(buf: &[u8]) -> Result<&[u8], String> {
    let expected_length = DER_PREFIX.len() + KEY_LENGTH;
    if buf.len() != expected_length {
        return Err(format!(
            "DER key length mismatch: {}, expected: {expected_length}",
            buf.len()
        ));
    }
    if buf[..DER_PREFIX.len()] != DER_PREFIX[..] {
        return Err("DER key prefix mismatch".to_string());
    }
    Ok(&buf[DER_PREFIX.len()..])
}

/// Parses a certificate from its CBOR encoding.
pub fn parse_certificate_cbor(certificate_cbor: &[u8]) -> Result<Certificate, String> {
    // 0xd9d9f7 (cf. https://tools.ietf.org/html/rfc7049#section-2.4.5) is the
    // self-describing CBOR tag required to be present by the interface spec.
    if certificate_cbor.len() < 3 || certificate_cbor[0..3] != [0xd9, 0xd9, 0xf7] {
        return Err("certificate CBOR doesn't have a self-describing tag".to_string());
    }
    serde_cbor::from_slice::<Certificate>(certificate_cbor)
        .map_err(|e| format!("failed to parse certificate CBOR: {e}"))
}

fn principal_is_within_ranges(principal: &Principal, ranges: &[(Principal, Principal)]) -> bool {
    ranges
        .iter()
        .any(|(start, end)| principal >= start && principal <= end)
}

/// Parses a CBOR array of `[start, end]` principal pairs.
fn parse_canister_ranges(data: &[u8]) -> Result<Vec<(Principal, Principal)>, String> {
    let ranges: Vec<(ByteBuf, ByteBuf)> = serde_cbor::from_slice(data)
        .map_err(|err| format!("failed to parse canister ranges CBOR: {err}"))?;
    ranges
        .into_iter()
        .map(|(start, end)| {
            // `Principal::from_slice` panics on an over-long slice, and this
            // input is attacker-controlled until the signature checks out.
            let start = Principal::try_from_slice(&start)
                .map_err(|err| format!("invalid canister range start: {err}"))?;
            let end = Principal::try_from_slice(&end)
                .map_err(|err| format!("invalid canister range end: {err}"))?;
            Ok((start, end))
        })
        .collect()
}

/// Decodes an unsigned LEB128 integer, as the state tree encodes `/time`.
fn decode_leb128_u128(mut bytes: &[u8]) -> Result<u128, String> {
    let mut result: u128 = 0;
    let mut shift: u32 = 0;
    loop {
        let (&byte, rest) = bytes
            .split_first()
            .ok_or_else(|| "truncated LEB128 integer".to_string())?;
        bytes = rest;

        let payload = u128::from(byte & 0x7f);
        // Reject any byte whose bits would not survive the shift, so a padded
        // or oversized encoding cannot silently wrap to a small timestamp.
        if shift >= u128::BITS || (payload << shift) >> shift != payload {
            return Err("LEB128 integer overflows u128".to_string());
        }
        result |= payload << shift;

        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_certification::{HashTree, empty, fork, labeled, leaf};
    use ic_verify_bls_signature::PrivateKey;

    #[test]
    fn leb128_round_trips_and_rejects_bad_encodings() {
        assert_eq!(decode_leb128_u128(&[0x00]).unwrap(), 0);
        assert_eq!(decode_leb128_u128(&[0x7f]).unwrap(), 127);
        assert_eq!(decode_leb128_u128(&[0x80, 0x01]).unwrap(), 128);
        // A realistic IC timestamp in nanoseconds.
        assert_eq!(
            decode_leb128_u128(&[0x80, 0xd3, 0xcf, 0xe9, 0xd6, 0xf8, 0x8e, 0xb9, 0x18]).unwrap(),
            1_761_536_123_382_000_000
        );
        // Trailing bytes after the terminator are ignored, as in the reference
        // implementation, which reads the integer out of a longer buffer.
        assert_eq!(decode_leb128_u128(&[0x01, 0xff]).unwrap(), 1);

        assert!(decode_leb128_u128(&[]).is_err());
        assert!(decode_leb128_u128(&[0x80]).is_err());
        assert!(decode_leb128_u128(&[0x80; 32]).is_err());
    }

    #[test]
    fn der_prefix_and_length_are_enforced() {
        let key = [0u8; KEY_LENGTH];
        let mut der = DER_PREFIX.to_vec();
        der.extend_from_slice(&key);
        assert_eq!(extract_der(&der).unwrap(), key.to_vec());

        assert!(extract_der(&der[..der.len() - 1]).is_err());

        let mut wrong_prefix = der.clone();
        wrong_prefix[0] ^= 0xff;
        assert!(extract_der(&wrong_prefix).is_err());
    }

    #[test]
    fn canister_ranges_bound_the_delegated_subnet() {
        let low = Principal::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 1, 1]);
        let high = Principal::from_slice(&[0, 0, 0, 0, 0, 0, 0, 10, 1, 1]);
        let ranges = vec![(low, high)];

        assert!(principal_is_within_ranges(&low, &ranges));
        assert!(principal_is_within_ranges(&high, &ranges));
        assert!(!principal_is_within_ranges(
            &Principal::anonymous(),
            &ranges
        ));
        // An empty or fully pruned range list proves no authority.
        assert!(!principal_is_within_ranges(&low, &[]));
    }

    #[test]
    fn canister_ranges_reject_malformed_principals() {
        let encoded = serde_cbor::to_vec(&vec![(
            ByteBuf::from(vec![0u8; 10]),
            ByteBuf::from(vec![0u8; 10]),
        )])
        .unwrap();
        assert_eq!(parse_canister_ranges(&encoded).unwrap().len(), 1);

        // A principal is at most 29 bytes; the reference implementation panics
        // on this input instead of reporting an error.
        let oversized = serde_cbor::to_vec(&vec![(
            ByteBuf::from(vec![0u8; 30]),
            ByteBuf::from(vec![0u8; 10]),
        )])
        .unwrap();
        assert!(parse_canister_ranges(&oversized).is_err());

        assert!(parse_canister_ranges(b"not cbor").is_err());
    }

    #[test]
    fn certificate_time_is_bounded_in_both_directions() {
        let now: u128 = 1_761_536_123_382_000_000;
        let offset: u128 = 300_000_000_000;

        let certificate_at = |time: u128| {
            let mut encoded = Vec::new();
            let mut value = time;
            loop {
                let mut byte = (value & 0x7f) as u8;
                value >>= 7;
                if value != 0 {
                    byte |= 0x80;
                }
                encoded.push(byte);
                if value == 0 {
                    break;
                }
            }
            Certificate {
                tree: labeled(b"time".to_vec(), leaf(encoded)),
                signature: vec![],
                delegation: None,
            }
        };

        verify_certificate_time(&certificate_at(now), now, offset).unwrap();
        verify_certificate_time(&certificate_at(now - offset), now, offset).unwrap();
        verify_certificate_time(&certificate_at(now + offset), now, offset).unwrap();

        let err =
            verify_certificate_time(&certificate_at(now + offset + 1), now, offset).unwrap_err();
        assert!(err.contains("too far in the future"), "{err}");

        let err =
            verify_certificate_time(&certificate_at(now - offset - 1), now, offset).unwrap_err();
        assert!(err.contains("too far in the past"), "{err}");

        let no_time = Certificate {
            tree: empty(),
            signature: vec![],
            delegation: None,
        };
        assert!(verify_certificate_time(&no_time, now, offset).is_err());
    }

    fn tagged_cbor(certificate: &Certificate) -> Vec<u8> {
        let mut out = vec![0xd9, 0xd9, 0xf7];
        out.extend(serde_cbor::to_vec(certificate).unwrap());
        out
    }

    /// Builds certificates the way a subnet does, so the delegation path can
    /// be exercised end to end instead of only in pieces. `ic-verify-bls-
    /// signature` exposes signing, so no test-only certificate builder crate
    /// is needed (the reference implementation's is unpublished).
    struct TestSubnet {
        root_key: PrivateKey,
        subnet_key: PrivateKey,
        subnet_id: Vec<u8>,
    }

    impl TestSubnet {
        const NOW_NS: u128 = 1_761_536_123_382_000_000;

        fn new() -> Self {
            Self {
                root_key: test_private_key(1),
                subnet_key: test_private_key(2),
                subnet_id: vec![0, 0, 0, 0, 0, 0, 0, 2, 1, 1],
            }
        }

        fn root_key_der(&self) -> Vec<u8> {
            der_encode(&self.root_key)
        }

        fn sign(&self, key: &PrivateKey, tree: &HashTree) -> Vec<u8> {
            let mut msg = IC_STATE_ROOT_DOMAIN_SEPARATOR.to_vec();
            msg.extend_from_slice(&tree.digest());
            key.sign(&msg).serialize().to_vec()
        }

        /// The certificate the subnet delegation is proved by, laid out either
        /// in the current `/canister_ranges` form or the legacy
        /// `/subnet/<id>/canister_ranges` one.
        fn delegation_certificate(
            &self,
            ranges: &[(Principal, Principal)],
            legacy_layout: bool,
        ) -> Certificate {
            let encoded_ranges = serde_cbor::to_vec(
                &ranges
                    .iter()
                    .map(|(start, end)| {
                        (
                            ByteBuf::from(start.as_slice().to_vec()),
                            ByteBuf::from(end.as_slice().to_vec()),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap();

            let public_key = labeled(b"public_key".to_vec(), leaf(der_encode(&self.subnet_key)));
            // A fork's labels have to be in order for `lookup_subtree` to find
            // them, exactly as a subnet builds the tree.
            let tree = if legacy_layout {
                let subnet = labeled(
                    b"subnet".to_vec(),
                    labeled(
                        self.subnet_id.clone(),
                        fork(
                            labeled(b"canister_ranges".to_vec(), leaf(encoded_ranges)),
                            public_key,
                        ),
                    ),
                );
                fork(
                    subnet,
                    labeled(b"time".to_vec(), leaf(encode_leb128(Self::NOW_NS))),
                )
            } else {
                let canister_ranges = labeled(
                    b"canister_ranges".to_vec(),
                    labeled(
                        self.subnet_id.clone(),
                        // The subnet's ranges are split over range keys.
                        labeled(b"0".to_vec(), leaf(encoded_ranges)),
                    ),
                );
                let subnet = labeled(
                    b"subnet".to_vec(),
                    labeled(self.subnet_id.clone(), public_key),
                );
                fork(
                    canister_ranges,
                    fork(
                        subnet,
                        labeled(b"time".to_vec(), leaf(encode_leb128(Self::NOW_NS))),
                    ),
                )
            };
            let signature = self.sign(&self.root_key, &tree);
            Certificate {
                tree,
                signature,
                delegation: None,
            }
        }

        /// A certificate signed by the subnet key and delegated from the root.
        fn certificate(&self, delegation_certificate: &Certificate) -> Certificate {
            let tree = labeled(b"time".to_vec(), leaf(encode_leb128(Self::NOW_NS)));
            let signature = self.sign(&self.subnet_key, &tree);
            Certificate {
                tree,
                signature,
                delegation: Some(Delegation {
                    subnet_id: self.subnet_id.clone(),
                    certificate: tagged_cbor(delegation_certificate),
                }),
            }
        }
    }

    fn test_private_key(seed: u8) -> PrivateKey {
        let mut bytes = [0u8; 32];
        bytes[31] = seed;
        PrivateKey::deserialize(&bytes).unwrap()
    }

    fn der_encode(key: &PrivateKey) -> Vec<u8> {
        let mut der = DER_PREFIX.to_vec();
        der.extend_from_slice(&key.public_key().serialize());
        der
    }

    fn encode_leb128(mut value: u128) -> Vec<u8> {
        let mut encoded = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            encoded.push(byte);
            if value == 0 {
                return encoded;
            }
        }
    }

    #[test]
    fn a_delegated_certificate_verifies_under_the_root_key() {
        let subnet = TestSubnet::new();
        let canister_id = Principal::from_slice(&[0, 0, 0, 0, 0, 0, 0, 5, 1, 1]);
        let ranges = [(
            Principal::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 1, 1]),
            Principal::from_slice(&[0, 0, 0, 0, 0, 0, 0, 10, 1, 1]),
        )];

        for legacy_layout in [false, true] {
            let delegation_certificate = subnet.delegation_certificate(&ranges, legacy_layout);
            let certificate = subnet.certificate(&delegation_certificate);

            verify_certificate(
                &certificate,
                canister_id.as_slice(),
                &subnet.root_key_der(),
                TestSubnet::NOW_NS,
                300_000_000_000,
            )
            .unwrap_or_else(|err| panic!("legacy_layout={legacy_layout}: {err}"));
        }
    }

    #[test]
    fn a_delegated_certificate_is_bound_to_the_subnet_ranges_and_keys() {
        let subnet = TestSubnet::new();
        let ranges = [(
            Principal::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 1, 1]),
            Principal::from_slice(&[0, 0, 0, 0, 0, 0, 0, 10, 1, 1]),
        )];
        let delegation_certificate = subnet.delegation_certificate(&ranges, false);
        let certificate = subnet.certificate(&delegation_certificate);
        let offset = 300_000_000_000;

        // A canister the delegated subnet does not host.
        let outside = Principal::from_slice(&[0, 0, 0, 0, 0, 0, 0, 11, 1, 1]);
        let err = verify_certificate(
            &certificate,
            outside.as_slice(),
            &subnet.root_key_der(),
            TestSubnet::NOW_NS,
            offset,
        )
        .unwrap_err();
        assert!(
            err.contains("not in the delegated subnet's canister ranges"),
            "{err}"
        );

        let canister_id = Principal::from_slice(&[0, 0, 0, 0, 0, 0, 0, 5, 1, 1]);

        // A root key that did not sign the delegation.
        let err = verify_certificate(
            &certificate,
            canister_id.as_slice(),
            &der_encode(&test_private_key(3)),
            TestSubnet::NOW_NS,
            offset,
        )
        .unwrap_err();
        assert_eq!(err, "certificate signature verification failed");

        // A certificate signed by the root key directly, rather than by the
        // subnet key the delegation names.
        let mut forged = certificate.clone();
        forged.signature = subnet.sign(&subnet.root_key, &forged.tree);
        let err = verify_certificate(
            &forged,
            canister_id.as_slice(),
            &subnet.root_key_der(),
            TestSubnet::NOW_NS,
            offset,
        )
        .unwrap_err();
        assert_eq!(err, "certificate signature verification failed");

        // A tampered tree no longer matches the signature.
        let mut tampered = certificate.clone();
        tampered.tree = labeled(
            b"time".to_vec(),
            leaf(encode_leb128(TestSubnet::NOW_NS + 1)),
        );
        assert!(
            verify_certificate(
                &tampered,
                canister_id.as_slice(),
                &subnet.root_key_der(),
                TestSubnet::NOW_NS,
                offset,
            )
            .is_err()
        );
    }

    #[test]
    fn a_delegation_without_ranges_is_rejected() {
        let subnet = TestSubnet::new();
        let canister_id = Principal::from_slice(&[0, 0, 0, 0, 0, 0, 0, 5, 1, 1]);

        // A well-formed, correctly ordered tree that simply carries no canister
        // ranges under either the current or the legacy path.
        let tree = fork(
            labeled(
                b"subnet".to_vec(),
                labeled(
                    subnet.subnet_id.clone(),
                    labeled(b"public_key".to_vec(), leaf(der_encode(&subnet.subnet_key))),
                ),
            ),
            labeled(b"time".to_vec(), leaf(encode_leb128(TestSubnet::NOW_NS))),
        );
        let signature = subnet.sign(&subnet.root_key, &tree);
        let delegation_certificate = Certificate {
            tree,
            signature,
            delegation: None,
        };
        let certificate = subnet.certificate(&delegation_certificate);

        let err = verify_certificate(
            &certificate,
            canister_id.as_slice(),
            &subnet.root_key_der(),
            TestSubnet::NOW_NS,
            300_000_000_000,
        )
        .unwrap_err();
        assert!(err.contains("canister id ranges not found"), "{err}");
    }

    #[test]
    fn a_delegation_may_not_be_delegated() {
        let inner = Certificate {
            tree: empty(),
            signature: vec![],
            delegation: None,
        };
        let nested = Certificate {
            tree: empty(),
            signature: vec![],
            delegation: Some(Delegation {
                subnet_id: vec![1],
                certificate: tagged_cbor(&inner),
            }),
        };
        let delegation = Delegation {
            subnet_id: vec![1],
            certificate: tagged_cbor(&nested),
        };
        let err = verify_delegation(&delegation, &[0u8; 10], &[]).unwrap_err();
        assert_eq!(err, "certificate has too many delegations");
    }

    #[test]
    fn certificate_cbor_requires_the_self_describing_tag() {
        let certificate = Certificate {
            tree: empty(),
            signature: vec![],
            delegation: None,
        };
        parse_certificate_cbor(&tagged_cbor(&certificate)).unwrap();

        assert_eq!(
            parse_certificate_cbor(&[]).unwrap_err(),
            "certificate CBOR doesn't have a self-describing tag"
        );
        assert!(
            parse_certificate_cbor(&serde_cbor::to_vec(&certificate).unwrap())
                .unwrap_err()
                .contains("self-describing tag")
        );
    }

    #[test]
    fn empty_ranges_authorize_no_canisters() {
        let subnet = TestSubnet::new();
        for legacy in [false, true] {
            let delegation = subnet.delegation_certificate(&[], legacy);
            let certificate = subnet.certificate(&delegation);
            let err = verify_certificate(
                &certificate,
                &[3],
                &subnet.root_key_der(),
                TestSubnet::NOW_NS,
                0,
            )
            .unwrap_err();
            assert!(err.contains("not in the delegated subnet's canister ranges"));
        }
    }

    #[test]
    fn pruning_ranges_does_not_remove_the_scope_check() {
        let subnet = TestSubnet::new();
        let inside = Principal::from_slice(&[1]);
        let outside = Principal::from_slice(&[3]);
        let ranges = [(inside, Principal::from_slice(&[2]))];
        let mut delegation = subnet.delegation_certificate(&ranges, false);
        let verify = |delegation: &Certificate, canister: &Principal| {
            verify_certificate(
                &subnet.certificate(delegation),
                canister.as_slice(),
                &subnet.root_key_der(),
                TestSubnet::NOW_NS,
                0,
            )
        };
        verify(&delegation, &inside).unwrap();
        assert!(verify(&delegation, &outside).is_err());
        let range_subtree = match delegation
            .tree
            .lookup_subtree([b"canister_ranges".as_slice(), subnet.subnet_id.as_slice()])
        {
            SubtreeLookupResult::Found(tree) => tree,
            _ => panic!("missing fixture subtree"),
        };
        let original_digest = delegation.tree.digest();
        delegation.tree = fork(
            labeled(
                b"canister_ranges".to_vec(),
                labeled(
                    subnet.subnet_id.clone(),
                    ic_certification::pruned(range_subtree.digest()),
                ),
            ),
            fork(
                labeled(
                    b"subnet".to_vec(),
                    labeled(
                        subnet.subnet_id.clone(),
                        labeled(b"public_key".to_vec(), leaf(der_encode(&subnet.subnet_key))),
                    ),
                ),
                labeled(b"time".to_vec(), leaf(encode_leb128(TestSubnet::NOW_NS))),
            ),
        );
        // Pruning preserves the original root signature, including cache hits.
        assert_eq!(delegation.tree.digest(), original_digest);
        for canister in [inside, outside] {
            let err = verify(&delegation, &canister).unwrap_err();
            assert!(err.contains("not in the delegated subnet's canister ranges"));
        }
    }
}
