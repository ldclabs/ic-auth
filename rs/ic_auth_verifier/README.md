# `ic_auth_verifier`

![License](https://img.shields.io/crates/l/ic_auth_verifier.svg)
[![Crates.io](https://img.shields.io/crates/d/ic_auth_verifier.svg)](https://crates.io/crates/ic_auth_verifier)
[![Test](https://github.com/ldclabs/ic-auth/actions/workflows/test.yml/badge.svg)](https://github.com/ldclabs/ic-auth/actions/workflows/test.yml)
[![Docs.rs](https://img.shields.io/docsrs/ic_auth_verifier?label=docs.rs)](https://docs.rs/ic_auth_verifier)
[![Latest Version](https://img.shields.io/crates/v/ic_auth_verifier.svg)](https://crates.io/crates/ic_auth_verifier)

Signature, delegation, HTTP envelope, and deep-link utilities for [IC-Auth](../../README.md). Verification runs locally; optional identity helpers add signing for native clients and services.

## Installation and features

```toml
[dependencies]
ic_auth_verifier = { version = "0.10", features = ["envelope"] }
```

| Feature | Available functionality |
| --- | --- |
| Default (no optional features) | DER public-key parsing, Ed25519/P-256/secp256k1 basic signature verification, SHA-256/SHA3-256/Keccak-256 |
| `envelope` | All of the above, plus canister signatures and certificates, delegation chains, `SignedEnvelope`, HTTP headers, and deep links |
| `identity` | Includes `envelope`; adds `ic-agent` identities, signing methods, delegated sessions, and `AtomicIdentity` |
| `full` | Alias for `identity` |

For canisters targeting `wasm32-unknown-unknown`, use the default configuration or `envelope`; keep `identity`/`full` disabled. Certificate verification uses the crate's own implementation and does not require browser APIs. For unreleased changes, use a Cargo path dependency on this directory.

## Sign and verify an envelope

This complete native example requires `features = ["identity"]` and `http = "1"` as a direct dependency.

```rust
use http::HeaderMap;
use ic_auth_verifier::{SignedEnvelope, new_basic_identity, sha3_256};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), String> {
    let identity = new_basic_identity();
    let message = b"login-challenge-123";
    let envelope = SignedEnvelope::sign_message(&identity, message)?;
    let mut headers = HeaderMap::new();
    envelope.to_authorization(&mut headers)?;

    let received = SignedEnvelope::from_authorization(&headers)
        .ok_or_else(|| "missing or malformed envelope".to_string())?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| err.to_string())?
        .as_millis() as u64;
    let expected_digest = sha3_256(message);
    received.verify(now_ms, None, Some(&expected_digest))?;
    println!("Authenticated principal: {}", received.sender());
    Ok(())
}
```

`sign_message` hashes the supplied bytes with SHA3-256. `sign_digest` signs the supplied digest directly. TypeScript's `signMessage` first CBOR-encodes its input value: pass `ic_auth_types::deterministic_cbor_into_vec(&value)` to the Rust `sign_message` method to match that operation.

## Verification behavior

`SignedEnvelope::verify(now_ms, expect_target, expect_digest)` uses UNIX time in **milliseconds** and the IC mainnet root key.

- A delegation chain may contain at most 5 entries. Each signature must authorize the next public key; the final key verifies the envelope signature.
- Delegation expiration is encoded in **nanoseconds**, with a permitted clock drift of 300,000 milliseconds (5 minutes).
- When `expect_target` is supplied, every delegation with a target list must include it. Omitting `expect_target` skips target membership checks; unrestricted delegations remain valid.
- When `expect_digest` and an embedded digest are both present, they must match. Either may supply the signed bytes; verification fails if both are absent.
- Delegation `permissions` are included in the signed delegation message. The verifier does not classify your application's operation as a query or update; enforce that policy in the application.

Compute the expected digest from the request or server-issued challenge. An embedded digest alone proves a signature over those bytes, not that they match the current HTTP request. Challenge expiry, one-time use, and application authorization are caller responsibilities. `sender()` only derives a principal; call it for authentication after `verify` succeeds.

## Wire format and HTTP headers

| Compact key | Meaning |
| --- | --- |
| `p` | DER public key of the original identity |
| `s` | Signature by the final signing key |
| `h` | Optional signed digest bytes |
| `d` | Optional ordered list of compact signed delegations |

Use `to_bytes` / `from_bytes` for CBOR, and `to_base64` / `from_base64` for unprefixed Base64URL. `to_bytes` produces deterministic CBOR; decoding rejects trailing bytes. Rust JSON serialization of byte fields uses the `b64:` prefix described in the [types README](../ic_auth_types/README.md).

Two HTTP representations are supported:

| API | Representation |
| --- | --- |
| `to_authorization` / `from_authorization` | `Authorization: ICP <base64url-cbor-envelope>` (scheme parsing is case-insensitive) |
| `to_headers` / `from_headers` | Individual headers listed below |

The component headers are `IC-Auth-Pubkey`, `IC-Auth-Content-Digest`, `IC-Auth-Signature`, and optional `IC-Auth-Delegation`. Values are unprefixed Base64URL; the delegation value contains CBOR. Component parsing requires the pubkey, digest, and signature. Both parsing APIs return `None` for missing or malformed data; a malformed delegation header also invalidates the envelope.

`IC-Auth-User` and `extract_user` carry/read principal metadata; they do not verify a signature. An application trusting a proxy's authenticated principal must establish that trust separately.

## Raw signatures and certificates

The default feature set supports basic signatures using the raw key returned by DER parsing:

```rust
use ic_auth_verifier::{user_public_key_from_der, verify_basic_sig};

fn verify(public_key_der: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
    let (algorithm, raw_public_key) = user_public_key_from_der(public_key_der)?;
    verify_basic_sig(algorithm, &raw_public_key, message, signature)
}
```

Ed25519 verifies the message directly. P-256 and secp256k1 hash it with SHA-256 before verification and accept fixed-width ECDSA signature bytes. `verify_basic_sig` does not verify canister signatures.

With `envelope` enabled:

- `verify_sig` dispatches by DER public-key algorithm and uses the mainnet root key.
- `verify_sig_with_rootkey` permits a custom IC root key. Root keys are always DER-encoded (133 bytes, like `IC_ROOT_PK_DER`), not the raw 96-byte BLS key.
- `verify_canister_sig` validates the signature tree, certified data, certificate signature, subnet delegation, canister ranges, and certificate time.
- `verify_certificate` and `parse_certificate_cbor` expose certificate-level operations.
- `verify_delegation_chain` verifies a nonempty chain ending in the expected session key, with an optional DER root key. It does not take an expected target or enforce application permissions.

Successful BLS verifications and whole canister signatures are remembered in a bounded in-process cache. A repeated canister signature, such as the delegation a session sends with every request, is accepted after re-checking only its certificate time.

The signature/certificate APIs take UNIX time in **nanoseconds**. `verify_canister_sig` defaults to a certificate time offset of 47 days in either direction; pass `Some(offset_ns)` for a different window. High-level envelope verification uses that default. Certificate freshness and delegation expiration are separate checks.

## Identity helpers

The `identity` feature re-exports `Identity`, `BasicIdentity`, `DelegatedIdentity`, and `AnonymousIdentity` from `ic-agent`.

- `new_basic_identity()` creates a random Ed25519 identity.
- `delegated_basic_identity(&identity, expires_in_ms)` creates a delegated session with a lifetime in milliseconds.
- `get_expiration(&identity)` returns the earliest delegation expiration in nanoseconds, when present.
- `AtomicIdentity` implements `Identity` and supports replacing the active identity with `set` while readers retain an `Arc` snapshot from `get`.

`AtomicIdentity::is_authenticated()` checks the principal and expiration from one snapshot. Expired sessions return `false` immediately; the verifier's separate delegation clock-drift allowance does not extend the client's authenticated session state.

## Deep-link sign-in

The `envelope` feature exposes `DeepLinkRequest`, `DeepLinkResponse`, `SignInRequest`, and `SignInResponse`.

`DeepLinkRequest::try_to_url` appends `os`, `action`, and optional `next_url` query parameters. Its payload becomes deterministic CBOR in a `b64:`-prefixed Base64URL fragment. Prefer this fallible method when serialization can fail; `to_url` panics on a serialization error.

Parse a callback with `DeepLinkResponse::from_url`, then decode its payload with `get_payload::<SignInResponse>()`. Parsing only decodes data; validate the origin and returned delegation chain before adopting the session.

| Payload | Compact fields |
| --- | --- |
| `SignInRequest` | `s`: session public key; `m`: maximum lifetime in milliseconds |
| `SignInResponse` | `u`: user public key; `d`: delegations; `a`: authentication method; `o`: origin |

The deep-link `SignInResponse` differs from the shared type with the same name in `ic_auth_types`.

## Development

From the repository root:

```bash
cargo test -p ic_auth_verifier --all-features
cargo clippy -p ic_auth_verifier --all-targets --all-features
cargo check -p ic_auth_verifier --features envelope --target wasm32-unknown-unknown
```

Install the WASM target with `rustup target add wasm32-unknown-unknown` if needed.

## Related packages

- [Shared Rust types](../ic_auth_types/README.md)
- [HTTP verification service](../ic_auth_verify_server/README.md)
- [TypeScript SDK](../../ts/ic-auth/README.md)
- [API reference](https://docs.rs/ic_auth_verifier)

## License

Copyright © 2024-2026 [LDC Labs](https://github.com/ldclabs).

Licensed under the MIT License. See [LICENSE](../../LICENSE).
