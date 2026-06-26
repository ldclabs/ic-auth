# `ic_auth_verifier`

![License](https://img.shields.io/crates/l/ic_auth_verifier.svg)
[![Crates.io](https://img.shields.io/crates/d/ic_auth_verifier.svg)](https://crates.io/crates/ic_auth_verifier)
[![Test](https://github.com/ldclabs/ic-auth/actions/workflows/test.yml/badge.svg)](https://github.com/ldclabs/ic-auth/actions/workflows/test.yml)
[![Docs.rs](https://img.shields.io/docsrs/ic_auth_verifier?label=docs.rs)](https://docs.rs/ic_auth_verifier)
[![Latest Version](https://img.shields.io/crates/v/ic_auth_verifier.svg)](https://crates.io/crates/ic_auth_verifier)

[IC-Auth](https://github.com/ldclabs/ic-auth) is a web authentication system based on the Internet Computer.

`ic_auth_verifier` verifies IC-Auth signatures, delegation chains, signed HTTP envelopes, and deep-link sign-in payloads. The base crate works with raw public keys; optional features add HTTP envelope parsing and `ic-agent` identity helpers for clients and services.

## Features

- Parses DER SubjectPublicKeyInfo values for Ed25519, ECDSA P-256, ECDSA secp256k1, and IC canister signatures.
- Verifies basic signatures and IC canister signatures against the mainnet root key or a supplied root key.
- Provides SHA-256, SHA3-256, and Keccak-256 helpers.
- `envelope` feature: signed envelope encoding, `Authorization: ICP ...`, `IC-Auth-*` headers, delegation-chain validation, and deep-link request/response helpers.
- `identity` feature: `ic-agent` identity helpers, random basic identities, delegated session identities, and `AtomicIdentity`.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
ic_auth_verifier = "0.9"
```

Enable signed envelope and deep-link support:

```toml
[dependencies]
ic_auth_verifier = { version = "0.9", features = ["envelope"] }
```

Enable identity helpers for native/server targets:

```toml
[dependencies]
ic_auth_verifier = { version = "0.9", features = ["identity"] }
```

Use `full` to enable the same identity-oriented surface:

```toml
[dependencies]
ic_auth_verifier = { version = "0.9", features = ["full"] }
```

Do not enable `identity` or `full` in canister code.

## Usage

### Envelope Signing

Requires the `identity` or `full` feature.

```rust
use ic_auth_verifier::{BasicIdentity, SignedEnvelope};

fn main() -> Result<(), String> {
    let identity = BasicIdentity::from_raw_key(&[8u8; 32]);
    let message = b"message";
    let envelope = SignedEnvelope::sign_message(&identity, message)?;

    // Add the envelope to an `Authorization: ICP ...` header, or split it into
    // `IC-Auth-*` component headers.
    // envelope.to_authorization(&mut headers)?;
    // envelope.to_headers(&mut headers)?;

    Ok(())
}
```

### Envelope Verification

Requires the `envelope` feature.

```rust
use ic_auth_verifier::SignedEnvelope;
use std::time::{SystemTime, UNIX_EPOCH};

fn verify(headers: &http::HeaderMap) -> Result<(), String> {
    let envelope = SignedEnvelope::from_authorization(headers)
        .ok_or_else(|| "missing IC-Auth envelope".to_string())?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| err.to_string())?
        .as_millis() as u64;

    envelope.verify(now_ms, None, None)
}
```

### Raw Signature Verification

```rust
use ic_auth_verifier::{user_public_key_from_der, verify_basic_sig};

fn verify(public_key_der: &[u8], signature: &[u8]) -> Result<(), String> {
    let (algorithm, raw_public_key) = user_public_key_from_der(public_key_der)?;
    verify_basic_sig(algorithm, &raw_public_key, b"message", signature)
}
```

## Related Crates

- [`ic_auth_types`](https://crates.io/crates/ic_auth_types): shared delegation, byte, and deterministic CBOR types.
- [`ic_auth_verify_server`](https://github.com/ldclabs/ic-auth/tree/main/rs/ic_auth_verify_server): HTTP verification service built on this crate.

## License

Copyright © 2024-2026 [LDC Labs](https://github.com/ldclabs).

`ldclabs/ic-auth` is licensed under the MIT License. See [LICENSE](../../LICENSE) for the full license text.
