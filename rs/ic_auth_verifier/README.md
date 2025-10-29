# `ic_auth_verifier`
![License](https://img.shields.io/crates/l/ic_auth_verifier.svg)
[![Crates.io](https://img.shields.io/crates/d/ic_auth_verifier.svg)](https://crates.io/crates/ic_auth_verifier)
[![Test](https://github.com/ldclabs/ic-auth/actions/workflows/test.yml/badge.svg)](https://github.com/ldclabs/ic-auth/actions/workflows/test.yml)
[![Docs.rs](https://img.shields.io/docsrs/ic_auth_verifier?label=docs.rs)](https://docs.rs/ic_auth_verifier)
[![Latest Version](https://img.shields.io/crates/v/ic_auth_verifier.svg)](https://crates.io/crates/ic_auth_verifier)

[IC-Auth](https://github.com/ldclabs/ic-auth) is a web authentication system based on the Internet Computer.

`ic_auth_verifier` is a Rust library for signing and verifying cryptographic signatures in the IC-Auth ecosystem.

## Features

- Verify signatures using multiple cryptographic algorithms:
  - Ed25519
  - ECDSA with secp256k1 curve
  - ECDSA with P-256 curve (secp256r1)
  - Internet Computer Canister Signatures
- Parse and validate DER-encoded public keys
- Compute various hash functions (SHA-256, SHA3-256, Keccak-256)
- Optional envelope functionality (enabled with the `envelope` feature)
- A thread-safe wrapper around an Identity implementation that can be atomically updated (enabled with the `identity` feature)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
ic_auth_verifier = "0.7"  # Replace with the latest version
```

To enable the `envelope` feature:

```toml
[dependencies]
ic_auth_verifier = { version = "0.7", features = ["envelope"] }
```

To enable the `identity` feature (It can not be compiled in canister):
```toml
[dependencies]
ic_auth_verifier = { version = "0.7", features = ["identity"] }
```

## Usage

### Basic Signing

```rust
use ic_auth_verifier::SignedEnvelope;

let identity = /* your ICP Identity */;

let message = b"message";
let envelope = SignedEnvelope::sign_message(&identity, message)?;
// Adds the SignedEnvelope to the Authorization header to be sent to the service which will verify the signature.
envelope.to_authorization(&mut headers)?;
// Or adds the SignedEnvelope components to the IC-Auth-* HTTP headers.
// envelope.to_headers(&mut headers)?;
```

### Basic Verification

```rust
use ic_auth_verifier::{SignedEnvelope, unix_timestamp};

let envelope = SignedEnvelope::from_authorization(&headers).unwrap();
// Verify the envelope
envelope.verify(unix_timestamp().as_millis() as u64, None, None)?;
```

## License
Copyright © 2024-2025 [LDC Labs](https://github.com/ldclabs).

`ldclabs/ic-auth` is licensed under the MIT License. See [LICENSE](../../LICENSE) for the full license text.
