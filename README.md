# ICAuth

🔏 The [Internet Computer](https://internetcomputer.org/) identity based web authentication.

## Overview

IC-Auth is a comprehensive web authentication system based on the Internet Computer (ICP) identity. It provides a secure, decentralized approach to user authentication for web applications by leveraging the cryptographic capabilities of the Internet Computer.

## Features

- **Multiple Cryptographic Algorithms Support**:
  - Ed25519
  - ECDSA with secp256k1 curve
  - ECDSA with P-256 curve (secp256r1)
  - Internet Computer Canister Signatures
- **Secure Authentication Flow**: Implements a secure delegation-based authentication system
- **Cross-Platform Compatibility**: Works across different platforms and programming languages
- **Lightweight Implementation**: Optimized for performance and minimal dependencies
- **Standards Compliance**: Follows cryptographic best practices and standards

## Components

### `ic_auth_types`

A Rust library providing essential data structures and utilities for working with Internet Computer authentication.

#### Features

- **Efficient Byte Handling**: Includes `ByteBufB64` and `ByteArrayB64` types for efficient serialization and deserialization of binary data with automatic Base64URL encoding for human-readable formats
- **Unique Identifiers**: Provides `Xid` type, a compact and lexicographically sortable globally unique identifier (12 bytes vs UUID's 16 bytes)
- **Authentication Primitives**: Includes types for delegations, signed delegations, and authentication responses
- **Candid Compatibility**: All types implement `CandidType` for seamless integration with the Internet Computer
- **Serde Support**: Full serialization/deserialization support for both human-readable (JSON) and binary formats (CBOR)
- **RFC 8949 Deterministic Encoding**: Use `deterministic_cbor_into` and `deterministic_cbor_into_vec` to ensure consistent binary representation for cryptographic operations.

#### Installation

```toml
[dependencies]
ic_auth_types = "0.7"  # Replace with the latest version
```

With XID compatibility:

```toml
[dependencies]
ic_auth_types = { version = "0.7", features = ["full"] }
```

### `ic_auth_verifier`

A Rust library for signing and verifying cryptographic signatures in the IC-Auth ecosystem.

#### Features

- **Signature Verification**: Verify signatures using multiple cryptographic algorithms
- **Public Key Handling**: Parse and validate DER-encoded public keys
- **Hashing Functions**: Compute various hash functions (SHA-256, SHA3-256, Keccak-256)
- **Envelope Support**: Optional envelope functionality for secure message signing and verification

#### Installation

```toml
[dependencies]
ic_auth_verifier = "0.7"  # Replace with the latest version
```

With envelope support:

```toml
[dependencies]
ic_auth_verifier = { version = "0.7", features = ["full"] }
```

## Usage Examples

### Basic Signing

```rust
use ic_auth_verifier::SignedEnvelope;

let identity = /* your ICP Identity */;

let message = b"message";
let envelope = SignedEnvelope::sign_message(&identity, message)?;
// Adds the SignedEnvelope to the Authorization header to be sent to the service
envelope.to_authorization(&mut headers)?;
// Or adds the SignedEnvelope components to the IC-Auth-* HTTP headers
// envelope.to_headers(&mut headers)?;
```

### Basic Verification

```rust
use ic_auth_verifier::{SignedEnvelope, unix_ms};

let envelope = SignedEnvelope::from_authorization(&headers).unwrap();
// Verify the envelope
envelope.verify(unix_ms(), None, None)?;
```

## Documentation

- [API Documentation](https://docs.rs/ic_auth_verifier)
- [Internet Computer Developer Documentation](https://internetcomputer.org/docs/current/developer-docs/)

## Related Projects

- [Internet Computer](https://internetcomputer.org/)
- [DFINITY](https://dfinity.org/)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

Copyright © 2024-2025 [LDC Labs](https://github.com/ldclabs).

`ldclabs/ic-auth` is licensed under the MIT License. See [LICENSE](LICENSE) for the full license text.
