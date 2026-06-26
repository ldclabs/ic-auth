# ICAuth

🔏 The [Internet Computer](https://internetcomputer.org/) identity based web authentication.

## Overview

IC-Auth is a web authentication toolkit based on Internet Computer identities. It provides shared Rust/TypeScript wire types, deterministic CBOR signing helpers, signature and delegation-chain verification, and a small HTTP verifier service.

## Features

- **Multiple signature algorithms**:
  - Ed25519
  - ECDSA with secp256k1 curve
  - ECDSA with P-256 curve (secp256r1)
  - Internet Computer Canister Signatures
- **Delegation-based authentication**: verifies delegation chains, expiration, and optional target canisters.
- **Deterministic wire format**: uses RFC 8949 deterministic CBOR for payloads that are hashed or signed.
- **Cross-language payloads**: Rust and TypeScript packages share compact `p`/`s`/`h`/`d` envelope forms.
- **HTTP integration**: supports `Authorization: ICP ...`, `IC-Auth-*` headers, and JSON/CBOR verification requests.

## Components

### `ic_auth_types`

A Rust crate with the shared IC-Auth data model: delegation records, compact wire forms, Base64URL byte wrappers, XID identifiers, and CBOR helpers.

Install:

```toml
[dependencies]
ic_auth_types = "0.9"
```

With XID compatibility:

```toml
[dependencies]
ic_auth_types = { version = "0.9", features = ["xid"] }
```

### `ic_auth_verifier`

A Rust crate for DER public-key parsing, raw signature verification, signed envelopes, delegation-chain verification, deep-link payloads, and optional `ic-agent` identity helpers.

Install:

```toml
[dependencies]
ic_auth_verifier = "0.9"
```

With envelope support:

```toml
[dependencies]
ic_auth_verifier = { version = "0.9", features = ["envelope"] }
```

With identity support for native/server targets:

```toml
[dependencies]
ic_auth_verifier = { version = "0.9", features = ["full"] }
```

### `ic_auth_verify_server`

A Rust HTTP service that verifies IC-Auth signed envelopes over JSON or CBOR.

Run locally:

```bash
cargo run -p ic_auth_verify_server
```

The default listen address is `127.0.0.1:8080`; override it with `SOCKET_ADDR`.

### `@ldclabs/ic-auth`

A TypeScript client SDK for deterministic CBOR encoding, compact envelope/delegation types, Base64URL helpers, and message signing with `@icp-sdk/core` identities.

Install:

```bash
npm install @ldclabs/ic-auth @icp-sdk/core @noble/hashes cborg
```

## Usage Examples

### Rust Envelope Signing

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

### Rust Envelope Verification

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

### TypeScript Signing

```typescript
import {
  Ed25519KeyIdentity,
  bytesToBase64Url,
  deterministicEncode,
  signMessage,
  toDelegationIdentity
} from '@ldclabs/ic-auth'

const identity = toDelegationIdentity(Ed25519KeyIdentity.generate())
const envelope = await signMessage(identity, new Map([['challenge', 'login']]))
const token = bytesToBase64Url(deterministicEncode(envelope))
```

## Documentation

- [ic_auth_types API Documentation](https://docs.rs/ic_auth_types)
- [ic_auth_verifier API Documentation](https://docs.rs/ic_auth_verifier)
- [@ldclabs/ic-auth on npm](https://www.npmjs.com/package/@ldclabs/ic-auth)
- [Internet Computer Developer Documentation](https://internetcomputer.org/docs/current/developer-docs/)

## Related Projects

- [Internet Computer](https://internetcomputer.org/)
- [DFINITY](https://dfinity.org/)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

Copyright © 2024-2026 [LDC Labs](https://github.com/ldclabs).

`ldclabs/ic-auth` is licensed under the MIT License. See [LICENSE](LICENSE) for the full license text.
