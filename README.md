# IC-Auth

🔏 Web authentication based on [Internet Computer](https://internetcomputer.org/) identities.

IC-Auth connects identity-based signing in TypeScript and Rust with signature verification in Rust applications, IC canisters, and an HTTP service. It supports Ed25519, ECDSA P-256, ECDSA secp256k1, and IC canister signatures, including delegated session identities.

## Packages

| Package | Purpose | Documentation |
| --- | --- | --- |
| `ic_auth_types` | Shared delegation types, Base64URL byte wrappers, deterministic CBOR, XID identifiers and allocation | [Rust types](rs/ic_auth_types/README.md) |
| `ic_auth_verifier` | Signature and delegation verification, HTTP envelopes, deep links, optional signing identities | [Rust verifier](rs/ic_auth_verifier/README.md) |
| `ic_auth_verify_server` | JSON/CBOR HTTP verification service | [HTTP API and deployment](rs/ic_auth_verify_server/README.md) |
| `@ldclabs/ic-auth` | TypeScript identities, signing, compact wire types, and deterministic CBOR | [TypeScript SDK](ts/ic-auth/README.md) |

Rust dependency examples use the workspace's `0.10` release line. The TypeScript package has its own version in [package.json](ts/ic-auth/package.json). To use changes from this checkout before publication, use Cargo path dependencies or build the TypeScript package locally.

## Choose an integration

- **TypeScript client:** sign a value or digest with `@ldclabs/ic-auth` and send the envelope to your backend.
- **Rust backend:** enable `ic_auth_verifier/envelope` to verify envelopes; enable `identity` to sign them too.
- **IC canister:** use `ic_auth_types` and `ic_auth_verifier` with `envelope`. Supply the IC time explicitly; leave the native `identity` and upstream `xid` features disabled.
- **HTTP verification:** run `ic_auth_verify_server` and call `POST /verify` with a JSON or CBOR body.

```toml
[dependencies]
ic_auth_types = "0.10"
ic_auth_verifier = { version = "0.10", features = ["envelope"] }
```

```bash
npm install @ldclabs/ic-auth @icp-sdk/core @noble/hashes cborg
```

## Sign in TypeScript

The SDK is an ES module package. It supports browser applications and declares Node.js 20+ support.

```typescript
import {
  Ed25519KeyIdentity,
  bytesToBase64Url,
  deterministicEncode,
  signMessage,
  toDelegationIdentity
} from '@ldclabs/ic-auth'

const identity = toDelegationIdentity(Ed25519KeyIdentity.generate())
const message = { challenge: 'login-123', origin: 'https://example.com' }
const envelope = await signMessage(identity, message)
const token = bytesToBase64Url(deterministicEncode(envelope))
const authorization = `ICP ${token}`
```

Send `authorization` to an application endpoint that uses the Rust envelope parser. The standalone verification service instead expects the token in its `signed_envelope` request-body field; see its [complete client example](rs/ic_auth_verify_server/README.md#call-from-typescript).

## Verify in Rust

This example requires `ic_auth_verifier` with `envelope`, plus `candid = "0.10"` and `http = "1"` as direct dependencies.

```rust
use candid::Principal;
use http::HeaderMap;
use ic_auth_verifier::SignedEnvelope;

fn authenticate(
    headers: &HeaderMap,
    now_ms: u64,
    expected_digest: &[u8],
    target: Option<Principal>,
) -> Result<Principal, String> {
    let envelope = SignedEnvelope::from_authorization(headers)
        .ok_or_else(|| "missing or malformed IC-Auth envelope".to_string())?;
    envelope.verify(now_ms, target, Some(expected_digest))?;
    Ok(envelope.sender())
}
```

Compute `expected_digest` from the request or challenge your application expects. `sender()` derives a principal from the public key; use it as an authenticated identity only after successful verification.

## Signing and wire conventions

An envelope contains the original public key (`p`), signature (`s`), optional digest (`h`), and optional delegation chain (`d`). Delegations authorize successive session keys while the principal remains derived from the original public key.

| Operation | Bytes signed |
| --- | --- |
| TypeScript `signMessage(identity, value)` | SHA3-256 of `deterministicEncode(value)` |
| Rust `SignedEnvelope::sign_message(identity, bytes)` | SHA3-256 of the supplied bytes |
| TypeScript `signArbitrary` / Rust `SignedEnvelope::sign_digest` | The supplied bytes directly |

For matching signatures across languages, encode the same value as deterministic CBOR in both languages before hashing. Use byte strings (`Uint8Array` in TypeScript and a byte wrapper in Rust) for binary data. A numeric array and a byte string have different CBOR encodings.

Rust JSON byte wrappers emit padded Base64URL with a `b64:` prefix and accept unprefixed input too. HTTP envelope tokens use unprefixed Base64URL. CBOR stores binary fields as byte strings. See the [type and wire reference](rs/ic_auth_types/README.md) for compact keys and Candid compatibility.

Verification checks signatures, delegation expiration, an optional target, and an optional expected digest. Applications define the signed request schema and enforce challenge expiry, one-time use, and authorization. The verifier does not maintain a replay ledger or infer an HTTP method, path, or body from the envelope.

## Run the verification service

From the repository root:

```bash
cargo run -p ic_auth_verify_server
curl --fail http://127.0.0.1:8080/
```

The default listen address is `127.0.0.1:8080`; set `SOCKET_ADDR` to override it. See the [server README](rs/ic_auth_verify_server/README.md) for Docker, content types, status codes, and verification requests.

## Development

Use a current stable Rust toolchain supporting edition 2024. Run Rust checks from the repository root:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features
cargo test --workspace --all-features
```

Check the canister-facing configurations separately:

```bash
rustup target add wasm32-unknown-unknown
cargo check -p ic_auth_types --target wasm32-unknown-unknown
cargo check -p ic_auth_verifier --features envelope --target wasm32-unknown-unknown
```

For the TypeScript package, use Node.js and pnpm:

```bash
cd ts/ic-auth
pnpm install --frozen-lockfile
pnpm build
pnpm test
pnpm coverage
```

## API references

- [ic_auth_types on docs.rs](https://docs.rs/ic_auth_types)
- [ic_auth_verifier on docs.rs](https://docs.rs/ic_auth_verifier)
- [@ldclabs/ic-auth on npm](https://www.npmjs.com/package/@ldclabs/ic-auth)

## License

Copyright © 2024-2026 [LDC Labs](https://github.com/ldclabs).

Licensed under the MIT License. See [LICENSE](LICENSE).
