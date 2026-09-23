# `ic_auth_verify_server`

An HTTP service that verifies [IC-Auth](../../README.md) envelopes and returns the authenticated Internet Computer principal. It accepts JSON or CBOR request bodies and uses `ic_auth_verifier` with its `envelope` feature. It is a workspace binary, not a published library crate.

## Run locally

From the repository root:

```bash
cargo run -p ic_auth_verify_server
```

The default listen address is `127.0.0.1:8080`. `SOCKET_ADDR` accepts a numeric IP address and port:

```bash
SOCKET_ADDR=0.0.0.0:8080 cargo run --release -p ic_auth_verify_server
```

Logs are written as structured JSON to stdout. Ctrl+C and, on Unix, SIGTERM trigger graceful shutdown. Verification is local and does not make outbound network calls. The listener serves HTTP; configure HTTPS and browser CORS at your application gateway when needed.

Envelope decoding and signature verification run on blocking workers, with concurrent verification limited to the available CPU parallelism. Requests wait asynchronously for a slot, and verification uses the current time after that wait.

## Endpoints

### `GET /`

Returns the service name and the version compiled from the crate manifest:

```bash
curl --fail http://127.0.0.1:8080/
```

```json
{
  "name": "ic_auth_verify_server",
  "version": "<crate version>"
}
```

JSON is the default. To request CBOR:

```bash
curl --fail -H 'Accept: application/cbor' http://127.0.0.1:8080/ --output info.cbor
```

### `POST /verify`

The body is an object containing the encoded envelope and optional expectations:

| Field | JSON | CBOR | Required |
| --- | --- | --- | --- |
| `signed_envelope` | Base64URL string containing CBOR envelope bytes | Byte string containing CBOR envelope bytes | Yes |
| `expect_digest` | Base64URL string containing exactly 32 bytes | Byte string of exactly 32 bytes | No |
| `expect_target` | Textual canister principal | Principal byte string | No |

JSON byte strings accept an optional `b64:` prefix and padded or unpadded Base64URL. Rust serializers emit the prefix. `signed_envelope` is an encoded envelope, not a nested JSON object. Generate it with `SignedEnvelope::to_base64()` in Rust or `bytesToBase64Url(deterministicEncode(envelope))` in TypeScript.

This is the request shape; angle-bracket values are placeholders:

```json
{
  "signed_envelope": "<base64url-cbor-envelope>",
  "expect_digest": "<base64url-32-byte-digest>",
  "expect_target": "aaaaa-aa"
}
```

Optional fields can be omitted or set to `null`. The service uses the current server time and the IC mainnet root key. Every targeted delegation must include `expect_target` when supplied. When `expect_digest` is omitted, verification uses the digest embedded in the envelope; it fails if neither is present.

A successful response has status `200`:

```json
{
  "user": "<authenticated principal>"
}
```

For JSON the principal is text; for CBOR it is a byte string. The principal comes from the original envelope public key after successful signature and delegation verification.

The service does not consume `Authorization` or `IC-Auth-*` headers as its verification input. Those helpers are available to applications integrating the [Rust verifier](../ic_auth_verifier/README.md) directly.

## Call from TypeScript

Start the service, install the SDK and peers, and run this ES module example in Node.js:

```bash
npm install @ldclabs/ic-auth @icp-sdk/core @noble/hashes cborg
```

```typescript
import {
  Ed25519KeyIdentity,
  bytesToBase64Url,
  deterministicEncode,
  digestMessage,
  signMessage,
  toDelegationIdentity
} from '@ldclabs/ic-auth'

const identity = toDelegationIdentity(Ed25519KeyIdentity.generate())
const challenge = { challenge: 'login-123', origin: 'https://example.com' }
const envelope = await signMessage(identity, challenge)
const response = await fetch('http://127.0.0.1:8080/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    signed_envelope: bytesToBase64Url(deterministicEncode(envelope)),
    expect_digest: bytesToBase64Url(digestMessage(challenge))
  })
})
if (!response.ok) throw new Error(await response.text())
console.log(await response.json())
```

This demonstrates the wire API. In an application, the backend should derive `expect_digest` from its expected request or issued challenge, check freshness and one-time use, and apply authorization to the returned principal. Passing expectations chosen entirely by a client does not bind verification to a backend's intended operation. The service stores no challenge or replay state.

For CBOR requests, use `deterministicEncode` on the outer request object, keep envelope/digest values as `Uint8Array`, use principal bytes for `expect_target`, and set `Content-Type: application/cbor`. Decode the response as CBOR rather than calling `response.json()`.

## Content negotiation and errors

- `POST /verify` selects its body parser from `Content-Type` only. It accepts `application/json`, `application/cbor`, and structured suffixes such as `application/vnd.example+cbor`.
- Successful POST responses use the request's JSON or CBOR format, regardless of `Accept`.
- `GET /` prefers a supported `Content-Type` header, otherwise negotiates `Accept` with quality values. Missing `Accept` and ordinary wildcards default to JSON. A request offering only unsupported response formats receives `406`.
- Specific `Accept` ranges override wildcards, including `q=0` exclusions. Only JSON and CBOR are response candidates; an unsupported preferred format does not prevent selecting an acceptable supported format.
- Errors produced while decoding or verifying payloads are plain text. An unsupported request content type returns `415` with no structured error body.
- Request bodies are limited to 64 KiB; larger bodies receive `413`. A signed envelope, even with a full delegation chain, is a few kilobytes.

| Status | Meaning |
| --- | --- |
| `200` | Metadata or verified principal |
| `400` | Malformed JSON/CBOR, invalid field representation or length, or invalid embedded envelope CBOR |
| `401` | Signature, delegation, target, expiration, or digest verification failed |
| `406` | No supported response format for `GET /` |
| `413` | Request body larger than 64 KiB |
| `415` | Missing or unsupported POST `Content-Type` |

See the verifier's [verification behavior](../ic_auth_verifier/README.md#verification-behavior) and [certificate defaults](../ic_auth_verifier/README.md#raw-signatures-and-certificates) for limits and time units.

## Docker

Build from the repository root so the Docker context includes the workspace manifests and Rust crates:

```bash
docker build -f rs/ic_auth_verify_server/Dockerfile -t ic_auth_verify_server .
docker run --rm -p 8080:8080 ic_auth_verify_server
```

The build uses `cargo build --release --locked`. The runtime image is a statically linked musl binary on `scratch`, runs as UID/GID `65532:65532`, and sets `SOCKET_ADDR=0.0.0.0:8080`. It has no shell or persistent application state.

## Cloudflare Workers and Containers

The [`ic-auth-worker`](../../ts/ic-auth-worker/README.md) application packages this service for Cloudflare Containers. Its Wrangler configuration builds this crate's Dockerfile with the repository root as the build context. The Worker routes requests to a fixed set of regional instances and preserves this HTTP API, including JSON/CBOR bodies and verification error codes.

Use it through a Worker service binding or configure a public route. A container startup or forwarding exception produces an additional `503` response with `Retry-After: 1`. See the [Worker setup and deployment guide](../../ts/ic-auth-worker/README.md) for configuration and caller examples.

## Development

From the repository root:

```bash
cargo test -p ic_auth_verify_server
cargo clippy -p ic_auth_verify_server --all-targets
```

## Related packages

- [Rust verifier](../ic_auth_verifier/README.md)
- [Shared Rust types](../ic_auth_types/README.md)
- [TypeScript SDK](../../ts/ic-auth/README.md)

## License

Copyright © 2024-2026 [LDC Labs](https://github.com/ldclabs).

Licensed under the MIT License. See [LICENSE](../../LICENSE).
