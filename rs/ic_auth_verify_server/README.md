# `ic_auth_verify_server`

`ic_auth_verify_server` is a small HTTP service for verifying IC-Auth signed envelopes. It accepts JSON or CBOR requests, verifies the embedded `SignedEnvelope`, and returns the authenticated Internet Computer principal.

## Endpoints

### `GET /`

Returns service metadata. The response format is selected from `Accept` or `Content-Type`.

```json
{
  "name": "ic_auth_verify_server",
  "version": "<crate version>"
}
```

### `POST /verify`

Request body:

```json
{
  "signed_envelope": "base64url-cbor-signed-envelope",
  "expect_target": "aaaaa-aa",
  "expect_digest": "base64url-32-byte-digest"
}
```

- `signed_envelope`: required deterministic-CBOR `SignedEnvelope`, encoded as Base64URL in JSON.
- `expect_target`: optional canister principal that targeted delegations must include.
- `expect_digest`: optional 32-byte digest. If omitted, the digest embedded in the envelope is used.

Successful response:

```json
{
  "user": "jjn6g-sh75l-r3cxb-wxrkl-frqld-6p6qq-d4ato-wske5-op7s5-n566f-bqe"
}
```

The endpoint returns `400` for malformed payloads, `401` for failed verification, and `415` when the request `Content-Type` is neither JSON nor CBOR.

## Content Types

- Request bodies: selected from `Content-Type` only — `application/json`, `application/cbor`, or structured suffixes such as `application/vnd.example+cbor`. Anything else is rejected with `415`.
- Response bodies: the request format when there is one, otherwise negotiated from `Accept`. Wildcard ranges (`*/*`, `application/*`) and a missing `Accept` both yield JSON; an `Accept` naming only unsupported types gets `406`.

## Running

```bash
cargo run -p ic_auth_verify_server
```

The default listen address is `127.0.0.1:8080`. Override it with:

```bash
SOCKET_ADDR=0.0.0.0:8080 cargo run -p ic_auth_verify_server
```

## Docker

```bash
docker build -f rs/ic_auth_verify_server/Dockerfile -t ic_auth_verify_server .
docker run --rm -p 8080:8080 ic_auth_verify_server
```

The image is a statically linked musl binary on `scratch` — roughly 3 MB, with
no shell, no package manager, and no writable state. It runs as UID 65532 and
sets `SOCKET_ADDR=0.0.0.0:8080` so the port is reachable from the host; override
it to bind elsewhere.

## License

Copyright © 2024-2026 [LDC Labs](https://github.com/ldclabs).

`ldclabs/ic-auth` is licensed under the MIT License. See [LICENSE](../../LICENSE) for the full license text.
