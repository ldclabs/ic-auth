# `@ldclabs/ic-auth`

![License](https://img.shields.io/npm/l/@ldclabs/ic-auth)
[![Test](https://github.com/ldclabs/ic-auth/actions/workflows/test.yml/badge.svg)](https://github.com/ldclabs/ic-auth/actions/workflows/test.yml)
[![NPM version](https://img.shields.io/npm/v/@ldclabs/ic-auth.svg)](https://www.npmjs.com/package/@ldclabs/ic-auth)

The TypeScript signing SDK for [IC-Auth](../../README.md). It provides deterministic CBOR, compact envelope and delegation types, SHA3-256 message digests, Base64URL helpers, and identity signing through `@icp-sdk/core`. Signature verification is provided by the [Rust verifier](../../rs/ic_auth_verifier/README.md) or [HTTP service](../../rs/ic_auth_verify_server/README.md).

## Installation

```bash
npm install @ldclabs/ic-auth @icp-sdk/core @noble/hashes cborg
```

The package ships ES modules and TypeScript declarations. It supports browser applications and declares Node.js `>=20.0.0`. Its peer dependency ranges are:

| Dependency      | Range     |
| --------------- | --------- |
| `@icp-sdk/core` | `>=5.0.0` |
| `@noble/hashes` | `>=1.8.0` |
| `cborg`         | `>=4.5.0` |

The examples use top-level `await`, so run them as ES modules. The package has an independent release version from the Rust workspace; see [package.json](package.json).

## Sign a structured message

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
console.log(`ICP ${token}`)
```

`toDelegationIdentity` preserves an existing `DelegationIdentity` or wraps a plain `SignIdentity` with an empty delegation chain. Pass an existing delegated identity to retain the user's principal and include its delegations in the envelope. Generating a fresh Ed25519 identity, as above, creates a new principal.

`signMessage` returns a `SignedEnvelopeCompact` containing `p`, `s`, and `h`, plus `d` when the identity has delegations. Send the token as `Authorization: ICP <token>` to your own endpoint using the Rust parser. The standalone service takes the token in a JSON/CBOR request body instead; see its [complete client example](../../rs/ic_auth_verify_server/README.md#call-from-typescript).

## Sign bytes or a precomputed digest

```typescript
import {
  Ed25519KeyIdentity,
  sha3_256,
  signArbitrary,
  toDelegationIdentity
} from '@ldclabs/ic-auth'

const identity = toDelegationIdentity(Ed25519KeyIdentity.generate())
const requestBytes = new TextEncoder().encode('login-challenge-123')
const digest = sha3_256(requestBytes)
const envelope = await signArbitrary(identity, digest)
```

| Helper                           | Operation                                              |
| -------------------------------- | ------------------------------------------------------ |
| `digestMessage(value)`           | SHA3-256 of deterministic CBOR for `value`             |
| `signMessage(identity, value)`   | Signs `digestMessage(value)`                           |
| `signArbitrary(identity, bytes)` | Signs the supplied bytes directly, storing them in `h` |

Calling `signMessage` with a `Uint8Array` hashes its **CBOR byte-string encoding**, including the CBOR prefix. To match Rust's `SignedEnvelope::sign_message(identity, raw_bytes)`, hash the raw bytes with `sha3_256` and call `signArbitrary`, as above. Alternatively, deterministically CBOR-encode the same structured value in Rust before calling `sign_message`.

The SDK does not define the application's challenge schema. The verifier should independently compute the expected digest and enforce challenge expiry, one-time use, target, and authorization rules.

## Deterministic CBOR and binary fields

`deterministicEncode` wraps `cborg`'s `encode` with RFC 8949 options and explicitly selects the shortest floating-point representation. This keeps encoded bytes stable with cborg versions before 5.1.4, whose preset forced float64. The package also exports `encode`, `decode`, `rfc8949EncodeOptions`, and `compareBytes`; the re-exported options are cborg's own preset.

Use `Uint8Array` for binary fields and `bigint` for delegation expiration in nanoseconds. Match the exact field names, value types, and optional-field presence on both sides when signing across languages. The default `encode` function is available for ordinary CBOR; use `deterministicEncode` for signed or hashed data.

`JSON.stringify(envelope)` is not the IC-Auth JSON wire encoding: it does not turn `Uint8Array` into Base64URL and cannot serialize `bigint`. Transport an envelope as CBOR, or Base64URL-encode its CBOR bytes for an HTTP token or the service's JSON request body.

## Compact types and conversions

| Type                            | Compact keys                                                                                        |
| ------------------------------- | --------------------------------------------------------------------------------------------------- |
| `SignedEnvelopeCompact`         | `p`: public key; `s`: signature; `h`: optional digest; `d`: optional delegation chain               |
| `DelegationCompact`             | `p`: delegated key; `e`: nanosecond expiration; `t`: optional targets; `perm`: optional permissions |
| `SignedDelegationCompact`       | `d`: delegation; `s`: signature                                                                     |
| `DeepLinkSignInRequestCompact`  | `s`: session key; `m`: maximum lifetime in milliseconds                                             |
| `DeepLinkSignInResponseCompact` | `u`: user key; `d`: delegations; `a`: authentication method; `o`: origin                            |

`DelegationPermissions` is `'queries' | 'all'`. Full-name types use `Uint8Array`, `bigint`, and `Principal` values. Compact delegation targets are `Uint8Array[]`, and compact deep-link responses contain `SignedDelegationCompact[]`. The converters restore Principal objects and bigint timestamps/lifetimes when expanding decoded compact payloads; compact integer fields accept `number | bigint` because CBOR decodes safe integers as numbers. The `toDelegation`, `toSignedDelegation`, `toSignedEnvelope`, and deep-link converters each have a corresponding `...Compact` conversion.

When upgrading callers that construct compact payloads themselves, replace Principal targets with `target.toUint8Array()` and use compact nested delegations. Prefer the conversion helpers to build these payloads. Full-name types containing Principal objects should be converted to compact form before CBOR transport.

```typescript
import { toSignedEnvelope, toSignedEnvelopeCompact } from '@ldclabs/ic-auth'

// Illustrative bytes for shape conversion, not a valid signed envelope.
const compact = { p: new Uint8Array([1, 2, 3]), s: new Uint8Array([4, 5, 6]) }
const full = toSignedEnvelope(compact)
const converted = toSignedEnvelopeCompact(full)
```

Converters map between typed shapes; they do not verify signatures or validate untrusted input. They may return the original object when it is already in the requested form. Envelope converters also accept the explicitly typed `LegacySignedEnvelope` shape with `public_key`. The TypeScript deep-link exports describe payloads and convert their fields; Rust provides the URL construction/parsing helpers.

## Base64 helpers

| Helper                    | Encoding                                                                           |
| ------------------------- | ---------------------------------------------------------------------------------- |
| `bytesToBase64Url(bytes)` | Unpadded Base64URL, suitable for envelope tokens                                   |
| `base64ToBytes(text)`     | Same as `fromBase64`                                                               |
| `toBase64(bytes)`         | Padded standard Base64                                                             |
| `fromBase64(text)`        | Standard Base64 or Base64URL decoding using native helpers, or `atob` without them |

Decoding accepts padded or unpadded input in either alphabet, and removes the `b64:` prefix that the Rust types write for byte fields in JSON. Malformed input throws in every runtime. The encoders return unprefixed values, which Rust also accepts.

## Development

From this directory, with Node.js and pnpm installed:

```bash
pnpm install --frozen-lockfile
pnpm format:check
pnpm typecheck
pnpm build
pnpm test
pnpm coverage
```

`pnpm build` emits JavaScript and declarations into `dist`. `pnpm typecheck` checks source and test types. Tests cover CBOR fixtures shared with Rust, wire conversions, delegation permissions, identity signing, and native/Node/browser Base64 handling. CI also runs the SDK with the minimum supported cborg version. `pnpm format` formats sources, configuration and this README with Prettier.

## Related packages

- [Shared Rust types](../../rs/ic_auth_types/README.md)
- [Rust verifier](../../rs/ic_auth_verifier/README.md)
- [HTTP verification service](../../rs/ic_auth_verify_server/README.md)
- [npm package](https://www.npmjs.com/package/@ldclabs/ic-auth)

## License

Copyright © 2024-2026 [LDC Labs](https://github.com/ldclabs).

Licensed under the MIT License. See [LICENSE](LICENSE).
