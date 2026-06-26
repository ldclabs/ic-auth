# @ldclabs/ic-auth

![License](https://img.shields.io/npm/l/@ldclabs/ic-auth)
[![Test](https://github.com/ldclabs/ic-auth/actions/workflows/test.yml/badge.svg)](https://github.com/ldclabs/ic-auth/actions/workflows/test.yml)
[![NPM version](http://img.shields.io/npm/v/@ldclabs/ic-auth.svg)](https://www.npmjs.com/package/@ldclabs/ic-auth)

[IC-Auth](https://github.com/ldclabs/ic-auth) is a web authentication system based on Internet Computer identities.

`@ldclabs/ic-auth` is the TypeScript client SDK for IC-Auth. It provides compact envelope and delegation types, deterministic CBOR encoding, SHA3-256 message digests, Base64URL helpers, and signing helpers built on `@icp-sdk/core` identities.

## Installation

Install the package using your favorite package manager:

```bash
npm install @ldclabs/ic-auth
```

or

```bash
yarn add @ldclabs/ic-auth
```

The package expects these peer dependencies in the host project:

```json
"peerDependencies": {
  "@icp-sdk/core": ">=5.0.0",
  "@noble/hashes": "^1.8.0",
  "cborg": ">=4.5.0"
}
```

## What It Exports

- `deterministicEncode`, `decode`, `encode`, and `rfc8949EncodeOptions` from `cborg`.
- `Delegation`, `SignedDelegation`, `SignedEnvelope`, and compact `p`/`s`/`h`/`d` wire forms.
- Conversion helpers such as `toSignedEnvelope`, `toSignedEnvelopeCompact`, `toDelegationCompact`, and deep-link sign-in type converters.
- `toDelegationIdentity`, `signArbitrary`, `signMessage`, `digestMessage`, and Base64URL helpers.
- `DelegationIdentity`, `Ed25519KeyIdentity`, and `Ed25519PublicKey` re-exported from `@icp-sdk/core/identity`.

## Sign a Message

```typescript
import {
  Ed25519KeyIdentity,
  bytesToBase64Url,
  deterministicEncode,
  signMessage,
  toDelegationIdentity
} from '@ldclabs/ic-auth'

async function main() {
  const baseIdentity = Ed25519KeyIdentity.generate()
  const identity = toDelegationIdentity(baseIdentity)

  const message = new Map<any, any>([
    ['challenge', 'login-123'],
    ['origin', 'https://example.com']
  ])

  const envelope = await signMessage(identity, message)
  const token = bytesToBase64Url(deterministicEncode(envelope))

  // Send `token` as an `Authorization: ICP ${token}` value, or send the
  // compact envelope bytes to an IC-Auth verifier.
  console.log(token)
}

main()
```

`signMessage` hashes the deterministic CBOR encoding of the supplied value with SHA3-256 and signs that digest. Use `signArbitrary` when you already have the digest bytes.

## Convert Wire Types

```typescript
import { toSignedEnvelope, toSignedEnvelopeCompact } from '@ldclabs/ic-auth'

const full = toSignedEnvelope({
  p: new Uint8Array([1, 2, 3]),
  s: new Uint8Array([4, 5, 6])
})

const compact = toSignedEnvelopeCompact(full)
```

The compact forms match the Rust serde names used by `ic_auth_types` and `ic_auth_verifier`.

## Related Packages

- [`ic_auth_types`](https://crates.io/crates/ic_auth_types): shared Rust data types and deterministic CBOR helpers.
- [`ic_auth_verifier`](https://crates.io/crates/ic_auth_verifier): Rust signature, envelope, and delegation verifier.
- [`ic_auth_verify_server`](https://github.com/ldclabs/ic-auth/tree/main/rs/ic_auth_verify_server): HTTP JSON/CBOR verification service.

## License

Copyright © 2024-2026 [LDC Labs](https://github.com/ldclabs).

Licensed under the MIT License. See [LICENSE](LICENSE) for details.
