# @ldclabs/ic-auth
![License](https://img.shields.io/npm/l/@ldclabs/ic-auth)
[![Test](https://github.com/ldclabs/ic-auth/actions/workflows/test.yml/badge.svg)](https://github.com/ldclabs/ic-auth/actions/workflows/test.yml)
[![NPM version](http://img.shields.io/npm/v/@ldclabs/ic-auth.svg)](https://www.npmjs.com/package/@ldclabs/ic-auth)

[IC-Auth](https://github.com/ldclabs/ic-auth) is a comprehensive web authentication system based on the Internet Computer (ICP) identity.

`@ldclabs/ic-auth` is the client-side TypeScript SDK for `ic-auth`, providing essential utilities for identity management and data serialization.

## Installation

Install the package using your favorite package manager:

```bash
npm install @ldclabs/ic-auth
```

or

```bash
yarn add @ldclabs/ic-auth
```

This package has peer dependencies on several `@dfinity` packages, which you should also have in your project.

```json
"peerDependencies": {
  "@dfinity/candid": ">=3.2.0",
  "@dfinity/agent": ">=3.2.0",
  "@dfinity/identity": ">=3.2.0",
  "@dfinity/principal": ">=3.2.0",
  "@noble/hashes": ">=1.8.0",
  "cborg": ">=4.2.0"
}
```

## Usage

Here is a basic example of how to use the library to create a custom identity and sign a message.

```typescript
import { DelegationIdentity, Ed25519KeyIdentity, toDelegationIdentity, signCborMessage } from '@ldclabs/ic-auth';

async function main() {
  // 1. Create a base identity (e.g., from a private key)
  const baseIdentity = Ed25519KeyIdentity.generate();

  // 2. Create an AuthIdentity
  const authIdentity = toDelegationIdentity(baseIdentity);

  // 4. Sign a message (e.g., a challenge from the backend)
  const message = { challenge: 'Hello, world!' };
  const signedEnvelope = await signCborMessage.signCborMessage(message);
}

main();
```

## License

Copyright © 2024-2025 [LDC Labs](https://github.com/ldclabs).

Licensed under the MIT License. See [LICENSE](../../LICENSE-MIT) for details.
