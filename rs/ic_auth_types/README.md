# `ic_auth_types`
![License](https://img.shields.io/crates/l/ic_auth_types.svg)
[![Crates.io](https://img.shields.io/crates/d/ic_auth_types.svg)](https://crates.io/crates/ic_auth_types)
[![Test](https://github.com/ldclabs/ic-auth/actions/workflows/test.yml/badge.svg)](https://github.com/ldclabs/ic-auth/actions/workflows/test.yml)
[![Docs.rs](https://img.shields.io/docsrs/ic_auth_types?label=docs.rs)](https://docs.rs/ic_auth_types)
[![Latest Version](https://img.shields.io/crates/v/ic_auth_types.svg)](https://crates.io/crates/ic_auth_types)

[IC-Auth](https://github.com/ldclabs/ic-auth) is a web authentication system based on the Internet Computer.

`ic_auth_types` is a Rust types library used for integrating with IC-Auth. It provides essential data structures and utilities for working with Internet Computer authentication.

## Features

- **Efficient Byte Handling**: Includes `ByteBufB64` and `ByteArrayB64` types for efficient serialization and deserialization of binary data with automatic Base64URL encoding for human-readable formats.
- **Unique Identifiers**: Provides `Xid` type, a compact and lexicographically sortable globally unique identifier (12 bytes vs UUID's 16 bytes).
- **Authentication Primitives**: Includes types for delegations, signed delegations, and authentication responses.
- **Candid Compatibility**: All types implement `CandidType` for seamless integration with the Internet Computer.
- **Serde Support**: Full serialization/deserialization support for both human-readable (JSON) and binary formats (CBOR).

## Usage

Add this to your `Cargo.toml`:
```toml
[dependencies]
ic_auth_types = "0.3"
```

Enables interoperability with the original `xid` crate:
```toml
[dependencies]
ic_auth_types = { version = "0.3", features = ["xid"] }
```

## Related Crates

- [`ic_auth_verifier`](https://crates.io/crates/ic_auth_verifier): Provides verification functionality for IC-Auth signatures.

## License
Copyright © 2024-2025 [LDC Labs](https://github.com/ldclabs).

`ldclabs/ic-auth` is licensed under the MIT License. See [LICENSE](../../LICENSE) for the full license text.
