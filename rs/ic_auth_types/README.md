# `ic_auth_types`

![License](https://img.shields.io/crates/l/ic_auth_types.svg)
[![Crates.io](https://img.shields.io/crates/d/ic_auth_types.svg)](https://crates.io/crates/ic_auth_types)
[![Test](https://github.com/ldclabs/ic-auth/actions/workflows/test.yml/badge.svg)](https://github.com/ldclabs/ic-auth/actions/workflows/test.yml)
[![Docs.rs](https://img.shields.io/docsrs/ic_auth_types?label=docs.rs)](https://docs.rs/ic_auth_types)
[![Latest Version](https://img.shields.io/crates/v/ic_auth_types.svg)](https://crates.io/crates/ic_auth_types)

[IC-Auth](https://github.com/ldclabs/ic-auth) is a web authentication system based on the Internet Computer.

`ic_auth_types` provides the shared Rust data model for IC-Auth: delegation records, compact wire forms, Base64URL byte wrappers, XID identifiers, and CBOR helpers used by signers and verifiers.

## Features

- `Delegation`, `SignedDelegation`, `SignInResponse`, and compact `p`/`e`/`t` wire forms.
- `ByteBufB64`, `ByteArrayB64`, and `BytesB64` for binary fields that become Base64URL strings in JSON and byte strings in CBOR.
- `Xid`, a compact 12-byte, lexicographically sortable identifier with optional interoperability with the `xid` crate.
- `CandidType` and Serde support for IC canister interfaces, JSON APIs, and CBOR payloads.
- `cbor_into_vec`, `cbor_from_slice`, and deterministic RFC 8949 CBOR helpers for signed or hashed payloads.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
ic_auth_types = "0.9"
```

Enable interoperability with the original `xid` crate:

```toml
[dependencies]
ic_auth_types = { version = "0.9", features = ["xid"] }
```

## Example

```rust
use candid::Principal;
use ic_auth_types::{
    ByteBufB64, Delegation, DelegationCompact, deterministic_cbor_into_vec,
};

fn main() -> Result<(), String> {
    let delegation = Delegation {
        pubkey: ByteBufB64::from(vec![1, 2, 3]),
        expiration: 1_900_000_000_000_000_000,
        targets: Some(vec![Principal::management_canister()]),
    };

    let compact: DelegationCompact = delegation.into();
    let bytes = deterministic_cbor_into_vec(&compact)?;
    assert!(!bytes.is_empty());

    Ok(())
}
```

## Feature Flags

- `default`: no optional dependencies.
- `xid`: enables conversion to and from `xid::Id`.
- `full`: currently aliases `xid`.

## Related Crates

- [`ic_auth_verifier`](https://crates.io/crates/ic_auth_verifier): signature, envelope, delegation-chain, and deep-link verification utilities.

## License

Copyright © 2024-2026 [LDC Labs](https://github.com/ldclabs).

`ldclabs/ic-auth` is licensed under the MIT License. See [LICENSE](../../LICENSE) for the full license text.
