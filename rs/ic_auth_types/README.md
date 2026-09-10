# `ic_auth_types`

![License](https://img.shields.io/crates/l/ic_auth_types.svg)
[![Crates.io](https://img.shields.io/crates/d/ic_auth_types.svg)](https://crates.io/crates/ic_auth_types)
[![Test](https://github.com/ldclabs/ic-auth/actions/workflows/test.yml/badge.svg)](https://github.com/ldclabs/ic-auth/actions/workflows/test.yml)
[![Docs.rs](https://img.shields.io/docsrs/ic_auth_types?label=docs.rs)](https://docs.rs/ic_auth_types)
[![Latest Version](https://img.shields.io/crates/v/ic_auth_types.svg)](https://crates.io/crates/ic_auth_types)

Shared Rust data types for [IC-Auth](../../README.md): delegation records, compact wire forms, byte wrappers, XID identifiers and allocation, and deterministic CBOR helpers. The default configuration works in IC canisters without a clock or random-number source.

## Installation

```toml
[dependencies]
ic_auth_types = "0.10"
```

The examples using Candid or JSON also need `candid = "0.10"` or `serde_json = "1"` as direct dependencies. For unreleased changes, point `ic_auth_types` at this directory with a Cargo `path` dependency.

## Feature flags

| Feature | Adds | Target |
| --- | --- | --- |
| Default | All shared types, CBOR helpers, `Xid`, and `XidGenerator` | Native and `wasm32-unknown-unknown` |
| `xid` | `Xid::new()`, `Xid::xid()`, and conversions to/from `xid::Id` | Native; the upstream generator is unsuitable for IC canisters |
| `full` | Alias for `xid` | Native |

Use `XidGenerator` for explicit-state allocation without enabling an optional feature.

## Delegations and wire types

| Type | Fields / compact keys |
| --- | --- |
| `Delegation` / `DelegationCompact` | `pubkey` / `p`, `expiration` / `e`, `targets` / `t`, `permissions` / `perm` |
| `SignedDelegation` / `SignedDelegationCompact` | `delegation` / `d`, `signature` / `s` |
| `SignInResponse` | `expiration`, `user_key`, `seed` |

Delegation expiration is a UNIX timestamp in **nanoseconds**. Optional targets are canister principals. `DelegationPermissions` supports `Queries` (`queries`) and `All` (`all`). Conversion between full and compact delegation types uses `From`/`Into`; compact Serde decoding also accepts the corresponding full field names.

The `SignInResponse` here describes session expiration, user key, and seed. The verifier's deep-link `SignInResponse` is a different type containing a user public key and delegation chain.

```rust
use candid::Principal;
use ic_auth_types::{
    ByteBufB64, Delegation, DelegationCompact, cbor_from_slice,
    deterministic_cbor_into_vec,
};

fn main() -> Result<(), String> {
    let delegation = Delegation {
        pubkey: ByteBufB64::from(vec![1, 2, 3]),
        expiration: 1_900_000_000_000_000_000,
        targets: Some(vec![Principal::management_canister()]),
        permissions: None,
    };
    let compact: DelegationCompact = delegation.clone().into();
    let bytes = deterministic_cbor_into_vec(&compact)?;
    let decoded: DelegationCompact = cbor_from_slice(&bytes)?;
    assert_eq!(Delegation::from(decoded), delegation);
    Ok(())
}
```

The public key above is illustrative data for serialization, not a signing key.

## Byte wrappers

- `ByteBufB64`: owned variable-length bytes.
- `ByteArrayB64<N>`: owned bytes with a fixed length checked during decoding.
- `BytesB64`: copy-on-write bytes, constructed from a borrowed slice or an owned vector.

Human-readable Serde formats emit padded Base64URL with a `b64:` prefix. Decoding accepts the prefix optionally, both standard and URL-safe alphabets, and padded or unpadded values. CBOR uses byte strings; Candid uses `vec nat8` (`blob`). The crate also re-exports `serde_bytes::{ByteArray, ByteBuf, Bytes}`.

```rust
use ic_auth_types::ByteBufB64;

fn main() -> Result<(), serde_json::Error> {
    let bytes = ByteBufB64::from(vec![1, 2, 3, 4]);
    assert_eq!(serde_json::to_string(&bytes)?, r#""b64:AQIDBA==""#);
    let decoded: ByteBufB64 = serde_json::from_str(r#""AQIDBA""#)?;
    assert_eq!(decoded, bytes);
    Ok(())
}
```

## Deterministic CBOR

| Helper | Behavior |
| --- | --- |
| `cbor_into_vec` / `cbor_into` | Ordinary CBOR serialization into a vector or writer |
| `deterministic_cbor_into_vec` / `deterministic_cbor_into` | RFC 8949 deterministic encoding, with map keys sorted by their encoded bytes |
| `cbor_from_slice` | Decodes exactly one item; rejects trailing bytes and supports IC/Candid-specific deserialization such as `Principal` |

Use deterministic encoding for bytes that are signed, hashed, or compared across Rust and TypeScript. `cbor_from_slice` validates decoding and complete consumption, but does not require the input to have been encoded deterministically.

## XID identifiers

`Xid` stores exactly 12 bytes and orders lexicographically by those bytes. Its text and JSON representation is a lowercase, 20-character base32 string. Parsing rejects invalid characters, noncanonical padding, and incorrect lengths. `EMPTY_XID` and `Xid::default()` are all zeros.

CBOR represents an XID as a byte string. Its Candid type and encoded bytes are identical to a 12-byte `Vec<u8>`; either can decode the other's encoding. Decoding as `Xid` enforces the 12-byte length, which Candid's `vec nat8` type itself does not express.

```rust
use ic_auth_types::Xid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = vec![1u8; 12];
    let encoded = candid::encode_one(&bytes)?;
    let id: Xid = candid::decode_one(&encoded)?;
    assert_eq!(candid::encode_one(&id)?, encoded);
    assert_eq!(candid::decode_one::<Vec<u8>>(&encoded)?, bytes);
    assert_eq!(id.to_string().parse::<Xid>().unwrap(), id);
    Ok(())
}
```

## Stateful XID allocation

`XidGenerator::new(fingerprint)` accepts a caller-provided 5-byte namespace fingerprint. Each generated ID consists of:

| Bytes | Contents |
| --- | --- |
| `0..4` | Big-endian 32-bit UNIX timestamp in **seconds** |
| `4..9` | The generator's 5-byte fingerprint |
| `9..12` | Big-endian 24-bit counter, starting at zero |

```rust
use ic_auth_types::{XidGenerator, cbor_from_slice, deterministic_cbor_into_vec};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let generator = XidGenerator::new([1, 2, 3, 4, 5]);
    let (first_id, next_state) = generator.allocate(100)?;

    // Persist next_state atomically with the record using first_id.
    let persisted = deterministic_cbor_into_vec(&next_state)?;
    let restored: XidGenerator = cbor_from_slice(&persisted)?;

    // A clock rollback keeps the timestamp and advances the counter.
    let (second_id, next_state) = restored.allocate(90)?;
    assert!(first_id < second_id);
    assert_eq!(next_state.last_second, Some(100));
    assert_eq!(next_state.next_counter, 2);
    Ok(())
}
```

`allocate(&self, seconds)` returns `(Xid, new_state)` without mutating the input. Equal or earlier times advance the current counter; a later second resets it. State supports Serde and Candid persistence.

| `XidGeneratorError` | Cause |
| --- | --- |
| `StateConflict` | `profile_version` is not 1 |
| `TimestampOutOfRange` | Supplied seconds exceed `u32::MAX` |
| `CapacityExceeded` | All `2^24` counter values for the last used second are allocated |

Exhaustion never wraps; allocation resumes when time advances beyond the last used second. Give independent generators distinct fingerprints, serialize allocations for each fingerprint, and commit the returned state with the record. Reusing a fingerprint with a fresh generator or allocating from an old state can reissue IDs. The generator does not derive fingerprints or persist state for you.

## Development

From the repository root:

```bash
cargo test -p ic_auth_types
cargo test -p ic_auth_types --all-features
cargo check -p ic_auth_types --target wasm32-unknown-unknown
```

Install the WASM target with `rustup target add wasm32-unknown-unknown` if needed.

## Related packages

- [Rust verifier](../ic_auth_verifier/README.md)
- [TypeScript SDK](../../ts/ic-auth/README.md)
- [API reference](https://docs.rs/ic_auth_types)

## License

Copyright © 2024-2026 [LDC Labs](https://github.com/ldclabs).

Licensed under the MIT License. See [LICENSE](../../LICENSE).
