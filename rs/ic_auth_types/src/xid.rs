// Source code: https://github.com/kazk/xid-rs/blob/main/src/id.rs
// The upstream generator is not usable in wasm32-unknown-unknown, so this
// crate keeps the wire-compatible identifier type and an explicit-state
// generator locally.

use candid::CandidType;
use core::{
    fmt::{self, Debug, Display},
    ops::Deref,
    str::FromStr,
};

/// Length of the raw XID byte array
pub const RAW_LEN: usize = 12;
/// Length of the base32 encoded XID string
const ENCODED_LEN: usize = 20;
/// Base32 encoding character set
const ENC: &[u8] = "0123456789abcdefghijklmnopqrstuv".as_bytes();
/// Lookup table for decoding base32 characters to their values
const DEC: [u8; 256] = gen_dec();

/// Represents a unique identifier with 12 bytes.
/// Based on the xid. See: <https://github.com/rs/xid>
///
/// XID is a globally unique identifier similar to UUID, but uses a more compact
/// representation (12 bytes vs 16 bytes) and is lexicographically sortable.
/// It's represented as a 20-character base32 string when serialized to text.
#[derive(CandidType, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Xid(pub [u8; RAW_LEN]);

/// A constant representing an empty XID (all zeros)
pub const EMPTY_XID: Xid = Xid([0u8; RAW_LEN]);

/// A deterministic XID generator that does not require a system clock or RNG.
///
/// IDs contain a big-endian UNIX timestamp (4 bytes), a caller-provided
/// fingerprint (5 bytes), and a big-endian counter (3 bytes). Each fingerprint
/// must have a single allocation history: persist the state returned by
/// [`Self::allocate`] atomically with the record using the ID, and serialize
/// concurrent allocations. Reusing an old state can reissue IDs.
#[derive(CandidType, Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct XidGenerator {
    /// State format version. Currently only version 1 is supported.
    pub profile_version: u8,
    /// Stable namespace fingerprint, distinct for independent generators.
    pub fingerprint: [u8; 5],
    /// Highest UNIX timestamp used by a successful allocation, in seconds.
    pub last_second: Option<u32>,
    /// Next counter value; `1 << 24` means the current second is exhausted.
    pub next_counter: u32,
}

/// An allocation failure that leaves the generator unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XidGeneratorError {
    /// The persisted generator uses an unsupported state format.
    StateConflict,
    /// The supplied UNIX timestamp does not fit in 32 bits.
    TimestampOutOfRange,
    /// All 24-bit counter values for the current second have been used.
    CapacityExceeded,
}

impl Display for XidGeneratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::StateConflict => "unsupported XID generator state version",
            Self::TimestampOutOfRange => "XID timestamp is out of range",
            Self::CapacityExceeded => "XID counter capacity exceeded",
        })
    }
}

impl std::error::Error for XidGeneratorError {}

impl XidGenerator {
    /// Creates a generator for a caller-defined namespace fingerprint.
    ///
    /// The caller is responsible for choosing distinct fingerprints for
    /// independent generators, for example from an application/canister hash.
    /// Do not recreate a generator for a fingerprint that has already issued IDs;
    /// restore its persisted state instead.
    pub fn new(fingerprint: [u8; 5]) -> Self {
        Self {
            profile_version: 1,
            fingerprint,
            last_second: None,
            next_counter: 0,
        }
    }

    /// Proposes an ID and the state to persist, without modifying `self`.
    ///
    /// `seconds` is a UNIX timestamp in seconds. Equal or earlier timestamps
    /// retain the last timestamp and advance its counter, so clock rollback
    /// cannot reissue IDs. A later second resets the counter to zero.
    /// Exhaustion never wraps the counter; allocation can resume only when
    /// the supplied timestamp exceeds the last used second.
    ///
    /// ```
    /// use ic_auth_types::XidGenerator;
    ///
    /// let generator = XidGenerator::new([1, 2, 3, 4, 5]);
    /// let (id, next) = generator.allocate(100)?;
    /// let (later_id, next) = next.allocate(90)?;
    /// assert!(id < later_id);
    /// assert_eq!(next.last_second, Some(100));
    /// # Ok::<(), ic_auth_types::XidGeneratorError>(())
    /// ```
    pub fn allocate(&self, seconds: u64) -> Result<(Xid, Self), XidGeneratorError> {
        if self.profile_version != 1 {
            return Err(XidGeneratorError::StateConflict);
        }
        let now = u32::try_from(seconds).map_err(|_| XidGeneratorError::TimestampOutOfRange)?;
        let mut next = self.clone();
        if self.last_second.is_none_or(|last| now > last) {
            next.last_second = Some(now);
            next.next_counter = 0;
        }
        if next.next_counter >= 1 << 24 {
            return Err(XidGeneratorError::CapacityExceeded);
        }

        let mut bytes = [0; RAW_LEN];
        bytes[..4].copy_from_slice(&next.last_second.unwrap().to_be_bytes());
        bytes[4..9].copy_from_slice(&next.fingerprint);
        bytes[9..].copy_from_slice(&next.next_counter.to_be_bytes()[1..]);
        next.next_counter += 1;
        Ok((Xid(bytes), next))
    }
}

/// Conversion from our Xid to the original xid crate's Id type
/// Only available when the "xid" feature is enabled
#[cfg(feature = "xid")]
impl From<Xid> for xid::Id {
    fn from(thread: Xid) -> Self {
        xid::Id(thread.0)
    }
}

/// Conversion from the original xid crate's Id type to our Xid
/// Only available when the "xid" feature is enabled
#[cfg(feature = "xid")]
impl From<xid::Id> for Xid {
    fn from(id: xid::Id) -> Self {
        Self(id.0)
    }
}

/// Implements string parsing for Xid
/// Allows creating an Xid from a base32 encoded string using `str.parse()`
impl FromStr for Xid {
    type Err = String;

    /// Parses a base32 encoded string into an Xid
    ///
    /// # Arguments
    ///
    /// * `s` - A base32 encoded string of exactly 20 characters
    ///
    /// # Returns
    ///
    /// * `Ok(Xid)` - If parsing was successful
    /// * `Err(String)` - If the string has invalid length or contains invalid characters
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != ENCODED_LEN {
            return Err(format!("Invalid length: {}", s.len()));
        }

        if let Some(c) = s.chars().find(|&c| !matches!(c, '0'..='9' | 'a'..='v')) {
            return Err(format!("Invalid character: {c}"));
        }

        let bs = s.as_bytes();
        let mut raw = [0_u8; RAW_LEN];
        raw[11] =
            (DEC[bs[17] as usize] << 6) | (DEC[bs[18] as usize] << 1) | (DEC[bs[19] as usize] >> 4);
        // check the last byte
        if ENC[((raw[11] << 4) & 31) as usize] != bs[19] {
            return Err(format!("Invalid character: {}", bs[19] as char));
        }

        raw[10] = (DEC[bs[16] as usize] << 3) | (DEC[bs[17] as usize] >> 2);
        raw[9] = (DEC[bs[14] as usize] << 5) | DEC[bs[15] as usize];
        raw[8] =
            (DEC[bs[12] as usize] << 7) | (DEC[bs[13] as usize] << 2) | (DEC[bs[14] as usize] >> 3);
        raw[7] = (DEC[bs[11] as usize] << 4) | (DEC[bs[12] as usize] >> 1);
        raw[6] =
            (DEC[bs[9] as usize] << 6) | (DEC[bs[10] as usize] << 1) | (DEC[bs[11] as usize] >> 4);
        raw[5] = (DEC[bs[8] as usize] << 3) | (DEC[bs[9] as usize] >> 2);
        raw[4] = (DEC[bs[6] as usize] << 5) | DEC[bs[7] as usize];
        raw[3] =
            (DEC[bs[4] as usize] << 7) | (DEC[bs[5] as usize] << 2) | (DEC[bs[6] as usize] >> 3);
        raw[2] = (DEC[bs[3] as usize] << 4) | (DEC[bs[4] as usize] >> 1);
        raw[1] =
            (DEC[bs[1] as usize] << 6) | (DEC[bs[2] as usize] << 1) | (DEC[bs[3] as usize] >> 4);
        raw[0] = (DEC[bs[0] as usize] << 3) | (DEC[bs[1] as usize] >> 2);
        Ok(Self(raw))
    }
}

/// Implements conversion from a byte slice to Xid
impl TryFrom<&[u8]> for Xid {
    type Error = String;

    /// Tries to create an Xid from a byte slice
    ///
    /// # Arguments
    ///
    /// * `bytes` - A slice of bytes that should be exactly 12 bytes long
    ///
    /// # Returns
    ///
    /// * `Ok(Xid)` - If the slice has the correct length
    /// * `Err(String)` - If the slice has an invalid length
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != RAW_LEN {
            return Err(format!("Invalid length: {}", bytes.len()));
        }

        let mut id = [0u8; RAW_LEN];
        id.copy_from_slice(bytes);
        Ok(Self(id))
    }
}

/// Implements conversion from a `Vec<u8>` to Xid
impl TryFrom<Vec<u8>> for Xid {
    type Error = String;

    /// Tries to create an Xid from a `Vec<u8>`
    ///
    /// # Arguments
    ///
    /// * `bytes` - A vector of bytes that should be exactly 12 bytes long
    ///
    /// # Returns
    ///
    /// * `Ok(Xid)` - If the vector has the correct length
    /// * `Err(String)` - If the vector has an invalid length
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let id: [u8; RAW_LEN] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| format!("Invalid length: {}", v.len()))?;
        Ok(Self(id))
    }
}

/// Implements string formatting for Xid
/// This converts the Xid to its base32 encoded string representation
impl Display for Xid {
    /// Formats the Xid as a base32 encoded string
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter to write the string to
    ///
    /// # Returns
    ///
    /// * `std::fmt::Result` - The result of the formatting operation
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(raw) = self;
        let mut bs = [0_u8; ENCODED_LEN];
        bs[19] = ENC[((raw[11] << 4) & 31) as usize];
        bs[18] = ENC[((raw[11] >> 1) & 31) as usize];
        bs[17] = ENC[(((raw[11] >> 6) | (raw[10] << 2)) & 31) as usize];
        bs[16] = ENC[(raw[10] >> 3) as usize];
        bs[15] = ENC[(raw[9] & 31) as usize];
        bs[14] = ENC[(((raw[9] >> 5) | (raw[8] << 3)) & 31) as usize];
        bs[13] = ENC[((raw[8] >> 2) & 31) as usize];
        bs[12] = ENC[(((raw[8] >> 7) | (raw[7] << 1)) & 31) as usize];
        bs[11] = ENC[(((raw[7] >> 4) | (raw[6] << 4)) & 31) as usize];
        bs[10] = ENC[((raw[6] >> 1) & 31) as usize];
        bs[9] = ENC[(((raw[6] >> 6) | (raw[5] << 2)) & 31) as usize];
        bs[8] = ENC[(raw[5] >> 3) as usize];
        bs[7] = ENC[(raw[4] & 31) as usize];
        bs[6] = ENC[(((raw[4] >> 5) | (raw[3] << 3)) & 31) as usize];
        bs[5] = ENC[((raw[3] >> 2) & 31) as usize];
        bs[4] = ENC[(((raw[3] >> 7) | (raw[2] << 1)) & 31) as usize];
        bs[3] = ENC[(((raw[2] >> 4) | (raw[1] << 4)) & 31) as usize];
        bs[2] = ENC[((raw[1] >> 1) & 31) as usize];
        bs[1] = ENC[(((raw[1] >> 6) | (raw[0] << 2)) & 31) as usize];
        bs[0] = ENC[(raw[0] >> 3) as usize];
        f.write_str(core::str::from_utf8(&bs).expect("valid utf8"))
    }
}

impl Debug for Xid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Xid({self})")
    }
}

/// Implements AsRef trait for Xid to get a reference to the underlying byte array
impl AsRef<[u8; RAW_LEN]> for Xid {
    fn as_ref(&self) -> &[u8; RAW_LEN] {
        &self.0
    }
}

/// Implements Deref trait for Xid to allow direct access to the underlying byte array
impl Deref for Xid {
    type Target = [u8; RAW_LEN];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Implements Default trait for Xid, returning an empty Xid
impl Default for Xid {
    fn default() -> Self {
        EMPTY_XID
    }
}

impl Xid {
    /// Creates a new Xid with a unique value
    /// Only available when the "xid" feature is enabled
    #[cfg(feature = "xid")]
    pub fn new() -> Self {
        Self(xid::new().0)
    }

    /// Returns the xid of the thread.
    /// Only available when the "xid" feature is enabled
    #[cfg(feature = "xid")]
    pub fn xid(&self) -> xid::Id {
        xid::Id(self.0)
    }

    /// Returns a slice of the underlying byte array
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Checks if this Xid is empty (all zeros)
    pub fn is_empty(&self) -> bool {
        self == &EMPTY_XID
    }
}

/// Implements serialization for Xid
/// Uses string representation for human-readable formats and raw bytes otherwise
impl serde::Serialize for Xid {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.collect_str(self)
        } else {
            serializer.serialize_bytes(self.as_slice())
        }
    }
}

/// Implements deserialization for Xid
/// Handles both string and byte array representations
impl<'de> serde::Deserialize<'de> for Xid {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(deserialize::XidVisitor)
        } else {
            deserializer.deserialize_bytes(deserialize::XidVisitor)
        }
    }
}

/// Module containing deserialization helpers for Xid
mod deserialize {
    use super::{RAW_LEN, Xid};
    use serde::de::Error;
    use std::{convert::TryFrom, str::FromStr};

    /// Visitor implementation for deserializing Xid from various formats
    pub(super) struct XidVisitor;

    impl<'de> serde::de::Visitor<'de> for XidVisitor {
        type Value = Xid;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("bytes or string")
        }

        /// Deserializes an Xid from a string
        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Xid::from_str(v).map_err(E::custom)
        }

        /// Deserializes an Xid from a byte array
        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Xid::try_from(value).map_err(E::custom)
        }

        /// Deserializes an Xid from a sequence of bytes
        fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
        where
            V: serde::de::SeqAccess<'de>,
        {
            let mut bytes = [0; RAW_LEN];

            for (idx, byte) in bytes.iter_mut().enumerate() {
                *byte = seq
                    .next_element()?
                    .ok_or_else(|| V::Error::invalid_length(idx, &self))?;
            }

            if let Some(_extra) = seq.next_element::<serde::de::IgnoredAny>()? {
                return Err(V::Error::invalid_length(RAW_LEN + 1, &self));
            }

            Ok(Xid(bytes))
        }
    }
}

/// Generates a lookup table for decoding base32 characters
///
/// This function creates a 256-element array where each index represents
/// an ASCII character code, and the value is the corresponding base32 value
/// (0-31) for that character. Only the indices for '0'-'9' and 'a'-'v' have
/// meaningful values; all other indices contain zeros.
const fn gen_dec() -> [u8; 256] {
    let mut dec = [0_u8; 256];
    let mut i = 0;
    while i < ENC.len() {
        dec[ENC[i] as usize] = i as u8;
        i += 1;
    }
    dec
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor_from_slice;
    use candid::Principal;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
    struct Test {
        thread: Xid,
        principal: Principal,
    }

    #[test]
    fn generator_layout_matches_xid_wire_format() {
        let generator = XidGenerator {
            last_second: Some(0x4d88e15b),
            next_counter: 0x412dc9,
            ..XidGenerator::new([0x60, 0xf4, 0x86, 0xe4, 0x28])
        };
        let before = generator.clone();
        let (id, next) = generator.allocate(0x4d88e15b).unwrap();
        assert_eq!(id.to_string(), "9m4e2mr0ui3e8a215n4g");
        assert_eq!(next.next_counter, 0x412dca);
        assert_eq!(generator, before);

        #[cfg(feature = "xid")]
        assert_eq!(id.xid().to_string(), id.to_string());
    }

    #[test]
    fn generator_is_deterministic_and_preserves_namespace() {
        let generator = XidGenerator::new([1, 2, 3, 4, 5]);
        let (first, next) = generator.allocate(0).unwrap();
        assert_eq!(generator.allocate(0).unwrap(), (first, next.clone()));
        assert_eq!(first.0, [0, 0, 0, 0, 1, 2, 3, 4, 5, 0, 0, 0]);
        assert_eq!(next.last_second, Some(0));
        assert_eq!(next.next_counter, 1);
        assert_eq!(next.profile_version, 1);
        assert_eq!(next.fingerprint, generator.fingerprint);
        assert_eq!(generator.last_second, None);
        assert_eq!(generator.next_counter, 0);
        let (other, _) = XidGenerator::new([1, 2, 3, 4, 6]).allocate(0).unwrap();
        assert_ne!(first, other);
    }

    #[test]
    fn generator_survives_serialization_and_clock_rollback() {
        let initial = XidGenerator::new([1, 2, 3, 4, 5]);
        let (a, state) = initial.allocate(100).unwrap();
        // Persist and restore both unused and active states in supported formats.
        for original in [initial, state.clone()] {
            let json = serde_json::to_vec(&original).unwrap();
            let from_json: XidGenerator = serde_json::from_slice(&json).unwrap();
            let cbor = crate::deterministic_cbor_into_vec(&original).unwrap();
            let from_cbor: XidGenerator = cbor_from_slice(&cbor).unwrap();
            let candid = candid::encode_one(&original).unwrap();
            let from_candid: XidGenerator = candid::decode_one(&candid).unwrap();
            for restored in [from_json, from_cbor, from_candid] {
                assert_eq!(restored, original);
                assert_eq!(restored.allocate(90), original.allocate(90));
            }
        }

        let encoded = crate::deterministic_cbor_into_vec(&state).unwrap();
        let state: XidGenerator = cbor_from_slice(&encoded).unwrap();
        let (b, state) = state.allocate(90).unwrap();
        let (c, state) = state.allocate(100).unwrap();
        assert_eq!(state.last_second, Some(100));
        assert_eq!(state.next_counter, 3);
        let (d, state) = state.allocate(101).unwrap();
        assert!(a < b && b < c && c < d);
        assert!(a.to_string() < b.to_string());
        assert!(b.to_string() < c.to_string());
        assert!(c.to_string() < d.to_string());
        assert_eq!(&b.0[9..], &[0, 0, 1]);
        assert_eq!(&c.0[9..], &[0, 0, 2]);
        assert_eq!(&d.0[9..], &[0, 0, 0]);
        assert_eq!(state.last_second, Some(101));
        assert_eq!(state.next_counter, 1);
    }

    #[test]
    fn generator_counter_carries_without_wrapping() {
        for counter in [0xff, 0xffff, (1 << 24) - 1] {
            let generator = XidGenerator {
                last_second: Some(100),
                next_counter: counter,
                ..XidGenerator::new([1; 5])
            };
            let (id, next) = generator.allocate(100).unwrap();
            assert_eq!(&id.0[9..], &counter.to_be_bytes()[1..]);
            assert_eq!(next.next_counter, counter + 1);
            if counter < (1 << 24) - 1 {
                let (after, _) = next.allocate(100).unwrap();
                assert!(id < after);
                assert_eq!(&after.0[9..], &(counter + 1).to_be_bytes()[1..]);
            } else {
                let encoded = crate::deterministic_cbor_into_vec(&next).unwrap();
                let exhausted: XidGenerator = cbor_from_slice(&encoded).unwrap();
                let before = exhausted.clone();
                for seconds in [99, 100] {
                    assert_eq!(
                        exhausted.allocate(seconds),
                        Err(XidGeneratorError::CapacityExceeded)
                    );
                    assert_eq!(exhausted, before);
                }
                let (after, next) = exhausted.allocate(101).unwrap();
                assert!(id < after);
                assert_eq!(&after.0[9..], &[0; 3]);
                assert_eq!(next.next_counter, 1);
                assert_eq!(next.last_second, Some(101));
            }
        }
    }

    #[test]
    fn generator_rejects_invalid_timestamps_and_versions_without_mutating() {
        let initial = XidGenerator::new([1; 5]);
        let (id, active) = initial.allocate(u32::MAX as u64).unwrap();
        assert_eq!(&id.0[..4], &[255; 4]);
        let (next_id, _) = active.allocate(u32::MAX as u64).unwrap();
        assert!(id < next_id);

        for generator in [initial, active] {
            let before = generator.clone();
            for seconds in [u32::MAX as u64 + 1, u64::MAX] {
                assert_eq!(
                    generator.allocate(seconds),
                    Err(XidGeneratorError::TimestampOutOfRange)
                );
                assert_eq!(generator, before);
            }
            for profile_version in [0, 2, u8::MAX] {
                let invalid = XidGenerator {
                    profile_version,
                    ..generator.clone()
                };
                let before = invalid.clone();
                assert_eq!(invalid.allocate(100), Err(XidGeneratorError::StateConflict));
                assert_eq!(invalid, before);
            }
        }
    }

    #[test]
    fn xid_roundtrips_all_bits_and_rejects_noncanonical_padding() {
        for bit in 0..RAW_LEN * 8 {
            let mut raw = [0; RAW_LEN];
            raw[bit / 8] = 1 << (bit % 8);
            let id = Xid(raw);
            assert_eq!(id.to_string().parse::<Xid>().unwrap(), id);
            let json = serde_json::to_vec(&id).unwrap();
            assert_eq!(serde_json::from_slice::<Xid>(&json).unwrap(), id);
            let cbor = crate::deterministic_cbor_into_vec(&id).unwrap();
            assert_eq!(cbor_from_slice::<Xid>(&cbor).unwrap(), id);
        }
        let maximum = Xid([255; RAW_LEN]);
        assert_eq!(maximum.to_string(), "vvvvvvvvvvvvvvvvvvvg");
        assert_eq!(maximum.to_string().parse::<Xid>().unwrap(), maximum);
        for &last in ENC {
            let text = format!("0000000000000000000{}", last as char);
            assert_eq!(text.parse::<Xid>().is_ok(), matches!(last, b'0' | b'g'));
        }
        for invalid in ["0000000000000000000A", "000000000000000000é"] {
            assert!(invalid.parse::<Xid>().is_err());
        }
    }

    // https://github.com/rs/xid/blob/efa678f304ab65d6d57eedcb086798381ae22206/id_test.go#L101
    #[test]
    fn test_to_string() {
        let xid = Xid([
            0x4d, 0x88, 0xe1, 0x5b, 0x60, 0xf4, 0x86, 0xe4, 0x28, 0x41, 0x2d, 0xc9,
        ]);
        assert_eq!(xid.to_string(), "9m4e2mr0ui3e8a215n4g");

        assert_eq!(format!("{xid:?}"), "Xid(9m4e2mr0ui3e8a215n4g)");
    }

    #[test]
    fn test_xid() {
        let t = Test {
            thread: EMPTY_XID,
            principal: Principal::anonymous(),
        };
        let data = serde_json::to_string(&t).unwrap();
        println!("{data}");
        assert_eq!(
            data,
            r#"{"thread":"00000000000000000000","principal":"2vxsx-fae"}"#
        );
        let t1: Test = serde_json::from_str(&data).unwrap();
        assert_eq!(t, t1);

        let mut data = Vec::new();
        cbor2::to_writer(&t, &mut data).unwrap();
        println!("{}", hex::encode(&data));
        assert_eq!(
            data,
            hex::decode("a2667468726561644c000000000000000000000000697072696e636970616c4104")
                .unwrap()
        );
        let t1: Test = cbor_from_slice(&data[..]).unwrap();
        assert_eq!(t, t1);
    }

    #[test]
    fn test_xid_candid_matches_byte_vector() {
        assert_eq!(Xid::ty(), Vec::<u8>::ty());

        for raw in [
            [0; RAW_LEN],
            [255; RAW_LEN],
            [
                0x4d, 0x88, 0xe1, 0x5b, 0x60, 0xf4, 0x86, 0xe4, 0x28, 0x41, 0x2d, 0xc9,
            ],
        ] {
            let xid = Xid(raw);
            let bytes = raw.to_vec();
            let encoded_xid = candid::encode_one(xid).unwrap();
            let encoded_bytes = candid::encode_one(&bytes).unwrap();

            assert_eq!(encoded_xid, encoded_bytes);
            assert_eq!(candid::decode_one::<Xid>(&encoded_xid).unwrap(), xid);
            assert_eq!(candid::decode_one::<Xid>(&encoded_bytes).unwrap(), xid);
            assert_eq!(candid::decode_one::<Vec<u8>>(&encoded_xid).unwrap(), bytes);
        }
    }

    #[test]
    fn test_xid_candid_rejects_invalid_byte_vector_lengths() {
        for len in [0, RAW_LEN - 1, RAW_LEN + 1] {
            let bytes = vec![0u8; len];
            let encoded = candid::encode_one(&bytes).unwrap();

            assert_eq!(candid::decode_one::<Vec<u8>>(&encoded).unwrap(), bytes);
            assert!(candid::decode_one::<Xid>(&encoded).is_err());
        }
    }

    #[test]
    fn test_xid_rejects_extra_sequence_bytes() {
        use serde::Deserializer as _;
        use serde::de::value::{Error as ValueError, SeqDeserializer};

        let bytes = vec![0u8; RAW_LEN + 1];
        let deserializer = SeqDeserializer::<_, ValueError>::new(bytes.into_iter());
        let err = deserializer
            .deserialize_seq(deserialize::XidVisitor)
            .unwrap_err();

        assert!(err.to_string().contains("invalid length 13"));
    }

    #[test]
    fn test_xid_rejects_short_sequence() {
        use serde::Deserializer as _;
        use serde::de::value::{Error as ValueError, SeqDeserializer};

        let bytes = vec![0u8; RAW_LEN - 1];
        let deserializer = SeqDeserializer::<_, ValueError>::new(bytes.into_iter());
        let err = deserializer
            .deserialize_seq(deserialize::XidVisitor)
            .unwrap_err();

        assert!(err.to_string().contains("invalid length 11"));
    }

    #[test]
    fn test_xid_public_api_and_error_paths() {
        assert_eq!(Xid::from_str("short").unwrap_err(), "Invalid length: 5");
        assert_eq!(
            Xid::from_str("0000000000000000000w").unwrap_err(),
            "Invalid character: w"
        );
        assert_eq!(
            Xid::from_str("00000000000000000001").unwrap_err(),
            "Invalid character: 1"
        );

        let raw = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let xid = Xid::try_from(raw.as_slice()).unwrap();
        assert_eq!(xid.as_ref(), &raw);
        assert_eq!(xid.deref(), &raw);
        assert_eq!(xid.as_slice(), raw.as_slice());
        assert!(!xid.is_empty());
        assert!(Xid::default().is_empty());
        assert!(EMPTY_XID.is_empty());
        assert_eq!(
            Xid::try_from(raw[..RAW_LEN - 1].as_ref()).unwrap_err(),
            "Invalid length: 11"
        );

        let xid = Xid::try_from(raw.to_vec()).unwrap();
        assert_eq!(xid.as_slice(), raw.as_slice());
        assert_eq!(
            Xid::try_from(raw[..RAW_LEN - 1].to_vec()).unwrap_err(),
            "Invalid length: 11"
        );

        let dec = gen_dec();
        assert_eq!(dec[b'0' as usize], 0);
        assert_eq!(dec[b'9' as usize], 9);
        assert_eq!(dec[b'a' as usize], 10);
        assert_eq!(dec[b'v' as usize], 31);

        #[cfg(feature = "xid")]
        {
            let generated = Xid::new();
            assert!(!generated.is_empty());
            let original = xid::Id(raw);
            let wrapped: Xid = original.into();
            assert_eq!(wrapped.as_slice(), raw.as_slice());
            let back: xid::Id = wrapped.into();
            assert_eq!(back.0, raw);
            assert_eq!(wrapped.xid().0, raw);
        }
    }

    #[test]
    fn test_xid_deserializes_exact_sequence() {
        use serde::Deserializer as _;
        use serde::de::value::{Error as ValueError, SeqDeserializer};

        let raw = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let deserializer = SeqDeserializer::<_, ValueError>::new(raw.into_iter());
        let xid = deserializer
            .deserialize_seq(deserialize::XidVisitor)
            .unwrap();

        assert_eq!(xid.as_slice(), raw.as_slice());
    }
}
