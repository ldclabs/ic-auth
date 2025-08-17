use base64::{
    Engine,
    prelude::{BASE64_URL_SAFE, BASE64_URL_SAFE_NO_PAD},
};
use candid::CandidType;
use core::{
    fmt::{self, Debug, Display},
    ops::{Deref, DerefMut},
    str::FromStr,
};

pub use serde_bytes::{self, ByteArray, ByteBuf, Bytes};

/// Wrapper around `Vec<u8>` to serialize and deserialize efficiently.
/// If the serialization format is human readable (formats like JSON and YAML), it will be encoded in Base64URL.
/// Otherwise, it will be serialized as a byte array.
///
/// # Examples
///
/// ```
/// use ic_auth_types::ByteBufB64;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct Example {
///     data: ByteBufB64,
/// }
///
/// let example = Example {
///     data: vec![1, 2, 3, 4].into(),
/// };
///
/// // Serializes to Base64URL in human-readable formats
/// let json = serde_json::to_string(&example).unwrap();
/// assert_eq!(json, r#"{"data":"AQIDBA=="}"#);
///
/// // Deserializes from Base64URL
/// let parsed: Example = serde_json::from_str(&json).unwrap();
/// assert_eq!(parsed.data.as_ref(), &[1, 2, 3, 4]);
/// ```
#[derive(CandidType, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteBufB64(pub Vec<u8>);

impl ByteBufB64 {
    /// Construct a new, empty `ByteBufB64`.
    pub fn new() -> Self {
        ByteBufB64(Vec::new())
    }

    /// Construct a new, empty `ByteBufB64` with the specified capacity.
    pub fn with_capacity(cap: usize) -> Self {
        ByteBufB64(Vec::with_capacity(cap))
    }

    /// Wrap existing bytes in a `ByteBufB64`.
    pub fn from<T: Into<Vec<u8>>>(bytes: T) -> Self {
        ByteBufB64(bytes.into())
    }

    /// Unwrap the vector of byte underlying this `ByteBufB64`.
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    // This would hit "cannot move out of borrowed content" if invoked through
    // the Deref impl; make it just work.
    #[doc(hidden)]
    pub fn into_boxed_slice(self) -> Box<[u8]> {
        self.0.into_boxed_slice()
    }

    #[doc(hidden)]
    #[allow(clippy::should_implement_trait)]
    pub fn into_iter(self) -> <Vec<u8> as IntoIterator>::IntoIter {
        self.0.into_iter()
    }
}

/// Wrapper around `[u8; N]` to serialize and deserialize efficiently.
/// If the serialization format is human readable (formats like JSON and YAML), it will be encoded in Base64URL.
/// Otherwise, it will be serialized as a byte array.
///
/// # Examples
///
/// ```
/// use ic_auth_types::ByteArrayB64;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct Example {
///     data: ByteArrayB64<4>,
/// }
///
/// let example = Example {
///     data: [1, 2, 3, 4].into(),
/// };
///
/// // Serializes to Base64URL in human-readable formats
/// let json = serde_json::to_string(&example).unwrap();
/// assert_eq!(json, r#"{"data":"AQIDBA=="}"#);
///
/// // Deserializes from Base64URL
/// let parsed: Example = serde_json::from_str(&json).unwrap();
/// assert_eq!(parsed.data.as_ref(), &[1, 2, 3, 4]);
/// ```
#[derive(CandidType, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteArrayB64<const N: usize>(pub [u8; N]);

impl<const N: usize> ByteArrayB64<N> {
    /// Construct a new, empty `ByteArrayB64`.
    pub fn new() -> Self {
        ByteArrayB64::default()
    }

    /// Wrap existing bytes in a `ByteArrayB64`.
    pub fn from<T: Into<[u8; N]>>(bytes: T) -> Self {
        ByteArrayB64(bytes.into())
    }

    /// Unwrap the array of byte underlying this `ByteArrayB64`.
    pub fn into_array(self) -> [u8; N] {
        self.0
    }

    /// Unwrap the vector of byte underlying this `ByteArrayB64`.
    pub fn into_vec(self) -> Vec<u8> {
        self.0.into()
    }

    #[doc(hidden)]
    #[allow(clippy::should_implement_trait)]
    pub fn into_iter(self) -> <[u8; N] as IntoIterator>::IntoIter {
        self.0.into_iter()
    }
}

impl<const N: usize> Default for ByteArrayB64<N> {
    fn default() -> Self {
        ByteArrayB64([0; N])
    }
}

impl Display for ByteBufB64 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_URL_SAFE.encode(&self.0))
    }
}

impl Debug for ByteBufB64 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ByteBufB64({self})")
    }
}

impl<const N: usize> Display for ByteArrayB64<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_URL_SAFE.encode(self.0))
    }
}

impl<const N: usize> Debug for ByteArrayB64<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ByteArrayB64<{N}>({self})")
    }
}

/// Implements `AsRef<[u8]>` for `ByteBufB64` to allow borrowing the underlying byte slice.
impl AsRef<[u8]> for ByteBufB64 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Implements `AsMut<[u8]>` for `ByteBufB64` to allow mutably borrowing the underlying byte slice.
impl AsMut<[u8]> for ByteBufB64 {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// Implements `AsRef<[u8; N]>` for `ByteArrayB64<N>` to allow borrowing the underlying byte array.
impl<const N: usize> AsRef<[u8; N]> for ByteArrayB64<N> {
    fn as_ref(&self) -> &[u8; N] {
        &self.0
    }
}

/// Implements `AsMut<[u8; N]>` for `ByteArrayB64<N>` to allow mutably borrowing the underlying byte array.
impl<const N: usize> AsMut<[u8; N]> for ByteArrayB64<N> {
    fn as_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

/// Implements `Deref` for `ByteBufB64` to allow transparent access to the underlying `Vec<u8>`.
impl Deref for ByteBufB64 {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Implements `DerefMut` for `ByteBufB64` to allow transparent mutable access to the underlying `Vec<u8>`.
impl DerefMut for ByteBufB64 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Implements `Deref` for `ByteArrayB64<N>` to allow transparent access to the underlying `[u8; N]`.
impl<const N: usize> Deref for ByteArrayB64<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Implements `DerefMut` for `ByteArrayB64<N>` to allow transparent mutable access to the underlying `[u8; N]`.
impl<const N: usize> DerefMut for ByteArrayB64<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Implements `From<Vec<u8>>` for `ByteBufB64` to allow easy conversion from a byte vector.
impl From<Vec<u8>> for ByteBufB64 {
    fn from(bytes: Vec<u8>) -> Self {
        ByteBufB64(bytes)
    }
}

/// Implements `From<[u8; N]>` for `ByteBufB64` to allow easy conversion from a byte array.
impl<const N: usize> From<[u8; N]> for ByteBufB64 {
    fn from(bytes: [u8; N]) -> Self {
        ByteBufB64(bytes.into())
    }
}

/// Implements `From<ByteBuf>` for `ByteBufB64` to allow easy conversion from a `serde_bytes::ByteBuf`.
impl From<ByteBuf> for ByteBufB64 {
    fn from(v: ByteBuf) -> Self {
        ByteBufB64(v.into_vec())
    }
}

/// Implements `From<[u8; N]>` for `ByteArrayB64<N>` to allow easy conversion from a byte array.
impl<const N: usize> From<[u8; N]> for ByteArrayB64<N> {
    fn from(bytes: [u8; N]) -> Self {
        ByteArrayB64(bytes)
    }
}

/// Implements `From<ByteArray<N>>` for `ByteArrayB64<N>` to allow easy conversion from a `serde_bytes::ByteArray<N>`.
impl<const N: usize> From<ByteArray<N>> for ByteArrayB64<N> {
    fn from(v: ByteArray<N>) -> Self {
        ByteArrayB64(v.into_array())
    }
}

/// Implements `FromStr` for `ByteBufB64` to allow easy conversion from a Base64URL encoded string.
impl FromStr for ByteBufB64 {
    type Err = base64::DecodeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = BASE64_URL_SAFE_NO_PAD.decode(s.trim_end_matches('='))?;
        Ok(ByteBufB64(v))
    }
}

/// Implements `From<&str>` for `ByteBufB64` to allow easy conversion from a Base64URL encoded string.
impl TryFrom<&str> for ByteBufB64 {
    type Error = base64::DecodeError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        ByteBufB64::from_str(s)
    }
}

/// Implements `FromStr` for `ByteArrayB64<N>` to allow easy conversion from a Base64URL encoded string.
impl<const N: usize> FromStr for ByteArrayB64<N> {
    type Err = base64::DecodeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = BASE64_URL_SAFE_NO_PAD.decode(s.trim_end_matches('='))?;
        let l = v.len();
        let v: [u8; N] = v
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength(l))?;
        Ok(ByteArrayB64(v))
    }
}

/// Implements `From<&str>` for `ByteArrayB64<N>` to allow easy conversion from a Base64URL encoded string.
impl<const N: usize> TryFrom<&str> for ByteArrayB64<N> {
    type Error = base64::DecodeError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        ByteArrayB64::from_str(s)
    }
}

/// Implements `serde::Serialize` for `ByteBufB64`.
/// Uses Base64URL encoding for human-readable formats and raw bytes for binary formats.
impl serde::Serialize for ByteBufB64 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            BASE64_URL_SAFE.encode(&self.0).serialize(serializer)
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

/// Implements `serde::Serialize` for `ByteArrayB64<N>`.
/// Uses Base64URL encoding for human-readable formats and raw bytes for binary formats.
impl<const N: usize> serde::Serialize for ByteArrayB64<N> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            BASE64_URL_SAFE.encode(self.0).serialize(serializer)
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

/// Implements `serde::Deserialize` for `ByteBufB64`.
/// Handles both Base64URL encoded strings (for human-readable formats) and raw bytes (for binary formats).
impl<'de> serde::Deserialize<'de> for ByteBufB64 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        if deserializer.is_human_readable() {
            deserializer
                .deserialize_str(deserialize::ByteBufB64Visitor)
                .map_err(D::Error::custom)
        } else {
            deserializer
                .deserialize_bytes(deserialize::ByteBufB64Visitor)
                .map_err(D::Error::custom)
        }
    }
}

/// Implements `serde::Deserialize` for `ByteArrayB64<N>`.
/// Handles both Base64URL encoded strings (for human-readable formats) and raw bytes (for binary formats).
impl<'de, const N: usize> serde::Deserialize<'de> for ByteArrayB64<N> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        if deserializer.is_human_readable() {
            deserializer
                .deserialize_str(deserialize::ByteArrayB64Visitor)
                .map_err(D::Error::custom)
        } else {
            deserializer
                .deserialize_bytes(deserialize::ByteArrayB64Visitor)
                .map_err(D::Error::custom)
        }
    }
}

/// Module containing visitor implementations for deserialization.
mod deserialize {
    use super::{ByteArrayB64, ByteBufB64};
    use core::str::FromStr;
    use serde::de::Error;

    /// Visitor for deserializing `ByteBufB64` from various formats.
    pub(super) struct ByteBufB64Visitor;

    impl<'de> serde::de::Visitor<'de> for ByteBufB64Visitor {
        type Value = ByteBufB64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("bytes or string")
        }

        /// Deserializes a Base64URL encoded string into a `ByteBufB64`.
        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            ByteBufB64::from_str(v).map_err(E::custom)
        }

        /// Deserializes a byte slice into a `ByteBufB64`.
        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(ByteBufB64(v.to_vec()))
        }

        /// Deserializes a byte vector into a `ByteBufB64`.
        fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(ByteBufB64(v))
        }

        /// Deserializes a sequence of bytes into a `ByteBufB64`.
        fn visit_seq<V>(self, mut v: V) -> Result<Self::Value, V::Error>
        where
            V: serde::de::SeqAccess<'de>,
        {
            let len = core::cmp::min(v.size_hint().unwrap_or(0), 4096);
            let mut bytes = Vec::with_capacity(len);

            while let Some(b) = v.next_element()? {
                bytes.push(b);
            }

            Ok(ByteBufB64(bytes))
        }
    }

    /// Visitor for deserializing `ByteArrayB64<N>` from various formats.
    pub(super) struct ByteArrayB64Visitor<const N: usize>;

    impl<'de, const N: usize> serde::de::Visitor<'de> for ByteArrayB64Visitor<N> {
        type Value = ByteArrayB64<N>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("bytes or string")
        }

        /// Deserializes a Base64URL encoded string into a `ByteArrayB64<N>`.
        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            ByteArrayB64::from_str(v).map_err(E::custom)
        }

        /// Deserializes a byte slice into a `ByteArrayB64<N>`.
        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let bytes = v.try_into().map_err(E::custom)?;
            Ok(ByteArrayB64(bytes))
        }

        /// Deserializes a sequence of bytes into a `ByteArrayB64<N>`.
        fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
        where
            V: serde::de::SeqAccess<'de>,
        {
            let mut bytes = [0; N];

            for (idx, byte) in bytes.iter_mut().enumerate() {
                *byte = seq
                    .next_element()?
                    .ok_or_else(|| V::Error::invalid_length(idx, &self))?;
            }

            Ok(ByteArrayB64(bytes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::encode_one;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
    struct Test {
        a: ByteBufB64,
        b: ByteArrayB64<4>,
    }

    #[test]
    fn test_it() {
        let t = Test {
            a: [1, 2, 3, 4].to_vec().into(),
            b: [1, 2, 3, 4].into(),
        };

        println!("{t:?}");
        // Test { a: ByteBufB64(AQIDBA==), b: ByteArrayB64<4>(AQIDBA==) }
        assert_eq!(format!("{}", t.a), "AQIDBA==");
        assert_eq!(format!("{}", t.b), "AQIDBA==");
        assert_eq!(format!("{:?}", t.a), "ByteBufB64(AQIDBA==)");
        assert_eq!(format!("{:?}", t.b), "ByteArrayB64<4>(AQIDBA==)");

        let data = serde_json::to_string(&t).unwrap();
        println!("{data}");
        assert_eq!(data, r#"{"a":"AQIDBA==","b":"AQIDBA=="}"#);
        let t1: Test = serde_json::from_str(&data).unwrap();
        assert_eq!(t, t1);
        let t1: Test = serde_json::from_str(r#"{"a":"AQIDBA=","b":"AQIDBA"}"#).unwrap();
        assert_eq!(t, t1);

        let mut data = Vec::new();
        ciborium::into_writer(&t, &mut data).unwrap();
        println!("{}", hex::encode(&data));
        assert_eq!(data, hex::decode("a26161440102030461624401020304").unwrap());
        let t1: Test = ciborium::from_reader(&data[..]).unwrap();
        assert_eq!(t, t1);

        let a = encode_one(vec![1u8, 2, 3, 4]).unwrap();
        println!("candid: {}", hex::encode(&a));
        assert_eq!(a, encode_one(ByteBuf::from(vec![1, 2, 3, 4])).unwrap());
        assert_eq!(a, encode_one(ByteBufB64::from(vec![1, 2, 3, 4])).unwrap());
        assert_eq!(a, encode_one(ByteArrayB64::from([1, 2, 3, 4])).unwrap());
    }
}
