use base64::{
    Engine,
    prelude::{BASE64_STANDARD, BASE64_STANDARD_NO_PAD, BASE64_URL_SAFE, BASE64_URL_SAFE_NO_PAD},
};
use candid::CandidType;
use core::{
    convert::TryFrom,
    fmt::{self, Debug, Display},
    ops::{Deref, DerefMut},
    str::FromStr,
};
use std::borrow::Cow;

pub use serde_bytes::{ByteArray, ByteBuf, Bytes};

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

    /// Returns the length of the contained byte buffer.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the contained byte buffer has a length of 0.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Encodes the contained bytes as a standard Base64 string.
    pub fn to_base64(&self) -> String {
        BASE64_STANDARD.encode(&self.0)
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

    /// Returns the length of the contained byte array (always N).
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns true if N == 0.
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Returns the underlying bytes as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns the underlying bytes as a mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Encodes the contained bytes as a standard Base64 string.
    pub fn to_base64(&self) -> String {
        BASE64_STANDARD.encode(self.0)
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

/// Implements `TryFrom<&[u8]>` for `ByteArrayB64<N>` to allow checked conversion from a slice.
impl<const N: usize> TryFrom<&[u8]> for ByteArrayB64<N> {
    type Error = core::array::TryFromSliceError;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; N] = s.try_into()?;
        Ok(ByteArrayB64(arr))
    }
}

/// Implements `TryFrom<Vec<u8>>` for `ByteArrayB64<N>` to allow checked conversion from a Vec<u8>.
impl<const N: usize> TryFrom<Vec<u8>> for ByteArrayB64<N> {
    type Error = Vec<u8>;

    fn try_from(s: Vec<u8>) -> Result<Self, Self::Error> {
        let arr: [u8; N] = s.try_into()?;
        Ok(ByteArrayB64(arr))
    }
}

/// Implements `FromStr` for `ByteBufB64` to allow easy conversion from a Base64URL encoded string.
impl FromStr for ByteBufB64 {
    type Err = base64::DecodeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = try_from_base64(s)?;
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
        let v = try_from_base64(s)?;
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

/// Wrapper around borrowed/owned byte slice to serialize and deserialize efficiently.
/// If the serialization format is human readable (formats like JSON and YAML), it will be encoded in Base64URL.
/// Otherwise, it will be serialized as a byte array.
///
/// This type mirrors serde_bytes::Bytes (borrow or own) while following the Base64URL
/// behavior consistent with ByteBufB64 in human-readable formats.
#[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BytesB64<'a>(pub Cow<'a, [u8]>);

impl<'a> BytesB64<'a> {
    /// Construct a new, empty `BytesB64`.
    pub fn new() -> Self {
        BytesB64(Cow::Borrowed(&[]))
    }

    /// Wrap a borrowed slice.
    pub fn from_slice(slice: &'a [u8]) -> Self {
        BytesB64(Cow::Borrowed(slice))
    }

    /// Wrap an owned vector.
    pub fn from_vec(vec: Vec<u8>) -> Self {
        BytesB64(Cow::Owned(vec))
    }

    /// Turn this into an owned Vec<u8>.
    pub fn into_owned(self) -> Vec<u8> {
        self.0.into_owned()
    }

    /// Returns the length of the contained byte slice.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the contained byte slice has a length of 0.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Encodes the contained bytes as a standard Base64 string.
    pub fn to_base64(&self) -> String {
        BASE64_STANDARD.encode(&self.0)
    }
}

impl<'a> Display for BytesB64<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_URL_SAFE.encode(self.0.as_ref()))
    }
}

impl<'a> Debug for BytesB64<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BytesB64({self})")
    }
}

/// Implements `AsRef<[u8]>` for `BytesB64` to allow borrowing the underlying byte slice.
impl<'a> AsRef<[u8]> for BytesB64<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Implements `Deref` for `BytesB64` to allow transparent access to the underlying byte slice.
impl<'a> Deref for BytesB64<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

/// Implements `From<&[u8]>` for `BytesB64` to allow easy conversion from a byte slice.
impl<'a> From<&'a [u8]> for BytesB64<'a> {
    fn from(s: &'a [u8]) -> Self {
        BytesB64(Cow::Borrowed(s))
    }
}

/// Implements `From<Vec<u8>>` for `BytesB64` to allow easy conversion from a byte vector.
impl<'a> From<Vec<u8>> for BytesB64<'a> {
    fn from(v: Vec<u8>) -> Self {
        BytesB64(Cow::Owned(v))
    }
}

/// Implements `From<ByteBuf>` for `BytesB64` to allow easy conversion from a `serde_bytes::ByteBuf`.
impl<'a> From<&'a ByteBuf> for BytesB64<'a> {
    fn from(v: &'a ByteBuf) -> Self {
        BytesB64(Cow::Borrowed(v.as_ref()))
    }
}

/// Implements `From<&'a ByteArray<N>>` for `BytesB64`
impl<'a, const N: usize> From<&'a ByteArray<N>> for BytesB64<'a> {
    fn from(v: &'a ByteArray<N>) -> Self {
        BytesB64(Cow::Borrowed(v.as_ref()))
    }
}

/// Implements `From<Bytes<'a>>` for `BytesB64<'a>` to allow easy conversion from a `serde_bytes::Bytes<'a>`.
impl<'a> From<&'a Bytes> for BytesB64<'a> {
    fn from(v: &'a Bytes) -> Self {
        BytesB64(Cow::Borrowed(v))
    }
}

/// Implements `From<&'a ByteBufB64>` for `BytesB64`
impl<'a> From<&'a ByteBufB64> for BytesB64<'a> {
    fn from(v: &'a ByteBufB64) -> Self {
        BytesB64(Cow::Borrowed(v.0.as_ref()))
    }
}

/// Implements `From<&'a ByteArrayB64<N>>` for `BytesB64`
impl<'a, const N: usize> From<&'a ByteArrayB64<N>> for BytesB64<'a> {
    fn from(v: &'a ByteArrayB64<N>) -> Self {
        BytesB64(Cow::Borrowed(v.0.as_ref()))
    }
}

/// Implements `FromStr` for `BytesB64` to allow easy conversion from a Base64URL encoded string.
impl<'a> FromStr for BytesB64<'a> {
    type Err = base64::DecodeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = try_from_base64(s)?;
        Ok(BytesB64(Cow::Owned(v)))
    }
}

/// Implements `From<&str>` for `BytesB64` to allow easy conversion from a Base64URL encoded string.
impl<'a> TryFrom<&str> for BytesB64<'a> {
    type Error = base64::DecodeError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        BytesB64::from_str(s)
    }
}

fn try_from_base64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let v = s.trim_end_matches('=');
    if v.contains(['+', '/']) {
        BASE64_STANDARD_NO_PAD.decode(v)
    } else {
        BASE64_URL_SAFE_NO_PAD.decode(v)
    }
}

/// Implements `serde::Serialize` for `BytesB64`.
/// Uses Base64URL encoding for human-readable formats and raw bytes for binary formats.
impl<'a> serde::Serialize for BytesB64<'a> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            BASE64_URL_SAFE
                .encode(self.0.as_ref())
                .serialize(serializer)
        } else {
            serializer.serialize_bytes(self.0.as_ref())
        }
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
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(deserialize::ByteBufB64Visitor)
        } else {
            deserializer.deserialize_bytes(deserialize::ByteBufB64Visitor)
        }
    }
}

/// Implements `serde::Deserialize` for `ByteArrayB64<N>`.
/// Handles both Base64URL encoded strings (for human-readable formats) and raw bytes (for binary formats).
impl<'de, const N: usize> serde::Deserialize<'de> for ByteArrayB64<N> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(deserialize::ByteArrayB64Visitor)
        } else {
            deserializer.deserialize_bytes(deserialize::ByteArrayB64Visitor)
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
            if v.len() != N {
                return Err(E::invalid_length(v.len(), &self));
            }
            let mut bytes = [0u8; N];
            bytes.copy_from_slice(v);
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

            // If there are extra elements, report an error for clearer diagnostics.
            if let Some(_extra) = seq.next_element::<serde::de::IgnoredAny>()? {
                return Err(V::Error::invalid_length(N + 1, &self));
            }

            Ok(ByteArrayB64(bytes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::BASE64_STANDARD;
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

    #[test]
    fn test_from_str_accepts_standard_and_url() {
        let data = vec![0u8, 1, 2, 253, 254, 255];

        let std_s = BASE64_STANDARD.encode(&data); // 标准 base64（含 '+' '/'）
        let url_s = BASE64_URL_SAFE.encode(&data); // URL safe base64（含 '-' '_'）

        let a = ByteBufB64::from_str(&std_s).unwrap();
        let b = ByteBufB64::from_str(&url_s).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, ByteBufB64::from(data.clone()));

        // ByteArrayB64 同样如此
        let arr: [u8; 6] = data.clone().try_into().unwrap();
        let a2 = ByteArrayB64::<6>::from_str(&std_s).unwrap();
        let b2 = ByteArrayB64::<6>::from_str(&url_s).unwrap();
        assert_eq!(a2, b2);
        assert_eq!(a2, ByteArrayB64::<6>::from(arr));
    }

    #[test]
    fn test_display_is_url_safe_padded() {
        // 选择一些字节，标准 base64 可能包含 '+' '/'，以验证显示时统一为 URL safe
        let data = vec![251u8, 255, 239]; // 只是示例
        let expected_url = BASE64_URL_SAFE.encode(&data);

        let bb = ByteBufB64::from(data.clone());
        assert_eq!(bb.to_string(), expected_url);

        let ab = ByteArrayB64::<3>::from([251u8, 255, 239]);
        assert_eq!(ab.to_string(), expected_url);
    }

    #[test]
    fn test_serde_deserialize_from_standard_and_url_strs() {
        #[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
        struct S {
            d: ByteBufB64,
        }

        let data = vec![9u8, 8, 7, 6, 5, 4];
        let std_s = BASE64_STANDARD.encode(&data);
        let url_s = BASE64_URL_SAFE.encode(&data);

        // 标准 base64
        let s_std = format!(r#"{{"d":"{std_s}"}}"#);
        let parsed_std: S = serde_json::from_str(&s_std).unwrap();
        assert_eq!(
            parsed_std,
            S {
                d: data.clone().into()
            }
        );

        // base64-url
        let s_url = format!(r#"{{"d":"{url_s}"}}"#);
        let parsed_url: S = serde_json::from_str(&s_url).unwrap();
        assert_eq!(
            parsed_url,
            S {
                d: data.clone().into()
            }
        );
    }

    #[test]
    fn test_bytearray_invalid_length_error() {
        let data = vec![1u8, 2, 3, 4, 5];
        let s = BASE64_URL_SAFE.encode(&data);
        let err = ByteArrayB64::<4>::from_str(&s).unwrap_err();
        assert_eq!(err, base64::DecodeError::InvalidLength(5));
    }

    #[test]
    fn test_bytesb64_from_str_standard_and_url() {
        let data = vec![10u8, 20, 30, 40, 50, 60, 70];
        let std_s = BASE64_STANDARD.encode(&data);
        let url_s = BASE64_URL_SAFE.encode(&data);

        let b_std = BytesB64::from_str(&std_s).unwrap();
        let b_url = BytesB64::from_str(&url_s).unwrap();

        assert_eq!(b_std.as_ref(), data.as_slice());
        assert_eq!(b_url.as_ref(), data.as_slice());
    }
}
