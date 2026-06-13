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
#[derive(CandidType, Default, Clone, Eq, Ord)]
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
#[derive(CandidType, Clone, Eq, Ord)]
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

impl<Rhs> PartialEq<Rhs> for ByteBufB64
where
    Rhs: ?Sized + AsRef<[u8]>,
{
    fn eq(&self, other: &Rhs) -> bool {
        self.as_ref().eq(other.as_ref())
    }
}

impl<const N: usize, Rhs> PartialEq<Rhs> for ByteArrayB64<N>
where
    Rhs: ?Sized + AsRef<[u8; N]>,
{
    fn eq(&self, other: &Rhs) -> bool {
        self.as_ref().eq(other.as_ref())
    }
}

impl<Rhs> PartialOrd<Rhs> for ByteBufB64
where
    Rhs: ?Sized + AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Rhs) -> Option<core::cmp::Ordering> {
        self.as_ref().partial_cmp(other.as_ref())
    }
}

impl<const N: usize, Rhs> PartialOrd<Rhs> for ByteArrayB64<N>
where
    Rhs: ?Sized + AsRef<[u8; N]>,
{
    fn partial_cmp(&self, other: &Rhs) -> Option<core::cmp::Ordering> {
        self.as_ref().partial_cmp(other.as_ref())
    }
}

impl core::hash::Hash for ByteBufB64 {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<const N: usize> core::hash::Hash for ByteArrayB64<N> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl IntoIterator for ByteBufB64 {
    type Item = u8;
    type IntoIter = <Vec<u8> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a ByteBufB64 {
    type Item = &'a u8;
    type IntoIter = <&'a [u8] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a mut ByteBufB64 {
    type Item = &'a mut u8;
    type IntoIter = <&'a mut [u8] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

impl<const N: usize> IntoIterator for ByteArrayB64<N> {
    type Item = u8;
    type IntoIter = <[u8; N] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, const N: usize> IntoIterator for &'a ByteArrayB64<N> {
    type Item = &'a u8;
    type IntoIter = <&'a [u8; N] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a, const N: usize> IntoIterator for &'a mut ByteArrayB64<N> {
    type Item = &'a mut u8;
    type IntoIter = <&'a mut [u8; N] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

/// Wrapper around borrowed/owned byte slice to serialize and deserialize efficiently.
/// If the serialization format is human readable (formats like JSON and YAML), it will be encoded in Base64URL.
/// Otherwise, it will be serialized as a byte array.
///
/// This type mirrors serde_bytes::Bytes (borrow or own) while following the Base64URL
/// behavior consistent with ByteBufB64 in human-readable formats.
#[derive(CandidType, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

/// Implements `serde::Deserialize` for `BytesB64`.
/// Handles both Base64URL encoded strings (for human-readable formats) and raw bytes (for binary formats).
impl<'de, 'a> serde::Deserialize<'de> for BytesB64<'a> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let visitor = deserialize::BytesB64Visitor(core::marker::PhantomData);
        if deserializer.is_human_readable() {
            deserializer.deserialize_any(visitor)
        } else {
            deserializer.deserialize_byte_buf(visitor)
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
            deserializer.deserialize_any(deserialize::ByteBufB64Visitor)
        } else {
            deserializer.deserialize_byte_buf(deserialize::ByteBufB64Visitor)
        }
    }
}

/// Implements `serde::Deserialize` for `ByteArrayB64<N>`.
/// Handles both Base64URL encoded strings (for human-readable formats) and raw bytes (for binary formats).
impl<'de, const N: usize> serde::Deserialize<'de> for ByteArrayB64<N> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            deserializer.deserialize_any(deserialize::ByteArrayB64Visitor)
        } else {
            deserializer.deserialize_byte_buf(deserialize::ByteArrayB64Visitor)
        }
    }
}

/// Module containing visitor implementations for deserialization.
mod deserialize {
    use super::{ByteArrayB64, ByteBufB64, BytesB64};
    use core::{marker::PhantomData, str::FromStr};
    use serde::de::Error;
    use std::borrow::Cow;

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

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            ByteBufB64::from_str(&v).map_err(E::custom)
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

    /// Visitor for deserializing `BytesB64` from various formats.
    pub(super) struct BytesB64Visitor<'a>(pub(super) PhantomData<&'a ()>);

    impl<'de, 'a> serde::de::Visitor<'de> for BytesB64Visitor<'a> {
        type Value = BytesB64<'a>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("bytes or string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            BytesB64::from_str(v).map_err(E::custom)
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            BytesB64::from_str(&v).map_err(E::custom)
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(BytesB64(Cow::Owned(v.to_vec())))
        }

        fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(BytesB64(Cow::Owned(v)))
        }

        fn visit_seq<V>(self, mut v: V) -> Result<Self::Value, V::Error>
        where
            V: serde::de::SeqAccess<'de>,
        {
            let len = core::cmp::min(v.size_hint().unwrap_or(0), 4096);
            let mut bytes = Vec::with_capacity(len);

            while let Some(b) = v.next_element()? {
                bytes.push(b);
            }

            Ok(BytesB64(Cow::Owned(bytes)))
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

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            ByteArrayB64::from_str(&v).map_err(E::custom)
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

        /// Deserializes a byte vector into a `ByteBufB64`.
        fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if v.len() != N {
                return Err(E::invalid_length(v.len(), &self));
            }

            Ok(ByteArrayB64(v.try_into().unwrap()))
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
    use crate::cbor_from_slice;
    use base64::prelude::BASE64_STANDARD;
    use candid::encode_one;
    use serde::de::Visitor as _;
    use serde::de::value::{Error as ValueError, SeqDeserializer};
    use serde::{Deserialize, Serialize};
    use std::hash::{Hash as _, Hasher as _};

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
        cbor2::to_writer(&t, &mut data).unwrap();
        println!("{}", hex::encode(&data));
        assert_eq!(data, hex::decode("a26161440102030461624401020304").unwrap());
        let t1: Test = cbor_from_slice(&data[..]).unwrap();
        assert_eq!(t, t1);

        let a = encode_one(vec![1u8, 2, 3, 4]).unwrap();
        println!("candid: {}", hex::encode(&a));
        assert_eq!(a, encode_one(ByteBuf::from(vec![1, 2, 3, 4])).unwrap());
        assert_eq!(a, encode_one(ByteBufB64::from(vec![1, 2, 3, 4])).unwrap());
        assert_eq!(a, encode_one(ByteArrayB64::from([1, 2, 3, 4])).unwrap());
        assert_eq!(a, encode_one(BytesB64::from_vec(vec![1, 2, 3, 4])).unwrap());
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
        assert!(BytesB64::from_str("@@@").is_err());
    }

    #[test]
    fn test_bytesb64_serde_roundtrip() {
        #[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
        struct S {
            d: BytesB64<'static>,
        }

        let value = S {
            d: BytesB64::from_vec(vec![251, 255, 239]),
        };

        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(json, r#"{"d":"-__v"}"#);
        let parsed: S = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, value);

        let mut data = Vec::new();
        cbor2::to_writer(&value, &mut data).unwrap();
        let parsed: S = cbor_from_slice(&data[..]).unwrap();
        assert_eq!(parsed, value);
    }

    #[test]
    fn test_bytebuf_public_api_and_traits() {
        let empty = ByteBufB64::new();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let mut buf = ByteBufB64::with_capacity(4);
        assert!(buf.is_empty());
        buf.push(1);
        buf.as_mut()[0] = 2;
        buf.deref_mut().push(3);
        assert_eq!(buf.deref().as_slice(), &[2, 3]);
        assert_eq!(buf.as_ref(), &[2, 3]);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.to_base64(), "AgM=");
        assert_eq!(buf.clone().into_vec(), vec![2, 3]);
        assert_eq!(buf.clone().into_boxed_slice().as_ref(), &[2, 3]);
        assert_eq!(buf.clone().into_iter().collect::<Vec<_>>(), vec![2, 3]);
        assert_eq!(buf.clone().into_iter().collect::<Vec<_>>(), vec![2, 3]);

        for byte in &mut buf {
            *byte += 1;
        }
        assert_eq!((&buf).into_iter().copied().collect::<Vec<_>>(), vec![3, 4]);

        let from_array = <ByteBufB64 as From<[u8; 3]>>::from([5, 6, 7]);
        assert_eq!(from_array.as_ref(), &[5, 6, 7]);
        let from_bytebuf = <ByteBufB64 as From<ByteBuf>>::from(ByteBuf::from(vec![8, 9]));
        assert_eq!(from_bytebuf.as_ref(), &[8, 9]);

        assert!(ByteBufB64::default() < ByteBufB64::from(vec![1]));
        assert_eq!(
            ByteBufB64::from(vec![1]).partial_cmp(&vec![2]),
            Some(core::cmp::Ordering::Less)
        );
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        ByteBufB64::from(vec![1, 2, 3]).hash(&mut hasher);
        assert_ne!(hasher.finish(), 0);
        assert_eq!(
            IntoIterator::into_iter(ByteBufB64::from(vec![18, 19])).collect::<Vec<_>>(),
            vec![18, 19]
        );
        assert_eq!(
            ByteBufB64::try_from("AgM=").unwrap(),
            ByteBufB64(vec![2, 3])
        );
    }

    #[test]
    fn test_bytearray_public_api_and_traits() {
        let empty = ByteArrayB64::<0>::new();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let mut arr = ByteArrayB64::<3>::from([1, 2, 3]);
        assert!(!arr.is_empty());
        assert_eq!(arr.len(), 3);
        assert_eq!(arr.as_slice(), &[1, 2, 3]);
        arr.as_mut_slice()[0] = 4;
        arr.as_mut()[1] = 5;
        arr.deref_mut()[2] = 6;
        assert_eq!(arr.deref(), &[4, 5, 6]);
        assert_eq!(arr.to_base64(), "BAUG");
        assert_eq!(arr.clone().into_array(), [4, 5, 6]);
        assert_eq!(arr.clone().into_vec(), vec![4, 5, 6]);
        assert_eq!(arr.clone().into_iter().collect::<Vec<_>>(), vec![4, 5, 6]);

        for byte in &mut arr {
            *byte += 1;
        }
        assert_eq!(
            (&arr).into_iter().copied().collect::<Vec<_>>(),
            vec![5, 6, 7]
        );
        assert_eq!(arr.into_iter().collect::<Vec<_>>(), vec![5, 6, 7]);

        let from_slice = ByteArrayB64::<3>::try_from([8, 9, 10].as_slice()).unwrap();
        assert_eq!(from_slice.as_ref(), &[8, 9, 10]);
        assert!(ByteArrayB64::<3>::try_from([1, 2].as_slice()).is_err());
        let from_vec = ByteArrayB64::<3>::try_from(vec![11, 12, 13]).unwrap();
        assert_eq!(from_vec.as_ref(), &[11, 12, 13]);
        assert_eq!(
            ByteArrayB64::<3>::try_from(vec![1, 2]).unwrap_err(),
            vec![1, 2]
        );
        assert_eq!(
            ByteArrayB64::<3>::try_from("AQID").unwrap().as_ref(),
            &[1, 2, 3]
        );
        assert_eq!(
            ByteArrayB64::<3>::from([1, 2, 3]).partial_cmp(&ByteArrayB64::<3>::from([2, 3, 4])),
            Some(core::cmp::Ordering::Less)
        );
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        ByteArrayB64::<3>::from([1, 2, 3]).hash(&mut hasher);
        assert_ne!(hasher.finish(), 0);
        assert_eq!(
            IntoIterator::into_iter(ByteArrayB64::<3>::from([20, 21, 22])).collect::<Vec<_>>(),
            vec![20, 21, 22]
        );

        let serde_array = ByteArray::new([14, 15, 16]);
        assert_eq!(
            <ByteArrayB64<3> as From<ByteArray<3>>>::from(serde_array).into_array(),
            [14, 15, 16]
        );
    }

    #[test]
    fn test_byte_wrapper_candid_metadata_and_empty_formatting() {
        let types = [
            ByteBufB64::ty(),
            ByteArrayB64::<0>::ty(),
            ByteArrayB64::<4>::ty(),
            BytesB64::<'static>::ty(),
        ];
        assert_eq!(types.len(), 4);
        assert!(types.iter().all(|ty| !format!("{ty:?}").is_empty()));

        let array = ByteArrayB64::<0>::new();
        assert_eq!(array.as_slice(), &[] as &[u8]);
        assert_eq!(array.clone().into_array(), [] as [u8; 0]);
        assert_eq!(array.into_vec(), Vec::<u8>::new());

        let buf = ByteBufB64::new();
        assert_eq!(buf.to_string(), "");
        assert_eq!(format!("{buf:?}"), "ByteBufB64()");

        let bytes = BytesB64::new();
        assert_eq!(bytes.to_base64(), "");
        assert_eq!(bytes.to_string(), "");
        assert_eq!(format!("{bytes:?}"), "BytesB64()");
        assert_eq!(bytes.into_owned(), Vec::<u8>::new());
    }

    #[test]
    fn test_bytesb64_public_api_and_conversions() {
        let empty = BytesB64::new();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let data = [1u8, 2, 3];
        let borrowed = BytesB64::from_slice(&data);
        assert_eq!(borrowed.as_ref(), data.as_slice());
        assert_eq!(borrowed.deref(), data.as_slice());
        assert_eq!(borrowed.to_base64(), "AQID");
        assert_eq!(format!("{borrowed}"), "AQID");
        assert_eq!(format!("{borrowed:?}"), "BytesB64(AQID)");

        let owned = BytesB64::from_vec(vec![4, 5, 6]);
        assert_eq!(owned.clone().into_owned(), vec![4, 5, 6]);
        assert_eq!(BytesB64::from(vec![7, 8]).as_ref(), &[7, 8]);
        assert_eq!(BytesB64::from(&data[..]).as_ref(), data.as_slice());

        let bytebuf = ByteBuf::from(vec![9, 10]);
        assert_eq!(BytesB64::from(&bytebuf).as_ref(), &[9, 10]);
        let bytes = Bytes::new(&data);
        assert_eq!(BytesB64::from(bytes).as_ref(), data.as_slice());
        let byte_array = ByteArray::new([11, 12, 13]);
        assert_eq!(BytesB64::from(&byte_array).as_ref(), &[11, 12, 13]);
        let b64 = ByteBufB64::from(vec![14, 15]);
        assert_eq!(BytesB64::from(&b64).as_ref(), &[14, 15]);
        let a64 = ByteArrayB64::<2>::from([16, 17]);
        assert_eq!(BytesB64::from(&a64).as_ref(), &[16, 17]);

        assert_eq!(
            BytesB64::try_from("AQID").unwrap().as_ref(),
            data.as_slice()
        );
    }

    #[test]
    fn test_deserialize_visitors_cover_string_bytes_and_sequences() {
        let bytebuf = deserialize::ByteBufB64Visitor
            .visit_string::<ValueError>("AQID".to_string())
            .unwrap();
        assert_eq!(bytebuf.as_ref(), &[1, 2, 3]);
        let bytebuf = deserialize::ByteBufB64Visitor
            .visit_bytes::<ValueError>(&[4, 5, 6])
            .unwrap();
        assert_eq!(bytebuf.as_ref(), &[4, 5, 6]);
        let bytebuf = deserialize::ByteBufB64Visitor
            .visit_byte_buf::<ValueError>(vec![7, 8, 9])
            .unwrap();
        assert_eq!(bytebuf.as_ref(), &[7, 8, 9]);
        let seq = SeqDeserializer::<_, ValueError>::new(vec![10u8, 11, 12].into_iter());
        let bytebuf = deserialize::ByteBufB64Visitor.visit_seq(seq).unwrap();
        assert_eq!(bytebuf.as_ref(), &[10, 11, 12]);

        let bytes = deserialize::BytesB64Visitor(core::marker::PhantomData)
            .visit_string::<ValueError>("AQID".to_string())
            .unwrap();
        assert_eq!(bytes.as_ref(), &[1, 2, 3]);
        let bytes = deserialize::BytesB64Visitor(core::marker::PhantomData)
            .visit_bytes::<ValueError>(&[4, 5, 6])
            .unwrap();
        assert_eq!(bytes.as_ref(), &[4, 5, 6]);
        let seq = SeqDeserializer::<_, ValueError>::new(vec![7u8, 8, 9].into_iter());
        let bytes = deserialize::BytesB64Visitor(core::marker::PhantomData)
            .visit_seq(seq)
            .unwrap();
        assert_eq!(bytes.as_ref(), &[7, 8, 9]);

        let array = deserialize::ByteArrayB64Visitor::<3>
            .visit_string::<ValueError>("AQID".to_string())
            .unwrap();
        assert_eq!(array.as_ref(), &[1, 2, 3]);
        let array = deserialize::ByteArrayB64Visitor::<3>
            .visit_bytes::<ValueError>(&[4, 5, 6])
            .unwrap();
        assert_eq!(array.as_ref(), &[4, 5, 6]);
        let err = deserialize::ByteArrayB64Visitor::<3>
            .visit_bytes::<ValueError>(&[1, 2])
            .unwrap_err();
        assert!(err.to_string().contains("invalid length"));
        let err = deserialize::ByteArrayB64Visitor::<3>
            .visit_byte_buf::<ValueError>(vec![1, 2])
            .unwrap_err();
        assert!(err.to_string().contains("invalid length"));
        let seq = SeqDeserializer::<_, ValueError>::new(vec![7u8, 8, 9].into_iter());
        let array = deserialize::ByteArrayB64Visitor::<3>
            .visit_seq(seq)
            .unwrap();
        assert_eq!(array.as_ref(), &[7, 8, 9]);
        let seq = SeqDeserializer::<_, ValueError>::new(vec![1u8, 2].into_iter());
        assert!(
            deserialize::ByteArrayB64Visitor::<3>
                .visit_seq(seq)
                .unwrap_err()
                .to_string()
                .contains("invalid length")
        );
        let seq = SeqDeserializer::<_, ValueError>::new(vec![1u8, 2, 3, 4].into_iter());
        assert!(
            deserialize::ByteArrayB64Visitor::<3>
                .visit_seq(seq)
                .unwrap_err()
                .to_string()
                .contains("invalid length")
        );

        #[allow(dead_code)]
        #[derive(Debug, Deserialize)]
        struct WithByteBuf {
            value: ByteBufB64,
        }
        #[allow(dead_code)]
        #[derive(Debug, Deserialize)]
        struct WithBytes {
            value: BytesB64<'static>,
        }
        #[allow(dead_code)]
        #[derive(Debug, Deserialize)]
        struct WithByteArray {
            value: ByteArrayB64<3>,
        }
        assert!(
            serde_json::from_str::<WithByteBuf>(r#"{"value":true}"#)
                .unwrap_err()
                .to_string()
                .contains("bytes or string")
        );
        assert!(
            serde_json::from_str::<WithBytes>(r#"{"value":true}"#)
                .unwrap_err()
                .to_string()
                .contains("bytes or string")
        );
        assert!(
            serde_json::from_str::<WithByteArray>(r#"{"value":true}"#)
                .unwrap_err()
                .to_string()
                .contains("bytes or string")
        );
    }
}
