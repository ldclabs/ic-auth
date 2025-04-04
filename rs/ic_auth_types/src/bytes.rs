use base64::{
    Engine,
    prelude::{BASE64_URL_SAFE, BASE64_URL_SAFE_NO_PAD},
};
use candid::CandidType;
use serde_bytes::{ByteArray, ByteBuf};
use std::ops::{Deref, DerefMut};

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
#[derive(CandidType, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteBufB64(pub Vec<u8>);

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
#[derive(CandidType, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteArrayB64<const N: usize>(pub [u8; N]);

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
    use super::{BASE64_URL_SAFE_NO_PAD, ByteArrayB64, ByteBufB64, Engine};
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
            let s = v.trim_end_matches('=');
            BASE64_URL_SAFE_NO_PAD
                .decode(s)
                .map(ByteBufB64)
                .map_err(E::custom)
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
            let s = v.trim_end_matches('=');
            let v = BASE64_URL_SAFE_NO_PAD.decode(s).map_err(E::custom)?;
            self.visit_bytes(&v)
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

        let data = serde_json::to_string(&t).unwrap();
        println!("{}", data);
        assert_eq!(data, r#"{"a":"AQIDBA==","b":"AQIDBA=="}"#);
        let t1: Test = serde_json::from_str(&data).unwrap();
        assert_eq!(t, t1);

        let mut data = Vec::new();
        ciborium::into_writer(&t, &mut data).unwrap();
        println!("{}", const_hex::encode(&data));
        assert_eq!(
            data,
            const_hex::decode("a26161440102030461624401020304").unwrap()
        );
        let t1: Test = ciborium::from_reader(&data[..]).unwrap();
        assert_eq!(t, t1);
    }
}
