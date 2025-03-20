// Source code: https://github.com/kazk/xid-rs/blob/main/src/id.rs
// We canot use it in wasm32-unknown-unknown, so we need to copy the code here.

use candid::CandidType;
use std::{ops::Deref, str::FromStr};

pub const RAW_LEN: usize = 12;
const ENCODED_LEN: usize = 20;
const ENC: &[u8] = "0123456789abcdefghijklmnopqrstuv".as_bytes();
const DEC: [u8; 256] = gen_dec();

/// Represents a unique identifier with 12 bytes.
/// Based on the xid. See: https://github.com/rs/xid
#[derive(CandidType, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Xid(pub [u8; RAW_LEN]);

pub const EMPTY_XID: Xid = Xid([0u8; RAW_LEN]);

#[cfg(feature = "xid")]
impl From<Xid> for xid::Id {
    fn from(thread: Xid) -> Self {
        xid::Id(thread.0)
    }
}

#[cfg(feature = "xid")]
impl From<xid::Id> for Xid {
    fn from(id: xid::Id) -> Self {
        Self(id.0.into())
    }
}

impl FromStr for Xid {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != ENCODED_LEN {
            return Err(format!("Invalid length: {}", s.len()));
        }

        if let Some(c) = s.chars().find(|&c| !matches!(c, '0'..='9' | 'a'..='v')) {
            return Err(format!("Invalid character: {}", c));
        }

        let bs = s.as_bytes();
        let mut raw = [0_u8; RAW_LEN];
        raw[11] = (DEC[bs[17] as usize] << 6) | (DEC[bs[18] as usize] << 1) | (DEC[bs[19] as usize] >> 4);
        // check the last byte
        if ENC[((raw[11] << 4) & 31) as usize] != bs[19] {
            return Err(format!("Invalid character: {}", bs[19] as char));
        }

        raw[10] = (DEC[bs[16] as usize] << 3) | (DEC[bs[17] as usize] >> 2);
        raw[9] = (DEC[bs[14] as usize] << 5) | DEC[bs[15] as usize];
        raw[8] = (DEC[bs[12] as usize] << 7) | (DEC[bs[13] as usize] << 2) | (DEC[bs[14] as usize] >> 3);
        raw[7] = (DEC[bs[11] as usize] << 4) | (DEC[bs[12] as usize] >> 1);
        raw[6] = (DEC[bs[9] as usize] << 6) | (DEC[bs[10] as usize] << 1) | (DEC[bs[11] as usize] >> 4);
        raw[5] = (DEC[bs[8] as usize] << 3) | (DEC[bs[9] as usize] >> 2);
        raw[4] = (DEC[bs[6] as usize] << 5) | DEC[bs[7] as usize];
        raw[3] = (DEC[bs[4] as usize] << 7) | (DEC[bs[5] as usize] << 2) | (DEC[bs[6] as usize] >> 3);
        raw[2] = (DEC[bs[3] as usize] << 4) | (DEC[bs[4] as usize] >> 1);
        raw[1] = (DEC[bs[1] as usize] << 6) | (DEC[bs[2] as usize] << 1) | (DEC[bs[3] as usize] >> 4);
        raw[0] = (DEC[bs[0] as usize] << 3) | (DEC[bs[1] as usize] >> 2);
        Ok(Self(raw))
    }
}

impl TryFrom<&[u8]> for Xid {
    type Error = String;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != RAW_LEN {
            return Err(format!("Invalid length: {}", bytes.len()));
        }

        let mut id = [0u8; RAW_LEN];
        id.copy_from_slice(bytes);
        Ok(Self(id))
    }
}

impl TryFrom<Vec<u8>> for Xid {
    type Error = String;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let id: [u8; RAW_LEN] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| format!("Invalid length: {}", v.len()))?;
        Ok(Self(id))
    }
}

impl std::fmt::Display for Xid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
        write!(f, "{}", std::str::from_utf8(&bs).expect("valid utf8"))
    }
}

impl AsRef<[u8; RAW_LEN]> for Xid {
    fn as_ref(&self) -> &[u8; RAW_LEN] {
        &self.0
    }
}

impl Deref for Xid {
    type Target = [u8; RAW_LEN];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Default for Xid {
    fn default() -> Self {
        EMPTY_XID
    }
}

impl Xid {
    #[cfg(feature = "xid")]
    pub fn new() -> Self {
        Self(xid::new().0)
    }

    /// Returns the xid of the thread.
    #[cfg(feature = "xid")]
    pub fn xid(&self) -> xid::Id {
        xid::Id(self.0)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self == &EMPTY_XID
    }
}

impl serde::Serialize for Xid {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            self.to_string().serialize(serializer)
        } else {
            serializer.serialize_bytes(self.as_slice())
        }
    }
}

impl<'de> serde::Deserialize<'de> for Xid {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        if deserializer.is_human_readable() {
            deserializer
                .deserialize_str(deserialize::XidVisitor)
                .map_err(D::Error::custom)
        } else {
            deserializer
                .deserialize_bytes(deserialize::XidVisitor)
                .map_err(D::Error::custom)
        }
    }
}

mod deserialize {
    use super::{RAW_LEN, Xid};
    use serde::de::Error;
    use std::{convert::TryFrom, str::FromStr};

    pub(super) struct XidVisitor;

    impl<'de> serde::de::Visitor<'de> for XidVisitor {
        type Value = Xid;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("bytes or string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Xid::from_str(v).map_err(E::custom)
        }

        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Xid::try_from(value).map_err(E::custom)
        }

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

            Ok(Xid(bytes))
        }
    }
}

#[rustfmt::skip]
const fn gen_dec() -> [u8; 256] {
    let mut dec = [0_u8; 256];
    // Fill in ranges b'0'..=b'9' and b'a'..=b'v'.
    // dec[48..=57].copy_from_slice(&(0..=9).collect::<Vec<u8>>());
    dec[48] = 0; dec[49] = 1; dec[50] = 2; dec[51] = 3; dec[52] = 4;
    dec[53] = 5; dec[54] = 6; dec[55] = 7; dec[56] = 8; dec[57] = 9;
    // dec[97..=118].copy_from_slice(&(10..=31).collect::<Vec<u8>>());
    dec[ 97] = 10; dec[ 98] = 11; dec[ 99] = 12; dec[100] = 13;
    dec[101] = 14; dec[102] = 15; dec[103] = 16; dec[104] = 17;
    dec[105] = 18; dec[106] = 19; dec[107] = 20; dec[108] = 21;
    dec[109] = 22; dec[110] = 23; dec[111] = 24; dec[112] = 25;
    dec[113] = 26; dec[114] = 27; dec[115] = 28; dec[116] = 29;
    dec[117] = 30; dec[118] = 31;
    dec
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::Principal;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
    struct Test {
        thread: Xid,
        principal: Principal,
    }

    // https://github.com/rs/xid/blob/efa678f304ab65d6d57eedcb086798381ae22206/id_test.go#L101
    #[test]
    fn test_to_string() {
        assert_eq!(
            Xid([
                0x4d, 0x88, 0xe1, 0x5b, 0x60, 0xf4, 0x86, 0xe4, 0x28, 0x41, 0x2d, 0xc9
            ])
            .to_string(),
            "9m4e2mr0ui3e8a215n4g"
        );
    }

    #[test]
    fn test_xid() {
        let t = Test {
            thread: EMPTY_XID,
            principal: Principal::anonymous(),
        };
        let data = serde_json::to_string(&t).unwrap();
        println!("{}", data);
        assert_eq!(
            data,
            r#"{"thread":"00000000000000000000","principal":"2vxsx-fae"}"#
        );
        let t1: Test = serde_json::from_str(&data).unwrap();
        assert_eq!(t, t1);

        let mut data = Vec::new();
        ciborium::into_writer(&t, &mut data).unwrap();
        println!("{}", const_hex::encode(&data));
        assert_eq!(
            data,
            const_hex::decode("a2667468726561644c000000000000000000000000697072696e636970616c4104")
                .unwrap()
        );
        let t1: Test = ciborium::from_reader(&data[..]).unwrap();
        assert_eq!(t, t1);
    }
}
