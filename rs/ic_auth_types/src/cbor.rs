// SPDX-License-Identifier: Apache-2.0
use serde::{de::DeserializeOwned, ser};
use std::io::Write;

/// Serializes an object as CBOR into a new Vec<u8>
pub fn cbor_into_vec<T: ?Sized + ser::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    cbor2::to_vec(value).map_err(|err| err.to_string())
}

/// Serializes an object as CBOR into a writer
pub fn cbor_into<T: ?Sized + ser::Serialize, W: Write>(value: &T, w: W) -> Result<(), String> {
    cbor2::to_writer(value, w).map_err(|err| err.to_string())
}

/// Deserializes one CBOR item from a byte slice.
pub fn cbor_from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    match cbor2::from_slice(bytes) {
        Ok(value) => Ok(value),
        Err(primary) => {
            let value =
                cbor2::from_slice::<cbor2::Value>(bytes).map_err(|_| format!("{primary:?}"))?;
            value.deserialized().map_err(|_| format!("{primary:?}"))
        }
    }
}

/// Serializes an object as CBOR into a new Vec<u8> using RFC 8949 Deterministic Encoding.
pub fn deterministic_cbor_into_vec<T: ?Sized + ser::Serialize>(
    value: &T,
) -> Result<Vec<u8>, String> {
    cbor2::to_canonical_vec(value).map_err(|err| err.to_string())
}

/// Serializes an object as CBOR into a writer using RFC 8949 Deterministic Encoding.
pub fn deterministic_cbor_into<T: ?Sized + ser::Serialize, W: Write>(
    value: &T,
    w: W,
) -> Result<(), String> {
    cbor2::to_canonical_writer(value, w).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::Principal;
    use cbor2::Value;
    use serde::{Deserialize, Serialize, Serializer, ser::Error as _};

    struct ToggleSerialize(bool);

    impl Serialize for ToggleSerialize {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if self.0 {
                Err(S::Error::custom("intentional serialize failure"))
            } else {
                serializer.serialize_unit()
            }
        }
    }

    fn tag_inner(value: Value) -> Option<Box<Value>> {
        match value {
            Value::Tag(_, inner) => Some(inner),
            _ => None,
        }
    }

    fn map_entries(value: Value) -> Option<Vec<(Value, Value)>> {
        match value {
            Value::Map(entries) => Some(entries),
            _ => None,
        }
    }

    #[test]
    fn test_deterministic_value() {
        // https://datatracker.ietf.org/doc/html/rfc8949#section-4.2.1
        let value1 = vec![
            (Value::from(10), Value::from(10)),     // 0x0a
            (Value::from(100), Value::from(100)),   // 0x1864
            (Value::from(-1), Value::from(-1)),     // 0x20
            (Value::from("z"), Value::from("z")),   // 0x617a
            (Value::from("aa"), Value::from("aa")), // 0x626161
            (
                Value::Array(vec![Value::from(100)]),
                Value::Array(vec![Value::from(100)]),
            ), // 0x811864
            (
                Value::Array(vec![Value::from(-1)]),
                Value::Array(vec![Value::from(-1)]),
            ), // 0x8120
            (Value::from(false), Value::from(false)), // 0xf4
        ];
        let value2 = value1.iter().cloned().rev().collect::<Vec<_>>();

        let data1 = cbor_into_vec(&Value::Map(value1)).unwrap();
        println!("{}", hex::encode(&data1));
        // a80a0a186418642020617a617a62616162616181186481186481208120f4f4
        let data2 = deterministic_cbor_into_vec(&Value::Map(value2)).unwrap();
        println!("{}", hex::encode(&data2));
        assert_eq!(data1, data2);
    }

    #[test]
    fn test_writer_helpers_and_tagged_values() {
        let value = vec![
            (Value::from("b"), Value::from(2)),
            (Value::from("a"), Value::from(1)),
        ];
        let mut plain = Vec::new();
        cbor_into(&Value::Map(value.clone()), &mut plain).unwrap();
        assert_eq!(plain, cbor_into_vec(&Value::Map(value.clone())).unwrap());

        let tagged = Value::Tag(24, Box::new(Value::Map(value.into_iter().rev().collect())));
        let mut deterministic = Vec::new();
        deterministic_cbor_into(&tagged, &mut deterministic).unwrap();
        assert_eq!(deterministic, deterministic_cbor_into_vec(&tagged).unwrap());

        let decoded: Value = cbor2::from_slice(deterministic.as_slice()).unwrap();
        let inner = tag_inner(decoded).unwrap();
        let entries = map_entries(*inner).unwrap();
        assert_eq!(entries[0].0, Value::from("a"));
        assert_eq!(entries[1].0, Value::from("b"));
        assert!(tag_inner(Value::Null).is_none());
        assert!(map_entries(Value::Null).is_none());
    }

    #[test]
    fn test_helpers_return_serialize_errors() {
        assert!(cbor_into_vec(&ToggleSerialize(false)).is_ok());
        assert!(
            cbor_into_vec(&ToggleSerialize(true))
                .unwrap_err()
                .contains("intentional")
        );
        assert!(cbor_into(&ToggleSerialize(false), Vec::new()).is_ok());
        assert!(
            cbor_into(&ToggleSerialize(true), Vec::new())
                .unwrap_err()
                .contains("intentional")
        );
        assert!(deterministic_cbor_into_vec(&ToggleSerialize(false)).is_ok());
        assert!(
            deterministic_cbor_into_vec(&ToggleSerialize(true))
                .unwrap_err()
                .contains("intentional")
        );
        assert!(deterministic_cbor_into(&ToggleSerialize(false), Vec::new()).is_ok());
        assert!(
            deterministic_cbor_into(&ToggleSerialize(true), Vec::new())
                .unwrap_err()
                .contains("intentional")
        );
    }

    #[test]
    fn test_cbor_from_slice_handles_principal_bytes() {
        #[derive(Debug, Deserialize, PartialEq, Serialize)]
        struct PrincipalPayload {
            principal: Principal,
        }

        let payload = PrincipalPayload {
            principal: Principal::management_canister(),
        };
        let data = cbor_into_vec(&payload).unwrap();
        let decoded: PrincipalPayload = cbor_from_slice(&data).unwrap();

        assert_eq!(decoded, payload);
    }
}
