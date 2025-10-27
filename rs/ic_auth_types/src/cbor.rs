// SPDX-License-Identifier: Apache-2.0
// https://github.com/ldclabs/ciborium/blob/main/ciborium/src/value/canonical.rs

use ciborium::value::Value;
use serde::ser;
use std::io::Write;

/// Serializes an object as CBOR into a new Vec<u8>
pub fn cbor_into_vec<T: ?Sized + ser::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    ciborium::into_writer(&value, &mut data).map_err(|err| format!("{err:?}"))?;
    Ok(data)
}

/// Serializes an object as CBOR into a writer
pub fn cbor_into<T: ?Sized + ser::Serialize, W: Write>(value: &T, w: W) -> Result<(), String> {
    ciborium::into_writer(&value, w).map_err(|err| format!("{err:?}"))?;
    Ok(())
}

/// Serializes an object as CBOR into a new Vec<u8> using RFC 8949 Deterministic Encoding.
pub fn deterministic_cbor_into_vec<T: ?Sized + ser::Serialize>(
    value: &T,
) -> Result<Vec<u8>, String> {
    let value = Value::serialized(value).map_err(|err| format!("{err:?}"))?;

    let value = deterministic_value(value)?;
    let mut data = Vec::new();
    ciborium::into_writer(&value, &mut data).map_err(|err| format!("{err:?}"))?;
    Ok(data)
}

/// Serializes an object as CBOR into a writer using RFC 8949 Deterministic Encoding.
pub fn deterministic_cbor_into<T: ?Sized + ser::Serialize, W: Write>(
    value: &T,
    w: W,
) -> Result<(), String> {
    let value = Value::serialized(value).map_err(|err| format!("{err:?}"))?;

    let value = deterministic_value(value)?;
    ciborium::into_writer(&value, w).map_err(|err| format!("{err:?}"))?;
    Ok(())
}

fn deterministic_value(value: Value) -> Result<Value, String> {
    match value {
        Value::Map(entries) => {
            let mut deterministic_entries: Vec<(Vec<u8>, (Value, Value))> =
                Vec::with_capacity(entries.len());
            for (k, v) in entries {
                let k = deterministic_value(k)?;
                let v = deterministic_value(v)?;
                let b = cbor_into_vec(&k)?;
                deterministic_entries.push((b, (k, v)));
            }

            // RFC 8949 Deterministic Encoding: The keys in every map MUST be sorted in the bytewise lexicographic order of their deterministic encodings.
            deterministic_entries.sort_by(|(k1, _), (k2, _)| k1.cmp(k2));
            Ok(Value::Map(
                deterministic_entries.into_iter().map(|(_, v)| v).collect(),
            ))
        }
        Value::Array(elements) => {
            let mut deterministic_elements: Vec<Value> = Vec::with_capacity(elements.len());
            for e in elements {
                deterministic_elements.push(deterministic_value(e)?);
            }
            Ok(Value::Array(deterministic_elements))
        }
        Value::Tag(tag, inner_value) => {
            // The tag itself is a u64; its representation is handled by the serializer.
            // The inner value must be in canonical form.
            Ok(Value::Tag(
                tag,
                Box::new(deterministic_value(*inner_value)?),
            ))
        }
        // Other Value variants (Integer, Bytes, Text, Bool, Null, Float)
        // are considered "canonical" in their structure.
        _ => Ok(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
