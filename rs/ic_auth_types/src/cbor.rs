// SPDX-License-Identifier: Apache-2.0
// https://github.com/ldclabs/ciborium/blob/main/ciborium/src/value/canonical.rs

use ciborium::value::Value;
use core::cmp::Ordering;
use serde::ser;

/// Serializes an object as CBOR into a new Vec<u8>
pub fn cbor_into_vec<T: ?Sized + ser::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    ciborium::into_writer(&value, &mut data).map_err(|err| format!("{err:?}"))?;
    Ok(data)
}

/// Serializes an object as CBOR into a new Vec<u8> using RFC 8949 Deterministic Encoding.
pub fn canonical_cbor_into_vec<T: ?Sized + ser::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let value = Value::serialized(value).map_err(|err| format!("{err:?}"))?;

    let value = canonical_value(value);
    let mut data = Vec::new();
    ciborium::into_writer(&value, &mut data).map_err(|err| format!("{err:?}"))?;
    Ok(data)
}

/// Manually serialize values to compare them.
fn serialized_canonical_cmp(v1: &Value, v2: &Value) -> Ordering {
    // There is an optimization to be done here, but it would take a lot more code
    // and using mixing keys, Arrays or Maps as CanonicalValue is probably not the
    // best use of this type as it is meant mainly to be used as keys.

    let mut bytes1 = Vec::new();
    let _ = ciborium::into_writer(v1, &mut bytes1);
    let mut bytes2 = Vec::new();
    let _ = ciborium::into_writer(v2, &mut bytes2);

    match bytes1.len().cmp(&bytes2.len()) {
        Ordering::Equal => bytes1.cmp(&bytes2),
        x => x,
    }
}

fn cmp_value(v1: &Value, v2: &Value) -> Ordering {
    use Value::*;

    match (v1, v2) {
        (Integer(i), Integer(o)) => {
            // Because of the first rule above, two numbers might be in a different
            // order than regular i128 comparison. For example, 10 < -1 in
            // canonical ordering, since 10 serializes to `0x0a` and -1 to `0x20`,
            // and -1 < -1000 because of their lengths.
            i.canonical_cmp(o)
        }
        (Text(s), Text(o)) => match s.len().cmp(&o.len()) {
            Ordering::Equal => s.cmp(o),
            x => x,
        },
        (Bool(s), Bool(o)) => s.cmp(o),
        (Null, Null) => Ordering::Equal,
        (Tag(t, v), Tag(ot, ov)) => match Value::from(*t).partial_cmp(&Value::from(*ot)) {
            Some(Ordering::Equal) | None => match v.partial_cmp(ov) {
                Some(x) => x,
                None => serialized_canonical_cmp(v1, v2),
            },
            Some(x) => x,
        },
        (_, _) => serialized_canonical_cmp(v1, v2),
    }
}

fn canonical_value(value: Value) -> Value {
    match value {
        Value::Map(entries) => {
            let mut canonical_entries: Vec<(Value, Value)> = entries
                .into_iter()
                .map(|(k, v)| (canonical_value(k), canonical_value(v)))
                .collect();

            // Sort entries based on the canonical comparison of their keys.
            // cmp_value (defined in this file) implements RFC 8949 key sorting.
            canonical_entries.sort_by(|(k1, _), (k2, _)| cmp_value(k1, k2));

            Value::Map(canonical_entries)
        }
        Value::Array(elements) => {
            let canonical_elements: Vec<Value> =
                elements.into_iter().map(canonical_value).collect();
            Value::Array(canonical_elements)
        }
        Value::Tag(tag, inner_value) => {
            // The tag itself is a u64; its representation is handled by the serializer.
            // The inner value must be in canonical form.
            Value::Tag(tag, Box::new(canonical_value(*inner_value)))
        }
        // Other Value variants (Integer, Bytes, Text, Bool, Null, Float)
        // are considered "canonical" in their structure.
        _ => value,
    }
}
