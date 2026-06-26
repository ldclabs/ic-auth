import { encode, rfc8949EncodeOptions } from 'cborg'

export { decode, encode, rfc8949EncodeOptions } from 'cborg'

/**
 * Encodes data using RFC 8949 deterministic CBOR.
 *
 * Deterministic encoding sorts map keys by the bytewise lexicographic order of
 * their deterministic encodings. Use this before hashing or signing IC-Auth
 * payloads so Rust and TypeScript produce the same bytes.
 */
export function deterministicEncode(data: any): Uint8Array {
  return encode(data, rfc8949EncodeOptions)
}

/**
 * Compares two byte arrays in lexicographic order.
 *
 * Returns `-1`, `0`, or `1`, matching the ordering rule used by
 * deterministic CBOR map keys.
 */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
    throw new Error('ic-auth: compareBytes: invalid arguments')
  }

  if (a === b) {
    return 0
  }

  const len = Math.min(a.length, b.length)
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) {
      return a[i] < b[i] ? -1 : 1
    }
  }

  if (a.length === b.length) {
    return 0
  }
  return a.length < b.length ? -1 : 1
}
