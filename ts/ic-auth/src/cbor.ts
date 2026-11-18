import { encode, rfc8949EncodeOptions, Token, Type } from 'cborg'

export { decode, encode, rfc8949EncodeOptions } from 'cborg'

const deterministicOptions = { ...rfc8949EncodeOptions, float64: false }
const presetSorter = rfc8949EncodeOptions.mapSorter
if (rfc8949EncodeOptions.float64 && presetSorter) {
  // Older presets sort float keys using float64 even when the values are
  // written at their shortest width. Width can change the order of two floats.
  deterministicOptions.mapSorter = (left, right) => {
    const [a] = left
    const [b] = right
    if (
      a instanceof Token &&
      b instanceof Token &&
      a.type === Type.float &&
      b.type === Type.float
    ) {
      return compareBytes(
        encode(a.value, deterministicOptions),
        encode(b.value, deterministicOptions)
      )
    }
    return presetSorter(left, right)
  }
}

/**
 * Encodes data using RFC 8949 deterministic CBOR.
 *
 * Deterministic encoding sorts map keys by the bytewise lexicographic order of
 * their deterministic encodings. Use this before hashing or signing IC-Auth
 * payloads. Floating-point keys use the same shortest encoding as their values.
 */
export function deterministicEncode(data: unknown): Uint8Array {
  return encode(data, deterministicOptions)
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
