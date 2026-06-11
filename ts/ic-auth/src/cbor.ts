import { encode, rfc8949EncodeOptions } from 'cborg'

export { decode, encode, rfc8949EncodeOptions } from 'cborg'

// RFC 8949 Deterministic Encoding: The keys in every map MUST be sorted in the bytewise lexicographic order of their deterministic encodings.
export function deterministicEncode(data: any): Uint8Array {
  return encode(data, rfc8949EncodeOptions)
}

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
