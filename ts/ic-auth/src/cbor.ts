import { encode, rfc8949EncodeOptions } from 'cborg'

export { decode, encode, rfc8949EncodeOptions } from 'cborg'

// RFC 8949 Deterministic Encoding: The keys in every map MUST be sorted in the bytewise lexicographic order of their deterministic encodings.
export function deterministicEncode(data: any): Uint8Array {
  return encode(data, rfc8949EncodeOptions)
}

export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  if (a instanceof Uint8Array && b instanceof Uint8Array) {
    if (a === b) {
      return 0
    }

    for (let i = 0; i < a.length; i++) {
      if (a[i] === b[i]) {
        continue
      }
      return a[i] < b[i] ? -1 : 1
    }

    if (b.length > a.length) {
      return -1
    }

    return 0
  }

  throw new Error('ic-auth: compareBytes: invalid arguments')
}
