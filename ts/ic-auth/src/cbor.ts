import { encode, Token } from 'cborg'

export { decode, encode } from 'cborg'

// RFC 8949 Deterministic Encoding: The keys in every map MUST be sorted in the bytewise lexicographic order of their deterministic encodings.
export function deterministicEncode(data: any): Uint8Array {
  return encode(data, { float64: true, mapSorter })
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

type TokenEx = Token & { _keyBytes?: Uint8Array }

function mapSorter(e1: (Token | Token[])[], e2: (Token | Token[])[]): number {
  if (e1[0] instanceof Token && e2[0] instanceof Token) {
    const t1 = e1[0] as TokenEx
    const t2 = e2[0] as TokenEx

    // different key types
    if (!t1._keyBytes) {
      t1._keyBytes = deterministicEncode(t1.value)
    }

    if (!t2._keyBytes) {
      t2._keyBytes = deterministicEncode(t2.value)
    }

    return compareBytes(t1._keyBytes, t2._keyBytes)
  }
  throw new Error('ic-auth: mapSorter: complex key types are not supported yet')
}
