// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { assert, describe, it } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils'
import { compareBytes, deterministicEncode } from './cbor.js'

describe('cbor', () => {
  it('compareBytes', () => {
    assert.equal(compareBytes(new Uint8Array(), new Uint8Array([1, 2, 3])), -1)
    assert.equal(compareBytes(new Uint8Array([1, 2, 3]), new Uint8Array()), 1)
    assert.equal(
      compareBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])),
      0
    )
    assert.equal(
      compareBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])),
      -1
    )
    assert.equal(
      compareBytes(new Uint8Array([1, 2, 4]), new Uint8Array([1, 2, 3])),
      1
    )
    assert.equal(
      compareBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])),
      -1
    )
    assert.equal(
      compareBytes(new Uint8Array([1, 2]), new Uint8Array([1, 1, 3])),
      1
    )
    assert.equal(
      compareBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2])),
      1
    )
    assert.equal(
      compareBytes(new Uint8Array([1, 1, 3]), new Uint8Array([1, 2])),
      -1
    )
  })

  it('deterministicEncode', () => {
    const value = new Map<any, any>()
    value.set(false, false)
    // value.set([-1], [-1])
    // value.set([100], [100])
    value.set('aa', 'aa')
    value.set('z', 'z')
    value.set(-1, -1)
    value.set(10, 10)
    value.set(100, 100)

    const data = deterministicEncode(value)
    assert.deepEqual(
      bytesToHex(data),
      'a60a0a186418642020617a617a626161626161f4f4'
    )
    // {10: 10, 100: 100, -1: -1, "z": "z", "aa": "aa", false: false}
  })
})
