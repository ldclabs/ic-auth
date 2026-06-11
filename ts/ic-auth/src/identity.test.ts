import { DelegationChain, DelegationIdentity } from '@icp-sdk/core/identity'
import { assert, describe, it } from 'vitest'
import { deterministicEncode } from './cbor.js'
import {
  base64ToBytes,
  bytesToBase64Url,
  digestMessage,
  Ed25519KeyIdentity,
  fromBase64,
  signArbitrary,
  signMessage,
  toBase64,
  toDelegationIdentity
} from './identity.js'

function pseudoRandomBytes(length: number, seed: number): Uint8Array {
  const out = new Uint8Array(length)
  let state = seed >>> 0
  for (let i = 0; i < length; i++) {
    state = (1664525 * state + 1013904223) >>> 0
    out[i] = state & 0xff
  }
  return out
}

describe('DelegationIdentity', () => {
  it('signMessage', async () => {
    const id = Ed25519KeyIdentity.fromSecretKey(new Uint8Array(32).fill(8))
    const did = toDelegationIdentity(id)
    assert.equal(
      did.getPrincipal().toText(),
      'jjn6g-sh75l-r3cxb-wxrkl-frqld-6p6qq-d4ato-wske5-op7s5-n566f-bqe'
    )
    const msg = new Map<any, any>()
    msg.set(false, false)
    msg.set('aa', 'aa')
    msg.set('z', 'z')
    msg.set(-1, -1)
    msg.set(10, 10)
    msg.set(100, 100)
    const sig = await signMessage(did, msg)
    const sig64_1 = bytesToBase64Url(deterministicEncode(sig))
    assert.equal(
      sig64_1,
      'o2FoWCDy_PBrUtbrh328ZTWvrZnuiE2EMKHfMz_1M6f3JN1nq2FwWCwwKjAFBgMrZXADIQATmPYsbRpFfFG6aktfPb0vafypMhYhjciZfkFr0X2TymFzWEAzEYt2uq3q2BiMmgz91CLI6Sj0Vs90pE-bTd37h35FpBOonchIBqXyjtBpnfguDbZkKzy_VWbs9bDx29_5lqwD'
    )

    delete sig.h
    assert.equal(
      bytesToBase64Url(deterministicEncode(sig)),
      'omFwWCwwKjAFBgMrZXADIQATmPYsbRpFfFG6aktfPb0vafypMhYhjciZfkFr0X2TymFzWEAzEYt2uq3q2BiMmgz91CLI6Sj0Vs90pE-bTd37h35FpBOonchIBqXyjtBpnfguDbZkKzy_VWbs9bDx29_5lqwD'
    )
  })

  it('toDelegationIdentity returns existing delegation identities unchanged', () => {
    const id = Ed25519KeyIdentity.fromSecretKey(new Uint8Array(32).fill(8))
    const delegated = toDelegationIdentity(id)

    assert.strictEqual(toDelegationIdentity(delegated), delegated)
  })

  it('signArbitrary includes non-empty delegation chains', async () => {
    const root = Ed25519KeyIdentity.fromSecretKey(new Uint8Array(32).fill(8))
    const session = Ed25519KeyIdentity.fromSecretKey(new Uint8Array(32).fill(9))
    const chain = await DelegationChain.create(
      root,
      session.getPublicKey(),
      new Date(Date.now() + 60_000)
    )
    const delegated = toDelegationIdentity(
      DelegationIdentity.fromDelegation(session, chain)
    )
    const digest = new Uint8Array([1, 2, 3])
    const signed = await signArbitrary(delegated, digest)

    assert.deepEqual(signed.h, digest)
    assert.equal(signed.d?.length, 1)
    assert.deepEqual(signed.d?.[0]?.d.p, session.getPublicKey().toDer())
  })
})

describe('base64', () => {
  it('encodes url-safe strings without padding', () => {
    const data = new TextEncoder().encode('hello world')
    const encoded = bytesToBase64Url(data)
    assert.equal(encoded, 'aGVsbG8gd29ybGQ')
    assert.deepEqual(base64ToBytes(encoded), data)

    const tricky = new Uint8Array([0xfb, 0xef, 0xff])
    assert.equal(bytesToBase64Url(tricky), '--__')
  })

  it('round-trips deterministic fuzz inputs', () => {
    for (let seed = 0; seed < 1000; seed++) {
      const length = (seed * 73) % 1025
      const sample = pseudoRandomBytes(length, seed + 1)
      const encoded = bytesToBase64Url(sample)
      const decoded = base64ToBytes(encoded)
      assert.deepEqual(decoded, sample)
      assert.match(encoded, /^[A-Za-z0-9_-]*$/)
    }
  })

  it('uses native Uint8Array base64 helpers when present', () => {
    const originalToBase64 = (Uint8Array.prototype as any).toBase64
    const originalFromBase64 = (Uint8Array as any).fromBase64
    const fromBase64Calls: any[] = []

    Object.defineProperty(Uint8Array.prototype, 'toBase64', {
      configurable: true,
      value(this: Uint8Array) {
        assert.deepEqual(this, new Uint8Array([1, 2, 3]))
        return 'native-base64'
      }
    })
    Object.defineProperty(Uint8Array, 'fromBase64', {
      configurable: true,
      value(value: string, options?: any) {
        fromBase64Calls.push({ value, options })
        return new Uint8Array([9, 8, 7])
      }
    })

    try {
      assert.equal(toBase64(new Uint8Array([1, 2, 3])), 'native-base64')
      assert.deepEqual(fromBase64('--__'), new Uint8Array([9, 8, 7]))
      assert.deepEqual(fromBase64('AQID'), new Uint8Array([9, 8, 7]))
      assert.deepEqual(fromBase64Calls, [
        { value: '--__', options: { alphabet: 'base64url' } },
        { value: 'AQID', options: undefined }
      ])
    } finally {
      if (originalToBase64) {
        Object.defineProperty(Uint8Array.prototype, 'toBase64', {
          configurable: true,
          value: originalToBase64
        })
      } else {
        delete (Uint8Array.prototype as any).toBase64
      }

      if (originalFromBase64) {
        Object.defineProperty(Uint8Array, 'fromBase64', {
          configurable: true,
          value: originalFromBase64
        })
      } else {
        delete (Uint8Array as any).fromBase64
      }
    }
  })

  it('uses Buffer fallback when native helpers are absent', () => {
    const originalToBase64 = (Uint8Array.prototype as any).toBase64
    const originalFromBase64 = (Uint8Array as any).fromBase64

    delete (Uint8Array.prototype as any).toBase64
    delete (Uint8Array as any).fromBase64

    try {
      const data = new Uint8Array([1, 2, 3, 4])
      const encoded = toBase64(data)

      assert.equal(encoded, Buffer.from(data).toString('base64'))
      assert.deepEqual(fromBase64(encoded), data)
    } finally {
      if (originalToBase64) {
        Object.defineProperty(Uint8Array.prototype, 'toBase64', {
          configurable: true,
          value: originalToBase64
        })
      }
      if (originalFromBase64) {
        Object.defineProperty(Uint8Array, 'fromBase64', {
          configurable: true,
          value: originalFromBase64
        })
      }
    }
  })

  it('falls back to btoa and atob without Buffer', () => {
    const originalBuffer = (globalThis as any).Buffer
    const originalBtoa = globalThis.btoa
    const originalAtob = globalThis.atob
    const originalToBase64 = (Uint8Array.prototype as any).toBase64
    const originalFromBase64 = (Uint8Array as any).fromBase64

    delete (Uint8Array.prototype as any).toBase64
    delete (Uint8Array as any).fromBase64
    ;(globalThis as any).Buffer = undefined
    ;(globalThis as any).btoa = (binary: string) =>
      originalBuffer.from(binary, 'binary').toString('base64')
    ;(globalThis as any).atob = (base64: string) =>
      originalBuffer.from(base64, 'base64').toString('binary')

    try {
      const data = pseudoRandomBytes(40000, 42)
      const encoded = toBase64(data)
      assert.deepEqual(fromBase64(encoded), data)
    } finally {
      ;(globalThis as any).Buffer = originalBuffer
      ;(globalThis as any).btoa = originalBtoa
      ;(globalThis as any).atob = originalAtob

      if (originalToBase64) {
        Object.defineProperty(Uint8Array.prototype, 'toBase64', {
          configurable: true,
          value: originalToBase64
        })
      }
      if (originalFromBase64) {
        Object.defineProperty(Uint8Array, 'fromBase64', {
          configurable: true,
          value: originalFromBase64
        })
      }
    }
  })
})

describe('digestMessage', () => {
  it('hashes deterministic CBOR', () => {
    const value = new Map<any, any>()
    value.set('z', 'z')
    value.set('aa', 'aa')

    assert.deepEqual(digestMessage(value), digestMessage(value))
    assert.deepEqual(digestMessage(value), digestMessage(value))
    assert.equal(digestMessage(value).length, 32)
  })
})
