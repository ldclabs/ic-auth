import { DelegationChain, DelegationIdentity } from '@icp-sdk/core/identity'
import { afterEach, assert, describe, it, vi } from 'vitest'
import { deterministicEncode } from './cbor.js'
import {
  base64ToBytes,
  bytesToBase64Url,
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

  const toBase64Descriptor = Object.getOwnPropertyDescriptor(
    Uint8Array.prototype,
    'toBase64'
  )
  const fromBase64Descriptor = Object.getOwnPropertyDescriptor(
    Uint8Array,
    'fromBase64'
  )

  afterEach(() => {
    vi.unstubAllGlobals()
    for (const [target, key, descriptor] of [
      [Uint8Array.prototype, 'toBase64', toBase64Descriptor],
      [Uint8Array, 'fromBase64', fromBase64Descriptor]
    ] as const) {
      if (descriptor) Object.defineProperty(target, key, descriptor)
      else Reflect.deleteProperty(target, key)
    }
  })

  function disableNativeBase64() {
    Object.defineProperty(Uint8Array.prototype, 'toBase64', {
      configurable: true,
      value: undefined
    })
    Object.defineProperty(Uint8Array, 'fromBase64', {
      configurable: true,
      value: undefined
    })
  }

  it('uses native standard and URL-safe encoding options directly', () => {
    const encode = vi.fn(() => 'native-encoded')
    const decode = vi.fn(() => new Uint8Array([9, 8, 7]))
    Object.defineProperty(Uint8Array.prototype, 'toBase64', {
      configurable: true,
      value: encode
    })
    Object.defineProperty(Uint8Array, 'fromBase64', {
      configurable: true,
      value: decode
    })

    const bytes = new Uint8Array([1, 2, 3])
    assert.equal(toBase64(bytes), 'native-encoded')
    assert.equal(bytesToBase64Url(bytes), 'native-encoded')
    assert.deepEqual(encode.mock.calls, [
      [],
      [{ alphabet: 'base64url', omitPadding: true }]
    ])
    assert.deepEqual(fromBase64('--__'), new Uint8Array([9, 8, 7]))
    fromBase64('AQID')
    base64ToBytes('--__')
    fromBase64('b64:--__')
    assert.deepEqual(decode.mock.calls, [
      ['--__', { alphabet: 'base64url' }],
      ['AQID'],
      ['--__', { alphabet: 'base64url' }],
      ['--__', { alphabet: 'base64url' }]
    ])
  })

  it.each(['Buffer', 'browser'] as const)(
    'round-trips offset views with the %s fallback',
    (runtime) => {
      disableNativeBase64()
      if (runtime === 'browser') vi.stubGlobal('Buffer', undefined)
      // Exclude sentinel bytes to exercise byteOffset and byteLength.
      const view = new Uint8Array([0, 0xfb, 0xef, 0xff, 0]).subarray(1, 4)
      assert.equal(toBase64(view), '++//')
      assert.equal(bytesToBase64Url(view), '--__')
      for (const encoded of ['++//', '--__']) {
        assert.deepEqual(fromBase64(encoded), view)
        assert.deepEqual(base64ToBytes(encoded), view)
      }
      for (const bytes of [
        new Uint8Array(),
        new Uint8Array([251]),
        new Uint8Array([251, 255]),
        pseudoRandomBytes(40000, 42)
      ]) {
        assert.deepEqual(fromBase64(toBase64(bytes)), bytes)
        assert.deepEqual(base64ToBytes(bytesToBase64Url(bytes)), bytes)
      }
    }
  )

  // Node releases before 25 have no native decoder. The fallback there must
  // not be `Buffer`, which skips invalid characters: it decoded `b64:AQID` to
  // [111, 174, 0, 64, 128] and `AQ!D` to [1, 0] instead of failing.
  it.each(['default', 'fallback'] as const)(
    'rejects malformed input and accepts the Rust b64: prefix (%s decoder)',
    (decoder) => {
      if (decoder === 'fallback') disableNativeBase64()
      assert.deepEqual(fromBase64('b64:AQID'), new Uint8Array([1, 2, 3]))
      assert.deepEqual(base64ToBytes('b64:-_8'), new Uint8Array([251, 255]))
      assert.deepEqual(fromBase64('b64:'), new Uint8Array())
      for (const malformed of ['AQ!D', 'AQID====', 'b64:AQ!D', 'b64b64:AQID']) {
        assert.throws(
          () => fromBase64(malformed),
          undefined,
          undefined,
          malformed
        )
      }
    }
  )

  it('uses real browser atob semantics instead of a Buffer decoder', () => {
    disableNativeBase64()
    vi.stubGlobal('Buffer', undefined)
    assert.throws(() => fromBase64('!'), /Invalid character/)
    assert.deepEqual(fromBase64('-_8'), new Uint8Array([251, 255]))
  })
})
