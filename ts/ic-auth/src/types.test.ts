import { Principal } from '@icp-sdk/core/principal'
import { assert, describe, it } from 'vitest'
import {
  DeepLinkSignInRequest,
  DeepLinkSignInResponse,
  Delegation,
  SignedDelegation,
  SignedEnvelope,
  toDeepLinkSignInRequest,
  toDeepLinkSignInRequestCompact,
  toDeepLinkSignInResponse,
  toDeepLinkSignInResponseCompact,
  toDelegation,
  toDelegationCompact,
  toSignedDelegation,
  toSignedDelegationCompact,
  toSignedEnvelope,
  toSignedEnvelopeCompact
} from './types.js'

const pubkey = new Uint8Array([1, 2, 3])
const signature = new Uint8Array([4, 5, 6])
const digest = new Uint8Array([7, 8, 9])
const target = Principal.managementCanister()

describe('types', () => {
  it('converts delegation forms', () => {
    const full: Delegation = {
      pubkey,
      expiration: 123n,
      targets: [target]
    }
    const compact = toDelegationCompact(full)

    assert.deepEqual(compact, { p: pubkey, e: 123n, t: [target] })
    assert.strictEqual(toDelegationCompact(compact), compact)
    assert.deepEqual(toDelegation(compact), full)
    assert.strictEqual(toDelegation(full), full)

    const withoutTargets = toDelegationCompact({
      pubkey,
      expiration: 456n
    })
    assert.deepEqual(withoutTargets, { p: pubkey, e: 456n })
  })

  it('converts signed delegation forms', () => {
    const full: SignedDelegation = {
      delegation: {
        pubkey,
        expiration: 123n
      },
      signature
    }
    const compact = toSignedDelegationCompact(full)

    assert.deepEqual(compact, {
      d: { p: pubkey, e: 123n },
      s: signature
    })
    assert.strictEqual(toSignedDelegationCompact(compact), compact)
    assert.deepEqual(toSignedDelegation(compact), full)
    assert.strictEqual(toSignedDelegation(full), full)
  })

  it('converts deep-link sign-in request forms', () => {
    const full: DeepLinkSignInRequest = {
      session_pubkey: pubkey,
      max_time_to_live: 60n
    }
    const compact = toDeepLinkSignInRequestCompact(full)

    assert.deepEqual(compact, { s: pubkey, m: 60n })
    assert.strictEqual(toDeepLinkSignInRequestCompact(compact), compact)
    assert.deepEqual(toDeepLinkSignInRequest(compact), full)
    assert.strictEqual(toDeepLinkSignInRequest(full), full)
  })

  it('converts deep-link sign-in response forms', () => {
    const delegation: SignedDelegation = {
      delegation: {
        pubkey,
        expiration: 123n
      },
      signature
    }
    const full: DeepLinkSignInResponse = {
      user_pubkey: pubkey,
      delegations: [delegation],
      authn_method: 'passkey',
      origin: 'https://example.com'
    }
    const compact = toDeepLinkSignInResponseCompact(full)

    assert.deepEqual(compact, {
      u: pubkey,
      d: [delegation],
      a: 'passkey',
      o: 'https://example.com'
    })
    assert.strictEqual(toDeepLinkSignInResponseCompact(compact), compact)
    assert.deepEqual(toDeepLinkSignInResponse(compact), full)
    assert.strictEqual(toDeepLinkSignInResponse(full), full)
  })

  it('converts signed envelope forms', () => {
    const delegation: SignedDelegation = {
      delegation: {
        pubkey,
        expiration: 123n
      },
      signature
    }
    const full: SignedEnvelope = {
      pubkey,
      signature,
      digest,
      delegation: [delegation]
    }
    const compact = toSignedEnvelopeCompact(full)

    assert.deepEqual(compact, {
      p: pubkey,
      s: signature,
      h: digest,
      d: [{ d: { p: pubkey, e: 123n }, s: signature }]
    })
    assert.strictEqual(toSignedEnvelopeCompact(compact), compact)
    assert.deepEqual(toSignedEnvelope(compact), full)
    assert.strictEqual(toSignedEnvelope(full), full)

    assert.deepEqual(
      toSignedEnvelope({
        public_key: pubkey,
        signature,
        digest,
        delegation: [delegation]
      } as any),
      full
    )

    assert.deepEqual(toSignedEnvelopeCompact({ pubkey, signature }), {
      p: pubkey,
      s: signature
    })

    assert.deepEqual(
      toSignedEnvelopeCompact({ public_key: pubkey, signature } as any),
      {
        p: pubkey,
        s: signature
      }
    )
  })
})
