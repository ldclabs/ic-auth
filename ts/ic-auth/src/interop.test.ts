import { readFileSync } from 'node:fs'
import { DelegationChain, DelegationIdentity } from '@icp-sdk/core/identity'
import { Principal } from '@icp-sdk/core/principal'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { assert, describe, it } from 'vitest'
import { decode, deterministicEncode } from './cbor.js'
import { digestMessage, Ed25519KeyIdentity, signMessage } from './identity.js'
import {
  toDeepLinkSignInResponse,
  toDeepLinkSignInResponseCompact
} from './types.js'

function fixture(name: string): string {
  return readFileSync(
    new URL(
      `../../../rs/ic_auth_verifier/tests/fixtures/${name}.hex`,
      import.meta.url
    ),
    'utf8'
  ).trim()
}

describe('Rust interoperability', () => {
  it('matches fixed CBOR bytes and SHA3 digest regardless of insertion order', () => {
    const forward = { amount: 1.5, challenge: 'login' }
    const reversed = { challenge: 'login', amount: 1.5 }
    for (const message of [forward, reversed]) {
      assert.equal(bytesToHex(deterministicEncode(message)), fixture('message'))
      assert.equal(
        bytesToHex(digestMessage(message)),
        fixture('message-digest')
      )
    }
    assert.equal(bytesToHex(deterministicEncode(1.5)), 'f93e00')
    assert.equal(
      bytesToHex(deterministicEncode({ nested: [7, 1.5] })),
      'a1666e65737465648207f93e00'
    )
  })

  it('produces a targeted delegation envelope verified by Rust', async () => {
    const root = Ed25519KeyIdentity.fromSecretKey(new Uint8Array(32).fill(8))
    const session = Ed25519KeyIdentity.fromSecretKey(new Uint8Array(32).fill(9))
    const chain = await DelegationChain.create(
      root,
      session.getPublicKey(),
      new Date('2030-01-01T00:00:00Z'),
      { targets: [Principal.anonymous()] }
    )
    const envelope = await signMessage(
      DelegationIdentity.fromDelegation(session, chain),
      { amount: 1.5, challenge: 'login' }
    )
    assert.equal(
      bytesToHex(deterministicEncode(envelope)),
      fixture('delegated-envelope')
    )
  })

  it('expands a Rust sign-in response and reproduces its compact CBOR', () => {
    const bytes = hexToBytes(fixture('sign-in-response'))
    const full = toDeepLinkSignInResponse(decode(bytes))
    assert.deepEqual(full.user_pubkey, new Uint8Array([1, 2, 3]))
    assert.deepEqual(
      full.delegations[0]?.delegation.pubkey,
      new Uint8Array([4, 5, 6])
    )
    assert.deepEqual(full.delegations[0]?.signature, new Uint8Array([7, 8, 9]))
    assert.equal(full.delegations[0]?.delegation.expiration, 123n)
    assert.equal(
      full.delegations[0]?.delegation.targets?.[0]?.toText(),
      '2vxsx-fae'
    )
    assert.equal(full.delegations[0]?.delegation.permissions, 'queries')
    assert.equal(full.authn_method, 'passkey')
    assert.equal(full.origin, 'https://example.com')
    assert.deepEqual(
      deterministicEncode(toDeepLinkSignInResponseCompact(full)),
      bytes
    )
  })
})
