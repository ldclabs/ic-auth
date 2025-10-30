import { assert, describe, it } from 'vitest'
import { deterministicEncode } from './cbor.js'
import {
  bytesToBase64Url,
  Ed25519KeyIdentity,
  signMessage,
  toDelegationIdentity
} from './identity.js'

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
      'pGFk92FoWCDy_PBrUtbrh328ZTWvrZnuiE2EMKHfMz_1M6f3JN1nq2FwWCwwKjAFBgMrZXADIQATmPYsbRpFfFG6aktfPb0vafypMhYhjciZfkFr0X2TymFzWEAzEYt2uq3q2BiMmgz91CLI6Sj0Vs90pE-bTd37h35FpBOonchIBqXyjtBpnfguDbZkKzy_VWbs9bDx29_5lqwD'
    )

    delete sig.h
    console.log('short', bytesToBase64Url(deterministicEncode(sig)))
    // 'o2Fk92FwWCwwKjAFBgMrZXADIQATmPYsbRpFfFG6aktfPb0vafypMhYhjciZfkFr0X2TymFzWEAzEYt2uq3q2BiMmgz91CLI6Sj0Vs90pE-bTd37h35FpBOonchIBqXyjtBpnfguDbZkKzy_VWbs9bDx29_5lqwD'
  })
})
