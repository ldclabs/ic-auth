import { SignIdentity } from '@dfinity/agent'
import { DelegationChain, DelegationIdentity } from '@dfinity/identity'
import { sha3_256 } from '@noble/hashes/sha3'
import { deterministicEncode } from './cbor.js'
import { SignedEnvelopeCompact, toSignedDelegationCompact } from './types.js'

export {
  DelegationIdentity,
  Ed25519KeyIdentity,
  Ed25519PublicKey
} from '@dfinity/identity'

export function toDelegationIdentity(
  identity: SignIdentity
): DelegationIdentity {
  return identity instanceof DelegationIdentity
    ? identity
    : DelegationIdentity.fromDelegation(
        identity,
        DelegationChain.fromDelegations([], identity.getPublicKey().toDer())
      )
}

export async function signArbitrary(
  identity: DelegationIdentity,
  data: Uint8Array
): Promise<SignedEnvelopeCompact> {
  const sig = await identity.sign(data)
  const delegations = identity
    .getDelegation()
    .delegations.map(toSignedDelegationCompact)
  return {
    p: identity.getPublicKey().toDer(),
    s: new Uint8Array(sig),
    d: delegations.length > 0 ? delegations : undefined,
    h: data
  }
}

export async function signCborMessage(
  identity: DelegationIdentity,
  obj: any
): Promise<SignedEnvelopeCompact> {
  const data = deterministicEncode(obj)
  const digest = sha3_256(data)
  return signArbitrary(identity, digest)
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return btoa(String.fromCodePoint(...bytes))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '')
}

export function base64ToBytes(str: string): Uint8Array {
  return Uint8Array.from(
    atob(str.replaceAll('-', '+').replaceAll('_', '/')),
    (m) => m.codePointAt(0)!
  )
}
