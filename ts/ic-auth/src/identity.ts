import { SignIdentity } from '@dfinity/agent'
import { DelegationChain, DelegationIdentity } from '@dfinity/identity'
import { sha3_256 } from '@noble/hashes/sha3'
import { deterministicEncode } from './cbor.js'
import { SignedEnvelopeCompact, toSignedDelegationCompact } from './types.js'

export { sha3_256 } from '@noble/hashes/sha3'

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
  const val: SignedEnvelopeCompact = {
    p: identity.getPublicKey().toDer(),
    s: new Uint8Array(sig),
    h: data
  }
  if (delegations.length > 0) {
    val.d = delegations
  }

  return val
}

export function digestMessage(obj: any): Uint8Array {
  const data = deterministicEncode(obj)
  return sha3_256(data)
}

export async function signMessage(
  identity: DelegationIdentity,
  obj: any
): Promise<SignedEnvelopeCompact> {
  return signArbitrary(identity, digestMessage(obj))
}

export function toBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64')
  }
  let result = ''
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    result += String.fromCharCode(...bytes.subarray(i, i + chunk))
  }
  return btoa(result)
}

export function fromBase64(str: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(str, 'base64'))
  }
  const binary = atob(str)
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes)
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '')
}

export function base64ToBytes(str: string): Uint8Array {
  const padded = str.replaceAll('-', '+').replaceAll('_', '/')
  return fromBase64(padded)
}
