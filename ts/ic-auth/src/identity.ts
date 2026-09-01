import { SignIdentity } from '@icp-sdk/core/agent'
import { DelegationChain, DelegationIdentity } from '@icp-sdk/core/identity'
import { sha3_256 } from '@noble/hashes/sha3.js'
import { deterministicEncode } from './cbor.js'
import { SignedEnvelopeCompact, toSignedDelegationCompact } from './types.js'

export { sha3_256 } from '@noble/hashes/sha3.js'

export {
  DelegationIdentity,
  Ed25519KeyIdentity,
  Ed25519PublicKey
} from '@icp-sdk/core/identity'

/**
 * Ensures a signing identity is represented as a `DelegationIdentity`.
 *
 * Plain signing identities are wrapped with an empty delegation chain so the
 * rest of the SDK can use the same envelope-building path for delegated and
 * non-delegated identities.
 */
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

/**
 * Signs an already-computed digest or arbitrary byte string.
 *
 * The returned envelope stores the signed bytes in `h` and includes compact
 * delegation records when the identity has a non-empty delegation chain.
 */
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

/**
 * Encodes an object as deterministic CBOR and returns its SHA3-256 digest.
 */
export function digestMessage(obj: any): Uint8Array {
  const data = deterministicEncode(obj)
  return sha3_256(data)
}

/**
 * Signs the SHA3-256 digest of an object's deterministic CBOR encoding.
 */
export async function signMessage(
  identity: DelegationIdentity,
  obj: any
): Promise<SignedEnvelopeCompact> {
  return signArbitrary(identity, digestMessage(obj))
}

/**
 * Encodes bytes as padded standard Base64.
 *
 * Uses native `Uint8Array` helpers when available, then falls back to Node
 * `Buffer`, then browser `btoa`.
 */
export function toBase64(bytes: Uint8Array): string {
  if (typeof (bytes as any).toBase64 === 'function') {
    return (bytes as any).toBase64()
  }
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64')
  }
  let result = ''
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    result += String.fromCharCode(...bytes.subarray(i, i + chunk))
  }
  return globalThis.btoa(result)
}

/**
 * Decodes standard Base64 or Base64URL into bytes.
 *
 * Uses native `Uint8Array` helpers when available, then falls back to Node
 * `Buffer`, then browser `atob`.
 */
export function fromBase64(str: string): Uint8Array {
  if (typeof (Uint8Array as any).fromBase64 === 'function') {
    if (str.includes('-') || str.includes('_')) {
      return (Uint8Array as any).fromBase64(str, { alphabet: 'base64url' })
    }
    return (Uint8Array as any).fromBase64(str)
  }
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(str, 'base64'))
  }
  const binary = globalThis.atob(str)
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

/**
 * Encodes bytes as unpadded Base64URL for IC-Auth headers and compact payloads.
 */
export function bytesToBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes)
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '')
}

/**
 * Decodes unpadded Base64URL into bytes.
 */
export function base64ToBytes(str: string): Uint8Array {
  const padded = str.replaceAll('-', '+').replaceAll('_', '/')
  return fromBase64(padded)
}
