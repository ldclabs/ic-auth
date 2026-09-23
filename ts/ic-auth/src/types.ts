import { Principal } from '@icp-sdk/core/principal'

/**
 * The kinds of requests a {@link Delegation} permits.
 *
 * - `queries`: Only query calls and `read_state` requests are permitted.
 * - `all`: All request types are permitted.
 */
export type DelegationPermissions = 'queries' | 'all'

/**
 * Full-name delegation record.
 *
 * A delegation authorizes `pubkey` to act for the previous identity in a chain
 * until `expiration`, optionally restricted to `targets`.
 */
export interface Delegation {
  /** Delegated-to DER public key. */
  pubkey: Uint8Array
  /** Expiration timestamp in nanoseconds since the Unix epoch. */
  expiration: bigint
  /** Optional canister targets for this delegation. */
  targets?: Principal[]
  /** Optional kinds of requests this delegation permits. */
  permissions?: DelegationPermissions
}

/**
 * Converts either full or compact delegation data into full-name form.
 */
export function toDelegation(obj: Delegation | DelegationCompact): Delegation {
  if ('pubkey' in obj && 'expiration' in obj) {
    return obj
  }

  const val: Delegation = {
    pubkey: obj.p,
    expiration: BigInt(obj.e)
  }
  if (obj.t) {
    val.targets = obj.t.map((target) => Principal.fromUint8Array(target))
  }
  if (obj.perm) {
    val.permissions = obj.perm
  }

  return val
}

/**
 * Compact delegation form used by IC-Auth CBOR/JSON payloads.
 */
export interface DelegationCompact {
  p: Uint8Array // pubkey
  e: bigint | number // expiration; CBOR decodes safe integers as numbers
  t?: Uint8Array[] // targets, encoded as CBOR byte strings
  perm?: DelegationPermissions // permissions
}

/**
 * Converts either full or compact delegation data into compact form.
 */
export function toDelegationCompact(
  obj: Delegation | DelegationCompact
): DelegationCompact {
  if ('p' in obj && 'e' in obj) {
    return obj
  }

  const val: DelegationCompact = {
    p: obj.pubkey,
    e: obj.expiration
  }
  if (obj.targets) {
    val.t = obj.targets.map((target) => target.toUint8Array())
  }
  if (obj.permissions) {
    val.perm = obj.permissions
  }

  return val
}

/**
 * Full-name signed delegation record.
 */
export interface SignedDelegation {
  /** Delegation payload that was signed. */
  delegation: Delegation
  /** Signature over the delegation message. */
  signature: Uint8Array
}

/**
 * Converts either full or compact signed delegation data into full-name form.
 */
export function toSignedDelegation(
  obj: SignedDelegation | SignedDelegationCompact
): SignedDelegation {
  if ('delegation' in obj && 'signature' in obj) {
    return obj
  }

  return {
    delegation: toDelegation(obj.d),
    signature: obj.s
  }
}

/**
 * Compact signed delegation form used by IC-Auth CBOR/JSON payloads.
 */
export interface SignedDelegationCompact {
  d: DelegationCompact // delegation
  s: Uint8Array // signature
}

/**
 * Converts either full or compact signed delegation data into compact form.
 */
export function toSignedDelegationCompact(
  obj: SignedDelegation | SignedDelegationCompact
): SignedDelegationCompact {
  if ('d' in obj && 's' in obj) {
    return obj
  }

  return {
    d: toDelegationCompact(obj.delegation),
    s: obj.signature
  }
}

/**
 * Full-name deep-link sign-in request payload.
 */
export interface DeepLinkSignInRequest {
  /** Session public key that should receive the returned delegation. */
  session_pubkey: Uint8Array
  /** Maximum session lifetime in milliseconds. */
  max_time_to_live: bigint
}

/**
 * Converts either full or compact sign-in request data into full-name form.
 */
export function toDeepLinkSignInRequest(
  obj: DeepLinkSignInRequest | DeepLinkSignInRequestCompact
): DeepLinkSignInRequest {
  if ('session_pubkey' in obj && 'max_time_to_live' in obj) {
    return obj
  }

  return {
    session_pubkey: obj.s,
    max_time_to_live: BigInt(obj.m)
  }
}

/**
 * Compact deep-link sign-in request payload.
 */
export interface DeepLinkSignInRequestCompact {
  s: Uint8Array // session_pubkey
  m: bigint | number // max_time_to_live; CBOR decodes safe integers as numbers
}

/**
 * Converts either full or compact sign-in request data into compact form.
 */
export function toDeepLinkSignInRequestCompact(
  obj: DeepLinkSignInRequest | DeepLinkSignInRequestCompact
): DeepLinkSignInRequestCompact {
  if ('s' in obj && 'm' in obj) {
    return obj
  }

  return {
    s: obj.session_pubkey,
    m: obj.max_time_to_live
  }
}

/**
 * Full-name deep-link sign-in response payload.
 */
export interface DeepLinkSignInResponse {
  /** User public key at the head of the delegation chain. */
  user_pubkey: Uint8Array
  /** Delegations that authorize the requested session key. */
  delegations: SignedDelegation[]
  /** Authentication method reported by the signer, such as `passkey`. */
  authn_method: string
  /** Origin associated with the authentication request. */
  origin: string
}

/**
 * Converts either full or compact sign-in response data into full-name form.
 */
export function toDeepLinkSignInResponse(
  obj: DeepLinkSignInResponse | DeepLinkSignInResponseCompact
): DeepLinkSignInResponse {
  if ('user_pubkey' in obj && 'delegations' in obj) {
    return obj
  }

  return {
    user_pubkey: obj.u,
    delegations: obj.d.map(toSignedDelegation),
    authn_method: obj.a,
    origin: obj.o
  }
}

/**
 * Compact deep-link sign-in response payload.
 */
export interface DeepLinkSignInResponseCompact {
  u: Uint8Array // user_pubkey
  d: SignedDelegationCompact[] // delegations
  a: string // authn_method
  o: string // origin
}

/**
 * Converts either full or compact sign-in response data into compact form.
 */
export function toDeepLinkSignInResponseCompact(
  obj: DeepLinkSignInResponse | DeepLinkSignInResponseCompact
): DeepLinkSignInResponseCompact {
  if ('u' in obj && 'd' in obj) {
    return obj
  }

  return {
    u: obj.user_pubkey,
    d: obj.delegations.map(toSignedDelegationCompact),
    a: obj.authn_method,
    o: obj.origin
  }
}

/**
 * Full-name signed envelope.
 *
 * This is the TypeScript counterpart of Rust `SignedEnvelopeFull`. Compact
 * payloads use `SignedEnvelopeCompact`.
 */
export interface SignedEnvelope {
  /** DER public key for the identity at the head of the envelope. */
  pubkey: Uint8Array
  /** Signature over `digest` or over the externally supplied digest. */
  signature: Uint8Array
  /** Optional signed digest. */
  digest?: Uint8Array
  /** Optional full-name delegation chain. */
  delegation?: SignedDelegation[]
}

/** Legacy full-name envelope using `public_key` instead of `pubkey`. */
export interface LegacySignedEnvelope {
  public_key: Uint8Array
  signature: Uint8Array
  digest?: Uint8Array
  delegation?: Array<SignedDelegation | SignedDelegationCompact>
}

/**
 * Converts compact, full-name, or legacy `public_key` envelope data into
 * full-name form.
 */
export function toSignedEnvelope(
  obj: SignedEnvelope | SignedEnvelopeCompact | LegacySignedEnvelope
): SignedEnvelope {
  if ('pubkey' in obj && 'signature' in obj) {
    return obj
  }

  if ('public_key' in obj && 'signature' in obj) {
    const val: SignedEnvelope = {
      pubkey: obj.public_key,
      signature: obj.signature
    }
    if (obj.digest) {
      val.digest = obj.digest
    }
    if (obj.delegation) {
      val.delegation = obj.delegation.map(toSignedDelegation)
    }
    return val
  }

  const val: SignedEnvelope = {
    pubkey: obj.p,
    signature: obj.s
  }
  if (obj.h) {
    val.digest = obj.h
  }
  if (obj.d) {
    val.delegation = obj.d.map(toSignedDelegation)
  }
  return val
}

/**
 * Compact signed envelope form used by deterministic CBOR signing.
 */
export interface SignedEnvelopeCompact {
  p: Uint8Array // pubkey | public_key
  s: Uint8Array // signature
  h?: Uint8Array // digest
  d?: SignedDelegationCompact[] // delegation
}

/**
 * Converts full-name or compact envelope data into compact form.
 */
export function toSignedEnvelopeCompact(
  obj: SignedEnvelope | SignedEnvelopeCompact | LegacySignedEnvelope
): SignedEnvelopeCompact {
  if ('p' in obj && 's' in obj) {
    return obj
  }

  const val: SignedEnvelopeCompact = {
    p: 'pubkey' in obj ? obj.pubkey : obj.public_key,
    s: obj.signature
  }
  if (obj.digest) {
    val.h = obj.digest
  }
  if (obj.delegation) {
    val.d = obj.delegation.map(toSignedDelegationCompact)
  }

  return val
}
