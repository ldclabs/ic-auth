import { Principal } from '@dfinity/principal'

export interface Delegation {
  pubkey: Uint8Array
  expiration: bigint
  targets?: Principal[]
}

export function toDelegation(obj: Delegation | DelegationCompact): Delegation {
  if ('pubkey' in obj && 'expiration' in obj) {
    return obj
  }

  const val: Delegation = {
    pubkey: obj.p,
    expiration: obj.e
  }
  if (obj.t) {
    val.targets = obj.t
  }

  return val
}

export interface DelegationCompact {
  p: Uint8Array // pubkey
  e: bigint // expiration
  t?: Principal[] // targets
}

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
    val.t = obj.targets
  }

  return val
}

export interface SignedDelegation {
  delegation: Delegation
  signature: Uint8Array
}

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

export interface SignedDelegationCompact {
  d: DelegationCompact // delegation
  s: Uint8Array // signature
}

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

export interface DeepLinkSignInRequest {
  session_pubkey: Uint8Array
  max_time_to_live: bigint
}

export function toDeepLinkSignInRequest(
  obj: DeepLinkSignInRequest | DeepLinkSignInRequestCompact
): DeepLinkSignInRequest {
  if ('session_pubkey' in obj && 'max_time_to_live' in obj) {
    return obj
  }

  return {
    session_pubkey: obj.s,
    max_time_to_live: obj.m
  }
}

export interface DeepLinkSignInRequestCompact {
  s: Uint8Array // session_pubkey
  m: bigint // max_time_to_live
}

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

export interface DeepLinkSignInResponse {
  user_pubkey: Uint8Array
  delegations: SignedDelegation[]
  authn_method: string
  origin: string
}

export function toDeepLinkSignInResponse(
  obj: DeepLinkSignInResponse | DeepLinkSignInResponseCompact
): DeepLinkSignInResponse {
  if ('user_pubkey' in obj && 'delegations' in obj) {
    return obj
  }

  return {
    user_pubkey: obj.u,
    delegations: obj.d,
    authn_method: obj.a,
    origin: obj.o
  }
}

export interface DeepLinkSignInResponseCompact {
  u: Uint8Array // user_pubkey
  d: SignedDelegation[] // delegations
  a: string // authn_method
  o: string // origin
}

export function toDeepLinkSignInResponseCompact(
  obj: DeepLinkSignInResponse | DeepLinkSignInResponseCompact
): DeepLinkSignInResponseCompact {
  if ('u' in obj && 'd' in obj) {
    return obj
  }

  return {
    u: obj.user_pubkey,
    d: obj.delegations,
    a: obj.authn_method,
    o: obj.origin
  }
}

export interface SignedEnvelope {
  pubkey: Uint8Array
  signature: Uint8Array
  digest?: Uint8Array
  delegation?: SignedDelegation[]
}

export function toSignedEnvelope(
  obj: SignedEnvelope | SignedEnvelopeCompact
): SignedEnvelope {
  if ('pubkey' in obj && 'signature' in obj) {
    return obj
  }

  if (
    'public_key' in obj &&
    'signature' in obj &&
    'digest' in obj &&
    'delegation' in obj
  ) {
    return {
      pubkey: obj.public_key as Uint8Array,
      signature: obj.signature as Uint8Array,
      digest: obj.digest as Uint8Array,
      delegation: obj.delegation as SignedDelegation[]
    }
  }

  return {
    pubkey: obj.p,
    signature: obj.s,
    digest: obj.h,
    delegation: obj.d?.map(toSignedDelegation)
  }
}

export interface SignedEnvelopeCompact {
  p: Uint8Array // pubkey | public_key
  s: Uint8Array // signature
  h?: Uint8Array // digest
  d?: SignedDelegationCompact[] // delegation
}

export function toSignedEnvelopeCompact(
  obj: SignedEnvelope | SignedEnvelopeCompact
): SignedEnvelopeCompact {
  if ('p' in obj && 's' in obj) {
    return obj
  }

  const val: SignedEnvelopeCompact = {
    p: obj.pubkey || (obj as any).public_key,
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
