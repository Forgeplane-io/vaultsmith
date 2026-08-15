import type { components } from './generated/api'

export type OperationMode = 'encrypt' | 'decrypt' | 'rotate'

export type AttestationBinding = components['schemas']['RotationBinding']
export type SignedAttestation = components['schemas']['RotationAttestation']
export type AttestationClaims = components['schemas']['RotationAttestationClaims']
export type VerificationReason = components['schemas']['AttestationVerificationReason']
export type VerificationResult = components['schemas']['VerifyAttestationResponse']

export type Profile = components['schemas']['Profile']

type EncryptRequest = components['schemas']['EncryptRequest']
type DecryptRequest = components['schemas']['DecryptRequest']
type RotateRequest = components['schemas']['RotateRequest']

export type Session = {
  authenticated: boolean
  authRequired: boolean
  email?: string
  csrfToken: string
  attestationEnabled?: boolean
}

export type SingleProfileOperationRequest = {
  profileId: string
  mode: 'encrypt' | 'decrypt'
  value: string
}

export type RotateOperationRequest = {
  mode: 'rotate'
  sourceProfileId: string
  destinationProfileId: string
  value: string
  attestation?: {
    binding?: AttestationBinding
  }
}

export type OperationRequest = SingleProfileOperationRequest | RotateOperationRequest

export type VerifyAttestationRequest = components['schemas']['VerifyAttestationRequest']

export type RotationResult = {
  vaultText: string
  attestation?: SignedAttestation
}

export const MAX_PLAINTEXT_BYTES = 1 << 20
export const MAX_VAULT_TEXT_BYTES = 5 << 20
export const OPERATION_TIMEOUT_MS = 40_000
const BOOTSTRAP_LOAD_TIMEOUT_MS = 10_000
const LOGOUT_TIMEOUT_MS = 10_000

export class ApiError extends Error {
  readonly code: string
  readonly status: number

  constructor(message: string, code = 'request_failed', status = 0) {
    super(message)
    this.name = 'ApiError'
    this.code = code
    this.status = status
  }
}

type ErrorEnvelope = {
  error?: {
    code?: unknown
    message?: unknown
  }
}

let csrfToken = ''

type JSONResponse = {
  payload: unknown
  status: number
}

async function requestJSONWithStatus(path: string, init?: RequestInit): Promise<JSONResponse> {
  const headers: Record<string, string> = { ...(init?.headers as Record<string, string> | undefined) }
  const method = (init?.method || 'GET').toUpperCase()
  if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS' && csrfToken && !Object.prototype.hasOwnProperty.call(headers, 'X-CSRF-Token')) {
    headers['X-CSRF-Token'] = csrfToken
  }
  let response: Response
  try {
    response = await fetch(path, { ...init, headers, credentials: 'same-origin' })
  } catch (reason) {
    if (reason instanceof Error && reason.name === 'AbortError') throw reason
    throw new ApiError('Unable to reach the Vaultsmith service', 'network_error')
  }

  let payload: unknown = null
  if (response.status !== 204) {
    try {
      payload = await response.json()
    } catch {
      payload = null
    }
  }
  if (!response.ok) {
    const envelope = isErrorEnvelope(payload) ? payload.error : undefined
    const code = typeof envelope?.code === 'string' ? envelope.code : 'request_failed'
    const message = typeof envelope?.message === 'string' ? envelope.message : 'Request failed'
    throw new ApiError(message, code, response.status)
  }
  return { payload, status: response.status }
}

async function requestJSON(path: string, init?: RequestInit): Promise<unknown> {
  return (await requestJSONWithStatus(path, init)).payload
}

type RequestTimeoutCode = 'session_timeout' | 'profiles_timeout' | 'logout_timeout'

function withRequestTimeout<T>(
  signal: AbortSignal | undefined,
  timeoutMs: number,
  timeoutCode: RequestTimeoutCode,
  timeoutMessage: string,
  request: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  if (signal?.aborted) return Promise.reject(new DOMException('The operation was aborted', 'AbortError'))

  const controller = new AbortController()
  let settled = false
  let timeoutId: ReturnType<typeof globalThis.setTimeout>

  return new Promise<T>((resolve, reject) => {
    const cleanup = () => {
      globalThis.clearTimeout(timeoutId)
      signal?.removeEventListener('abort', abortRequest)
    }
    const resolveOnce = (result: T) => {
      if (settled) return
      settled = true
      cleanup()
      resolve(result)
    }
    const rejectOnce = (reason: unknown) => {
      if (settled) return
      settled = true
      cleanup()
      reject(reason)
    }
    const abortRequest = () => {
      rejectOnce(new DOMException('The operation was aborted', 'AbortError'))
      controller.abort()
    }

    signal?.addEventListener('abort', abortRequest, { once: true })
    timeoutId = globalThis.setTimeout(() => {
      rejectOnce(new ApiError(timeoutMessage, timeoutCode))
      controller.abort()
    }, timeoutMs)

    try {
      request(controller.signal).then(resolveOnce, rejectOnce)
    } catch (reason) {
      rejectOnce(reason)
    }
  })
}

async function requestSession(signal: AbortSignal): Promise<Session> {
  const payload = await requestJSON('/api/v1/session', {
    method: 'GET',
    headers: { Accept: 'application/json' },
    signal,
  })
  if (!isSessionEnvelope(payload)) {
    throw new ApiError('The service returned an invalid session response', 'invalid_response')
  }
  return {
    ...payload,
    // Older servers did not expose this additive capability field.
    attestationEnabled: payload.attestationEnabled === true,
  }
}

export async function fetchSession(signal?: AbortSignal): Promise<Session> {
  const session = await withRequestTimeout(
    signal,
    BOOTSTRAP_LOAD_TIMEOUT_MS,
    'session_timeout',
    'Session loading timed out',
    requestSession,
  )
  csrfToken = session.csrfToken
  return session
}
export async function fetchProfiles(signal?: AbortSignal): Promise<Profile[]> {
  const payload = await withRequestTimeout(
    signal,
    BOOTSTRAP_LOAD_TIMEOUT_MS,
    'profiles_timeout',
    'Profile loading timed out',
    (requestSignal) => requestJSON('/api/v1/profiles', {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: requestSignal,
    }),
  )
  if (!isProfileEnvelope(payload)) {
    throw new ApiError('The service returned an invalid profile response', 'invalid_response')
  }
  return payload.profiles
}

export async function logout(signal?: AbortSignal): Promise<void> {
  await withRequestTimeout(
    signal,
    LOGOUT_TIMEOUT_MS,
    'logout_timeout',
    'Sign out timed out',
    async (requestSignal) => {
      const response = await requestJSONWithStatus('/auth/logout', {
        method: 'POST',
        headers: { Accept: 'application/json' },
        signal: requestSignal,
      })
      if (response.status === 204) {
        return
      }

      if (requestSignal.aborted) {
        throw new DOMException('The operation was aborted', 'AbortError')
      }
      const verifiedSession = await requestSession(requestSignal)
      if (verifiedSession.authenticated) {
        throw new ApiError('Sign out was not confirmed', 'logout_unconfirmed', response.status)
      }
    },
  )
  csrfToken = ''
}

export async function runOperation(request: OperationRequest, signal?: AbortSignal): Promise<string | RotationResult> {
  const operation = request.mode === 'rotate'
    ? {
      path: '/api/v1/rotations',
      body: {
        sourceProfileId: request.sourceProfileId,
        destinationProfileId: request.destinationProfileId,
        vaultText: request.value,
        ...(request.attestation ? { attestation: request.attestation } : {}),
      } satisfies RotateRequest,
      responseField: 'vaultText' as const,
    }
    : {
      path: `/api/v1/profiles/${encodeURIComponent(request.profileId)}/${request.mode}`,
      body: request.mode === 'encrypt'
        ? { plaintext: request.value } satisfies EncryptRequest
        : { vaultText: request.value } satisfies DecryptRequest,
      responseField: request.mode === 'encrypt' ? 'vaultText' as const : 'plaintext' as const,
    }
  const payload = await requestJSON(operation.path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(operation.body),
    signal,
  })
  if (!isOperationResponse(payload, operation.responseField)) {
    throw new ApiError('The service returned an invalid operation response', 'invalid_response')
  }
  if (request.mode !== 'rotate') return payload[operation.responseField]
  const candidate = payload as { vaultText: string; attestation?: unknown }
  if (candidate.attestation !== undefined && !isSignedAttestation(candidate.attestation)) {
    throw new ApiError('The service returned an invalid attestation response', 'invalid_response')
  }
  return candidate.attestation
    ? { vaultText: candidate.vaultText, attestation: candidate.attestation }
    : candidate.vaultText
}

export async function verifyAttestation(request: VerifyAttestationRequest, signal?: AbortSignal): Promise<VerificationResult> {
  const payload = await requestJSON('/api/v1/attestations/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
    signal,
  })
  if (!isVerificationResult(payload)) {
    throw new ApiError('The service returned an invalid verification response', 'invalid_response')
  }
  return payload
}

export function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength
}

export function maxInputBytes(mode: OperationMode): number {
  return mode === 'encrypt' ? MAX_PLAINTEXT_BYTES : MAX_VAULT_TEXT_BYTES
}

function isErrorEnvelope(value: unknown): value is ErrorEnvelope & { error: NonNullable<ErrorEnvelope['error']> } {
  if (!value || typeof value !== 'object' || !('error' in value)) return false
  const error = (value as ErrorEnvelope).error
  return Boolean(error && typeof error === 'object')
}

function isSessionEnvelope(value: unknown): value is Session {
  if (!value || typeof value !== 'object') return false
  const candidate = value as Partial<Session>
  return typeof candidate.authenticated === 'boolean'
    && typeof candidate.authRequired === 'boolean'
    && typeof candidate.csrfToken === 'string'
    && (candidate.email === undefined || typeof candidate.email === 'string')
    && (candidate.attestationEnabled === undefined || typeof candidate.attestationEnabled === 'boolean')
}

function isProfileEnvelope(value: unknown): value is { profiles: Profile[] } {
  if (!value || typeof value !== 'object' || !('profiles' in value)) return false
  const profiles = (value as { profiles?: unknown }).profiles
  return Array.isArray(profiles) && profiles.every(isProfile)
}

function isProfile(value: unknown): value is Profile {
  if (!value || typeof value !== 'object') return false
  const candidate = value as Partial<Profile>
  const capabilities = candidate.capabilities
  return typeof candidate.id === 'string'
    && typeof candidate.label === 'string'
    && Boolean(capabilities && typeof capabilities === 'object')
    && typeof capabilities?.encrypt === 'boolean'
    && typeof capabilities?.decrypt === 'boolean'
    && typeof capabilities?.rotateSource === 'boolean'
    && typeof capabilities?.rotateDestination === 'boolean'
}

function isOperationResponse(
  value: unknown,
  field: 'vaultText' | 'plaintext',
): value is Record<typeof field, string> {
  if (!value || typeof value !== 'object' || !(field in value)) return false
  return typeof (value as Record<string, unknown>)[field] === 'string'
}

function isSignedAttestation(value: unknown): value is SignedAttestation {
  if (!value || typeof value !== 'object') return false
  const candidate = value as Partial<SignedAttestation>
  return typeof candidate.protected === 'string'
    && typeof candidate.payload === 'string'
    && typeof candidate.signature === 'string'
}

function isAttestationBinding(value: unknown): value is AttestationBinding {
  if (!value || typeof value !== 'object') return false
  const candidate = value as Partial<AttestationBinding>
  return (candidate.repository === undefined || typeof candidate.repository === 'string')
    && (candidate.revision === undefined || typeof candidate.revision === 'string')
    && (candidate.path === undefined || typeof candidate.path === 'string')
    && (candidate.selector === undefined || typeof candidate.selector === 'string')
}

function isAttestationClaims(value: unknown): value is AttestationClaims {
  if (!value || typeof value !== 'object') return false
  const candidate = value as Partial<AttestationClaims>
  return typeof candidate.issuer === 'string'
    && typeof candidate.issuedAt === 'string'
    && candidate.operation === 'rotate'
    && typeof candidate.sourceProfileId === 'string'
    && typeof candidate.destinationProfileId === 'string'
    && typeof candidate.kid === 'string'
    && (candidate.binding === undefined || isAttestationBinding(candidate.binding))
}

function isVerificationResult(value: unknown): value is VerificationResult {
  if (!value || typeof value !== 'object') return false
  const candidate = value as Partial<VerificationResult>
  const reasons: VerificationReason[] = [
    'signature_invalid', 'unknown_key', 'key_revoked', 'issuer_mismatch',
    'unsupported_version', 'input_digest_mismatch', 'output_digest_mismatch', 'binding_mismatch',
  ]
  return typeof candidate.valid === 'boolean'
    && (candidate.reason === undefined || reasons.includes(candidate.reason))
    && (candidate.attestation === undefined || isAttestationClaims(candidate.attestation))
}
