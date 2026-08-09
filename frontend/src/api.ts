export type OperationMode = 'encrypt' | 'decrypt' | 'rotate'

export type Profile = {
  id: string
  label: string
}

export type Session = {
  authenticated: boolean
  authRequired: boolean
  email?: string
  csrfToken: string
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
}

export type OperationRequest = SingleProfileOperationRequest | RotateOperationRequest

export const MAX_PLAINTEXT_BYTES = 1 << 20
export const MAX_VAULT_TEXT_BYTES = 5 << 20
export const OPERATION_TIMEOUT_MS = 30_000
const PROFILE_LOAD_TIMEOUT_MS = 10_000

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

async function requestJSON(path: string, init?: RequestInit): Promise<unknown> {
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
  try {
    payload = await response.json()
  } catch {
    payload = null
  }
  if (!response.ok) {
    const envelope = isErrorEnvelope(payload) ? payload.error : undefined
    const code = typeof envelope?.code === 'string' ? envelope.code : 'request_failed'
    const message = typeof envelope?.message === 'string' ? envelope.message : 'Request failed'
    throw new ApiError(message, code, response.status)
  }
  return payload
}

export async function fetchSession(signal?: AbortSignal): Promise<Session> {
  const payload = await requestJSON('/api/v1/session', {
    method: 'GET',
    headers: { Accept: 'application/json' },
    signal,
  })
  if (!isSessionEnvelope(payload)) {
    throw new ApiError('The service returned an invalid session response', 'invalid_response')
  }
  csrfToken = payload.csrfToken
  return payload
}
export async function fetchProfiles(signal?: AbortSignal): Promise<Profile[]> {
  if (signal?.aborted) {
    throw new DOMException('The operation was aborted', 'AbortError')
  }
  const timeoutController = new AbortController()
  let timedOut = false
  const timeoutId = globalThis.setTimeout(() => {
    timedOut = true
    timeoutController.abort()
  }, PROFILE_LOAD_TIMEOUT_MS)
  const abortRequest = () => timeoutController.abort()
  signal?.addEventListener('abort', abortRequest, { once: true })

  try {
    const payload = await requestJSON('/api/v1/profiles', {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: timeoutController.signal,
    })
    if (!isProfileEnvelope(payload)) {
      throw new ApiError('The service returned an invalid profile response', 'invalid_response')
    }
    return payload.profiles
  } catch (reason) {
    if (timedOut) throw new ApiError('Profile loading timed out', 'profiles_timeout')
    throw reason
  } finally {
    globalThis.clearTimeout(timeoutId)
    signal?.removeEventListener('abort', abortRequest)
  }
}

export async function logout(): Promise<void> {
  await requestJSON('/auth/logout', {
    method: 'POST',
    headers: { Accept: 'application/json' },
  })
}

export async function runOperation(request: OperationRequest, signal?: AbortSignal): Promise<string> {
  const payload = await requestJSON('/api/v1/operations', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
    signal,
  })
  if (!isValueEnvelope(payload)) {
    throw new ApiError('The service returned an invalid operation response', 'invalid_response')
  }
  return payload.value
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
}

function isProfileEnvelope(value: unknown): value is { profiles: Profile[] } {
  if (!value || typeof value !== 'object' || !('profiles' in value)) return false
  const profiles = (value as { profiles?: unknown }).profiles
  return Array.isArray(profiles) && profiles.every(isProfile)
}

function isProfile(value: unknown): value is Profile {
  if (!value || typeof value !== 'object') return false
  const candidate = value as Partial<Profile>
  return typeof candidate.id === 'string' && typeof candidate.label === 'string'
}

function isValueEnvelope(value: unknown): value is { value: string } {
  if (!value || typeof value !== 'object' || !('value' in value)) return false
  return typeof (value as { value?: unknown }).value === 'string'
}
