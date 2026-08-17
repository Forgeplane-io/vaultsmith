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

export type GenerateRequest = components['schemas']['GenerateRequest']
export type GenerateResponse = components['schemas']['GenerateResponse']
export type GenerateKind = GenerateRequest['kind']
export type GenerateSSHKeyAlgorithm = components['schemas']['GenerateSSHKeyAlgorithm']
export type GenerateX509KeyAlgorithm = components['schemas']['GenerateX509KeyAlgorithm']

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

export async function generateMaterial(request: GenerateRequest, signal?: AbortSignal): Promise<GenerateResponse> {
  const wireRequest = toGenerateWireRequest(request)
  const payload = await requestJSON('/api/v1/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(wireRequest),
    signal,
  })
  if (!isGenerateResponse(payload, wireRequest)) {
    throw new ApiError('The service returned an invalid Generate response', 'invalid_response')
  }
  return normalizeGenerateResponse(payload)
}

function toGenerateWireRequest(request: GenerateRequest): GenerateRequest {
  switch (request.kind) {
    case 'password':
      return {
        kind: 'password',
        profileId: request.profileId,
        parameters: {
          length: request.parameters.length,
          lowercase: request.parameters.lowercase,
          uppercase: request.parameters.uppercase,
          digits: request.parameters.digits,
          symbols: request.parameters.symbols,
          minLowercase: request.parameters.minLowercase,
          minUppercase: request.parameters.minUppercase,
          minDigits: request.parameters.minDigits,
          minSymbols: request.parameters.minSymbols,
          excludeAmbiguous: request.parameters.excludeAmbiguous,
        },
      }
    case 'token':
      return {
        kind: 'token',
        profileId: request.profileId,
        parameters: {
          encoding: request.parameters.encoding,
          bytes: request.parameters.bytes,
        },
      }
    case 'ssh_keypair':
      return {
        kind: 'ssh_keypair',
        profileId: request.profileId,
        parameters: { algorithm: request.parameters.algorithm },
      }
    case 'age_identity':
      return { kind: 'age_identity', profileId: request.profileId, parameters: {} }
    case 'x509_csr': {
      const subject = request.parameters.subject
      const sans = request.parameters.sans
      return {
        kind: 'x509_csr',
        profileId: request.profileId,
        parameters: {
          algorithm: request.parameters.algorithm,
          ...(subject ? {
            subject: {
              commonName: subject.commonName,
              serialNumber: subject.serialNumber,
              country: subject.country,
              organization: subject.organization,
              organizationalUnit: subject.organizationalUnit,
              locality: subject.locality,
              province: subject.province,
              streetAddress: subject.streetAddress,
              postalCode: subject.postalCode,
            },
          } : {}),
          ...(sans ? {
            sans: {
              dnsNames: sans.dnsNames,
              ipAddresses: sans.ipAddresses,
              emailAddresses: sans.emailAddresses,
              uris: sans.uris,
            },
          } : {}),
        },
      }
    }
  }
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

function isGenerateResponse(value: unknown, request: GenerateRequest): value is GenerateResponse {
  if (!value || typeof value !== 'object') return false
  const candidate = value as Record<string, unknown>
  if (candidate.kind !== request.kind
    || candidate.profileId !== request.profileId
    || typeof candidate.profileId !== 'string'
    || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(candidate.profileId)) return false
  if (!candidate.effectiveParameters || typeof candidate.effectiveParameters !== 'object') return false
  if (!candidate.secret || typeof candidate.secret !== 'object') return false

  const effective = candidate.effectiveParameters as Record<string, unknown>
  const secret = candidate.secret as Record<string, unknown>
  if (!isCanonicalGeneratedVaultText(secret.vaultText, candidate.profileId)) return false

  switch (request.kind) {
    case 'password': {
      const integerFields = ['length', 'minLowercase', 'minUppercase', 'minDigits', 'minSymbols'] as const
      const booleanFields = ['lowercase', 'uppercase', 'digits', 'symbols', 'excludeAmbiguous'] as const
      if (secret.format !== 'password_ascii'
        || !integerFields.every((field) => Number.isInteger(effective[field]))
        || !booleanFields.every((field) => typeof effective[field] === 'boolean')) return false
      const length = effective.length as number
      const minima = integerFields.slice(1).map((field) => effective[field] as number)
      const enabledClasses = booleanFields.slice(0, 4).map((field) => effective[field] as boolean)
      const parameters = request.parameters
      const expectedLowercase = parameters.lowercase ?? true
      const expectedUppercase = parameters.uppercase ?? true
      const expectedDigits = parameters.digits ?? true
      const expectedSymbols = parameters.symbols ?? false
      return length === (parameters.length ?? 32)
        && effective.lowercase === expectedLowercase
        && effective.uppercase === expectedUppercase
        && effective.digits === expectedDigits
        && effective.symbols === expectedSymbols
        && effective.minLowercase === (parameters.minLowercase ?? (expectedLowercase ? 1 : 0))
        && effective.minUppercase === (parameters.minUppercase ?? (expectedUppercase ? 1 : 0))
        && effective.minDigits === (parameters.minDigits ?? (expectedDigits ? 1 : 0))
        && effective.minSymbols === (parameters.minSymbols ?? (expectedSymbols ? 1 : 0))
        && effective.excludeAmbiguous === (parameters.excludeAmbiguous ?? false)
        && length >= 22 && length <= 128
        && enabledClasses.some(Boolean)
        && minima.every((minimum) => minimum >= 0 && minimum <= 32)
        && minima.every((minimum, index) => enabledClasses[index] || minimum === 0)
        && minima.reduce((sum, minimum) => sum + minimum, 0) <= length
    }
    case 'token': {
      if (effective.encoding !== 'base64url' && effective.encoding !== 'hex') return false
      if (!Number.isInteger(effective.bytes) || (effective.bytes as number) < 16 || (effective.bytes as number) > 64) return false
      return effective.encoding === (request.parameters.encoding ?? 'base64url')
        && effective.bytes === (request.parameters.bytes ?? 32)
        && secret.format === (effective.encoding === 'base64url' ? 'token_base64url' : 'token_hex')
    }
    case 'ssh_keypair': {
      if (!isSSHAlgorithm(effective.algorithm)
        || effective.algorithm !== request.parameters.algorithm
        || secret.format !== 'openssh_private_key'
        || !candidate.public || typeof candidate.public !== 'object') return false
      const publicResult = candidate.public as Record<string, unknown>
      return publicResult.format === 'openssh_authorized_key'
        && isCanonicalAuthorizedKey(publicResult.authorizedKey, effective.algorithm)
        && isSHA256Fingerprint(publicResult.fingerprint)
    }
    case 'age_identity': {
      if (effective.algorithm !== 'x25519'
        || secret.format !== 'age_x25519_identity'
        || !candidate.public || typeof candidate.public !== 'object') return false
      const publicResult = candidate.public as Record<string, unknown>
      return publicResult.format === 'age_x25519_recipient' && isCanonicalAgeRecipient(publicResult.recipient)
    }
    case 'x509_csr': {
      if (!isX509Algorithm(effective.algorithm)
        || effective.algorithm !== request.parameters.algorithm
        || secret.format !== 'pkcs8_private_key_pem'
        || !candidate.public || typeof candidate.public !== 'object') return false
      const publicResult = candidate.public as Record<string, unknown>
      return publicResult.format === 'pkcs10_csr_pem'
        && isCanonicalCSRPEM(publicResult.csrPem)
        && isSHA256Fingerprint(publicResult.fingerprint)
    }
    default:
      return false
  }
}

function normalizeGenerateResponse(value: GenerateResponse): GenerateResponse {
  switch (value.kind) {
    case 'password':
      return {
        kind: value.kind,
        profileId: value.profileId,
        effectiveParameters: {
          length: value.effectiveParameters.length,
          lowercase: value.effectiveParameters.lowercase,
          uppercase: value.effectiveParameters.uppercase,
          digits: value.effectiveParameters.digits,
          symbols: value.effectiveParameters.symbols,
          minLowercase: value.effectiveParameters.minLowercase,
          minUppercase: value.effectiveParameters.minUppercase,
          minDigits: value.effectiveParameters.minDigits,
          minSymbols: value.effectiveParameters.minSymbols,
          excludeAmbiguous: value.effectiveParameters.excludeAmbiguous,
        },
        secret: { format: value.secret.format, vaultText: value.secret.vaultText },
      }
    case 'token':
      return {
        kind: value.kind,
        profileId: value.profileId,
        effectiveParameters: {
          encoding: value.effectiveParameters.encoding,
          bytes: value.effectiveParameters.bytes,
        },
        secret: { format: value.secret.format, vaultText: value.secret.vaultText },
      }
    case 'ssh_keypair':
      return {
        kind: value.kind,
        profileId: value.profileId,
        effectiveParameters: { algorithm: value.effectiveParameters.algorithm },
        secret: { format: value.secret.format, vaultText: value.secret.vaultText },
        public: {
          format: value.public.format,
          authorizedKey: value.public.authorizedKey,
          fingerprint: value.public.fingerprint,
        },
      }
    case 'age_identity':
      return {
        kind: value.kind,
        profileId: value.profileId,
        effectiveParameters: { algorithm: value.effectiveParameters.algorithm },
        secret: { format: value.secret.format, vaultText: value.secret.vaultText },
        public: { format: value.public.format, recipient: value.public.recipient },
      }
    case 'x509_csr':
      return {
        kind: value.kind,
        profileId: value.profileId,
        effectiveParameters: { algorithm: value.effectiveParameters.algorithm },
        secret: { format: value.secret.format, vaultText: value.secret.vaultText },
        public: {
          format: value.public.format,
          csrPem: value.public.csrPem,
          fingerprint: value.public.fingerprint,
        },
      }
  }
}

function isSSHAlgorithm(value: unknown): value is GenerateSSHKeyAlgorithm {
  return value === 'ed25519' || value === 'ecdsa_p256' || value === 'rsa_3072' || value === 'rsa_4096'
}

function isX509Algorithm(value: unknown): value is GenerateX509KeyAlgorithm {
  return value === 'ed25519' || value === 'ecdsa_p256' || value === 'ecdsa_p384' || value === 'rsa_3072' || value === 'rsa_4096'
}

function isSHA256Fingerprint(value: unknown): value is string {
  if (typeof value !== 'string' || !/^SHA256:[A-Za-z0-9+/]{43}$/.test(value)) return false
  return decodeCanonicalBase64(value.slice('SHA256:'.length), false)?.length === 32
}

function isCanonicalGeneratedVaultText(value: unknown, profileId: string): value is string {
  if (typeof value !== 'string' || value.length > MAX_VAULT_TEXT_BYTES || !value.endsWith('\n') || value.endsWith('\n\n') || value.includes('\r')) return false
  const lines = value.slice(0, -1).split('\n')
  if (lines.shift() !== `$ANSIBLE_VAULT;1.2;AES256;${profileId}` || lines.length === 0) return false
  if (!lines.every((line, index) => line.length > 0
    && line.length <= 80
    && (index === lines.length - 1 || line.length === 80)
    && /^[0-9a-f]+$/.test(line))) return false

  const outerBody = lines.join('')
  if (outerBody.length % 2 !== 0) return false
  let payload = ''
  for (let index = 0; index < outerBody.length; index += 2) {
    payload += String.fromCharCode(Number.parseInt(outerBody.slice(index, index + 2), 16))
  }
  const fields = payload.split('\n')
  return fields.length === 3
    && /^[0-9a-fA-F]{64}$/.test(fields[0])
    && /^[0-9a-fA-F]{64}$/.test(fields[1])
    && /^[0-9a-fA-F]+$/.test(fields[2])
    && fields[2].length % 32 === 0
}

function isCanonicalAuthorizedKey(value: unknown, algorithm: GenerateSSHKeyAlgorithm): value is string {
  if (typeof value !== 'string' || value.includes('\n') || value.includes('\r')) return false
  const keyType = algorithm === 'ed25519'
    ? 'ssh-ed25519'
    : algorithm === 'ecdsa_p256'
      ? 'ecdsa-sha2-nistp256'
      : 'ssh-rsa'
  const prefix = `${keyType} `
  if (!value.startsWith(prefix) || value.slice(prefix.length).includes(' ')) return false
  const decoded = decodeCanonicalBase64(value.slice(prefix.length), true)
  if (!decoded) return false
  const type = readSSHField(decoded, 0)
  if (!type || type.value !== keyType) return false

  if (algorithm === 'ed25519') {
    const key = readSSHField(decoded, type.next)
    return Boolean(key && key.value.length === 32 && key.next === decoded.length)
  }
  if (algorithm === 'ecdsa_p256') {
    const curve = readSSHField(decoded, type.next)
    const point = curve ? readSSHField(decoded, curve.next) : null
    return Boolean(curve
      && point
      && curve.value === 'nistp256'
      && point.value.length === 65
      && point.value.charCodeAt(0) === 0x04
      && point.next === decoded.length)
  }

  const exponent = readSSHField(decoded, type.next)
  const modulus = exponent ? readSSHField(decoded, exponent.next) : null
  const expectedBits = algorithm === 'rsa_3072' ? 3072 : 4096
  return Boolean(exponent
    && modulus
    && exponent.value === '\x01\x00\x01'
    && isCanonicalPositiveSSHMPInt(modulus.value)
    && sshMPIntBitLength(modulus.value) === expectedBits
    && modulus.next === decoded.length)
}

function isCanonicalAgeRecipient(value: unknown): value is string {
  if (typeof value !== 'string' || !/^age1[ac-hj-np-z02-9]{58}$/.test(value)) return false
  const alphabet = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
  const data = [...value.slice(4)].map((character) => alphabet.indexOf(character))
  if (data.some((part) => part < 0) || (data[51] & 15) !== 0) return false
  const hrp = [...'age'].map((character) => character.charCodeAt(0))
  return bech32Polymod([...hrp.map((part) => part >> 5), 0, ...hrp.map((part) => part & 31), ...data]) === 1
}

function isCanonicalCSRPEM(value: unknown): value is string {
  if (typeof value !== 'string' || value.includes('\r') || !value.endsWith('\n') || value.endsWith('\n\n')) return false
  const lines = value.slice(0, -1).split('\n')
  if (lines.length < 3
    || lines[0] !== '-----BEGIN CERTIFICATE REQUEST-----'
    || lines[lines.length - 1] !== '-----END CERTIFICATE REQUEST-----') return false
  const bodyLines = lines.slice(1, -1)
  if (!bodyLines.every((line, index) => line.length > 0
    && line.length <= 64
    && (index === bodyLines.length - 1 || line.length === 64))) return false
  const decoded = decodeCanonicalBase64(bodyLines.join(''), true)
  return Boolean(decoded && isPKCS10DER(decoded))
}

function decodeCanonicalBase64(value: string, padded: boolean): string | null {
  if (!value || (padded && value.length % 4 !== 0)) return null
  if (padded ? !/^[A-Za-z0-9+/]+={0,2}$/.test(value) : !/^[A-Za-z0-9+/]+$/.test(value)) return null
  try {
    const decoded = globalThis.atob(padded ? value : value + '='.repeat((4 - value.length % 4) % 4))
    const canonical = globalThis.btoa(decoded)
    return (padded ? canonical === value : canonical.replace(/=+$/, '') === value) ? decoded : null
  } catch {
    return null
  }
}

function readUint32(value: string, offset: number): number {
  return ((value.charCodeAt(offset) << 24) >>> 0)
    + (value.charCodeAt(offset + 1) << 16)
    + (value.charCodeAt(offset + 2) << 8)
    + value.charCodeAt(offset + 3)
}

type SSHField = {
  value: string
  next: number
}

function readSSHField(value: string, offset: number): SSHField | null {
  if (offset < 0 || offset + 4 > value.length) return null
  const length = readUint32(value, offset)
  const start = offset + 4
  const end = start + length
  if (!Number.isSafeInteger(length) || end < start || end > value.length) return null
  return { value: value.slice(start, end), next: end }
}

function isCanonicalPositiveSSHMPInt(value: string): boolean {
  if (value.length === 0) return false
  const first = value.charCodeAt(0)
  if (first === 0) return value.length > 1 && value.charCodeAt(1) >= 0x80
  return first < 0x80
}

function sshMPIntBitLength(value: string): number {
  const offset = value.charCodeAt(0) === 0 ? 1 : 0
  if (offset >= value.length) return 0
  const first = value.charCodeAt(offset)
  return (value.length - offset - 1) * 8 + (32 - Math.clz32(first))
}

type DERElement = {
  tag: number
  contentStart: number
  end: number
}

function isPKCS10DER(value: string): boolean {
  const root = readDERElement(value, 0)
  if (!root || root.tag !== 0x30 || root.end !== value.length) return false
  const rootChildren = readDERChildren(value, root)
  if (!rootChildren || rootChildren.length !== 3) return false
  const [requestInfo, signatureAlgorithm, signature] = rootChildren
  if (requestInfo.tag !== 0x30
    || !isAlgorithmIdentifier(value, signatureAlgorithm)
    || !isDERBitString(value, signature, false)) return false

  const requestInfoChildren = readDERChildren(value, requestInfo)
  if (!requestInfoChildren || requestInfoChildren.length !== 4) return false
  const [version, subject, subjectPublicKeyInfo, attributes] = requestInfoChildren
  if (version.tag !== 0x02
    || version.end - version.contentStart !== 1
    || value.charCodeAt(version.contentStart) !== 0
    || subject.tag !== 0x30
    || subjectPublicKeyInfo.tag !== 0x30
    || attributes.tag !== 0xa0) return false

  const relativeNames = readDERChildren(value, subject)
  if (!relativeNames || !relativeNames.every((relativeName) => relativeName.tag === 0x31 && isAttributeTypeAndValueSet(value, relativeName))) return false

  const publicKeyChildren = readDERChildren(value, subjectPublicKeyInfo)
  if (!publicKeyChildren
    || publicKeyChildren.length !== 2
    || !isAlgorithmIdentifier(value, publicKeyChildren[0])
    || !isDERBitString(value, publicKeyChildren[1], true)) return false

  const requestAttributes = readDERChildren(value, attributes)
  return Boolean(requestAttributes && requestAttributes.every((attribute) => isCSRAttribute(value, attribute)))
}

function readDERElement(value: string, offset: number): DERElement | null {
  if (offset < 0 || offset + 2 > value.length) return null
  const tag = value.charCodeAt(offset)
  if ((tag & 0x1f) === 0x1f) return null
  const firstLength = value.charCodeAt(offset + 1)
  let length = firstLength
  let contentStart = offset + 2
  if (firstLength >= 0x80) {
    const lengthBytes = firstLength & 0x7f
    if (lengthBytes === 0 || lengthBytes > 4 || contentStart + lengthBytes > value.length || value.charCodeAt(contentStart) === 0) return null
    length = 0
    for (let index = 0; index < lengthBytes; index += 1) {
      length = length * 256 + value.charCodeAt(contentStart + index)
    }
    if (length < 0x80) return null
    contentStart += lengthBytes
  }
  const end = contentStart + length
  if (!Number.isSafeInteger(length) || end < contentStart || end > value.length) return null
  return { tag, contentStart, end }
}

function readDERChildren(value: string, parent: DERElement): DERElement[] | null {
  const children: DERElement[] = []
  let offset = parent.contentStart
  while (offset < parent.end) {
    const child = readDERElement(value, offset)
    if (!child || child.end > parent.end) return null
    children.push(child)
    offset = child.end
  }
  return offset === parent.end ? children : null
}

function isAlgorithmIdentifier(value: string, element: DERElement): boolean {
  if (element.tag !== 0x30) return false
  const children = readDERChildren(value, element)
  return Boolean(children
    && (children.length === 1 || children.length === 2)
    && isDERObjectIdentifier(value, children[0]))
}

function isDERObjectIdentifier(value: string, element: DERElement): boolean {
  if (element.tag !== 0x06 || element.contentStart === element.end) return false
  let componentStart = element.contentStart
  for (let index = element.contentStart; index < element.end; index += 1) {
    const octet = value.charCodeAt(index)
    if (index === componentStart && octet === 0x80) return false
    if ((octet & 0x80) === 0) componentStart = index + 1
  }
  return componentStart === element.end
}

function isDERBitString(value: string, element: DERElement, requireZeroUnusedBits: boolean): boolean {
  if (element.tag !== 0x03 || element.end - element.contentStart < 2) return false
  const unusedBits = value.charCodeAt(element.contentStart)
  if (unusedBits > 7 || (requireZeroUnusedBits && unusedBits !== 0)) return false
  if (unusedBits === 0) return true
  const finalOctet = value.charCodeAt(element.end - 1)
  return (finalOctet & ((1 << unusedBits) - 1)) === 0
}

function isAttributeTypeAndValueSet(value: string, set: DERElement): boolean {
  const values = readDERChildren(value, set)
  return Boolean(values && values.length > 0 && values.every((attribute) => {
    if (attribute.tag !== 0x30) return false
    const children = readDERChildren(value, attribute)
    return Boolean(children && children.length === 2 && isDERObjectIdentifier(value, children[0]))
  }))
}

function isCSRAttribute(value: string, attribute: DERElement): boolean {
  if (attribute.tag !== 0x30) return false
  const children = readDERChildren(value, attribute)
  if (!children
    || children.length !== 2
    || !isDERObjectIdentifier(value, children[0])
    || children[1].tag !== 0x31) return false
  const values = readDERChildren(value, children[1])
  return Boolean(values && values.length > 0)
}

function bech32Polymod(values: number[]): number {
  const generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
  let checksum = 1
  for (const value of values) {
    const top = checksum >>> 25
    checksum = ((checksum & 0x1ffffff) << 5) ^ value
    for (let index = 0; index < generators.length; index += 1) {
      if ((top >>> index) & 1) checksum ^= generators[index]
    }
  }
  return checksum >>> 0
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
