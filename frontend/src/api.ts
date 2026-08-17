import type { components } from './generated/api'
import * as z from 'zod/mini'
import { signedAttestationSchema, type SignedAttestation } from './attestation'

export type { SignedAttestation } from './attestation'

export type OperationMode = 'encrypt' | 'decrypt' | 'rotate'

export type AttestationBinding = components['schemas']['RotationBinding']
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

type GeneratePasswordResponse = components['schemas']['GeneratePasswordResponse']
type GenerateTokenResponse = components['schemas']['GenerateTokenResponse']
type GenerateSSHKeyPairResponse = components['schemas']['GenerateSSHKeyPairResponse']
type GenerateAgeIdentityResponse = components['schemas']['GenerateAgeIdentityResponse']
type GenerateX509CSRResponse = components['schemas']['GenerateX509CSRResponse']
type GenerateX509CSRParameters = components['schemas']['GenerateX509CSRParameters']

const unparsedAttestationSchema = z.unknown()
const errorEnvelopeSchema = z.looseObject({
  error: z.looseObject({
    code: z.catch(z.optional(z.string()), undefined),
    message: z.catch(z.optional(z.string()), undefined),
  }),
})

const sessionSchema = z.looseObject({
  authenticated: z.boolean(),
  authRequired: z.boolean(),
  email: z.optional(z.string()),
  csrfToken: z.string(),
  attestationEnabled: z.optional(z.boolean()),
})

const profileSchema = z.looseObject({
  id: z.string(),
  label: z.string(),
  capabilities: z.looseObject({
    encrypt: z.boolean(),
    decrypt: z.boolean(),
    rotateSource: z.boolean(),
    rotateDestination: z.boolean(),
  }),
}) satisfies z.ZodMiniType<Profile>

const profilesResponseSchema = z.looseObject({
  profiles: z.array(profileSchema),
})

const attestationBindingSchema = z.looseObject({
  repository: z.optional(z.string()),
  revision: z.optional(z.string()),
  path: z.optional(z.string()),
  selector: z.optional(z.string()),
}) satisfies z.ZodMiniType<AttestationBinding>

const attestationClaimsSchema = z.looseObject({
  issuer: z.string(),
  issuedAt: z.string(),
  operation: z.literal('rotate'),
  sourceProfileId: z.string(),
  destinationProfileId: z.string(),
  kid: z.string(),
  binding: z.optional(attestationBindingSchema),
}) satisfies z.ZodMiniType<AttestationClaims>

const verificationReasonSchema = z.enum([
  'signature_invalid',
  'unknown_key',
  'key_revoked',
  'issuer_mismatch',
  'unsupported_version',
  'input_digest_mismatch',
  'output_digest_mismatch',
  'binding_mismatch',
] satisfies VerificationReason[])

const verificationResultSchema = z.looseObject({
  valid: z.boolean(),
  reason: z.optional(verificationReasonSchema),
  attestation: z.optional(attestationClaimsSchema),
}) satisfies z.ZodMiniType<VerificationResult>

const encryptResponseSchema = z.looseObject({ vaultText: z.string() })
const decryptResponseSchema = z.looseObject({ plaintext: z.string() })
const rotateResponseSchema = z.looseObject({
  vaultText: z.string(),
  attestation: z.optional(unparsedAttestationSchema),
})

const generatePasswordResponseSchema = z.object({
  kind: z.literal('password'),
  profileId: z.string(),
  effectiveParameters: z.object({
    length: z.number(),
    lowercase: z.boolean(),
    uppercase: z.boolean(),
    digits: z.boolean(),
    symbols: z.boolean(),
    minLowercase: z.number(),
    minUppercase: z.number(),
    minDigits: z.number(),
    minSymbols: z.number(),
    excludeAmbiguous: z.boolean(),
  }),
  secret: z.object({
    format: z.literal('password_ascii'),
    vaultText: z.string(),
  }),
}) satisfies z.ZodMiniType<GeneratePasswordResponse>

const generateTokenResponseSchema = z.object({
  kind: z.literal('token'),
  profileId: z.string(),
  effectiveParameters: z.object({
    encoding: z.enum(['base64url', 'hex']),
    bytes: z.number(),
  }),
  secret: z.object({
    format: z.enum(['token_base64url', 'token_hex']),
    vaultText: z.string(),
  }),
}) satisfies z.ZodMiniType<GenerateTokenResponse>

const generateSSHKeyPairResponseSchema = z.object({
  kind: z.literal('ssh_keypair'),
  profileId: z.string(),
  effectiveParameters: z.object({
    algorithm: z.enum(['ed25519', 'ecdsa_p256', 'rsa_3072', 'rsa_4096']),
  }),
  secret: z.object({
    format: z.literal('openssh_private_key'),
    vaultText: z.string(),
  }),
  public: z.object({
    format: z.literal('openssh_authorized_key'),
    authorizedKey: z.string(),
    fingerprint: z.string(),
  }),
}) satisfies z.ZodMiniType<GenerateSSHKeyPairResponse>

const generateAgeIdentityResponseSchema = z.object({
  kind: z.literal('age_identity'),
  profileId: z.string(),
  effectiveParameters: z.object({ algorithm: z.literal('x25519') }),
  secret: z.object({
    format: z.literal('age_x25519_identity'),
    vaultText: z.string(),
  }),
  public: z.object({
    format: z.literal('age_x25519_recipient'),
    recipient: z.string(),
  }),
}) satisfies z.ZodMiniType<GenerateAgeIdentityResponse>

const generateX509CSRResponseSchema = z.object({
  kind: z.literal('x509_csr'),
  profileId: z.string(),
  effectiveParameters: z.object({
    algorithm: z.enum(['ed25519', 'ecdsa_p256', 'ecdsa_p384', 'rsa_3072', 'rsa_4096']),
  }),
  secret: z.object({
    format: z.literal('pkcs8_private_key_pem'),
    vaultText: z.string(),
  }),
  public: z.object({
    format: z.literal('pkcs10_csr_pem'),
    csrPem: z.string(),
    fingerprint: z.string(),
  }),
}) satisfies z.ZodMiniType<GenerateX509CSRResponse>

const generateResponseSchema = z.union([
  generatePasswordResponseSchema,
  generateTokenResponseSchema,
  generateSSHKeyPairResponseSchema,
  generateAgeIdentityResponseSchema,
  generateX509CSRResponseSchema,
]) satisfies z.ZodMiniType<GenerateResponse>

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

export type OperationResult = {
  output: string
  attestation: SignedAttestation | null
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

let csrfToken = ''

type JSONRequestInit = Omit<RequestInit, 'headers'> & {
  headers?: Readonly<Record<string, string>>
}

async function fetchSameOrigin(path: string, init?: JSONRequestInit): Promise<Response> {
  const headers = { ...init?.headers }
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
  return response
}

async function responseError(response: Response): Promise<ApiError> {
  try {
    const parsedEnvelope = errorEnvelopeSchema.safeParse(await response.json())
    const code = parsedEnvelope.success ? parsedEnvelope.data.error.code ?? 'request_failed' : 'request_failed'
    const message = parsedEnvelope.success ? parsedEnvelope.data.error.message ?? 'Request failed' : 'Request failed'
    return new ApiError(message, code, response.status)
  } catch {
    return new ApiError('Request failed', 'request_failed', response.status)
  }
}

async function requestJSON<Output>(
  path: string,
  responseSchema: z.ZodMiniType<Output>,
  invalidResponseMessage: string,
  init?: JSONRequestInit,
): Promise<Output> {
  const response = await fetchSameOrigin(path, init)
  if (!response.ok) throw await responseError(response)
  try {
    return responseSchema.parse(await response.json())
  } catch {
    throw new ApiError(invalidResponseMessage, 'invalid_response')
  }
}

async function requestStatus(path: string, init?: JSONRequestInit): Promise<number> {
  const response = await fetchSameOrigin(path, init)
  if (!response.ok) throw await responseError(response)
  if (response.status !== 204) {
    try {
      await response.json()
    } catch {
      // The status is authoritative for successful logout responses.
    }
  }
  return response.status
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
    const rejectOnce = (reason: Error) => {
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
      request(controller.signal).then(resolveOnce, (cause) => rejectOnce(normalizeRequestFailure(cause)))
    } catch (cause) {
      rejectOnce(normalizeRequestFailure(cause))
    }
  })
}

function normalizeRequestFailure(cause: unknown): Error {
  return cause instanceof Error ? cause : new ApiError('Request failed')
}

async function requestSession(signal: AbortSignal): Promise<Session> {
  const payload = await requestJSON(
    '/api/v1/session',
    sessionSchema,
    'The service returned an invalid session response',
    {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal,
    },
  )
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
    (requestSignal) => requestJSON(
      '/api/v1/profiles',
      profilesResponseSchema,
      'The service returned an invalid profile response',
      {
        method: 'GET',
        headers: { Accept: 'application/json' },
        signal: requestSignal,
      },
    ),
  )
  return payload.profiles
}

export async function logout(signal?: AbortSignal): Promise<void> {
  await withRequestTimeout(
    signal,
    LOGOUT_TIMEOUT_MS,
    'logout_timeout',
    'Sign out timed out',
    async (requestSignal) => {
      const status = await requestStatus('/auth/logout', {
        method: 'POST',
        headers: { Accept: 'application/json' },
        signal: requestSignal,
      })
      if (status === 204) {
        return
      }

      if (requestSignal.aborted) {
        throw new DOMException('The operation was aborted', 'AbortError')
      }
      const verifiedSession = await requestSession(requestSignal)
      if (verifiedSession.authenticated) {
        throw new ApiError('Sign out was not confirmed', 'logout_unconfirmed', status)
      }
    },
  )
  csrfToken = ''
}

export async function runOperation(request: OperationRequest, signal?: AbortSignal): Promise<OperationResult> {
  if (request.mode === 'rotate') {
    const body = {
      sourceProfileId: request.sourceProfileId,
      destinationProfileId: request.destinationProfileId,
      vaultText: request.value,
      attestation: request.attestation,
    } satisfies RotateRequest
    const payload = await requestJSON(
      '/api/v1/rotations',
      rotateResponseSchema,
      'The service returned an invalid operation response',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal,
      },
    )
    if (payload.attestation === undefined) return { output: payload.vaultText, attestation: null }

    const parsedAttestation = signedAttestationSchema.safeParse(payload.attestation)
    if (!parsedAttestation.success) {
      throw new ApiError('The service returned an invalid attestation response', 'invalid_response')
    }
    return { output: payload.vaultText, attestation: parsedAttestation.data }
  }

  const path = `/api/v1/profiles/${encodeURIComponent(request.profileId)}/${request.mode}`
  if (request.mode === 'encrypt') {
    const body = { plaintext: request.value } satisfies EncryptRequest
    const payload = await requestJSON(
      path,
      encryptResponseSchema,
      'The service returned an invalid operation response',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal,
      },
    )
    return { output: payload.vaultText, attestation: null }
  }

  const body = { vaultText: request.value } satisfies DecryptRequest
  const payload = await requestJSON(
    path,
    decryptResponseSchema,
    'The service returned an invalid operation response',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal,
    },
  )
  return { output: payload.plaintext, attestation: null }
}

export async function generateMaterial(request: GenerateRequest, signal?: AbortSignal): Promise<GenerateResponse> {
  const wireRequest = toGenerateWireRequest(request)
  const payload = await requestJSON(
    '/api/v1/generate',
    generateResponseSchema,
    'The service returned an invalid Generate response',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(wireRequest),
      signal,
    },
  )
  if (!matchesGenerateRequest(payload, wireRequest)) {
    throw new ApiError('The service returned an invalid Generate response', 'invalid_response')
  }
  return payload
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
      const parameters: GenerateX509CSRParameters = { algorithm: request.parameters.algorithm }
      if (subject) {
        parameters.subject = {
          commonName: subject.commonName,
          serialNumber: subject.serialNumber,
          country: subject.country,
          organization: subject.organization,
          organizationalUnit: subject.organizationalUnit,
          locality: subject.locality,
          province: subject.province,
          streetAddress: subject.streetAddress,
          postalCode: subject.postalCode,
        }
      }
      if (sans) {
        parameters.sans = {
          dnsNames: sans.dnsNames,
          ipAddresses: sans.ipAddresses,
          emailAddresses: sans.emailAddresses,
          uris: sans.uris,
        }
      }
      return {
        kind: 'x509_csr',
        profileId: request.profileId,
        parameters,
      }
    }
  }
}

export async function verifyAttestation(request: VerifyAttestationRequest, signal?: AbortSignal): Promise<VerificationResult> {
  return requestJSON(
    '/api/v1/attestations/verify',
    verificationResultSchema,
    'The service returned an invalid verification response',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
      signal,
    },
  )
}

export function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength
}

export function maxInputBytes(mode: OperationMode): number {
  return mode === 'encrypt' ? MAX_PLAINTEXT_BYTES : MAX_VAULT_TEXT_BYTES
}
function matchesGenerateRequest(response: GenerateResponse, request: GenerateRequest): boolean {
  if (response.profileId !== request.profileId
    || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(response.profileId)
    || !isCanonicalGeneratedVaultText(response.secret.vaultText, response.profileId)) return false

  switch (response.kind) {
    case 'password': {
      if (request.kind !== 'password') return false
      const effective = response.effectiveParameters
      const length = effective.length
      const minima = [effective.minLowercase, effective.minUppercase, effective.minDigits, effective.minSymbols]
      const enabledClasses = [effective.lowercase, effective.uppercase, effective.digits, effective.symbols]
      const parameters = request.parameters
      const expectedLowercase = parameters.lowercase ?? true
      const expectedUppercase = parameters.uppercase ?? true
      const expectedDigits = parameters.digits ?? true
      const expectedSymbols = parameters.symbols ?? false
      return Number.isInteger(length)
        && minima.every(Number.isInteger)
        && length === (parameters.length ?? 32)
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
      if (request.kind !== 'token') return false
      const effective = response.effectiveParameters
      if (!Number.isInteger(effective.bytes) || effective.bytes < 16 || effective.bytes > 64) return false
      return effective.encoding === (request.parameters.encoding ?? 'base64url')
        && effective.bytes === (request.parameters.bytes ?? 32)
        && response.secret.format === (effective.encoding === 'base64url' ? 'token_base64url' : 'token_hex')
    }
    case 'ssh_keypair': {
      if (request.kind !== 'ssh_keypair') return false
      const effective = response.effectiveParameters
      return effective.algorithm === request.parameters.algorithm
        && isCanonicalAuthorizedKey(response.public.authorizedKey, effective.algorithm)
        && isSHA256Fingerprint(response.public.fingerprint)
    }
    case 'age_identity': {
      return request.kind === 'age_identity' && isCanonicalAgeRecipient(response.public.recipient)
    }
    case 'x509_csr': {
      if (request.kind !== 'x509_csr') return false
      return response.effectiveParameters.algorithm === request.parameters.algorithm
        && isCanonicalCSRPEM(response.public.csrPem)
        && isSHA256Fingerprint(response.public.fingerprint)
    }
  }
}

function isSHA256Fingerprint(value: string): boolean {
  if (!/^SHA256:[A-Za-z0-9+/]{43}$/.test(value)) return false
  return decodeCanonicalBase64(value.slice('SHA256:'.length), false)?.length === 32
}

function isCanonicalGeneratedVaultText(value: string, profileId: string): boolean {
  if (value.length > MAX_VAULT_TEXT_BYTES || !value.endsWith('\n') || value.endsWith('\n\n') || value.includes('\r')) return false
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

function isCanonicalAuthorizedKey(value: string, algorithm: GenerateSSHKeyAlgorithm): boolean {
  if (value.includes('\n') || value.includes('\r')) return false
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

function isCanonicalAgeRecipient(value: string): boolean {
  if (!/^age1[ac-hj-np-z02-9]{58}$/.test(value)) return false
  const alphabet = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
  const data = Array.from(value.slice(4), (character) => alphabet.indexOf(character))
  if (data.some((part) => part < 0) || (data[51] & 15) !== 0) return false
  const hrp = [...'age'].map((character) => character.charCodeAt(0))
  return bech32Polymod([...hrp.map((part) => part >> 5), 0, ...hrp.map((part) => part & 31), ...data]) === 1
}

function isCanonicalCSRPEM(value: string): boolean {
  if (value.includes('\r') || !value.endsWith('\n') || value.endsWith('\n\n')) return false
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
