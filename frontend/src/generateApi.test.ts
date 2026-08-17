import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { GenerateRequest } from './api'

let api: typeof import('./api')

type JsonValue = string | number | boolean | null | readonly JsonValue[] | { readonly [key: string]: JsonValue }
type SSHGenerateRequest = Extract<GenerateRequest, { kind: 'ssh_keypair' }>
type SSHRequestWithAdditions = SSHGenerateRequest & {
  parameters: SSHGenerateRequest['parameters'] & { ignoredParameter: string }
  ignoredTopLevel: string
}
type X509GenerateRequest = Extract<GenerateRequest, { kind: 'x509_csr' }>
type X509RequestWithAdditions = X509GenerateRequest & {
  parameters: X509GenerateRequest['parameters'] & {
    ignoredParameter: boolean
    subject: NonNullable<X509GenerateRequest['parameters']['subject']> & { ignoredSubject: boolean }
    sans: NonNullable<X509GenerateRequest['parameters']['sans']> & { ignoredSAN: boolean }
  }
  ignoredTopLevel: boolean
}
type PasswordResponseAdditions = {
  public?: { futureValue: string }
  futureField?: boolean
}

const jsonResponse = (body: JsonValue, init: ResponseInit = {}) => new Response(JSON.stringify(body), {
  status: 200,
  headers: { 'Content-Type': 'application/json' },
  ...init,
})

const vaultPayload = `${'a'.repeat(64)}\n${'b'.repeat(64)}\n${'c'.repeat(32)}`
const vaultBody = [...vaultPayload]
  .map((character) => character.charCodeAt(0).toString(16).padStart(2, '0'))
  .join('')
  .match(/.{1,80}/g)?.join('\n') || ''
const vaultText = `$ANSIBLE_VAULT;1.2;AES256;dev\n${vaultBody}\n`
const sshAuthorizedKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
const sshFingerprint = 'SHA256:kmYcvdi2GkPeWxB6XLjrZB8JHsy2Hm8luHMFp9GMvqk'
const csrPEM = [
  '-----BEGIN CERTIFICATE REQUEST-----',
  'MIGZME0CAQAwGjEYMBYGA1UEAwwPc2VydmljZS5leGFtcGxlMCowBQYDK2VwAyEA',
  'nwQd4U7B1lyYq9K+KTsCLRL3Bwg0uER3F3y2GI3I8NWgADAFBgMrZXADQQAhoinL',
  'lJP7GK3r0yxKpkP4HHmXQ9egZ8yvKprUY3b+0x3LfVK58oyCefLMFhf58YP1zMiW',
  'Saivu0HqELyyZYYI',
  '-----END CERTIFICATE REQUEST-----',
  '',
].join('\n')
const fingerprint = 'SHA256:NqTDLcU0/nq3jI+Mrf/fqaNvLW0/4hglFn1m1p0Y/OI'

const passwordResponse = (extra: PasswordResponseAdditions = {}) => ({
  kind: 'password',
  profileId: 'dev',
  effectiveParameters: {
    length: 32,
    lowercase: true,
    uppercase: true,
    digits: true,
    symbols: false,
    minLowercase: 1,
    minUppercase: 1,
    minDigits: 1,
    minSymbols: 0,
    excludeAmbiguous: false,
  },
  secret: { format: 'password_ascii', vaultText },
  ...extra,
})

function sshField(value: string): string {
  const length = value.length
  return String.fromCharCode((length >>> 24) & 0xff, (length >>> 16) & 0xff, (length >>> 8) & 0xff, length & 0xff) + value
}

function rsaAuthorizedKey(bits: 3072 | 4096): string {
  const modulus = String.fromCharCode(0, 0x80) + String.fromCharCode(...new Uint8Array(bits / 8 - 1))
  return `ssh-rsa ${globalThis.btoa(sshField('ssh-rsa') + sshField('\x01\x00\x01') + sshField(modulus))}`
}

describe('Generate API client', () => {
  beforeEach(async () => {
    vi.restoreAllMocks()
    vi.resetModules()
    api = await import('./api')
  })

  it('posts an allow-listed discriminated request with same-origin CSRF and no retry header', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse({ authenticated: true, authRequired: true, csrfToken: 'csrf-fixture' }))
      .mockResolvedValueOnce(jsonResponse({
        kind: 'ssh_keypair',
        profileId: 'dev',
        effectiveParameters: { algorithm: 'ed25519', futureNested: true },
        secret: { format: 'openssh_private_key', vaultText, futureNested: true },
        public: { format: 'openssh_authorized_key', authorizedKey: sshAuthorizedKey, fingerprint: sshFingerprint, futureNested: true },
        futureField: true,
      }))

    const request = {
      kind: 'ssh_keypair',
      profileId: 'dev',
      parameters: { algorithm: 'ed25519', ignoredParameter: 'do not send' },
      ignoredTopLevel: 'do not send',
    } satisfies SSHRequestWithAdditions

    await api.fetchSession()
    const result = await api.generateMaterial(request)
    expect(result).toEqual({
      kind: 'ssh_keypair',
      profileId: 'dev',
      effectiveParameters: { algorithm: 'ed25519' },
      secret: { format: 'openssh_private_key', vaultText },
      public: { format: 'openssh_authorized_key', authorizedKey: sshAuthorizedKey, fingerprint: sshFingerprint },
    })

    expect(fetchMock).toHaveBeenLastCalledWith('/api/v1/generate', expect.objectContaining({
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': 'csrf-fixture' },
    }))
    const init = fetchMock.mock.lastCall?.[1]
    expect(JSON.parse(String(init?.body))).toEqual({ kind: 'ssh_keypair', profileId: 'dev', parameters: { algorithm: 'ed25519' } })
    expect(init?.headers).not.toHaveProperty('Idempotency-Key')
  })

  it('recursively strips undeclared X.509 request properties without changing identity bytes or order', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(jsonResponse({
      kind: 'x509_csr',
      profileId: 'dev',
      effectiveParameters: { algorithm: 'ecdsa_p256' },
      secret: { format: 'pkcs8_private_key_pem', vaultText },
      public: { format: 'pkcs10_csr_pem', csrPem: csrPEM, fingerprint },
    }))
    const request = {
      kind: 'x509_csr',
      profileId: 'dev',
      ignoredTopLevel: true,
      parameters: {
        algorithm: 'ecdsa_p256',
        ignoredParameter: true,
        subject: { commonName: ' service.example ', organization: ['Second', 'First'], ignoredSubject: true },
        sans: { dnsNames: ['b.example', 'a.example'], ignoredSAN: true },
      },
    } satisfies X509RequestWithAdditions

    await api.generateMaterial(request)

    expect(JSON.parse(String(fetchMock.mock.lastCall?.[1]?.body))).toEqual({
      kind: 'x509_csr',
      profileId: 'dev',
      parameters: {
        algorithm: 'ecdsa_p256',
        subject: { commonName: ' service.example ', organization: ['Second', 'First'] },
        sans: { dnsNames: ['b.example', 'a.example'] },
      },
    })
  })

  it('rejects malformed or internally inconsistent secret-bearing responses', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse({
        kind: 'token',
        profileId: 'dev',
        effectiveParameters: { encoding: 'hex', bytes: 32 },
        secret: { format: 'token_base64url', vaultText },
      }))
      .mockResolvedValueOnce(jsonResponse({
        kind: 'x509_csr',
        profileId: 'dev',
        effectiveParameters: { algorithm: 'ecdsa_p256' },
        secret: { format: 'pkcs8_private_key_pem', vaultText },
      }))
      .mockResolvedValueOnce(jsonResponse({
        ...passwordResponse(),
        effectiveParameters: {
          ...passwordResponse().effectiveParameters,
          lowercase: false,
          uppercase: false,
          digits: false,
        },
      }))

    await expect(api.generateMaterial({ kind: 'token', profileId: 'dev', parameters: {} }))
      .rejects.toMatchObject({ name: 'ApiError', code: 'invalid_response' })
    await expect(api.generateMaterial({
      kind: 'x509_csr',
      profileId: 'dev',
      parameters: { algorithm: 'ecdsa_p256', subject: { commonName: 'service.example' } },
    })).rejects.toMatchObject({ name: 'ApiError', code: 'invalid_response' })
    await expect(api.generateMaterial({ kind: 'password', profileId: 'dev', parameters: {} }))
      .rejects.toMatchObject({ name: 'ApiError', code: 'invalid_response' })
    expect(fetchMock).toHaveBeenCalledTimes(3)
  })

  it('accepts canonical token and native age response forms', async () => {
    const ageRecipient = 'age1lvyvwawkr0mcnnnncaghunadrqkmuf9e6507x9y920xxpp866cnql7dp2z'
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse({
        kind: 'token',
        profileId: 'dev',
        effectiveParameters: { encoding: 'base64url', bytes: 32 },
        secret: { format: 'token_base64url', vaultText },
      }))
      .mockResolvedValueOnce(jsonResponse({
        kind: 'age_identity',
        profileId: 'dev',
        effectiveParameters: { algorithm: 'x25519' },
        secret: { format: 'age_x25519_identity', vaultText },
        public: { format: 'age_x25519_recipient', recipient: ageRecipient },
      }))

    await expect(api.generateMaterial({ kind: 'token', profileId: 'dev', parameters: {} }))
      .resolves.toMatchObject({ kind: 'token' })
    await expect(api.generateMaterial({ kind: 'age_identity', profileId: 'dev', parameters: {} }))
      .resolves.toMatchObject({ kind: 'age_identity', public: { recipient: ageRecipient } })
  })

  it('rejects responses for another invocation and noncanonical public serialization', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse({ ...passwordResponse(), profileId: 'production' }))
      .mockResolvedValueOnce(jsonResponse({
        kind: 'ssh_keypair',
        profileId: 'dev',
        effectiveParameters: { algorithm: 'ecdsa_p256' },
        secret: { format: 'openssh_private_key', vaultText },
        public: { format: 'openssh_authorized_key', authorizedKey: sshAuthorizedKey, fingerprint: sshFingerprint },
      }))
      .mockResolvedValueOnce(jsonResponse({
        kind: 'ssh_keypair',
        profileId: 'dev',
        effectiveParameters: { algorithm: 'ed25519' },
        secret: { format: 'openssh_private_key', vaultText },
        public: { format: 'openssh_authorized_key', authorizedKey: `${sshAuthorizedKey} comment`, fingerprint: sshFingerprint },
      }))

    await expect(api.generateMaterial({ kind: 'password', profileId: 'dev', parameters: {} }))
      .rejects.toMatchObject({ code: 'invalid_response' })
    await expect(api.generateMaterial({ kind: 'ssh_keypair', profileId: 'dev', parameters: { algorithm: 'ed25519' } }))
      .rejects.toMatchObject({ code: 'invalid_response' })
    await expect(api.generateMaterial({ kind: 'ssh_keypair', profileId: 'dev', parameters: { algorithm: 'ed25519' } }))
      .rejects.toMatchObject({ code: 'invalid_response' })
    expect(fetchMock).toHaveBeenCalledTimes(3)
  })

  it('fully consumes SSH key blobs, enforces RSA size, and requires PKCS#10 DER', async () => {
    const trailingEd25519 = `ssh-ed25519 ${globalThis.btoa(globalThis.atob(sshAuthorizedKey.split(' ')[1]) + '\x00')}`
    const invalidCSR = '-----BEGIN CERTIFICATE REQUEST-----\nMAMCAQA=\n-----END CERTIFICATE REQUEST-----\n'
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse({
        kind: 'ssh_keypair',
        profileId: 'dev',
        effectiveParameters: { algorithm: 'rsa_3072' },
        secret: { format: 'openssh_private_key', vaultText },
        public: { format: 'openssh_authorized_key', authorizedKey: rsaAuthorizedKey(3072), fingerprint },
      }))
      .mockResolvedValueOnce(jsonResponse({
        kind: 'ssh_keypair',
        profileId: 'dev',
        effectiveParameters: { algorithm: 'rsa_3072' },
        secret: { format: 'openssh_private_key', vaultText },
        public: { format: 'openssh_authorized_key', authorizedKey: rsaAuthorizedKey(4096), fingerprint },
      }))
      .mockResolvedValueOnce(jsonResponse({
        kind: 'ssh_keypair',
        profileId: 'dev',
        effectiveParameters: { algorithm: 'ed25519' },
        secret: { format: 'openssh_private_key', vaultText },
        public: { format: 'openssh_authorized_key', authorizedKey: trailingEd25519, fingerprint },
      }))
      .mockResolvedValueOnce(jsonResponse({
        kind: 'x509_csr',
        profileId: 'dev',
        effectiveParameters: { algorithm: 'ecdsa_p256' },
        secret: { format: 'pkcs8_private_key_pem', vaultText },
        public: { format: 'pkcs10_csr_pem', csrPem: invalidCSR, fingerprint },
      }))

    await expect(api.generateMaterial({ kind: 'ssh_keypair', profileId: 'dev', parameters: { algorithm: 'rsa_3072' } }))
      .resolves.toMatchObject({ public: { authorizedKey: rsaAuthorizedKey(3072) } })
    await expect(api.generateMaterial({ kind: 'ssh_keypair', profileId: 'dev', parameters: { algorithm: 'rsa_3072' } }))
      .rejects.toMatchObject({ code: 'invalid_response' })
    await expect(api.generateMaterial({ kind: 'ssh_keypair', profileId: 'dev', parameters: { algorithm: 'ed25519' } }))
      .rejects.toMatchObject({ code: 'invalid_response' })
    await expect(api.generateMaterial({
      kind: 'x509_csr',
      profileId: 'dev',
      parameters: { algorithm: 'ecdsa_p256', subject: { commonName: 'service.example' } },
    })).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('ignores and drops additive password response properties, including public', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(jsonResponse(passwordResponse({
      public: { futureValue: 'must not enter UI state' },
      futureField: true,
    })))

    await expect(api.generateMaterial({ kind: 'password', profileId: 'dev', parameters: {} }))
      .resolves.toEqual(passwordResponse())
  })
})
