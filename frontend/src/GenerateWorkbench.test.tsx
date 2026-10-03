import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, type GenerateRequest, type GenerateResponse, type Profile } from './api'
import GenerateWorkbench, { normalizePublicDownload } from './GenerateWorkbench'
import { formatAnsibleVaultSnippet } from './ansibleSnippet'
import { normalizeVaultPaste } from './pasteHandling'

const profiles: Profile[] = [
  { id: 'dev', label: 'Development', capabilities: { encrypt: true, decrypt: true, rotateSource: true, rotateDestination: true } },
]

const vaultPayload = `${'a'.repeat(64)}\n${'b'.repeat(64)}\n${'c'.repeat(32)}`
const vaultBody = [...vaultPayload]
  .map((character) => character.charCodeAt(0).toString(16).padStart(2, '0'))
  .join('')
  .match(/.{1,80}/g)?.join('\n') || ''
const vaultText = `$ANSIBLE_VAULT;1.2;AES256;dev\n${vaultBody}\n`
const sshAuthorizedKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
const sshFingerprint = 'SHA256:kmYcvdi2GkPeWxB6XLjrZB8JHsy2Hm8luHMFp9GMvqk'
const ageRecipient = 'age1lvyvwawkr0mcnnnncaghunadrqkmuf9e6507x9y920xxpp866cnql7dp2z'
const csrPEM = [
  '-----BEGIN CERTIFICATE REQUEST-----',
  'MIGZME0CAQAwGjEYMBYGA1UEAwwPc2VydmljZS5leGFtcGxlMCowBQYDK2VwAyEA',
  'nwQd4U7B1lyYq9K+KTsCLRL3Bwg0uER3F3y2GI3I8NWgADAFBgMrZXADQQAhoinL',
  'lJP7GK3r0yxKpkP4HHmXQ9egZ8yvKprUY3b+0x3LfVK58oyCefLMFhf58YP1zMiW',
  'Saivu0HqELyyZYYI',
  '-----END CERTIFICATE REQUEST-----',
  '',
].join('\n')
const x509Fingerprint = 'SHA256:NqTDLcU0/nq3jI+Mrf/fqaNvLW0/4hglFn1m1p0Y/OI'

function responseFor(request: GenerateRequest): GenerateResponse {
  switch (request.kind) {
    case 'password':
      return {
        kind: 'password',
        profileId: request.profileId,
        effectiveParameters: {
          length: request.parameters.length ?? 32,
          lowercase: request.parameters.lowercase ?? true,
          uppercase: request.parameters.uppercase ?? true,
          digits: request.parameters.digits ?? true,
          symbols: request.parameters.symbols ?? false,
          minLowercase: request.parameters.minLowercase ?? 1,
          minUppercase: request.parameters.minUppercase ?? 1,
          minDigits: request.parameters.minDigits ?? 1,
          minSymbols: request.parameters.minSymbols ?? 0,
          excludeAmbiguous: request.parameters.excludeAmbiguous ?? false,
        },
        secret: { format: 'password_ascii', vaultText },
      }
    case 'token':
      return {
        kind: 'token',
        profileId: request.profileId,
        effectiveParameters: { encoding: request.parameters.encoding ?? 'base64url', bytes: request.parameters.bytes ?? 32 },
        secret: { format: request.parameters.encoding === 'hex' ? 'token_hex' : 'token_base64url', vaultText },
      }
    case 'ssh_keypair':
      return {
        kind: 'ssh_keypair',
        profileId: request.profileId,
        effectiveParameters: { algorithm: request.parameters.algorithm },
        secret: { format: 'openssh_private_key', vaultText },
        public: { format: 'openssh_authorized_key', authorizedKey: sshAuthorizedKey, fingerprint: sshFingerprint },
      }
    case 'age_identity':
      return {
        kind: 'age_identity',
        profileId: request.profileId,
        effectiveParameters: { algorithm: 'x25519' },
        secret: { format: 'age_x25519_identity', vaultText },
        public: { format: 'age_x25519_recipient', recipient: ageRecipient },
      }
    case 'x509_csr':
      return {
        kind: 'x509_csr',
        profileId: request.profileId,
        effectiveParameters: { algorithm: request.parameters.algorithm },
        secret: { format: 'pkcs8_private_key_pem', vaultText },
        public: { format: 'pkcs10_csr_pem', csrPem: csrPEM, fingerprint: x509Fingerprint },
      }
  }
}

function renderWorkbench(generate = vi.fn(async (request: GenerateRequest) => responseFor(request))) {
  render(
    <GenerateWorkbench
      profiles={profiles}
      profilesReady
      disabled={false}
      modeSwitch={<button type="button">Change operation</button>}
      onUnauthorized={vi.fn()}
      onForbidden={vi.fn().mockResolvedValue(undefined)}
      generate={generate}
    />,
  )
  return generate
}

describe('Generate workbench', () => {
  afterEach(() => {
    cleanup()
    vi.restoreAllMocks()
  })

  it.each(['password', 'token', 'ssh_keypair', 'age_identity', 'x509_csr'] as const)('copies only the sealed %s value as an Ansible snippet', async (kind) => {
    const generate = renderWorkbench()
    const user = userEvent.setup()
    const clipboard = { writeText: vi.fn<(value: string) => Promise<void>>().mockResolvedValue(undefined) }
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: clipboard })
    expect(screen.queryByRole('textbox', { name: 'Ansible variable name' })).not.toBeInTheDocument()
    await user.selectOptions(screen.getByRole('combobox', { name: 'Material' }), kind)
    if (kind === 'x509_csr') await user.type(screen.getByRole('textbox', { name: 'Common name' }), 'service.example')
    await user.click(screen.getByRole('button', { name: 'Generate sealed material' }))
    const name = await screen.findByRole('textbox', { name: 'Ansible variable name' })
    const copy = screen.getByRole('button', { name: 'Copy Ansible snippet' })
    expect(copy).toBeDisabled()
    await user.type(name, 'yes')
    name.focus()
    await user.keyboard('{Enter}')
    expect(generate).toHaveBeenCalledOnce()
    await user.click(copy)
    expect(clipboard.writeText).toHaveBeenCalledOnce()
    const [snippet] = clipboard.writeText.mock.calls[0]
    expect(snippet).toBe(formatAnsibleVaultSnippet('yes', vaultText))
    expect(normalizeVaultPaste(snippet)).toBe(vaultText.trim())
    expect(screen.getByText('Copied Ansible snippet')).toBeVisible()
    expect(generate).toHaveBeenCalledOnce()
  })

  it('uses accessible identifier validation without changing the generated result', async () => {
    renderWorkbench()
    const user = userEvent.setup()
    const clipboard = { writeText: vi.fn().mockResolvedValue(undefined) }
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: clipboard })
    await user.click(screen.getByRole('button', { name: 'Generate sealed material' }))
    const name = await screen.findByRole('textbox', { name: 'Ansible variable name' })
    expect(name).toHaveAttribute('autocapitalize', 'off')
    expect(name).toHaveAttribute('autocorrect', 'off')
    for (const [value, message] of [
      ['1secret', 'Start with a letter or underscore.'],
      ['bad-key', 'Variable names cannot contain hyphens.'],
      ['class', 'This name is reserved by Ansible.'],
      ['secret\nother: value', 'Use only letters, numbers, and underscores.'],
    ]) {
      fireEvent.change(name, { target: { value } })
      expect(name).toHaveAttribute('aria-invalid', 'true')
      expect(name).toHaveAccessibleDescription(message)
      expect(screen.getByRole('button', { name: 'Copy Ansible snippet' })).toBeDisabled()
    }
    expect(clipboard.writeText).not.toHaveBeenCalled()
    fireEvent.change(name, { target: { value: 'app_secret' } })
    expect(name).toHaveAttribute('aria-invalid', 'false')
    expect(screen.getByRole('button', { name: 'Copy Ansible snippet' })).toBeEnabled()
    expect(screen.getByRole('textbox', { name: 'Sealed Vault value' })).toHaveValue(vaultText)
  })

  it.each(['unavailable', 'blocked'])('provides a manual snippet when clipboard access is %s and clears it on retry', async (failure) => {
    renderWorkbench()
    const user = userEvent.setup()
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: failure === 'unavailable' ? undefined : { writeText: vi.fn().mockRejectedValue(new Error('denied')) },
    })
    await user.click(screen.getByRole('button', { name: 'Generate sealed material' }))
    const name = await screen.findByRole('textbox', { name: 'Ansible variable name' })
    await user.type(name, 'app_secret')
    await user.click(screen.getByRole('button', { name: 'Copy Ansible snippet' }))
    const fallback = await screen.findByRole('textbox', { name: 'Ansible snippet to copy manually' })
    expect(fallback).toHaveAttribute('readonly')
    expect(fallback).toHaveValue(formatAnsibleVaultSnippet('app_secret', vaultText))
    expect(screen.getByRole('alert')).toHaveTextContent(`Clipboard access was ${failure}; copy the Ansible snippet manually`)
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: vi.fn().mockResolvedValue(undefined) } })
    await user.click(screen.getByRole('button', { name: 'Copy Ansible snippet' }))
    expect(screen.queryByRole('textbox', { name: 'Ansible snippet to copy manually' })).not.toBeInTheDocument()
    expect(screen.getByText('Copied Ansible snippet')).toBeVisible()
  })

  it('rejects a sealed result ending in an unpaired high surrogate before snippet copy', async () => {
    const malformedText = `${vaultText.trimEnd()}${String.fromCharCode(0xD800)}`
    renderWorkbench(vi.fn(async (request: GenerateRequest) => {
      const response = responseFor(request)
      response.secret.vaultText = malformedText
      return response
    }))
    const user = userEvent.setup()
    const clipboard = { writeText: vi.fn().mockResolvedValue(undefined) }
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: clipboard })
    await user.click(screen.getByRole('button', { name: 'Generate sealed material' }))
    await user.type(await screen.findByRole('textbox', { name: 'Ansible variable name' }), 'app_secret')
    await user.click(screen.getByRole('button', { name: 'Copy Ansible snippet' }))

    expect(screen.getByRole('alert')).toHaveTextContent('Could not prepare the Ansible snippet; copy the result manually')
    expect(screen.getByRole('alert')).not.toHaveTextContent(malformedText)
    expect(clipboard.writeText).not.toHaveBeenCalled()
    expect(screen.queryByRole('textbox', { name: 'Ansible snippet to copy manually' })).not.toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: 'Sealed Vault value' })).toHaveValue(malformedText)
  })

  it('discards late snippet feedback on rename or a new result and clears snippet state with the form', async () => {
    renderWorkbench()
    const user = userEvent.setup()
    let rejectCopy!: (reason: Error) => void
    const clipboard = { writeText: vi.fn(() => new Promise<void>((_resolve, reject) => { rejectCopy = reject })) }
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: clipboard })
    await user.click(screen.getByRole('button', { name: 'Generate sealed material' }))
    const name = await screen.findByRole('textbox', { name: 'Ansible variable name' })
    await user.type(name, 'old_name')
    await user.click(screen.getByRole('button', { name: 'Copy Ansible snippet' }))
    fireEvent.change(name, { target: { value: 'new_name' } })
    await act(async () => rejectCopy(new Error('denied')))
    expect(screen.queryByRole('textbox', { name: 'Ansible snippet to copy manually' })).not.toBeInTheDocument()
    expect(screen.queryByText(/Clipboard access/)).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Copy Ansible snippet' }))
    const rejectOldResult = rejectCopy
    await user.click(screen.getByRole('button', { name: 'Generate sealed material' }))
    expect(await screen.findByRole('textbox', { name: 'Ansible variable name' })).toHaveValue('')
    await act(async () => rejectOldResult(new Error('denied')))
    expect(screen.queryByRole('textbox', { name: 'Ansible snippet to copy manually' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Clear Generate form' }))
    expect(screen.queryByRole('textbox', { name: 'Ansible variable name' })).not.toBeInTheDocument()
  })

  it('sends explicit visible defaults for every material kind', async () => {
    const generate = renderWorkbench()
    const user = userEvent.setup()
    const material = screen.getByRole('combobox', { name: 'Material' })

    expect(screen.getByRole('spinbutton', { name: 'Length' })).toHaveValue(32)
    expect(screen.getByRole('checkbox', { name: 'Lowercase' })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: 'Uppercase' })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: 'Digits' })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: 'Symbols' })).not.toBeChecked()
    await user.click(screen.getByRole('button', { name: 'Generate sealed material' }))
    await waitFor(() => expect(generate).toHaveBeenCalledTimes(1))
    expect(generate.mock.calls[0]?.[0]).toEqual({
      kind: 'password',
      profileId: 'dev',
      parameters: {
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
    })
    expect(await screen.findByRole('textbox', { name: 'Sealed Vault value' })).toHaveValue(vaultText)

    await user.selectOptions(material, 'token')
    expect(screen.queryByRole('textbox', { name: 'Sealed Vault value' })).not.toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Encoding' })).toHaveValue('base64url')
    expect(screen.getByRole('spinbutton', { name: 'Random bytes' })).toHaveValue(32)
    await user.click(screen.getByRole('button', { name: 'Generate sealed material' }))

    await user.selectOptions(material, 'ssh_keypair')
    expect(screen.getByRole('combobox', { name: 'SSH algorithm' })).toHaveValue('ed25519')
    await user.click(screen.getByRole('button', { name: 'Generate sealed material' }))

    await user.selectOptions(material, 'age_identity')
    expect(screen.getByText('X25519')).toBeVisible()
    await user.click(screen.getByRole('button', { name: 'Generate sealed material' }))

    await user.selectOptions(material, 'x509_csr')
    expect(screen.getByRole('combobox', { name: 'Private-key algorithm' })).toHaveValue('ecdsa_p256')
    expect(screen.getByRole('button', { name: 'Generate sealed material' })).toBeDisabled()
    await user.type(screen.getByRole('textbox', { name: 'Common name' }), 'service.example')
    await user.click(screen.getByRole('button', { name: 'Generate sealed material' }))

    await waitFor(() => expect(generate).toHaveBeenCalledTimes(5))
    expect(generate.mock.calls.slice(1).map(([request]) => request)).toEqual([
      { kind: 'token', profileId: 'dev', parameters: { encoding: 'base64url', bytes: 32 } },
      { kind: 'ssh_keypair', profileId: 'dev', parameters: { algorithm: 'ed25519' } },
      { kind: 'age_identity', profileId: 'dev', parameters: {} },
      { kind: 'x509_csr', profileId: 'dev', parameters: { algorithm: 'ecdsa_p256', subject: { commonName: 'service.example' } } },
    ])
    expect(screen.getByLabelText('Effective parameters')).toHaveTextContent('ECDSA P-256')
    await user.click(screen.getByRole('button', { name: 'Clear Generate form' }))
    expect(material).toHaveValue('password')
    expect(screen.getByRole('spinbutton', { name: 'Length' })).toHaveValue(32)
    expect(screen.queryByRole('textbox', { name: 'Sealed Vault value' })).not.toBeInTheDocument()
  })

  it('preserves caller-entered X.509 values and array order in the typed request', async () => {
    const generate = renderWorkbench()
    const user = userEvent.setup()
    await user.selectOptions(screen.getByRole('combobox', { name: 'Material' }), 'x509_csr')
    await user.selectOptions(screen.getByRole('combobox', { name: 'Private-key algorithm' }), 'rsa_3072')
    fireEvent.change(screen.getByRole('textbox', { name: 'Common name' }), { target: { value: ' service.example ' } })
    fireEvent.change(screen.getByRole('textbox', { name: 'Country' }), { target: { value: 'DE\nUS' } })
    fireEvent.change(screen.getByRole('textbox', { name: 'Organization' }), { target: { value: 'Second\nFirst' } })
    fireEvent.change(screen.getByRole('textbox', { name: 'DNS names' }), { target: { value: 'b.example\n\na.example' } })
    fireEvent.change(screen.getByRole('textbox', { name: 'URIs' }), { target: { value: 'spiffe://example/service\nhttps://example.test/path' } })

    expect(screen.getByRole('button', { name: 'Generate sealed material' })).toBeDisabled()
    expect(screen.getByRole('alert')).toHaveTextContent('cannot contain empty rows')
    fireEvent.change(screen.getByRole('textbox', { name: 'DNS names' }), { target: { value: 'b.example\na.example\n' } })
    expect(screen.getByRole('button', { name: 'Generate sealed material' })).toBeDisabled()
    expect(screen.getByRole('alert')).toHaveTextContent('cannot contain empty rows')
    fireEvent.change(screen.getByRole('textbox', { name: 'DNS names' }), { target: { value: 'b.example\na.example' } })

    await user.click(screen.getByRole('button', { name: 'Generate sealed material' }))

    await waitFor(() => expect(generate).toHaveBeenCalledOnce())
    expect(generate.mock.calls[0]?.[0]).toEqual({
      kind: 'x509_csr',
      profileId: 'dev',
      parameters: {
        algorithm: 'rsa_3072',
        subject: { commonName: ' service.example ', country: ['DE', 'US'], organization: ['Second', 'First'] },
        sans: { dnsNames: ['b.example', 'a.example'], uris: ['spiffe://example/service', 'https://example.test/path'] },
      },
    })
  })

  it('copies every handoff value and downloads only the normalized public artifact', async () => {
    const generate = renderWorkbench()
    const user = userEvent.setup()
    const clipboard = { writeText: vi.fn().mockResolvedValue(undefined) }
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: clipboard })
    let downloadedBlob: Blob | undefined
    const createObjectURL = vi.fn((blob: Blob) => {
      downloadedBlob = blob
      return 'blob:fixture'
    })
    const revokeObjectURL = vi.fn()
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectURL })
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: revokeObjectURL })
    let clickedDownload = ''
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function click(this: HTMLAnchorElement) {
      clickedDownload = this.download
    })

    await user.selectOptions(screen.getByRole('combobox', { name: 'Material' }), 'ssh_keypair')
    await user.click(screen.getByRole('button', { name: 'Generate sealed material' }))
    await screen.findByRole('textbox', { name: 'SSH public key' })

    await user.click(screen.getByRole('button', { name: 'Copy sealed Vault value' }))
    await user.click(screen.getByRole('button', { name: 'Copy SSH public key' }))
    await user.click(screen.getByRole('button', { name: 'Copy fingerprint' }))
    expect(clipboard.writeText.mock.calls.map(([value]) => value)).toEqual([vaultText, sshAuthorizedKey, sshFingerprint])

    expect(screen.queryByRole('button', { name: /Download sealed/i })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Download SSH public key' }))
    expect(clickedDownload).toBe('vaultsmith-ssh-public-key.pub')
    expect(createObjectURL).toHaveBeenCalledOnce()
    expect(downloadedBlob?.type).toBe('text/plain;charset=utf-8')
    await expect(downloadedBlob?.text()).resolves.toBe(`${sshAuthorizedKey}\n`)
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:fixture')
    expect(generate).toHaveBeenCalledOnce()
  })

  it('clears the previous sealed result before a new randomized request resolves', async () => {
    let resolveSecond!: (response: GenerateResponse) => void
    const generate = vi.fn()
      .mockResolvedValueOnce(responseFor({ kind: 'password', profileId: 'dev', parameters: {} }))
      .mockImplementationOnce(() => new Promise<GenerateResponse>((resolve) => { resolveSecond = resolve }))
    const user = userEvent.setup()
    renderWorkbench(generate)

    await user.click(screen.getByRole('button', { name: 'Generate sealed material' }))
    expect(await screen.findByRole('textbox', { name: 'Sealed Vault value' })).toHaveValue(vaultText)
    fireEvent.submit(screen.getByRole('form', { name: 'Generate material form' }))

    expect(screen.queryByRole('textbox', { name: 'Sealed Vault value' })).not.toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveTextContent('Generating and sealing')
    expect(screen.getByRole('button', { name: 'Change operation' })).toBeDisabled()
    await act(async () => resolveSecond(responseFor({ kind: 'password', profileId: 'dev', parameters: {} })))
    expect(await screen.findByRole('textbox', { name: 'Sealed Vault value' })).toHaveValue(vaultText)
  })

  it('treats a dropped connection as an ambiguous non-retryable outcome', async () => {
    const generate = vi.fn().mockRejectedValue(new ApiError('connection lost', 'network_error'))
    const user = userEvent.setup()
    renderWorkbench(generate)

    await user.click(screen.getByRole('button', { name: 'Generate sealed material' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('result is unknown; do not retry automatically')
    expect(generate).toHaveBeenCalledOnce()
    expect(screen.queryByRole('textbox', { name: 'Sealed Vault value' })).not.toBeInTheDocument()
  })

  it('normalizes any trailing public line endings to exactly one LF', () => {
    expect(normalizePublicDownload('public-value')).toBe('public-value\n')
    expect(normalizePublicDownload('public-value\n')).toBe('public-value\n')
    expect(normalizePublicDownload('public-value\r\n\n')).toBe('public-value\n')
  })
})
