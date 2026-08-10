import { act, cleanup, createEvent, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { MAX_PLAINTEXT_BYTES, OPERATION_TIMEOUT_MS } from './api'
import App from './App'

const jsonResponse = (body: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })

const emptyResponse = (status = 204) => new Response(null, { status })

const defaultProfiles = [{ id: 'dev', label: 'Development', capabilities: { encrypt: true, decrypt: true } }]
const sourceAndDestinationProfiles = [
  ...defaultProfiles,
  { id: 'prod', label: 'Production', capabilities: { encrypt: true, decrypt: true } },
]
const asymmetricProfiles = [
  { id: 'write', label: 'Write only', capabilities: { encrypt: true, decrypt: false } },
  { id: 'read', label: 'Read only', capabilities: { encrypt: false, decrypt: true } },
]

function profilesResponse(profiles = defaultProfiles) {
  return jsonResponse({ profiles })
}

const sessionResponse = () => jsonResponse({ authenticated: false, authRequired: false, csrfToken: '' })
const authenticatedSessionResponse = () => jsonResponse({
  authenticated: true,
  authRequired: true,
  email: 'operator@example.test',
  csrfToken: 'csrf-token',
})

function mockProfileLoad(profiles = defaultProfiles) {
  return vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(sessionResponse())
    .mockResolvedValueOnce(profilesResponse(profiles))
}

function mockAuthenticatedProfileLoad(profiles = defaultProfiles) {
  return vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(authenticatedSessionResponse())
    .mockResolvedValueOnce(profilesResponse(profiles))
}

const pastedVault = '$ANSIBLE_VAULT;1.2;AES256;dev\n00112233'
const pastedYamlVault = `app_secret: !vault |\n          ${pastedVault.replace('\n', '\n          ')}`

async function findReadyValueInput() {
  const input = await screen.findByRole('textbox', { name: 'Value to encrypt' })
  await waitFor(() => expect(input).toBeEnabled())
  return input
}

describe('Vaultsmith operator experience', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  afterEach(() => {
    vi.useRealTimers()
    cleanup()
  })

  it('keeps the user on an explicit signed-out screen after logout', async () => {
    mockAuthenticatedProfileLoad()
      .mockResolvedValueOnce(emptyResponse())
    const user = userEvent.setup()

    render(<App />)
    await user.click(await screen.findByRole('button', { name: 'Sign out' }))

    expect(await screen.findByRole('heading', { level: 1, name: 'Signed out' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Sign in again' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Sign out' })).not.toBeInTheDocument()
  })

  it('clears revealed plaintext immediately and keeps sign-out single-flight', async () => {
    let resolveLogout!: (response: Response) => void
    let resolveResultCopy!: () => void
    const fetchMock = mockAuthenticatedProfileLoad()
      .mockResolvedValueOnce(jsonResponse({ value: 'decrypted-secret' }))
      .mockImplementationOnce(() => new Promise<Response>((resolve) => {
        resolveLogout = resolve
      }))
    const user = userEvent.setup()
    const clipboard = { writeText: vi.fn(() => new Promise<void>((resolve) => { resolveResultCopy = resolve })) }
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: clipboard })

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set decrypt mode' }))
    const input = screen.getByRole('textbox', { name: 'Protected value to decrypt' })
    await user.type(input, pastedVault)
    await user.click(screen.getByRole('button', { name: 'Decrypt' }))
    await user.click(await screen.findByRole('button', { name: 'Reveal result' }))
    expect(screen.getByRole('textbox', { name: 'Decrypted value' })).toHaveValue('decrypted-secret')
    await user.click(screen.getByRole('button', { name: 'Copy result' }))
    expect(clipboard.writeText).toHaveBeenCalledWith('decrypted-secret')

    const signOut = screen.getByRole('button', { name: 'Sign out' })
    act(() => {
      fireEvent.click(signOut)
      fireEvent.click(signOut)
    })

    expect(screen.getByRole('button', { name: 'Signing out…' })).toBeDisabled()
    expect(screen.getByRole('form', { name: 'Vault operation form' })).toHaveAttribute('aria-busy', 'true')
    expect(input).toBeDisabled()
    expect(input).toHaveValue('')
    expect(screen.getByRole('textbox', { name: 'Decrypted value' })).toHaveValue('')
    expect(screen.queryByRole('button', { name: 'Reveal result' })).not.toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Environment' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Set encrypt mode' })).toBeDisabled()
    await waitFor(() => expect(fetchMock.mock.calls.filter(([path]) => path === '/auth/logout')).toHaveLength(1))

    await act(async () => { resolveResultCopy() })
    expect(screen.getByRole('status')).toHaveTextContent('Signing out…')
    expect(screen.getByRole('textbox', { name: 'Decrypted value' })).toHaveValue('')

    resolveLogout(emptyResponse())
    expect(await screen.findByRole('heading', { level: 1, name: 'Signed out' })).toBeInTheDocument()
  })

  it('clears snippet state and ignores a pending clipboard callback when sign-out fails', async () => {
    const ciphertext = '$ANSIBLE_VAULT;1.2;AES256;dev\n00112233'
    let rejectLateCopy!: (reason?: unknown) => void
    const fetchMock = mockAuthenticatedProfileLoad()
      .mockResolvedValueOnce(jsonResponse({ value: ciphertext }))
      .mockResolvedValueOnce(jsonResponse(
        { error: { code: 'not_ready', message: 'private service detail' } },
        { status: 503 },
      ))
    const clipboard = {
      writeText: vi.fn()
        .mockRejectedValueOnce(new Error('first clipboard failure'))
        .mockImplementationOnce(() => new Promise<void>((_resolve, reject) => {
          rejectLateCopy = reject
        })),
    }
    const user = userEvent.setup()
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: clipboard })

    render(<App />)
    const input = await findReadyValueInput()
    await user.type(input, 'fixture-value')
    await user.click(screen.getByRole('button', { name: 'Encrypt' }))
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Encrypted value' })).toHaveValue(ciphertext))
    await user.type(screen.getByRole('textbox', { name: 'Ansible variable name' }), 'app_secret')
    const copySnippet = screen.getByRole('button', { name: 'Copy Ansible snippet' })
    await user.click(copySnippet)
    expect(await screen.findByRole('textbox', { name: 'Ansible snippet to copy manually' })).toBeInTheDocument()
    await user.click(copySnippet)

    await user.click(screen.getByRole('button', { name: 'Sign out' }))

    expect(input).toHaveValue('')
    expect(screen.getByRole('textbox', { name: 'Encrypted value' })).toHaveValue('')
    expect(screen.queryByRole('textbox', { name: 'Ansible variable name' })).not.toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: 'Ansible snippet to copy manually' })).not.toBeInTheDocument()
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Sign-out was not confirmed. The service is unavailable. Retry sign-out.')
    expect(alert).not.toHaveTextContent('private service detail')
    expect(screen.getByRole('button', { name: 'Retry sign out' })).toBeInTheDocument()
    expect(fetchMock.mock.calls.filter(([path]) => path === '/auth/logout')).toHaveLength(1)

    await act(async () => {
      rejectLateCopy(new Error('late clipboard failure'))
    })

    expect(screen.getByRole('alert')).toHaveTextContent('Sign-out was not confirmed')
    expect(screen.queryByRole('textbox', { name: 'Ansible snippet to copy manually' })).not.toBeInTheDocument()
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })

  it('aborts an active operation and ignores its late completion when sign-out starts', async () => {
    let resolveOperation!: (response: Response) => void
    let resolveLogout: ((response: Response) => void) | undefined
    let operationSignal: AbortSignal | null | undefined
    const operationResponse = new Promise<Response>((resolve) => {
      resolveOperation = resolve
    })
    const fetchMock = mockAuthenticatedProfileLoad()
      .mockImplementationOnce((_input, init) => {
        operationSignal = init?.signal
        return operationResponse
      })
      .mockImplementationOnce(() => new Promise<Response>((resolve) => {
        resolveLogout = resolve
      }))
    const user = userEvent.setup()

    render(<App />)
    const input = await findReadyValueInput()
    await user.type(input, 'fixture-value')
    await user.click(screen.getByRole('button', { name: 'Encrypt' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Encrypting…')

    const signOut = screen.getByRole('button', { name: 'Sign out' })
    try {
      expect(signOut).toBeEnabled()
      await user.click(signOut)
      expect(operationSignal?.aborted).toBe(true)
      expect(input).toHaveValue('')
      expect(screen.getByRole('textbox', { name: 'Encrypted value' })).toHaveValue('')
      expect(fetchMock.mock.calls.filter(([path]) => path === '/auth/logout')).toHaveLength(1)

      resolveLogout?.(jsonResponse(
        { error: { code: 'not_ready', message: 'private service detail' } },
        { status: 503 },
      ))
      expect(await screen.findByRole('alert')).toHaveTextContent('Sign-out was not confirmed')

      resolveOperation(jsonResponse({ value: 'late-vault-output' }))
      await act(async () => { await Promise.resolve() })
      expect(screen.getByRole('textbox', { name: 'Encrypted value' })).toHaveValue('')
      expect(screen.queryByDisplayValue('late-vault-output')).not.toBeInTheDocument()
    } finally {
      resolveLogout?.(emptyResponse())
      resolveOperation(emptyResponse())
    }
  })

  it('times out an unconfirmed sign-out, ignores its late response, and retries manually', async () => {
    let resolveLateLogout!: (response: Response) => void
    let logoutSignal: AbortSignal | null | undefined
    const fetchMock = mockAuthenticatedProfileLoad()
      .mockImplementationOnce((_input, init) => {
        logoutSignal = init?.signal
        return new Promise<Response>((resolve) => {
          resolveLateLogout = resolve
        })
      })
      .mockResolvedValueOnce(emptyResponse())

    render(<App />)
    const input = await findReadyValueInput()
    fireEvent.change(input, { target: { value: 'fixture-value' } })
    vi.useFakeTimers()

    try {
      fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
      expect(input).toHaveValue('')
      expect(screen.getByRole('button', { name: 'Signing out…' })).toBeDisabled()
      await act(async () => { await vi.advanceTimersByTimeAsync(10_000) })

      expect(logoutSignal?.aborted).toBe(true)
      expect(screen.queryByRole('heading', { name: 'Signed out' })).not.toBeInTheDocument()
      expect(screen.getByRole('alert')).toHaveTextContent('Sign-out was not confirmed. The request timed out. Retry sign-out.')
      expect(fetchMock.mock.calls.filter(([path]) => path === '/auth/logout')).toHaveLength(1)

      resolveLateLogout(emptyResponse())
      await act(async () => { await Promise.resolve() })
      expect(screen.queryByRole('heading', { name: 'Signed out' })).not.toBeInTheDocument()
      expect(screen.getByRole('alert')).toHaveTextContent('Sign-out was not confirmed')

      fireEvent.click(screen.getByRole('button', { name: 'Retry sign out' }))
      await act(async () => { await Promise.resolve(); await Promise.resolve() })
      expect(screen.getByRole('heading', { level: 1, name: 'Signed out' })).toBeInTheDocument()
      expect(fetchMock.mock.calls.filter(([path]) => path === '/auth/logout')).toHaveLength(2)
    } finally {
      resolveLateLogout?.(emptyResponse())
      vi.useRealTimers()
    }
  })

  it('shows the signed-out screen after a verified anonymous session', async () => {
    const fetchMock = mockAuthenticatedProfileLoad()
      .mockResolvedValueOnce(jsonResponse({ accepted: true }))
      .mockResolvedValueOnce(jsonResponse({ authenticated: false, authRequired: true, csrfToken: '' }))
    const user = userEvent.setup()

    render(<App />)
    await user.click(await screen.findByRole('button', { name: 'Sign out' }))

    expect(await screen.findByRole('heading', { level: 1, name: 'Signed out' })).toBeInTheDocument()
    expect(fetchMock.mock.calls.filter(([path]) => path === '/api/v1/session')).toHaveLength(2)
  })

  it('invalidates a pending profile load when sign-out starts and ignores its late completion', async () => {
    let resolveProfiles!: (response: Response) => void
    let profileSignal: AbortSignal | null | undefined
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(authenticatedSessionResponse())
      .mockImplementationOnce((_input, init) => {
        profileSignal = init?.signal
        return new Promise<Response>((resolve) => {
          resolveProfiles = resolve
        })
      })
      .mockResolvedValueOnce(jsonResponse(
        { error: { code: 'not_ready', message: 'private service detail' } },
        { status: 503 },
      ))
    const user = userEvent.setup()

    render(<App />)
    await user.click(await screen.findByRole('button', { name: 'Sign out' }))

    expect(profileSignal?.aborted).toBe(true)
    expect(await screen.findByRole('alert')).toHaveTextContent('Sign-out was not confirmed')
    resolveProfiles(profilesResponse())
    await act(async () => { await Promise.resolve(); await Promise.resolve() })

    expect(screen.getByRole('alert')).toHaveTextContent('Sign-out was not confirmed')
    expect(screen.queryByRole('option', { name: 'Development' })).not.toBeInTheDocument()
    expect(fetchMock.mock.calls.filter(([path]) => path === '/api/v1/profiles')).toHaveLength(1)
  })

  it('disables environment-load retry while sign-out is in progress', async () => {
    let resolveLogout!: (response: Response) => void
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(authenticatedSessionResponse())
      .mockRejectedValueOnce(new Error('offline'))
      .mockImplementationOnce(() => new Promise<Response>((resolve) => {
        resolveLogout = resolve
      }))
    const user = userEvent.setup()

    render(<App />)
    const retryProfiles = await screen.findByRole('button', { name: 'Retry loading environments' })
    await user.click(screen.getByRole('button', { name: 'Sign out' }))

    expect(retryProfiles).toBeDisabled()
    fireEvent.click(retryProfiles)
    expect(fetchMock).toHaveBeenCalledTimes(3)

    resolveLogout(jsonResponse(
      { error: { code: 'not_ready', message: 'private service detail' } },
      { status: 503 },
    ))
    expect(await screen.findByRole('alert')).toHaveTextContent('Sign-out was not confirmed')
  })

  it('loads a public profile label without exposing its environment name', async () => {
    const fetchMock = mockProfileLoad()

    render(<App />)

    expect(screen.getByRole('status')).toHaveTextContent('Checking session')
    expect(await screen.findByRole('option', { name: 'Development' })).toBeInTheDocument()
    expect(screen.queryByText(/VAULT_PASSWORD/i)).not.toBeInTheDocument()
    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/v1/session', expect.anything())
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/v1/profiles', expect.anything())
  })

  it('uses endpoint-specific guidance when profiles cannot be found', async () => {
    const sentinel = 'private-route-detail'
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(sessionResponse())
      .mockResolvedValueOnce(jsonResponse(
        { error: { code: 'not_found', message: sentinel } },
        { status: 404 },
      ))

    render(<App />)

    expect(await screen.findByRole('alert')).toHaveTextContent('The environments endpoint was not found. Check the service route and try again.')
    expect(screen.getByRole('alert')).not.toHaveTextContent(sentinel)
  })

  it('encrypts the entered value using the selected profile', async () => {
    const fetchMock = mockProfileLoad()
      .mockResolvedValueOnce(jsonResponse({ value: 'vault-output' }))
    const user = userEvent.setup()

    render(<App />)
    const input = await findReadyValueInput()
    expect(screen.getByRole('button', { name: 'Clear values' })).toBeDisabled()
    await user.type(input, 'fixture-value')
    expect(screen.getByRole('button', { name: 'Clear values' })).toBeEnabled()
    await user.click(screen.getByRole('button', { name: 'Encrypt' }))

    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Encrypted value' })).toHaveValue('vault-output'))
    expect(fetchMock).toHaveBeenLastCalledWith(
      '/api/v1/operations',
      expect.objectContaining({
        method: 'POST',
      }),
    )
    expect(JSON.parse(String(fetchMock.mock.lastCall?.[1]?.body))).toEqual({ profileId: 'dev', mode: 'encrypt', value: 'fixture-value' })
  })

  it('copies an encrypted result as an Ansible snippet with a valid variable name', async () => {
    const ciphertext = '$ANSIBLE_VAULT;1.2;AES256;dev\n00112233'
    mockProfileLoad()
      .mockResolvedValueOnce(jsonResponse({ value: ciphertext }))
    const clipboard = { writeText: vi.fn().mockResolvedValue(undefined) }
    const user = userEvent.setup()
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: clipboard })

    render(<App />)
    const input = await findReadyValueInput()
    await user.type(input, 'fixture-value')
    await user.click(screen.getByRole('button', { name: 'Encrypt' }))
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Encrypted value' })).toHaveValue(ciphertext))

    const keyInput = screen.getByRole('textbox', { name: 'Ansible variable name' })
    const snippetButton = screen.getByRole('button', { name: 'Copy Ansible snippet' })
    expect(keyInput).toHaveAttribute('autocapitalize', 'off')
    expect(keyInput).toHaveAttribute('autocorrect', 'off')
    expect(snippetButton).toBeDisabled()
    await user.type(keyInput, 'bad-key')
    expect(snippetButton).toBeDisabled()
    await user.clear(keyInput)
    await user.type(keyInput, 'class')
    expect(snippetButton).toBeDisabled()
    expect(screen.getByText('This name is reserved by Ansible.')).toBeVisible()
    await user.clear(keyInput)
    await user.type(keyInput, 'app_secret')
    expect(snippetButton).toBeEnabled()
    keyInput.focus()
    await user.keyboard('{Enter}')

    await user.click(snippetButton)

    expect(clipboard.writeText).toHaveBeenCalledWith(
      `app_secret: !vault |\n          $ANSIBLE_VAULT;1.2;AES256;dev\n          00112233`,
    )
    expect(screen.getByRole('status')).toHaveTextContent('Copied Ansible snippet')
    expect(screen.getByRole('status')).not.toHaveTextContent(ciphertext)
    await user.clear(keyInput)
    await user.type(keyInput, 'db_secret')
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })

  it('keeps Ansible snippet controls out of decrypt results and gives generic copy failure guidance', async () => {
    const ciphertext = '$ANSIBLE_VAULT;1.1;AES256\n00112233'
    mockProfileLoad()
      .mockResolvedValueOnce(jsonResponse({ value: 'decrypted-value' }))
    const clipboard = { writeText: vi.fn().mockRejectedValue(new Error('private clipboard detail')) }
    const user = userEvent.setup()
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: clipboard })

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set decrypt mode' }))
    await user.type(screen.getByRole('textbox', { name: 'Protected value to decrypt' }), ciphertext)
    await user.click(screen.getByRole('button', { name: 'Decrypt' }))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Reveal result' })).toBeInTheDocument())

    expect(screen.queryByRole('textbox', { name: 'Ansible variable name' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Copy without revealing' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Clipboard access was blocked; reveal the result to copy it manually')
    expect(screen.getByRole('button', { name: 'Reveal result' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Reveal result' }))
    await user.click(screen.getByRole('button', { name: 'Copy result' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Clipboard access was blocked; copy the result manually')
    expect(screen.getByRole('alert')).not.toHaveTextContent('private clipboard detail')
  })

  it('renders a selectable Ansible snippet fallback when snippet copy fails', async () => {
    const ciphertext = '$ANSIBLE_VAULT;1.2;AES256;dev\n00112233'
    const snippet = `app_secret: !vault |\n          $ANSIBLE_VAULT;1.2;AES256;dev\n          00112233`
    mockProfileLoad()
      .mockResolvedValueOnce(jsonResponse({ value: ciphertext }))
    const clipboard = { writeText: vi.fn().mockRejectedValue(new Error('private clipboard detail')) }
    const user = userEvent.setup()
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: clipboard })

    render(<App />)
    const input = await findReadyValueInput()
    await user.type(input, 'fixture-value')
    await user.click(screen.getByRole('button', { name: 'Encrypt' }))
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Encrypted value' })).toHaveValue(ciphertext))
    await user.type(screen.getByRole('textbox', { name: 'Ansible variable name' }), 'app_secret')
    await user.click(screen.getByRole('button', { name: 'Copy Ansible snippet' }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Clipboard access was blocked; copy the Ansible snippet manually')
    expect(alert).not.toHaveTextContent(ciphertext)
    expect(screen.getByRole('textbox', { name: 'Ansible snippet to copy manually' })).toHaveValue(snippet)
  })

  it('ignores late snippet clipboard failures after the result is cleared', async () => {
    const ciphertext = '$ANSIBLE_VAULT;1.2;AES256;dev\n00112233'
    let rejectCopy: ((reason?: unknown) => void) | undefined
    mockProfileLoad()
      .mockResolvedValueOnce(jsonResponse({ value: ciphertext }))
    const clipboard = {
      writeText: vi.fn(() => new Promise<void>((_resolve, reject) => {
        rejectCopy = reject
      })),
    }
    const user = userEvent.setup()
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: clipboard })

    render(<App />)
    const input = await findReadyValueInput()
    await user.type(input, 'fixture-value')
    await user.click(screen.getByRole('button', { name: 'Encrypt' }))
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Encrypted value' })).toHaveValue(ciphertext))
    await user.type(screen.getByRole('textbox', { name: 'Ansible variable name' }), 'app_secret')
    await user.click(screen.getByRole('button', { name: 'Copy Ansible snippet' }))
    expect(clipboard.writeText).toHaveBeenCalledOnce()

    await user.click(screen.getByRole('button', { name: 'Clear values' }))
    await act(async () => {
      rejectCopy?.(new Error('late clipboard failure'))
    })

    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: 'Ansible snippet to copy manually' })).not.toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: 'Encrypted value' })).toHaveValue('')
  })

  it('ignores late result clipboard completions after result handoff', async () => {
    const ciphertext = '$ANSIBLE_VAULT;1.2;AES256;dev\n00112233'
    let resolveCopy: (() => void) | undefined
    mockProfileLoad()
      .mockResolvedValueOnce(jsonResponse({ value: ciphertext }))
    const clipboard = {
      writeText: vi.fn(() => new Promise<void>((resolve) => {
        resolveCopy = resolve
      })),
    }
    const user = userEvent.setup()
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: clipboard })

    render(<App />)
    const input = await findReadyValueInput()
    await user.type(input, 'fixture-value')
    await user.click(screen.getByRole('button', { name: 'Encrypt' }))
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Encrypted value' })).toHaveValue(ciphertext))
    await user.click(screen.getByRole('button', { name: 'Copy result' }))
    expect(clipboard.writeText).toHaveBeenCalledOnce()

    await user.click(screen.getByRole('button', { name: 'Decrypt this result' }))
    expect(screen.getByRole('textbox', { name: 'Protected value to decrypt' })).toHaveValue(ciphertext)
    expect(screen.getByRole('status')).toHaveTextContent('Switched to Decrypt mode and placed the result in the protected value input.')

    await act(async () => {
      resolveCopy?.()
    })

    expect(screen.getByRole('status')).toHaveTextContent('Switched to Decrypt mode and placed the result in the protected value input.')
    expect(screen.getByRole('status')).not.toHaveTextContent('Copied')
  })

  it('keeps clear available for a retained variable name after the source is cleared', async () => {
    const ciphertext = '$ANSIBLE_VAULT;1.2;AES256;dev\n00112233'
    mockProfileLoad()
      .mockResolvedValueOnce(jsonResponse({ value: ciphertext }))
    const user = userEvent.setup()

    render(<App />)
    const input = await findReadyValueInput()
    await user.type(input, 'fixture-value')
    await user.click(screen.getByRole('button', { name: 'Encrypt' }))
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Encrypted value' })).toHaveValue(ciphertext))
    const keyInput = screen.getByRole('textbox', { name: 'Ansible variable name' })
    await user.type(keyInput, 'app_secret')

    await user.clear(input)

    const clearButton = screen.getByRole('button', { name: 'Clear values' })
    expect(clearButton).toBeEnabled()
    await user.click(clearButton)
    await waitFor(() => expect(screen.queryByRole('textbox', { name: 'Ansible variable name' })).not.toBeInTheDocument())
    expect(clearButton).toBeDisabled()
  })

  it('clears results after input, mode, or profile changes without clearing the input', async () => {
    mockProfileLoad(sourceAndDestinationProfiles)
      .mockResolvedValueOnce(jsonResponse({ value: 'first-output' }))
      .mockResolvedValueOnce(jsonResponse({ value: 'second-output' }))
      .mockResolvedValueOnce(jsonResponse({ value: 'decrypted-output' }))
    const user = userEvent.setup()

    render(<App />)
    const input = await findReadyValueInput()
    await user.type(input, 'fixture-value')
    await user.click(screen.getByRole('button', { name: 'Encrypt' }))
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Encrypted value' })).toHaveValue('first-output'))

    await user.clear(input)
    expect(screen.getByRole('textbox', { name: 'Encrypted value' })).toHaveValue('')

    await user.type(input, 'new-value')
    await user.click(screen.getByRole('button', { name: 'Encrypt' }))
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Encrypted value' })).toHaveValue('second-output'))

    await user.click(screen.getByRole('button', { name: 'Set decrypt mode' }))
    expect(screen.getByRole('textbox', { name: 'Protected value to decrypt' })).toHaveValue('new-value')
    expect(screen.getByRole('textbox', { name: 'Decrypted value' })).toHaveValue('')

    await user.click(screen.getByRole('button', { name: 'Decrypt' }))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Reveal result' })).toBeInTheDocument())

    await user.selectOptions(screen.getByRole('combobox', { name: 'Environment' }), 'prod')
    expect(screen.queryByRole('button', { name: 'Reveal result' })).not.toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: 'Decrypted value' })).toHaveValue('')
    expect(screen.getByRole('textbox', { name: 'Protected value to decrypt' })).toHaveValue('new-value')
  })

  it('keeps Clear values disabled while an operation is in flight', async () => {
    let resolveOperation!: (response: Response) => void
    const operation = new Promise<Response>((resolve) => {
      resolveOperation = resolve
    })
    mockProfileLoad()
      .mockReturnValueOnce(operation)
    const user = userEvent.setup()

    render(<App />)
    const input = await findReadyValueInput()
    await user.type(input, 'fixture-value')
    await user.click(screen.getByRole('button', { name: 'Encrypt' }))

    expect(screen.getByRole('button', { name: 'Clear values' })).toBeDisabled()
    resolveOperation(jsonResponse({ value: 'vault-output' }))
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Encrypted value' })).toHaveValue('vault-output'))
  })

  it('switches to decrypt mode and sends vault text', async () => {
    const fetchMock = mockProfileLoad()
      .mockResolvedValueOnce(jsonResponse({ value: 'decrypted-value' }))
    const user = userEvent.setup()

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set decrypt mode' }))
    expect(screen.getByText(/protected text or a YAML !vault block/i)).toBeInTheDocument()
    expect(screen.getByText(/YAML !vault block/i)).toBeInTheDocument()
    const input = screen.getByRole('textbox', { name: 'Protected value to decrypt' })
    await user.type(input, '$ANSIBLE_VAULT;1.1;AES256\nfixture')
    await user.click(screen.getByRole('button', { name: 'Decrypt' }))

    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Decrypted value' })).toHaveValue('Decrypted value hidden'))
    expect(fetchMock).toHaveBeenLastCalledWith(
      '/api/v1/operations',
      expect.objectContaining({ method: 'POST' }),
    )
    expect(JSON.parse(String(fetchMock.mock.lastCall?.[1]?.body))).toEqual({ profileId: 'dev', mode: 'decrypt', value: '$ANSIBLE_VAULT;1.1;AES256\nfixture' })
  })

  it('extracts a pasted Vault block in decrypt mode without reading navigator clipboard', async () => {
    const getData = vi.fn().mockReturnValue(pastedYamlVault)
    const readText = vi.fn()
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { readText } })
    mockProfileLoad()
    const user = userEvent.setup()

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set decrypt mode' }))
    const input = screen.getByRole('textbox', { name: 'Protected value to decrypt' })
    const event = createEvent.paste(input, { clipboardData: { getData } as unknown as DataTransfer })
    const preventDefault = vi.spyOn(event, 'preventDefault')
    fireEvent(input, event)

    expect(input).toHaveValue(pastedVault)
    expect(preventDefault).toHaveBeenCalledOnce()
    expect(getData).toHaveBeenCalledWith('text/plain')
    expect(readText).not.toHaveBeenCalled()
    const notice = screen.getByText('Protected text normalized for Vault operation.')
    expect(notice).toHaveAttribute('aria-live', 'polite')
    expect(notice).not.toHaveTextContent(pastedVault)
  })

  it('extracts a pasted Vault block in rotate mode', async () => {
    const getData = vi.fn().mockReturnValue(pastedYamlVault)
    const readText = vi.fn()
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { readText } })
    mockProfileLoad(sourceAndDestinationProfiles)
    const user = userEvent.setup()

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set re-key mode' }))
    const input = screen.getByRole('textbox', { name: 'Protected value to re-key' })
    const event = createEvent.paste(input, { clipboardData: { getData } as unknown as DataTransfer })
    const preventDefault = vi.spyOn(event, 'preventDefault')
    fireEvent(input, event)

    expect(input).toHaveValue(pastedVault)
    expect(preventDefault).toHaveBeenCalledOnce()
    expect(getData).toHaveBeenCalledWith('text/plain')
    expect(readText).not.toHaveBeenCalled()
    expect(screen.getByText('Protected text normalized for Vault operation.')).toBeInTheDocument()
  })

  it('does not inspect clipboard data while pasting in encrypt mode', async () => {
    const getData = vi.fn().mockReturnValue(pastedYamlVault)
    mockProfileLoad()
    const user = userEvent.setup()

    render(<App />)
    const input = await findReadyValueInput()
    const event = createEvent.paste(input, { clipboardData: { getData } as unknown as DataTransfer })
    const preventDefault = vi.spyOn(event, 'preventDefault')
    fireEvent(input, event)

    expect(getData).not.toHaveBeenCalled()
    expect(preventDefault).not.toHaveBeenCalled()
    expect(input).toHaveValue('')
  })

  it('supports rotate mode with source and destination profiles', async () => {
    const fetchMock = mockProfileLoad(sourceAndDestinationProfiles)
      .mockResolvedValueOnce(jsonResponse({ value: '$ANSIBLE_VAULT;1.2;AES256;prod\nrotated-ciphertext' }))
    const user = userEvent.setup()

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set re-key mode' }))
    expect(screen.getByRole('combobox', { name: 'From environment' })).toHaveValue('dev')
    expect(screen.getByRole('combobox', { name: 'To environment' })).toHaveValue('prod')
    const input = screen.getByRole('textbox', { name: 'Protected value to re-key' })
    await user.type(input, '$ANSIBLE_VAULT;1.1;AES256\nfixture')
    await user.click(screen.getByRole('button', { name: 'Re-key' }))

    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Re-keyed value' })).toHaveValue('$ANSIBLE_VAULT;1.2;AES256;prod\nrotated-ciphertext'))
    expect(screen.getByRole('textbox', { name: 'Ansible variable name' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Copy Ansible snippet' })).toBeDisabled()
    expect(fetchMock).toHaveBeenLastCalledWith(
      '/api/v1/operations',
      expect.objectContaining({
        method: 'POST',
      }),
    )
    expect(JSON.parse(String(fetchMock.mock.lastCall?.[1]?.body))).toEqual({ mode: 'rotate', sourceProfileId: 'dev', destinationProfileId: 'prod', value: '$ANSIBLE_VAULT;1.1;AES256\nfixture' })
  })

  it('filters selectors by action and clears ineligible selections across modes', async () => {
    const fetchMock = mockProfileLoad(asymmetricProfiles)
    const user = userEvent.setup()

    render(<App />)
    const encryptSelect = await screen.findByRole('combobox', { name: 'Environment' })
    expect(within(encryptSelect).getByRole('option', { name: 'Write only' })).toBeInTheDocument()
    expect(within(encryptSelect).queryByRole('option', { name: 'Read only' })).not.toBeInTheDocument()
    expect(encryptSelect).toHaveValue('write')

    await user.click(screen.getByRole('button', { name: 'Set decrypt mode' }))
    const decryptSelect = screen.getByRole('combobox', { name: 'Environment' })
    expect(within(decryptSelect).getByRole('option', { name: 'Read only' })).toBeInTheDocument()
    expect(within(decryptSelect).queryByRole('option', { name: 'Write only' })).not.toBeInTheDocument()
    expect(decryptSelect).toHaveValue('')

    await user.type(screen.getByRole('textbox', { name: 'Protected value to decrypt' }), 'vault-text')
    expect(screen.getByRole('button', { name: 'Decrypt' })).toBeDisabled()
    fireEvent.submit(screen.getByRole('form', { name: 'Vault operation form' }))
    expect(fetchMock.mock.calls.filter(([path]) => path === '/api/v1/operations')).toHaveLength(0)

    await user.selectOptions(decryptSelect, 'read')
    await user.click(screen.getByRole('button', { name: 'Set re-key mode' }))
    const sourceSelect = screen.getByRole('combobox', { name: 'From environment' })
    const destinationSelect = screen.getByRole('combobox', { name: 'To environment' })
    expect(within(sourceSelect).getByRole('option', { name: 'Read only' })).toBeInTheDocument()
    expect(within(sourceSelect).queryByRole('option', { name: 'Write only' })).not.toBeInTheDocument()
    expect(within(destinationSelect).getByRole('option', { name: 'Write only' })).toBeInTheDocument()
    expect(within(destinationSelect).queryByRole('option', { name: 'Read only' })).not.toBeInTheDocument()
    expect(sourceSelect).toHaveValue('read')
    expect(destinationSelect).toHaveValue('write')
  })

  it('selects the first available operation when Encrypt is unavailable at startup', async () => {
    mockProfileLoad([asymmetricProfiles[1]])

    render(<App />)
    await screen.findByRole('option', { name: 'Read only' })

    expect(screen.getByRole('button', { name: 'Set decrypt mode' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('button', { name: 'Set encrypt mode' })).toBeDisabled()
    expect(screen.getByRole('combobox', { name: 'Environment' })).toHaveValue('read')
    expect(screen.getByRole('textbox', { name: 'Protected value to decrypt' })).toBeEnabled()
    expect(screen.getByText('No environments are available for encryption.')).toBeVisible()
  })

  it('shows specific inline Ansible variable validation without moving the Copy action', async () => {
    mockProfileLoad()
      .mockResolvedValueOnce(jsonResponse({ value: '$ANSIBLE_VAULT;1.2;AES256;dev\\n00112233' }))
    const user = userEvent.setup()

    render(<App />)
    const input = await findReadyValueInput()
    await user.type(input, 'fixture-value')
    await user.click(screen.getByRole('button', { name: 'Encrypt' }))
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Encrypted value' })).toHaveValue('$ANSIBLE_VAULT;1.2;AES256;dev\\n00112233'))

    const variableInput = screen.getByRole('textbox', { name: 'Ansible variable name' })
    const copyButton = screen.getByRole('button', { name: 'Copy Ansible snippet' })
    await user.type(variableInput, '1secret')
    expect(screen.getByText('Start with a letter or underscore.')).toBeVisible()
    expect(variableInput).toHaveAttribute('aria-invalid', 'true')
    expect(copyButton).toBeDisabled()

    await user.clear(variableInput)
    await user.type(variableInput, 'foo-bar')
    expect(screen.getByText('Variable names cannot contain hyphens.')).toBeVisible()
    expect(copyButton).toBeDisabled()

    await user.clear(variableInput)
    await user.type(variableInput, 'app_secret')
    expect(screen.queryByText('Variable names cannot contain hyphens.')).not.toBeInTheDocument()
    expect(variableInput).toHaveAttribute('aria-invalid', 'false')
    expect(copyButton).toBeEnabled()
  })

  it('uses the explicit destination in re-key handoff terminology', async () => {
    mockProfileLoad(sourceAndDestinationProfiles)
      .mockResolvedValueOnce(jsonResponse({ value: '$ANSIBLE_VAULT;1.2;AES256;prod\\n00112233' }))
    const user = userEvent.setup()

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set re-key mode' }))
    await user.type(screen.getByRole('textbox', { name: 'Protected value to re-key' }), 'vault-text')
    await user.click(screen.getByRole('button', { name: 'Re-key' }))
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Re-keyed value' })).toHaveValue('$ANSIBLE_VAULT;1.2;AES256;prod\\n00112233'))

    expect(screen.getByRole('button', { name: 'Decrypt with destination environment' })).toBeEnabled()
    expect(screen.queryByRole('button', { name: 'Use result as input' })).not.toBeInTheDocument()
  })

  it('disables unavailable modes and exposes the reason', async () => {
    mockProfileLoad([asymmetricProfiles[0]])

    render(<App />)
    await screen.findByRole('option', { name: 'Write only' })

    expect(screen.getByRole('button', { name: 'Set encrypt mode' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Set decrypt mode' })).toBeDisabled()
    expect(screen.getByText('No environments are available for decryption.')).toBeVisible()
    expect(screen.getByRole('button', { name: 'Set re-key mode' })).toBeDisabled()
    expect(screen.getByText('Re-key requires an available decrypt source and encrypt destination.')).toBeVisible()
  })

  it('does not hand a rotated result to an ineligible decrypt destination', async () => {
    mockProfileLoad(asymmetricProfiles)
      .mockResolvedValueOnce(jsonResponse({ value: '$ANSIBLE_VAULT;1.2;AES256;write\nrotated' }))
    const user = userEvent.setup()

    render(<App />)
    await screen.findByRole('option', { name: 'Write only' })
    await user.click(screen.getByRole('button', { name: 'Set re-key mode' }))
    await user.selectOptions(screen.getByRole('combobox', { name: 'From environment' }), 'read')
    await user.selectOptions(screen.getByRole('combobox', { name: 'To environment' }), 'write')
    await user.type(screen.getByRole('textbox', { name: 'Protected value to re-key' }), 'vault-text')
    await user.click(screen.getByRole('button', { name: 'Re-key' }))
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Re-keyed value' })).toHaveValue('$ANSIBLE_VAULT;1.2;AES256;write\nrotated'))

    const handoff = screen.getByRole('button', { name: 'Decrypt with destination environment' })
    expect(handoff).toBeDisabled()
    expect(handoff).toHaveAccessibleDescription('The destination environment is not available for decryption.')
    expect(screen.getByText('The destination environment is not available for decryption.')).toBeVisible()
  })

  it('does not restore a late operation result after cancellation', async () => {
    let resolveOperation!: (response: Response) => void
    const operation = new Promise<Response>((resolve) => {
      resolveOperation = resolve
    })
    mockProfileLoad()
      .mockReturnValueOnce(operation)
    const user = userEvent.setup()

    render(<App />)
    const input = await findReadyValueInput()
    await user.type(input, 'fixture-value')
    await user.click(screen.getByRole('button', { name: 'Encrypt' }))
    expect(screen.getByRole('status')).toHaveTextContent('Encrypting…')

    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    resolveOperation(jsonResponse({ value: 'late-output' }))

    await waitFor(() => expect(screen.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument())
    expect(screen.getByRole('status')).toHaveTextContent('Operation cancelled')
    expect(screen.getByRole('textbox', { name: 'Encrypted value' })).toHaveValue('')
  })

  it('disables rotate mode when no profiles are available', async () => {
    mockProfileLoad([])

    render(<App />)
    await screen.findByRole('option', { name: 'No environments available' })

    const rotateMode = screen.getByRole('button', { name: 'Set re-key mode' })
    expect(rotateMode).toBeDisabled()
  })

  it('enforces the encrypt UTF-8 byte limit before submission', async () => {
    mockProfileLoad()
    render(<App />)
    const input = await findReadyValueInput()
    const overLimit = '🙂'.repeat(MAX_PLAINTEXT_BYTES / 4 + 1)
    fireEvent.change(input, { target: { value: overLimit } })

    expect(screen.getByText(`${MAX_PLAINTEXT_BYTES.toLocaleString()} bytes`, { exact: false })).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent('Value exceeds the 1 MiB limit')
    expect(screen.getByRole('button', { name: 'Encrypt' })).toBeDisabled()
  })

  it('hands off an encrypted result into decrypt input without retaining output state', async () => {
    const ciphertext = '$ANSIBLE_VAULT;1.2;AES256;dev\n00112233'
    const setItem = vi.spyOn(Storage.prototype, 'setItem')
    mockProfileLoad()
      .mockResolvedValueOnce(jsonResponse({ value: ciphertext }))
    const user = userEvent.setup()

    render(<App />)
    const input = await findReadyValueInput()
    await user.type(input, 'fixture-value')
    await user.click(screen.getByRole('button', { name: 'Encrypt' }))
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Encrypted value' })).toHaveValue(ciphertext))

    const handoff = screen.getByRole('button', { name: 'Decrypt this result' })
    expect(handoff).toBeEnabled()
    await user.click(handoff)

    expect(screen.getByRole('button', { name: 'Set decrypt mode' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('textbox', { name: 'Protected value to decrypt' })).toHaveValue(ciphertext)
    expect(screen.getByRole('textbox', { name: 'Decrypted value' })).toHaveValue('')
    expect(screen.queryByRole('textbox', { name: 'Ansible variable name' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Encrypt this result' })).toBeDisabled()
    expect(screen.getByRole('status')).toHaveAttribute('aria-live', 'polite')
    expect(screen.getByRole('status')).toHaveTextContent('Switched to Decrypt mode and placed the result in the protected value input.')
    expect(screen.getByRole('status')).not.toHaveTextContent(ciphertext)
    expect(setItem).not.toHaveBeenCalled()
  })

  it('hands off a decrypted result into encrypt input and clears reveal state', async () => {
    const plaintext = 'decrypted-value'
    mockProfileLoad()
      .mockResolvedValueOnce(jsonResponse({ value: plaintext }))
    const user = userEvent.setup()

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set decrypt mode' }))
    await user.type(screen.getByRole('textbox', { name: 'Protected value to decrypt' }), 'vault-text')
    await user.click(screen.getByRole('button', { name: 'Decrypt' }))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Reveal result' })).toBeInTheDocument())
    expect(screen.getByRole('textbox', { name: 'Decrypted value' })).toHaveValue('Decrypted value hidden')

    await user.click(screen.getByRole('button', { name: 'Encrypt this result' }))

    expect(screen.getByRole('button', { name: 'Set encrypt mode' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('textbox', { name: 'Value to encrypt' })).toHaveValue(plaintext)
    expect(screen.getByRole('textbox', { name: 'Encrypted value' })).toHaveValue('')
    expect(screen.queryByRole('button', { name: 'Reveal result' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Copy result' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Decrypt this result' })).toBeDisabled()
    expect(screen.getByRole('status')).toHaveTextContent('Switched to Encrypt mode and placed the result in the value input.')
  })

  it('hands off a rotated result into decrypt input using the destination profile', async () => {
    const ciphertext = '$ANSIBLE_VAULT;1.2;AES256;prod\n00112233'
    mockProfileLoad(sourceAndDestinationProfiles)
      .mockResolvedValueOnce(jsonResponse({ value: ciphertext }))
    const user = userEvent.setup()

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set re-key mode' }))
    await user.type(screen.getByRole('textbox', { name: 'Protected value to re-key' }), 'vault-text')
    await user.click(screen.getByRole('button', { name: 'Re-key' }))
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Re-keyed value' })).toHaveValue(ciphertext))
    await user.type(screen.getByRole('textbox', { name: 'Ansible variable name' }), 'app_secret')

    await user.click(screen.getByRole('button', { name: 'Decrypt with destination environment' }))

    expect(screen.getByRole('button', { name: 'Set decrypt mode' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('combobox', { name: 'Environment' })).toHaveValue('prod')
    expect(screen.getByRole('textbox', { name: 'Protected value to decrypt' })).toHaveValue(ciphertext)
    expect(screen.getByRole('textbox', { name: 'Decrypted value' })).toHaveValue('')
    expect(screen.queryByRole('textbox', { name: 'Ansible variable name' })).not.toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveTextContent('Switched to Decrypt mode and placed the result in the protected value input.')
  })

  it('reveals, copies, and clears decrypted output only on explicit actions', async () => {
    mockProfileLoad()
      .mockResolvedValueOnce(jsonResponse({ value: 'decrypted-value' }))
    const clipboard = { writeText: vi.fn().mockResolvedValue(undefined) }
    const user = userEvent.setup()
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: clipboard })

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set decrypt mode' }))
    await user.type(screen.getByRole('textbox', { name: 'Protected value to decrypt' }), 'vault-text')
    await user.click(screen.getByRole('button', { name: 'Decrypt' }))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Reveal result' })).toBeInTheDocument())
    expect(screen.getByRole('textbox', { name: 'Decrypted value' })).toHaveValue('Decrypted value hidden')

    expect(screen.getByRole('button', { name: 'Copy without revealing' })).toBeEnabled()
    await user.click(screen.getByRole('button', { name: 'Copy without revealing' }))
    expect(clipboard.writeText).toHaveBeenLastCalledWith('decrypted-value')
    expect(screen.getByRole('textbox', { name: 'Decrypted value' })).toHaveValue('Decrypted value hidden')

    await user.click(screen.getByRole('button', { name: 'Reveal result' }))
    expect(screen.getByRole('textbox', { name: 'Decrypted value' })).toHaveValue('decrypted-value')
    await user.click(screen.getByRole('button', { name: 'Copy result' }))
    expect(clipboard.writeText).toHaveBeenLastCalledWith('decrypted-value')
    await user.click(screen.getByRole('button', { name: 'Clear values' }))
    expect(screen.getByRole('textbox', { name: 'Decrypted value' })).toHaveValue('')
  })

  it('disables browser assistance on sensitive textareas', async () => {
    mockProfileLoad()
    render(<App />)
    const input = await findReadyValueInput()
    expect(input).toHaveAttribute('spellcheck', 'false')
    expect(input).toHaveAttribute('autocomplete', 'off')
    expect(input).toHaveAttribute('autocorrect', 'off')
    expect(input).toHaveAttribute('autocapitalize', 'off')
    expect(screen.getByRole('textbox', { name: 'Encrypted value' })).toHaveAttribute('autocapitalize', 'off')
  })

  it('offers a retry when profiles fail to load', async () => {
    vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(sessionResponse())
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce(sessionResponse())
      .mockResolvedValueOnce(profilesResponse())
    const user = userEvent.setup()

    render(<App />)

    await screen.findByRole('button', { name: 'Retry loading environments' })
    await user.click(screen.getByRole('button', { name: 'Retry loading environments' }))

    expect(await screen.findByRole('option', { name: 'Development' })).toBeInTheDocument()
  })

  it('offers one manual retry after session bootstrap times out', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(
        { error: { code: 'session_timeout', message: 'private-session-detail' } },
        { status: 504 },
      ))
      .mockResolvedValueOnce(sessionResponse())
      .mockResolvedValueOnce(profilesResponse())
    const user = userEvent.setup()

    render(<App />)

    expect(await screen.findByRole('alert')).toHaveTextContent('Session loading timed out. Check the service and try again.')
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const retry = screen.getByRole('button', { name: 'Retry loading session' })
    await user.click(retry)

    expect(await screen.findByRole('option', { name: 'Development' })).toBeInTheDocument()
    expect(fetchMock.mock.calls.filter(([path]) => path === '/api/v1/session')).toHaveLength(2)
    expect(fetchMock.mock.calls.filter(([path]) => path === '/api/v1/profiles')).toHaveLength(1)
  })

  it('refreshes stale capabilities after forbidden without retrying the operation', async () => {
    let resolveRefresh!: (response: Response) => void
    const refreshResponse = new Promise<Response>((resolve) => {
      resolveRefresh = resolve
    })
    const refreshedProfiles = [
      { id: 'dev', label: 'Development', capabilities: { encrypt: true, decrypt: false } },
      { id: 'prod', label: 'Production', capabilities: { encrypt: false, decrypt: true } },
    ]
    const fetchMock = mockProfileLoad(sourceAndDestinationProfiles)
      .mockResolvedValueOnce(jsonResponse(
        { error: { code: 'forbidden', message: 'private-policy-detail' } },
        { status: 403 },
      ))
      .mockReturnValueOnce(refreshResponse)
    const user = userEvent.setup()

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set re-key mode' }))
    const input = screen.getByRole('textbox', { name: 'Protected value to re-key' })
    await user.type(input, 'vault-text')
    await user.click(screen.getByRole('button', { name: 'Re-key' }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(4))
    expect(screen.getByRole('status')).toHaveTextContent('Refreshing environments…')
    expect(screen.getByRole('status')).not.toHaveTextContent('Environments were refreshed')
    expect(screen.getByRole('button', { name: 'Re-key' })).toBeDisabled()
    expect(input).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Clear values' })).toBeEnabled()

    await user.click(screen.getByRole('button', { name: 'Clear values' }))
    expect(input).toHaveValue('')
    expect(input).toBeEnabled()
    expect(screen.getByRole('status')).toHaveTextContent('Refreshing environments…')
    await user.type(input, 'replacement-value')
    expect(screen.getByRole('status')).toHaveTextContent('Refreshing environments…')
    expect(screen.getByRole('button', { name: 'Re-key' })).toBeDisabled()
    expect(fetchMock.mock.calls.filter(([path]) => path === '/api/v1/operations')).toHaveLength(1)

    resolveRefresh(profilesResponse(refreshedProfiles))

    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Your permissions changed. Environments were refreshed; review the selection and try again.'))
    expect(screen.getByRole('button', { name: 'Set re-key mode' })).toHaveAttribute('aria-pressed', 'true')
    expect(input).toHaveValue('replacement-value')
    expect(screen.getByRole('combobox', { name: 'From environment' })).toHaveValue('')
    expect(screen.getByRole('combobox', { name: 'To environment' })).toHaveValue('')
    expect(within(screen.getByRole('combobox', { name: 'From environment' })).getByRole('option', { name: 'Production' })).toBeInTheDocument()
    expect(within(screen.getByRole('combobox', { name: 'To environment' })).getByRole('option', { name: 'Development' })).toBeInTheDocument()
    expect(fetchMock.mock.calls.filter(([path]) => path === '/api/v1/operations')).toHaveLength(1)
  })

  it('switches to an available operation after a permission refresh removes the current mode', async () => {
    const fetchMock = mockProfileLoad(defaultProfiles)
      .mockResolvedValueOnce(jsonResponse(
        { error: { code: 'forbidden', message: 'private-policy-detail' } },
        { status: 403 },
      ))
      .mockResolvedValueOnce(profilesResponse([asymmetricProfiles[1]]))
    const user = userEvent.setup()

    render(<App />)
    const input = await findReadyValueInput()
    await user.type(input, 'fixture-value')
    await user.click(screen.getByRole('button', { name: 'Encrypt' }))

    await waitFor(() => expect(fetchMock.mock.calls.filter(([path]) => path === '/api/v1/profiles')).toHaveLength(2))
    expect(screen.getByRole('button', { name: 'Set decrypt mode' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByText('Encrypt is unavailable. Switched to Decrypt.')).toBeVisible()
    expect(screen.getByRole('combobox', { name: 'Environment' })).toHaveValue('')
  })

  it('keeps recovery and clearing available when stale-capability refresh fails', async () => {
    let resolveRetry!: (response: Response) => void
    const retryResponse = new Promise<Response>((resolve) => {
      resolveRetry = resolve
    })
    const fetchMock = mockProfileLoad()
      .mockResolvedValueOnce(jsonResponse(
        { error: { code: 'forbidden', message: 'private-policy-detail' } },
        { status: 403 },
      ))
      .mockRejectedValueOnce(new Error('private-network-detail'))
      .mockResolvedValueOnce(sessionResponse())
      .mockReturnValueOnce(retryResponse)
    const user = userEvent.setup()

    render(<App />)
    const input = await findReadyValueInput()
    await user.type(input, 'fixture-value')
    await user.click(screen.getByRole('button', { name: 'Encrypt' }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Your permissions changed, but environments could not be refreshed. Check the service and retry loading environments.')
    expect(alert).not.toHaveTextContent('private')
    expect(input).toHaveValue('fixture-value')
    expect(input).toBeEnabled()
    expect(screen.getByRole('combobox', { name: 'Environment' })).toHaveValue('dev')
    expect(screen.getByRole('combobox', { name: 'Environment' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Encrypt' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Clear values' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Retry loading environments' })).toBeEnabled()
    expect(fetchMock.mock.calls.filter(([path]) => path === '/api/v1/operations')).toHaveLength(1)

    await user.click(screen.getByRole('button', { name: 'Clear values' }))
    expect(input).toHaveValue('')
    expect(screen.getByRole('button', { name: 'Retry loading environments' })).toBeEnabled()

    await user.click(screen.getByRole('button', { name: 'Retry loading environments' }))
    expect(input).toBeEnabled()
    expect(screen.getByRole('status')).toHaveTextContent('Refreshing environments…')
    await user.type(input, 'replacement-value')
    expect(screen.getByRole('status')).toHaveTextContent('Refreshing environments…')
    expect(fetchMock.mock.calls.filter(([path]) => path === '/api/v1/operations')).toHaveLength(1)

    resolveRetry(profilesResponse(defaultProfiles))
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Your permissions changed. Environments were refreshed; review the selection and try again.'))
    expect(input).toHaveValue('replacement-value')
  })

  it.each([
    { status: 409, code: 'forbidden' },
    { status: 403, code: 'not_ready' },
  ])('does not refresh capabilities for $status + $code', async ({ status, code }) => {
    const fetchMock = mockProfileLoad()
      .mockResolvedValueOnce(jsonResponse(
        { error: { code, message: 'private-error-detail' } },
        { status },
      ))
    const user = userEvent.setup()

    render(<App />)
    const input = await findReadyValueInput()
    await user.type(input, 'fixture-value')
    await user.click(screen.getByRole('button', { name: 'Encrypt' }))

    await screen.findByRole('alert')
    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(fetchMock.mock.calls.filter(([path]) => path === '/api/v1/profiles')).toHaveLength(1)
  })

  it('gives safe, actionable guidance when decryption fails', async () => {
    mockProfileLoad()
      .mockResolvedValueOnce(jsonResponse(
        { error: { code: 'operation_failed', message: 'vault operation failed' } },
        { status: 422 },
      ))
    const user = userEvent.setup()

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set decrypt mode' }))
    const input = screen.getByRole('textbox', { name: 'Protected value to decrypt' })
    await user.type(input, '$ANSIBLE_VAULT;1.1;AES256\nfixture')
    await user.click(screen.getByRole('button', { name: 'Decrypt' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/check the selected Environment/i)
    expect(screen.getByRole('alert')).toHaveTextContent(/protected text or a YAML !vault block/i)
    expect(input).toHaveValue('$ANSIBLE_VAULT;1.1;AES256\nfixture')
  })

  it('announces in-flight work and cancels it without losing the input', async () => {
    mockProfileLoad()
      .mockImplementationOnce((_input, init) => new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
      }))
    const user = userEvent.setup()

    render(<App />)
    const input = await findReadyValueInput()
    await user.type(input, 'fixture-value')
    await user.click(screen.getByRole('button', { name: 'Encrypt' }))

    expect(screen.getByRole('status')).toHaveTextContent('Encrypting…')
    expect(document.querySelector('form')).toHaveAttribute('aria-busy', 'true')
    await user.click(screen.getByRole('button', { name: 'Cancel' }))

    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Operation cancelled'))
    expect(document.querySelector('form')).toHaveAttribute('aria-busy', 'false')
    expect(input).toHaveValue('fixture-value')
    expect(screen.getByRole('textbox', { name: 'Encrypted value' })).toHaveValue('')
  })

  it('times out a stalled operation with recovery guidance', async () => {
    mockProfileLoad()
      .mockImplementationOnce((_input, init) => new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
      }))
    const user = userEvent.setup()

    render(<App />)
    const input = await findReadyValueInput()
    await user.type(input, 'fixture-value')
    vi.useFakeTimers()
    fireEvent.click(screen.getByRole('button', { name: 'Encrypt' }))
    await act(async () => {
      await vi.advanceTimersByTimeAsync(OPERATION_TIMEOUT_MS)
    })

    expect(screen.getByRole('alert')).toHaveTextContent(/timed out/i)
    expect(screen.getByRole('alert')).toHaveTextContent(/try again/i)
    expect(input).toHaveValue('fixture-value')
  })

  it('warns when retained input changes meaning across modes', async () => {
    mockProfileLoad()
    const user = userEvent.setup()

    render(<App />)
    const input = await findReadyValueInput()
    await user.type(input, 'retained-value')
    await user.click(screen.getByRole('button', { name: 'Set decrypt mode' }))

    expect(await screen.findByText(/Input kept; protected text expected/i)).toBeInTheDocument()
    await user.type(input, 'x')
    expect(screen.queryByText(/Input kept; protected text expected/i)).not.toBeInTheDocument()
  })

  it('shows safe advisory metadata for a recognized Vault header without the ciphertext body', async () => {
    mockProfileLoad()
    const user = userEvent.setup()

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set decrypt mode' }))
    const input = screen.getByRole('textbox', { name: 'Protected value to decrypt' })
    fireEvent.change(input, { target: { value: '$ANSIBLE_VAULT;1.2;AES256;dev\nfixture-ciphertext' } })

    const diagnostics = screen.getByRole('region', { name: 'Vault format diagnostics' })
    expect(diagnostics).toHaveTextContent('Vault 1.2')
    expect(diagnostics).toHaveTextContent('Checks the header only; this does not verify encryption.')
    expect(diagnostics).toHaveTextContent('AES256')
    expect(diagnostics).toHaveTextContent('dev')
    expect(diagnostics).toHaveTextContent(/Input size/)
    expect(diagnostics).not.toHaveTextContent('fixture-ciphertext')
    expect(screen.getByRole('button', { name: 'Decrypt' })).toBeEnabled()
  })

  it('shows label mismatch guidance without blocking decrypt or rotate', async () => {
    mockProfileLoad(sourceAndDestinationProfiles)
    const user = userEvent.setup()

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set decrypt mode' }))
    const decryptInput = screen.getByRole('textbox', { name: 'Protected value to decrypt' })
    fireEvent.change(decryptInput, { target: { value: '$ANSIBLE_VAULT;1.2;AES256;prod\nfixture' } })
    expect(screen.getByRole('region', { name: 'Vault format diagnostics' })).toHaveTextContent(/differs from selected environment ID “dev” \(Development\)/)
    expect(screen.getByRole('button', { name: 'Decrypt' })).toBeEnabled()

    await user.click(screen.getByRole('button', { name: 'Set re-key mode' }))
    const rotateInput = screen.getByRole('textbox', { name: 'Protected value to re-key' })
    fireEvent.change(rotateInput, { target: { value: '$ANSIBLE_VAULT;1.2;AES256;prod\nfixture' } })
    expect(screen.getByRole('region', { name: 'Vault format diagnostics' })).toHaveTextContent(/differs from selected environment ID “dev” \(Development\)/)
    expect(screen.getByRole('button', { name: 'Re-key' })).toBeEnabled()
  })

  it('offers an exact decrypt-capable Vault ID as an explicit environment choice', async () => {
    const fetchMock = mockProfileLoad(sourceAndDestinationProfiles)
    const user = userEvent.setup()

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set decrypt mode' }))
    const environment = screen.getByRole('combobox', { name: 'Environment' })
    const input = screen.getByRole('textbox', { name: 'Protected value to decrypt' })
    fireEvent.change(input, { target: { value: '$ANSIBLE_VAULT;1.2;AES256;prod\nfixture' } })

    const suggestion = screen.getByRole('button', { name: 'Use Production' })
    expect(suggestion).toHaveAttribute('type', 'button')
    expect(environment).toHaveValue('dev')
    expect(fetchMock.mock.calls.filter(([path]) => path === '/api/v1/operations')).toHaveLength(0)

    await user.click(suggestion)

    expect(environment).toHaveValue('prod')
    expect(input).toHaveValue('$ANSIBLE_VAULT;1.2;AES256;prod\nfixture')
    expect(screen.queryByRole('button', { name: 'Use Production' })).not.toBeInTheDocument()
    expect(fetchMock.mock.calls.filter(([path]) => path === '/api/v1/operations')).toHaveLength(0)
  })

  it('changes only the rotate source when a Vault ID suggestion is accepted', async () => {
    const profiles = [
      ...sourceAndDestinationProfiles,
      { id: 'stage', label: 'Staging', capabilities: { encrypt: true, decrypt: true } },
    ]
    const fetchMock = mockProfileLoad(profiles)
    const user = userEvent.setup()

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set re-key mode' }))
    const source = screen.getByRole('combobox', { name: 'From environment' })
    const destination = screen.getByRole('combobox', { name: 'To environment' })
    const input = screen.getByRole('textbox', { name: 'Protected value to re-key' })
    fireEvent.change(input, { target: { value: '$ANSIBLE_VAULT;1.2;AES256;stage\nfixture' } })

    expect(source).toHaveValue('dev')
    expect(destination).toHaveValue('prod')
    await user.click(screen.getByRole('button', { name: 'Use Staging' }))

    expect(source).toHaveValue('stage')
    expect(destination).toHaveValue('prod')
    expect(input).toHaveValue('$ANSIBLE_VAULT;1.2;AES256;stage\nfixture')
    expect(fetchMock.mock.calls.filter(([path]) => path === '/api/v1/operations')).toHaveLength(0)
  })

  it('does not offer a Vault ID action for ineligible or unsafe inspection states', async () => {
    const profiles = [
      { id: 'dev', label: 'Development', capabilities: { encrypt: true, decrypt: true } },
      { id: 'prod', label: 'Production', capabilities: { encrypt: true, decrypt: false } },
      { id: 'stage', label: 'Staging', capabilities: { encrypt: true, decrypt: true } },
    ]
    mockProfileLoad(profiles)
    const user = userEvent.setup()

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set decrypt mode' }))
    const input = screen.getByRole('textbox', { name: 'Protected value to decrypt' })
    const assertNoSuggestion = (value: string) => {
      fireEvent.change(input, { target: { value } })
      expect(screen.queryByRole('button', { name: /^Use (Development|Production|Staging)$/ })).not.toBeInTheDocument()
    }

    assertNoSuggestion('$ANSIBLE_VAULT;1.2;AES256;dev\nfixture')
    assertNoSuggestion('$ANSIBLE_VAULT;1.1;AES256\nfixture')
    assertNoSuggestion('$ANSIBLE_VAULT;1.2;AES256\nfixture')
    assertNoSuggestion('$ANSIBLE_VAULT;1.2;AES256;prod\nfixture')
    assertNoSuggestion('$ANSIBLE_VAULT;1.2;AES256;missing\nfixture')
    assertNoSuggestion('$ANSIBLE_VAULT;1.2;AES256;Stage\nfixture')
    assertNoSuggestion('$ANSIBLE_VAULT;1.2;AES256;stage')
    assertNoSuggestion(`$ANSIBLE_VAULT;1.2;AES256;stage${String.fromCharCode(0x202e)}hidden\nfixture`)
    assertNoSuggestion('$ANSIBLE_VAULT;1.2;AES128;stage\nfixture')
  })

  it('offers a retained Vault ID after a permission refresh clears the selection', async () => {
    const refreshedProfiles = [
      { id: 'dev', label: 'Development', capabilities: { encrypt: true, decrypt: false } },
      { id: 'prod', label: 'Production', capabilities: { encrypt: true, decrypt: true } },
    ]
    const fetchMock = mockProfileLoad(sourceAndDestinationProfiles)
      .mockResolvedValueOnce(jsonResponse(
        { error: { code: 'forbidden', message: 'private-policy-detail' } },
        { status: 403 },
      ))
      .mockResolvedValueOnce(profilesResponse(refreshedProfiles))
    const user = userEvent.setup()

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set decrypt mode' }))
    const input = screen.getByRole('textbox', { name: 'Protected value to decrypt' })
    fireEvent.change(input, { target: { value: '$ANSIBLE_VAULT;1.2;AES256;prod\nfixture' } })
    await user.click(screen.getByRole('button', { name: 'Decrypt' }))

    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Environments were refreshed'))
    const environment = screen.getByRole('combobox', { name: 'Environment' })
    expect(environment).toHaveValue('')
    expect(input).toHaveValue('$ANSIBLE_VAULT;1.2;AES256;prod\nfixture')
    expect(fetchMock.mock.calls.filter(([path]) => path === '/api/v1/operations')).toHaveLength(1)

    await user.click(screen.getByRole('button', { name: 'Use Production' }))

    expect(environment).toHaveValue('prod')
    expect(input).toHaveValue('$ANSIBLE_VAULT;1.2;AES256;prod\nfixture')
    expect(fetchMock.mock.calls.filter(([path]) => path === '/api/v1/operations')).toHaveLength(1)
  })

  it('prioritizes unsupported format guidance over label mismatch', async () => {
    mockProfileLoad()
    const user = userEvent.setup()

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set decrypt mode' }))
    const input = screen.getByRole('textbox', { name: 'Protected value to decrypt' })
    fireEvent.change(input, { target: { value: `$ANSIBLE_VAULT;1.2;AES128;prod${String.fromCharCode(10)}fixture` } })

    const diagnostics = screen.getByRole('region', { name: 'Vault format diagnostics' })
    expect(diagnostics).toHaveTextContent('The Vault version or cipher is not recognized by this inspector.')
    expect(diagnostics).not.toHaveTextContent(/differs from selected environment/)
  })

  it('does not render server-provided details for unknown operation errors', async () => {
    const sentinel = 'private-backend-detail'
    mockProfileLoad()
      .mockResolvedValueOnce(jsonResponse(
        { error: { code: 'backend_detail', message: sentinel } },
        { status: 500 },
      ))
    const user = userEvent.setup()

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set decrypt mode' }))
    const input = screen.getByRole('textbox', { name: 'Protected value to decrypt' })
    await user.type(input, `$ANSIBLE_VAULT;1.1;AES256${String.fromCharCode(10)}fixture`)
    await user.click(screen.getByRole('button', { name: 'Decrypt' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Value operation failed')
    expect(screen.getByRole('alert')).not.toHaveTextContent(sentinel)
  })

  it('keeps fixed guidance for known service errors', async () => {
    const sentinel = 'private-ready-detail'
    mockProfileLoad()
      .mockResolvedValueOnce(jsonResponse(
        { error: { code: 'not_ready', message: sentinel } },
        { status: 503 },
      ))
    const user = userEvent.setup()

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set decrypt mode' }))
    const input = screen.getByRole('textbox', { name: 'Protected value to decrypt' })
    await user.type(input, `$ANSIBLE_VAULT;1.1;AES256${String.fromCharCode(10)}fixture`)
    await user.click(screen.getByRole('button', { name: 'Decrypt' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Vaultsmith service is not ready. Try again shortly.')
    expect(screen.getByRole('alert')).not.toHaveTextContent(sentinel)
  })

  it('announces malformed header guidance without echoing the submitted value', async () => {
    mockProfileLoad()
    const user = userEvent.setup()

    render(<App />)
    await screen.findByRole('option', { name: 'Development' })
    await user.click(screen.getByRole('button', { name: 'Set decrypt mode' }))
    const input = screen.getByRole('textbox', { name: 'Protected value to decrypt' })
    fireEvent.change(input, { target: { value: 'private-fixture-ciphertext' } })

    const diagnostics = screen.getByRole('region', { name: 'Vault format diagnostics' })
    const guidance = screen.getByText(/No Ansible Vault header was found/i)
    expect(guidance).toHaveAttribute('aria-live', 'polite')
    expect(diagnostics).not.toHaveTextContent('private-fixture-ciphertext')
    expect(screen.getByRole('button', { name: 'Decrypt' })).toBeEnabled()
  })
})
