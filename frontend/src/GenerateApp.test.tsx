import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { OPERATION_TIMEOUT_MS } from './api'
import App from './App'

type JsonValue = string | number | boolean | null | readonly JsonValue[] | { readonly [key: string]: JsonValue }

const jsonResponse = (body: JsonValue, init: ResponseInit = {}) => new Response(JSON.stringify(body), {
  status: 200,
  headers: { 'Content-Type': 'application/json' },
  ...init,
})

const session = (authenticated = false) => authenticated
  ? jsonResponse({
    authenticated: true,
    authRequired: true,
    email: 'operator@example.test',
    csrfToken: 'csrf-fixture',
  })
  : jsonResponse({
    authenticated: false,
    authRequired: false,
    csrfToken: '',
  })

const profilesResponse = () => jsonResponse({
  profiles: [
    { id: 'dev', label: 'Development', capabilities: { encrypt: true, decrypt: true, rotateSource: true, rotateDestination: true } },
    { id: 'read', label: 'Read only', capabilities: { encrypt: false, decrypt: true, rotateSource: true, rotateDestination: false } },
  ],
})

const vaultPayload = `${'a'.repeat(64)}\n${'b'.repeat(64)}\n${'c'.repeat(32)}`
const vaultBody = [...vaultPayload]
  .map((character) => character.charCodeAt(0).toString(16).padStart(2, '0'))
  .join('')
  .match(/.{1,80}/g)?.join('\n') || ''

const passwordResult = {
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
  secret: { format: 'password_ascii', vaultText: `$ANSIBLE_VAULT;1.2;AES256;dev\n${vaultBody}\n` },
}

describe('Generate view integration', () => {
  afterEach(() => {
    vi.useRealTimers()
    cleanup()
    vi.restoreAllMocks()
  })

  it('uses the canonical Generate route with only encrypt-capable environments', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(session())
      .mockResolvedValueOnce(profilesResponse())
      .mockResolvedValueOnce(jsonResponse(passwordResult))
    const user = userEvent.setup()

    render(<App />)
    const generateMode = await screen.findByRole('button', { name: 'Set generate mode' })
    await waitFor(() => expect(generateMode).toBeEnabled())
    await user.click(generateMode)

    expect(screen.getByRole('heading', { level: 1, name: 'Generate sealed private material' })).toBeVisible()
    expect(screen.getByRole('combobox', { name: 'Environment' })).toHaveValue('dev')
    expect(screen.queryByRole('option', { name: 'Read only' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Generate sealed material' }))

    expect(await screen.findByRole('textbox', { name: 'Sealed Vault value' })).toHaveValue(passwordResult.secret.vaultText)
    expect(fetchMock).toHaveBeenLastCalledWith('/api/v1/generate', expect.objectContaining({ method: 'POST' }))
    expect(JSON.parse(String(fetchMock.mock.lastCall?.[1]?.body))).toEqual({
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
  })

  it('cancels Generate without losing settings or letting a late result unlock a newer request', async () => {
    let resolveCancelled!: (response: Response) => void
    let resolveCurrent!: (response: Response) => void
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(session())
      .mockResolvedValueOnce(profilesResponse())
      .mockImplementationOnce(() => new Promise<Response>((resolve) => { resolveCancelled = resolve }))
      .mockImplementationOnce(() => new Promise<Response>((resolve) => { resolveCurrent = resolve }))
    const user = userEvent.setup()

    render(<App />)
    const generateMode = await screen.findByRole('button', { name: 'Set generate mode' })
    await waitFor(() => expect(generateMode).toBeEnabled())
    await user.click(generateMode)
    fireEvent.change(screen.getByRole('spinbutton', { name: 'Length' }), { target: { value: 64 } })
    await user.click(screen.getByRole('button', { name: 'Generate sealed material' }))

    const signal = fetchMock.mock.calls[2]?.[1]?.signal
    const aborted = vi.fn()
    signal?.addEventListener('abort', aborted)
    expect(signal?.aborted).toBe(false)
    expect(screen.getByRole('button', { name: 'Clear Generate form' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Set encrypt mode' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Cancel' }))

    expect(signal?.aborted).toBe(true)
    expect(aborted).toHaveBeenCalledOnce()
    expect(screen.getByRole('alert')).toHaveTextContent('Generation cancelled. The result is unknown; do not retry automatically.')
    expect(screen.getByRole('spinbutton', { name: 'Length' })).toHaveValue(64)
    expect(screen.getByRole('button', { name: 'Generate sealed material' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Set encrypt mode' })).toBeEnabled()
    expect(screen.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(3)

    await user.click(screen.getByRole('button', { name: 'Generate sealed material' }))
    const result = { ...passwordResult, effectiveParameters: { ...passwordResult.effectiveParameters, length: 64 } }
    await act(async () => resolveCancelled(jsonResponse(result)))
    expect(screen.queryByRole('textbox', { name: 'Sealed Vault value' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Generating and sealing…' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Set encrypt mode' })).toBeDisabled()

    await act(async () => resolveCurrent(jsonResponse(result)))
    expect(await screen.findByRole('textbox', { name: 'Sealed Vault value' })).toHaveValue(passwordResult.secret.vaultText)
    expect(screen.getByRole('button', { name: 'Generate sealed material' })).toBeEnabled()
    expect(fetchMock).toHaveBeenCalledTimes(4)
  })

  it('distinguishes a Generate timeout from cancellation without retrying', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(session())
      .mockResolvedValueOnce(profilesResponse())
      .mockImplementationOnce((_input, init) => new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
      }))
    const user = userEvent.setup()
    render(<App />)
    const generateMode = await screen.findByRole('button', { name: 'Set generate mode' })
    await waitFor(() => expect(generateMode).toBeEnabled())
    await user.click(generateMode)

    vi.useFakeTimers()
    fireEvent.click(screen.getByRole('button', { name: 'Generate sealed material' }))
    await act(async () => { await vi.advanceTimersByTimeAsync(OPERATION_TIMEOUT_MS) })

    expect(fetchMock.mock.calls[2]?.[1]?.signal?.aborted).toBe(true)
    expect(screen.getByRole('alert')).toHaveTextContent('Generation timed out. The result is unknown; do not retry automatically.')
    expect(screen.getByRole('button', { name: 'Generate sealed material' })).toBeEnabled()
    expect(screen.queryByRole('textbox', { name: 'Sealed Vault value' })).not.toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(3)
  })

  it('keeps Generate disabled until a ready catalog has an encrypt-capable environment', async () => {
    let resolveProfiles!: (response: Response) => void
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(session())
      .mockImplementationOnce(() => new Promise<Response>((resolve) => { resolveProfiles = resolve }))

    render(<App />)
    const generateMode = await screen.findByRole('button', { name: 'Set generate mode' })
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
    expect(generateMode).toBeDisabled()

    await act(async () => resolveProfiles(jsonResponse({
      profiles: [
        { id: 'read', label: 'Read only', capabilities: { encrypt: false, decrypt: true, rotateSource: true, rotateDestination: false } },
      ],
    })))

    expect(await screen.findByText('No environments are available for encryption.')).toBeVisible()
    expect(generateMode).toBeDisabled()
  })

  it('locks navigation during a forbidden refresh and requires explicit environment reselection', async () => {
    let resolveRefresh!: (response: Response) => void
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(session())
      .mockResolvedValueOnce(profilesResponse())
      .mockResolvedValueOnce(jsonResponse({ error: { code: 'forbidden', message: 'Forbidden' } }, { status: 403 }))
      .mockImplementationOnce(() => new Promise<Response>((resolve) => { resolveRefresh = resolve }))
    const user = userEvent.setup()

    render(<App />)
    const generateMode = await screen.findByRole('button', { name: 'Set generate mode' })
    await waitFor(() => expect(generateMode).toBeEnabled())
    await user.click(generateMode)
    await user.click(screen.getByRole('button', { name: 'Generate sealed material' }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(4))
    expect(screen.getByRole('status')).toHaveTextContent('Refreshing environments')
    expect(screen.getByRole('button', { name: 'Set encrypt mode' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Generating and sealing…' })).toBeDisabled()

    await act(async () => resolveRefresh(jsonResponse({
      profiles: [
        { id: 'production', label: 'Production', capabilities: { encrypt: true, decrypt: false, rotateSource: false, rotateDestination: false } },
      ],
    })))

    expect(await screen.findByRole('status')).toHaveTextContent('permissions changed')
    expect(screen.getByRole('combobox', { name: 'Environment' })).toHaveValue('')
    expect(screen.getByRole('option', { name: 'Production' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Generate sealed material' })).toBeDisabled()
  })

  it('offers recovery when a forbidden capability refresh fails', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(session())
      .mockResolvedValueOnce(profilesResponse())
      .mockResolvedValueOnce(jsonResponse({ error: { code: 'forbidden', message: 'Forbidden' } }, { status: 403 }))
      .mockResolvedValueOnce(jsonResponse({ error: { code: 'not_ready', message: 'Unavailable' } }, { status: 503 }))
      .mockResolvedValueOnce(session())
      .mockResolvedValueOnce(profilesResponse())
    const user = userEvent.setup()

    render(<App />)
    const generateMode = await screen.findByRole('button', { name: 'Set generate mode' })
    await waitFor(() => expect(generateMode).toBeEnabled())
    await user.click(generateMode)
    await user.click(screen.getByRole('button', { name: 'Generate sealed material' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('environments could not be refreshed')
    const retry = screen.getByRole('button', { name: 'Retry loading environments' })
    expect(retry).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Set encrypt mode' })).toBeDisabled()

    await user.click(retry)

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(6))
    expect(await screen.findByRole('status')).toHaveTextContent('permissions changed')
    expect(screen.getByRole('button', { name: 'Generate sealed material' })).toBeEnabled()
  })

  it('drops an in-memory Generate result as soon as sign-out starts', async () => {
    let resolveLogout!: (response: Response) => void
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(session(true))
      .mockResolvedValueOnce(profilesResponse())
      .mockResolvedValueOnce(jsonResponse(passwordResult))
      .mockImplementationOnce(() => new Promise<Response>((resolve) => { resolveLogout = resolve }))
    const user = userEvent.setup()

    render(<App />)
    const generateMode = await screen.findByRole('button', { name: 'Set generate mode' })
    await waitFor(() => expect(generateMode).toBeEnabled())
    await user.click(generateMode)
    await user.click(screen.getByRole('button', { name: 'Generate sealed material' }))
    expect(await screen.findByRole('textbox', { name: 'Sealed Vault value' })).toHaveValue(passwordResult.secret.vaultText)

    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))

    expect(screen.queryByRole('form', { name: 'Generate material form' })).not.toBeInTheDocument()
    expect(screen.queryByDisplayValue(passwordResult.secret.vaultText)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Signing out…' })).toBeDisabled()

    await act(async () => resolveLogout(new Response(null, { status: 204 })))
    expect(await screen.findByRole('heading', { name: 'Signed out' })).toBeInTheDocument()
  })
})
