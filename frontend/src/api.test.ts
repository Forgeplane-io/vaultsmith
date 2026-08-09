import { beforeEach, describe, expect, it, vi } from 'vitest'

let api: typeof import('./api')

const jsonResponse = (body: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })

const stalledJSONResponse = (signal: AbortSignal | null | undefined, onBodyStart: () => void) => ({
  ok: true,
  status: 200,
  json: () => {
    onBodyStart()
    return new Promise<unknown>((_resolve, reject) => {
      signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true })
    })
  },
}) as Response

describe('API client', () => {
  beforeEach(async () => {
    vi.restoreAllMocks()
    vi.resetModules()
    api = await import('./api')
  })

  it('loads public profiles from the same-origin endpoint', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse({ profiles: [{ id: 'dev', label: 'Development', capabilities: { encrypt: true, decrypt: false } }] }),
    )

    await expect(api.fetchProfiles()).resolves.toEqual([
      { id: 'dev', label: 'Development', capabilities: { encrypt: true, decrypt: false } },
    ])
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/profiles', expect.objectContaining({ headers: { Accept: 'application/json' } }))
  })

  it('rejects a profile response without boolean capabilities', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse({ profiles: [{ id: 'dev', label: 'Development' }] }),
    )

    await expect(api.fetchProfiles()).rejects.toMatchObject({ name: 'ApiError', code: 'invalid_response' })
  })

  it('rejects a malformed session response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse({ authenticated: true, authRequired: true }))

    await expect(api.fetchSession()).rejects.toMatchObject({ name: 'ApiError', code: 'invalid_response' })
  })

  it('times out a stalled session request', async () => {
    vi.useFakeTimers()
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true })
    }))

    try {
      const session = api.fetchSession()
      const timedOut = expect(session).rejects.toMatchObject({ name: 'ApiError', code: 'session_timeout' })
      await vi.runOnlyPendingTimersAsync()
      await timedOut
    } finally {
      vi.useRealTimers()
    }
  })

  it('reports a session timeout when response headers arrive but the body stalls', async () => {
    vi.useFakeTimers()
    let markBodyStarted!: () => void
    const bodyStarted = new Promise<void>((resolve) => { markBodyStarted = resolve })
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) =>
      Promise.resolve(stalledJSONResponse(init?.signal, markBodyStarted)))

    try {
      const session = api.fetchSession()
      const timedOut = expect(session).rejects.toMatchObject({ name: 'ApiError', code: 'session_timeout' })
      await bodyStarted
      await vi.advanceTimersByTimeAsync(10_000)
      await timedOut
    } finally {
      vi.useRealTimers()
    }
  })

  it('sends the exact operation contract', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse({ value: 'vault-output' }))

    await expect(api.runOperation({ profileId: 'dev', mode: 'encrypt', value: 'fixture-value' })).resolves.toBe('vault-output')
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/operations',
      expect.objectContaining({
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({ profileId: 'dev', mode: 'encrypt', value: 'fixture-value' })
  })

  it('sends the exact rotate operation contract', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse({ value: 'rotated-vault-output' }))

    await expect(api.runOperation({ mode: 'rotate', sourceProfileId: 'dev', destinationProfileId: 'prod', value: 'vault-input' })).resolves.toBe('rotated-vault-output')
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/operations',
      expect.objectContaining({
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({ mode: 'rotate', sourceProfileId: 'dev', destinationProfileId: 'prod', value: 'vault-input' })
  })

  it('sends a CSRF-protected same-origin logout request', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementationOnce(async () => jsonResponse({
      authenticated: true,
      authRequired: true,
      email: 'operator@example.test',
      csrfToken: 'csrf-fixture',
    })).mockImplementationOnce(async () => jsonResponse({ ok: true }))

    await api.fetchSession()
    await api.logout()

    expect(fetchMock).toHaveBeenNthCalledWith(2, '/auth/logout', expect.objectContaining({
      method: 'POST',
      credentials: 'same-origin',
      headers: { Accept: 'application/json', 'X-CSRF-Token': 'csrf-fixture' },
    }))
  })

  it('turns API errors into safe typed errors', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse(
        { error: { code: 'operation_failed', message: 'vault operation failed' } },
        { status: 422 },
      ),
    )

    await expect(api.runOperation({ profileId: 'dev', mode: 'decrypt', value: 'ciphertext' })).rejects.toMatchObject({
      name: 'ApiError',
      code: 'operation_failed',
      status: 422,
      message: 'vault operation failed',
    })
  })

  it('uses a generic message when the server response is not JSON', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('sensitive upstream detail', { status: 500 }))

    await expect(api.fetchProfiles()).rejects.toMatchObject({ name: 'ApiError', message: 'Request failed' })
  })

  it('times out a stalled profile request', async () => {
    vi.useFakeTimers()
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true })
    }))

    try {
      const profiles = api.fetchProfiles()
      const timedOut = expect(profiles).rejects.toMatchObject({ name: 'ApiError', code: 'profiles_timeout' })
      await vi.runOnlyPendingTimersAsync()
      await timedOut
    } finally {
      vi.useRealTimers()
    }
  })

  it('reports a profile timeout when response headers arrive but the body stalls', async () => {
    vi.useFakeTimers()
    let markBodyStarted!: () => void
    const bodyStarted = new Promise<void>((resolve) => { markBodyStarted = resolve })
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) =>
      Promise.resolve(stalledJSONResponse(init?.signal, markBodyStarted)))

    try {
      const profiles = api.fetchProfiles()
      const timedOut = expect(profiles).rejects.toMatchObject({ name: 'ApiError', code: 'profiles_timeout' })
      await bodyStarted
      await vi.advanceTimersByTimeAsync(10_000)
      await timedOut
    } finally {
      vi.useRealTimers()
    }
  })

  it('does not start a session request when the caller signal is already aborted', async () => {
    const controller = new AbortController()
    controller.abort()
    const fetchMock = vi.spyOn(globalThis, 'fetch')

    await expect(api.fetchSession(controller.signal)).rejects.toMatchObject({ name: 'AbortError' })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('preserves caller cancellation when the session request rejects after the timeout boundary', async () => {
    vi.useFakeTimers()
    const controller = new AbortController()
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => {
        globalThis.setTimeout(() => reject(new DOMException('aborted', 'AbortError')), 10_000)
      }, { once: true })
    }))

    try {
      const session = api.fetchSession(controller.signal)
      const cancelled = expect(session).rejects.toMatchObject({ name: 'AbortError' })
      controller.abort()
      await vi.runOnlyPendingTimersAsync()
      await cancelled
    } finally {
      vi.useRealTimers()
    }
  })

  it('preserves caller cancellation while reading the session response body', async () => {
    const controller = new AbortController()
    let markBodyStarted!: () => void
    const bodyStarted = new Promise<void>((resolve) => { markBodyStarted = resolve })
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) =>
      Promise.resolve(stalledJSONResponse(init?.signal, markBodyStarted)))

    const session = api.fetchSession(controller.signal)
    const cancelled = expect(session).rejects.toMatchObject({ name: 'AbortError' })
    await bodyStarted
    controller.abort()
    await cancelled
  })

  it('does not start a profile request when the caller signal is already aborted', async () => {
    const controller = new AbortController()
    controller.abort()
    const fetchMock = vi.spyOn(globalThis, 'fetch')

    await expect(api.fetchProfiles(controller.signal)).rejects.toMatchObject({ name: 'AbortError' })
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
