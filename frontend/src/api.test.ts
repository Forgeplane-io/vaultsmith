import { beforeEach, describe, expect, it, vi } from 'vitest'

let api: typeof import('./api')

const jsonResponse = (body: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })

const emptyResponse = (status = 204) => new Response(null, { status })

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
    })).mockImplementationOnce(async () => emptyResponse())

    await api.fetchSession()
    await api.logout()

    expect(fetchMock).toHaveBeenNthCalledWith(2, '/auth/logout', expect.objectContaining({
      method: 'POST',
      credentials: 'same-origin',
      headers: { Accept: 'application/json', 'X-CSRF-Token': 'csrf-fixture' },
    }))
  })

  it('confirms a non-204 logout response only after an anonymous session check', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse({ accepted: true }))
      .mockResolvedValueOnce(jsonResponse({ authenticated: false, authRequired: true, csrfToken: '' }))

    await expect(api.logout()).resolves.toBeUndefined()

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(fetchMock).toHaveBeenNthCalledWith(1, '/auth/logout', expect.objectContaining({ method: 'POST' }))
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/v1/session', expect.objectContaining({ method: 'GET' }))
  })

  it('rejects a non-204 logout response when the session remains authenticated', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse({ accepted: true }))
      .mockResolvedValueOnce(jsonResponse({
        authenticated: true,
        authRequired: true,
        email: 'operator@example.test',
        csrfToken: 'csrf-fixture',
      }))

    await expect(api.logout()).rejects.toMatchObject({
      name: 'ApiError',
      code: 'logout_unconfirmed',
    })
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('settles a stalled logout locally after ten seconds and ignores its late response', async () => {
    vi.useFakeTimers()
    let resolveLogout!: (response: Response) => void
    let logoutSignal: AbortSignal | null | undefined
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      logoutSignal = init?.signal
      return new Promise<Response>((resolve) => {
        resolveLogout = resolve
      })
    })

    const logoutRequest = api.logout()
    const outcome = logoutRequest.then(
      () => ({ state: 'resolved' as const, reason: null }),
      (reason: unknown) => ({ state: 'rejected' as const, reason }),
    )
    let settled = false
    void outcome.then(() => { settled = true })

    try {
      await vi.advanceTimersByTimeAsync(9_999)
      expect(settled).toBe(false)
      await vi.advanceTimersByTimeAsync(1)
      expect(settled).toBe(true)
      expect(logoutSignal?.aborted).toBe(true)
      expect(await outcome).toMatchObject({
        state: 'rejected',
        reason: { name: 'ApiError', code: 'logout_timeout' },
      })

      resolveLogout(jsonResponse({ accepted: true }))
      await vi.advanceTimersByTimeAsync(0)
      expect(await outcome).toMatchObject({
        state: 'rejected',
        reason: { code: 'logout_timeout' },
      })
      expect(fetchMock).toHaveBeenCalledOnce()
    } finally {
      resolveLogout?.(emptyResponse())
      await Promise.resolve()
      vi.useRealTimers()
    }
  })

  it('bounds a stalled anonymous-session verification within the same logout timeout', async () => {
    vi.useFakeTimers()
    let resolveVerification: ((response: Response) => void) | undefined
    let verificationSignal: AbortSignal | null | undefined
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse({ accepted: true }))
      .mockImplementationOnce((_input, init) => {
        verificationSignal = init?.signal
        return new Promise<Response>((resolve) => {
          resolveVerification = resolve
        })
      })

    const outcome = api.logout().then(
      () => ({ state: 'resolved' as const, reason: null }),
      (reason: unknown) => ({ state: 'rejected' as const, reason }),
    )

    try {
      await vi.advanceTimersByTimeAsync(10_000)
      expect(await outcome).toMatchObject({
        state: 'rejected',
        reason: { name: 'ApiError', code: 'logout_timeout' },
      })
      expect(verificationSignal?.aborted).toBe(true)
      expect(fetchMock).toHaveBeenCalledTimes(2)

      resolveVerification?.(jsonResponse({ authenticated: false, authRequired: true, csrfToken: '' }))
      await Promise.resolve()
      expect(await outcome).toMatchObject({
        state: 'rejected',
        reason: { code: 'logout_timeout' },
      })
    } finally {
      resolveVerification?.(jsonResponse({ authenticated: false, authRequired: true, csrfToken: '' }))
      await Promise.resolve()
      vi.useRealTimers()
    }
  })

  it('does not let a timed-out verification restore CSRF authority after a newer logout succeeds', async () => {
    vi.useFakeTimers()
    let resolveLateVerification: ((response: Response) => void) | undefined
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse({
        authenticated: true,
        authRequired: true,
        email: 'operator@example.test',
        csrfToken: 'csrf-current',
      }))
      .mockResolvedValueOnce(jsonResponse({ accepted: true }))
      .mockImplementationOnce(() => new Promise<Response>((resolve) => {
        resolveLateVerification = resolve
      }))
      .mockResolvedValueOnce(emptyResponse())
      .mockResolvedValueOnce(jsonResponse({ value: 'vault-output' }))

    try {
      await api.fetchSession()
      const firstLogout = api.logout()
      const timedOut = expect(firstLogout).rejects.toMatchObject({ name: 'ApiError', code: 'logout_timeout' })
      await vi.advanceTimersByTimeAsync(10_000)
      await timedOut
      expect(fetchMock).toHaveBeenCalledTimes(3)

      await expect(api.logout()).resolves.toBeUndefined()
      resolveLateVerification?.(jsonResponse({
        authenticated: false,
        authRequired: true,
        csrfToken: 'csrf-late',
      }))
      await vi.advanceTimersByTimeAsync(0)

      await api.runOperation({ profileId: 'dev', mode: 'encrypt', value: 'fixture-value' })
      expect(fetchMock).toHaveBeenNthCalledWith(5, '/api/v1/operations', expect.objectContaining({
        headers: { 'Content-Type': 'application/json' },
      }))
    } finally {
      resolveLateVerification?.(jsonResponse({ authenticated: false, authRequired: true, csrfToken: '' }))
      await vi.advanceTimersByTimeAsync(0)
      vi.useRealTimers()
    }
  })

  it('does not retry a failed logout request', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(
      { error: { code: 'not_ready', message: 'private service detail' } },
      { status: 503 },
    ))

    await expect(api.logout()).rejects.toMatchObject({
      name: 'ApiError',
      code: 'not_ready',
      status: 503,
    })
    expect(fetchMock).toHaveBeenCalledOnce()
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
