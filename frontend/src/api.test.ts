import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, fetchProfiles, PROFILE_LOAD_TIMEOUT_MS, runOperation } from './api'

const jsonResponse = (body: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })

describe('API client', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('loads public profiles from the same-origin endpoint', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse({ profiles: [{ id: 'dev', label: 'Development' }] }),
    )

    await expect(fetchProfiles()).resolves.toEqual([{ id: 'dev', label: 'Development' }])
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/profiles', expect.objectContaining({ headers: { Accept: 'application/json' } }))
  })

  it('sends the exact operation contract', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse({ value: 'vault-output' }))

    await expect(runOperation({ profileId: 'dev', mode: 'encrypt', value: 'fixture-value' })).resolves.toBe('vault-output')
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/operations',
      expect.objectContaining({
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ profileId: 'dev', mode: 'encrypt', value: 'fixture-value' }),
      }),
    )
  })

  it('sends the exact rotate operation contract', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse({ value: 'rotated-vault-output' }))

    await expect(runOperation({ mode: 'rotate', sourceProfileId: 'dev', destinationProfileId: 'prod', value: 'vault-input' })).resolves.toBe('rotated-vault-output')
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/operations',
      expect.objectContaining({
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'rotate', sourceProfileId: 'dev', destinationProfileId: 'prod', value: 'vault-input' }),
      }),
    )
  })

  it('turns API errors into safe typed errors', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse(
        { error: { code: 'operation_failed', message: 'vault operation failed' } },
        { status: 422 },
      ),
    )

    await expect(runOperation({ profileId: 'dev', mode: 'decrypt', value: 'ciphertext' })).rejects.toMatchObject({
      name: 'ApiError',
      code: 'operation_failed',
      status: 422,
      message: 'vault operation failed',
    })
  })

  it('uses a generic message when the server response is not JSON', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('sensitive upstream detail', { status: 500 }))

    await expect(fetchProfiles()).rejects.toEqual(expect.any(ApiError))
    await expect(fetchProfiles()).rejects.toMatchObject({ message: 'Request failed' })
  })

  it('times out a stalled profile request', async () => {
    vi.useFakeTimers()
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true })
    }))

    try {
      const profiles = fetchProfiles()
      const timedOut = expect(profiles).rejects.toMatchObject({ name: 'ApiError', code: 'profiles_timeout' })
      await vi.advanceTimersByTimeAsync(PROFILE_LOAD_TIMEOUT_MS)
      await timedOut
    } finally {
      vi.useRealTimers()
    }
  })

  it('does not start a profile request when the caller signal is already aborted', async () => {
    const controller = new AbortController()
    controller.abort()
    const fetchMock = vi.spyOn(globalThis, 'fetch')

    await expect(fetchProfiles(controller.signal)).rejects.toMatchObject({ name: 'AbortError' })
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
