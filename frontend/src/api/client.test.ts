import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, apiRequest, asBoolean, asNumber, displayDate, readCookie, setUnauthorizedHandler } from './client'

afterEach(() => {
  vi.restoreAllMocks()
  setUnauthorizedHandler()
  document.cookie = 'northflux_csrf=; Max-Age=0; path=/'
})

describe('API client', () => {
  it('reads named cookies without confusing similarly named values', () => {
    expect(readCookie('northflux_csrf', 'other=1; northflux_csrf=safe%20token; csrf=wrong')).toBe('safe%20token')
    expect(readCookie('missing', 'other=1')).toBeUndefined()
  })

  it('sends JSON, same-origin credentials, and the decoded CSRF token on mutations', async () => {
    document.cookie = 'northflux_csrf=safe%20token; path=/'
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(
      JSON.stringify({ ok: true }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    ))

    await expect(apiRequest<{ ok: boolean }>('/api/example', { method: 'POST', body: { value: 7 } })).resolves.toEqual({ ok: true })
    const [, request] = fetchMock.mock.calls[0] ?? []
    const headers = new Headers(request?.headers)
    expect(request?.credentials).toBe('same-origin')
    expect(headers.get('X-CSRF-Token')).toBe('safe token')
    expect(headers.get('Content-Type')).toBe('application/json')
    expect(request?.body).toBe(JSON.stringify({ value: 7 }))
  })

  it('does not add a CSRF header to safe requests', async () => {
    document.cookie = 'northflux_csrf=token; path=/'
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('plain text', { status: 200 }))
    await expect(apiRequest<string>('/health')).resolves.toBe('plain text')
    const [, request] = fetchMock.mock.calls[0] ?? []
    expect(new Headers(request?.headers).has('X-CSRF-Token')).toBe(false)
  })

  it('normalises JSON and validation errors into ApiError', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(
      JSON.stringify({ detail: [{ loc: ['body', 'token'], msg: 'Required' }] }),
      { status: 422, statusText: 'Unprocessable', headers: { 'content-type': 'application/json' } },
    ))
    await expect(apiRequest('/api/example')).rejects.toMatchObject({ name: 'ApiError', status: 422 })
  })

  it('uses a useful detail from API failures and handles offline requests', async () => {
    const unauthorized = vi.fn()
    setUnauthorizedHandler(unauthorized)
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(
      JSON.stringify({ detail: 'Session expired' }),
      { status: 401, headers: { 'content-type': 'application/json' } },
    )).mockResolvedValueOnce(new Response(
      JSON.stringify({ detail: 'Access denied' }),
      { status: 403, headers: { 'content-type': 'application/json' } },
    )).mockRejectedValueOnce(new Error('offline'))
    await expect(apiRequest('/api/private')).rejects.toEqual(new ApiError(401, 'Session expired'))
    expect(unauthorized).toHaveBeenCalledTimes(1)
    await expect(apiRequest('/api/private')).rejects.toEqual(new ApiError(403, 'Access denied'))
    expect(unauthorized).toHaveBeenCalledTimes(1)
    await expect(apiRequest('/api/private')).rejects.toMatchObject({ status: 0, detail: expect.stringContaining('could not reach') })
  })

  it('rejects an unreadable JSON success instead of handing null to page callbacks', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{broken', { status: 200, headers: { 'content-type': 'application/json' } }))
    await expect(apiRequest('/api/scan')).rejects.toMatchObject({ name: 'ApiError', detail: expect.stringContaining('unreadable') })
  })

  it('does not apply an obsolete 401 from an already cancelled request to the current session', async () => {
    const unauthorized = vi.fn()
    setUnauthorizedHandler(unauthorized)
    const controller = new AbortController()
    let complete!: (response: Response) => void
    const response = new Promise<Response>((resolve) => { complete = resolve })
    vi.spyOn(globalThis, 'fetch').mockReturnValue(response)
    const request = apiRequest('/api/old-request', { signal: controller.signal })
    controller.abort()
    complete(new Response(JSON.stringify({ detail: 'Old session expired' }), { status: 401, headers: { 'content-type': 'application/json' } }))
    await expect(request).rejects.toMatchObject({ name: 'AbortError' })
    expect(unauthorized).not.toHaveBeenCalled()
  })
})

describe('API presentation normalisers', () => {
  it.each([[true, true], [1, true], ['YES', true], ['off', false], [0, false], [null, false]])('normalises %s to %s', (input, expected) => {
    expect(asBoolean(input)).toBe(expected)
  })

  it('normalises finite numbers and preserves a fallback for invalid input', () => {
    expect(asNumber('42')).toBe(42)
    expect(asNumber('not-a-number', 9)).toBe(9)
  })

  it('formats valid dates and preserves invalid or empty values safely', () => {
    expect(displayDate(null)).toBe('Never')
    expect(displayDate('not-a-date')).toBe('not-a-date')
    expect(displayDate('2026-09-21T12:00:00Z')).not.toBe('2026-09-21T12:00:00Z')
  })
})
