export class ApiError extends Error {
  readonly status: number
  readonly detail: string

  constructor(status: number, detail: string) {
    super(detail)
    this.name = 'ApiError'
    this.status = status
    this.detail = detail
  }
}

const unsafeMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])
let unauthorizedHandler: (() => void) | undefined

export function setUnauthorizedHandler(handler?: () => void): void {
  unauthorizedHandler = handler
}

export function readCookie(name: string, cookieString = document.cookie): string | undefined {
  const encodedName = `${encodeURIComponent(name)}=`
  return cookieString
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith(encodedName))
    ?.slice(encodedName.length)
}

export interface ApiRequestOptions extends Omit<RequestInit, 'body'> {
  body?: unknown
}

function errorDetail(payload: unknown, fallback: string): string {
  if (typeof payload === 'object' && payload !== null && 'detail' in payload) {
    const detail = (payload as { detail?: unknown }).detail
    if (typeof detail === 'string') return detail
    if (Array.isArray(detail)) return detail.map(String).join(', ')
  }
  return fallback
}

export async function apiRequest<T>(path: string, options: ApiRequestOptions = {}): Promise<T> {
  const method = (options.method ?? 'GET').toUpperCase()
  const headers = new Headers(options.headers)
  headers.set('Accept', 'application/json')

  let body: BodyInit | undefined
  if (options.body !== undefined) {
    headers.set('Content-Type', 'application/json')
    body = JSON.stringify(options.body)
  }

  if (unsafeMethods.has(method)) {
    const csrf = readCookie('northflux_csrf')
    if (csrf) headers.set('X-CSRF-Token', decodeURIComponent(csrf))
  }

  let response: Response
  try {
    response = await fetch(path, {
      ...options,
      method,
      headers,
      body,
      credentials: 'same-origin',
    })
  } catch {
    options.signal?.throwIfAborted()
    throw new ApiError(0, 'NorthFlux could not reach the service. Check your connection and try again.')
  }

  options.signal?.throwIfAborted()
  const contentType = response.headers.get('content-type') ?? ''
  let unreadable = false
  const payload: unknown = contentType.includes('application/json')
    ? await response.json().catch(() => { unreadable = true; return null })
    : await response.text().catch(() => '')

  // Cancellation also applies while a response body is being read. An old
  // request must not invalidate a newer session when its late 401 arrives.
  options.signal?.throwIfAborted()
  if (!response.ok) {
    if (response.status === 401) unauthorizedHandler?.()
    throw new ApiError(response.status, errorDetail(payload, response.statusText || 'Request failed'))
  }
  if (unreadable) throw new ApiError(502, 'NorthFlux received an unreadable response from the service. Please try again.')

  return payload as T
}

export function asBoolean(value: unknown): boolean {
  if (typeof value === 'boolean') return value
  if (typeof value === 'number') return value !== 0
  return ['1', 'true', 'yes', 'on'].includes(String(value ?? '').trim().toLowerCase())
}

export function asNumber(value: unknown, fallback = 0): number {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : fallback
}

export function displayDate(value: unknown): string {
  if (!value) return 'Never'
  const date = new Date(String(value))
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString()
}
