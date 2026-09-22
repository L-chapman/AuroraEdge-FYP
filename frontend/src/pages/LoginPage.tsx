import { useState } from 'react'
import type { FormEvent } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { apiRequest, ApiError } from '../api/client'
import type { SessionStatus } from '../api/types'
import { useSession } from '../auth/session-context'
import { Button, Field, InlineNotice, LoadingState } from '../components/ui'

interface LocationState {
  from?: { pathname?: string }
  reason?: string
}

export function LoginPage() {
  const [token, setToken] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const { session, loading, refresh } = useSession()
  const location = useLocation()
  const state = (location.state ?? {}) as LocationState

  if (loading) return <LoadingState label="Preparing secure sign in" fullPage />
  if (session && (!session.required || session.authenticated)) {
    return <Navigate to={state.from?.pathname ?? '/'} replace />
  }

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setError('')
    if (!token.trim()) {
      setError('Enter your operator token.')
      return
    }
    setSubmitting(true)
    try {
      await apiRequest<SessionStatus>('/api/v1/auth/login', {
        method: 'POST',
        body: { token },
      })
      setToken('')
      await refresh()
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.detail : 'Sign in failed. Try again.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="auth-page">
      <section className="auth-panel" aria-labelledby="sign-in-title">
        <div className="auth-brand" aria-hidden="true">N</div>
        <p className="eyebrow">NorthFlux Security</p>
        <h1 id="sign-in-title">Operator sign in</h1>
        <p>Use the private dashboard token configured by your NorthFlux administrator.</p>
        {state.reason === 'session-error' ? (
          <InlineNotice tone="warning">Your session could not be verified. Sign in again to continue.</InlineNotice>
        ) : null}
        <form onSubmit={submit} noValidate>
          <Field label="Operator token" htmlFor="operator-token" error={error || undefined}>
            <input
              id="operator-token"
              name="token"
              type="password"
              autoComplete="current-password"
              value={token}
              aria-invalid={Boolean(error)}
              onChange={(event) => setToken(event.target.value)}
              autoFocus
            />
          </Field>
          <Button type="submit" disabled={submitting} className="button--full">
            {submitting ? 'Signing in…' : 'Sign in securely'}
          </Button>
        </form>
        <p className="auth-footnote">Your token is submitted over the current connection and is never stored in browser storage.</p>
      </section>
    </main>
  )
}
