import { useState } from 'react'
import type { FormEvent } from 'react'
import { Link, Navigate, useLocation } from 'react-router-dom'
import { apiRequest, ApiError } from '../api/client'
import type { SessionStatus } from '../api/types'
import { useSession } from '../auth/session-context'
import { BrandMark } from '../components/BrandMark'
import { Icon } from '../components/Icon'
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
      <div className="auth-layout">
      <section className="auth-introduction" aria-labelledby="welcome-title">
        <div className="brand auth-wordmark"><BrandMark /><span><strong>NorthFlux</strong><small>Security</small></span></div>
        <p className="eyebrow">See clearly. Act confidently.</p>
        <h2 id="welcome-title">A clearer view of<br /><span>your email security.</span></h2>
        <p>Understand how your domains are protected against email impersonation—and what needs your attention next.</p>
        <ol className="auth-features">
          <li><span><Icon name="scan" /></span><div><strong>Find the gaps</strong><p>Check the records that help protect your email.</p></div></li>
          <li><span><Icon name="history" /></span><div><strong>Follow the changes</strong><p>Keep a history and review changes over time.</p></div></li>
          <li><span><Icon name="shield" /></span><div><strong>Stay in control</strong><p>Review clear guidance before changing your setup.</p></div></li>
        </ol>
        <p className="auth-ownership">Self-hosted. Your workspace, on your infrastructure.</p>
      </section>
      <section className="auth-panel" aria-labelledby="sign-in-title">
        <span className="auth-panel__icon"><Icon name="shield" /></span>
        <p className="eyebrow">Welcome to your workspace</p>
        <h1 id="sign-in-title">Operator sign in</h1>
        <p>Enter the private access token set up for this NorthFlux installation.</p>
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
        <Link className="auth-privacy" to="/privacy">How NorthFlux handles your data<Icon name="arrow" /></Link>
      </section>
      </div>
    </main>
  )
}
