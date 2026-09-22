import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import type { PropsWithChildren } from 'react'
import { Navigate, Outlet, useLocation } from 'react-router-dom'
import { ApiError, apiRequest, setUnauthorizedHandler } from '../api/client'
import type { ApiRequestOptions } from '../api/client'
import type { SessionStatus } from '../api/types'
import { LoadingState } from '../components/ui'
import { SessionContext, useSession } from './session-context'

async function sessionRequest(path: string, options: ApiRequestOptions = {}): Promise<SessionStatus> {
  const payload = await apiRequest<unknown>(path, options)
  if (!payload || typeof payload !== 'object' || !('required' in payload) || !('authenticated' in payload)
    || typeof payload.required !== 'boolean' || typeof payload.authenticated !== 'boolean') {
    throw new ApiError(502, 'NorthFlux could not verify the session response. Sign in again to continue.')
  }
  return payload as SessionStatus
}

export function SessionProvider({ children }: PropsWithChildren) {
  const queryClient = useQueryClient()
  const sessionQuery = useQuery({
    queryKey: ['session'],
    queryFn: ({ signal }) => sessionRequest('/api/v1/auth/session', { signal }),
    retry: false,
    staleTime: 30_000,
  })

  useEffect(() => {
    setUnauthorizedHandler(() => {
      // A session read started before expiry must not restore authentication
      // after this authoritative 401. Cancellation discards its eventual result.
      void queryClient.cancelQueries({ queryKey: ['session'], exact: true }, { revert: false })
      queryClient.setQueryData<SessionStatus>(['session'], {
        required: true,
        authenticated: false,
        expires_at: null,
      })
      queryClient.removeQueries({
        predicate: (query) => query.queryKey[0] !== 'session',
      })
    })
    return () => setUnauthorizedHandler()
  }, [queryClient])

  const value = {
    session: sessionQuery.data,
    loading: sessionQuery.isLoading,
    refresh: async () => queryClient.fetchQuery({
      queryKey: ['session'],
      queryFn: ({ signal }) => sessionRequest('/api/v1/auth/session', { signal }),
      staleTime: 0,
    }),
    signOut: async () => {
      const status = await sessionRequest('/api/v1/auth/logout', { method: 'POST' })
      await queryClient.cancelQueries({ queryKey: ['session'], exact: true }, { revert: false })
      queryClient.setQueryData(['session'], status)
      queryClient.removeQueries({ predicate: (query) => query.queryKey[0] !== 'session' })
    },
  }

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
}

export function ProtectedRoute() {
  const location = useLocation()
  const { session, loading } = useSession()

  if (loading) return <LoadingState label="Checking your secure session" fullPage />
  if (!session) {
    return <Navigate to="/login" replace state={{ from: location, reason: 'session-error' }} />
  }
  if (session.required && !session.authenticated) {
    return <Navigate to="/login" replace state={{ from: location }} />
  }
  return <Outlet />
}
