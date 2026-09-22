import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import type { PropsWithChildren } from 'react'
import { Navigate, Outlet, useLocation } from 'react-router-dom'
import { apiRequest, setUnauthorizedHandler } from '../api/client'
import type { SessionStatus } from '../api/types'
import { LoadingState } from '../components/ui'
import { SessionContext, useSession } from './session-context'

export function SessionProvider({ children }: PropsWithChildren) {
  const queryClient = useQueryClient()
  const sessionQuery = useQuery({
    queryKey: ['session'],
    queryFn: () => apiRequest<SessionStatus>('/api/v1/auth/session'),
    retry: false,
    staleTime: 30_000,
  })

  useEffect(() => {
    setUnauthorizedHandler(() => {
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
      queryFn: () => apiRequest<SessionStatus>('/api/v1/auth/session'),
      staleTime: 0,
    }),
    signOut: async () => {
      const status = await apiRequest<SessionStatus>('/api/v1/auth/logout', { method: 'POST' })
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
