import { createContext, useContext } from 'react'
import type { SessionStatus } from '../api/types'

export interface SessionContextValue {
  session: SessionStatus | undefined
  loading: boolean
  refresh: () => Promise<unknown>
  signOut: () => Promise<void>
}

export const SessionContext = createContext<SessionContextValue | null>(null)

export function useSession(): SessionContextValue {
  const value = useContext(SessionContext)
  if (!value) throw new Error('useSession must be used inside SessionProvider')
  return value
}
