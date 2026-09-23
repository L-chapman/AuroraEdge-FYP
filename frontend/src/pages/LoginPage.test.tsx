import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { SessionContext } from '../auth/session-context'
import { LoginPage } from './LoginPage'

function Destination() {
  const location = useLocation()
  return <p>{location.pathname}{location.search}{location.hash}</p>
}

afterEach(cleanup)

describe('Sign-in return destination', () => {
  it.each([true, false])('preserves the requested query and fragment when authentication is required: %s', async (required) => {
    render(<SessionContext.Provider value={{ session: { required, authenticated: true }, loading: false, refresh: vi.fn(), signOut: vi.fn() }}>
      <MemoryRouter initialEntries={[{ pathname: '/login', state: { from: { pathname: '/scan', search: '?domain=example.com', hash: '#scan-options' } } }]}>
        <Routes><Route path="/login" element={<LoginPage />} /><Route path="/scan" element={<Destination />} /></Routes>
      </MemoryRouter>
    </SessionContext.Provider>)
    expect(await screen.findByText('/scan?domain=example.com#scan-options')).toBeVisible()
  })
})
