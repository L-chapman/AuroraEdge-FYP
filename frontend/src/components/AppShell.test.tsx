import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { SessionContext } from '../auth/session-context'
import { AppShell } from './AppShell'

function renderShell(signOut = vi.fn<() => Promise<void>>().mockResolvedValue(undefined)) {
  render(
    <SessionContext.Provider value={{ session: { required: true, authenticated: true }, loading: false, refresh: vi.fn(), signOut }}>
      <MemoryRouter>
        <Routes>
          <Route element={<AppShell />}><Route index element={<h1>Workspace overview</h1>} /><Route path="scan" element={<h1>Scanner</h1>} /></Route>
          <Route path="login" element={<h1>Signed out</h1>} />
        </Routes>
      </MemoryRouter>
    </SessionContext.Provider>,
  )
  return signOut
}

afterEach(cleanup)

describe('AppShell session actions', () => {
  it('only leaves the workspace after sign-out succeeds', async () => {
    const user = userEvent.setup()
    const signOut = renderShell()
    await user.click(screen.getByRole('button', { name: 'Sign out' }))
    expect(signOut).toHaveBeenCalledOnce()
    expect(await screen.findByRole('heading', { name: 'Signed out' })).toBeVisible()
  })

  it('shows a failed sign-out clearly and allows a safe retry', async () => {
    const user = userEvent.setup()
    const signOut = vi.fn<() => Promise<void>>()
      .mockRejectedValueOnce(new Error('Network unavailable'))
      .mockResolvedValueOnce(undefined)
    renderShell(signOut)

    await user.click(screen.getByRole('button', { name: 'Menu' }))
    await user.click(screen.getByRole('button', { name: 'Sign out' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Your session may still be active')
    expect(screen.getByRole('heading', { name: 'Workspace overview' })).toBeVisible()
    expect(screen.getByRole('button', { name: 'Menu' })).toHaveAttribute('aria-expanded', 'false')
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeEnabled()

    await user.click(screen.getByRole('button', { name: 'Sign out' }))
    expect(await screen.findByRole('heading', { name: 'Signed out' })).toBeVisible()
    expect(signOut).toHaveBeenCalledTimes(2)
  })
})

describe('AppShell menu disclosure', () => {
  it('closes on Escape and returns focus to the menu control', async () => {
    const user = userEvent.setup()
    renderShell()
    const menu = screen.getByRole('button', { name: 'Menu' })
    await user.click(menu)
    expect(menu).toHaveAttribute('aria-expanded', 'true')
    screen.getByRole('link', { name: 'Scan' }).focus()
    await user.keyboard('{Escape}')
    expect(menu).toHaveAttribute('aria-expanded', 'false')
    expect(menu).toHaveFocus()
  })

  it('closes when the user clicks outside navigation', async () => {
    const user = userEvent.setup()
    renderShell()
    const menu = screen.getByRole('button', { name: 'Menu' })
    await user.click(menu)
    await user.click(screen.getByRole('heading', { name: 'Workspace overview' }))
    expect(menu).toHaveAttribute('aria-expanded', 'false')
  })

  it('closes after choosing a route and updates the active link', async () => {
    const user = userEvent.setup()
    renderShell()
    await user.click(screen.getByRole('button', { name: 'Menu' }))
    await user.click(screen.getByRole('link', { name: 'Scan' }))
    expect(screen.getByRole('heading', { name: 'Scanner' })).toBeVisible()
    expect(screen.getByRole('main')).toHaveFocus()
    expect(screen.getByRole('link', { name: 'Scan' })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByRole('button', { name: 'Menu' })).toHaveAttribute('aria-expanded', 'false')
  })
})
