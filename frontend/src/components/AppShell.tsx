import { useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useSession } from '../auth/session-context'
import { Button } from './ui'

const navigation = [
  { to: '/', label: 'Overview', end: true },
  { to: '/scan', label: 'Scan' },
  { to: '/domains', label: 'Domains' },
  { to: '/generator', label: 'Generator' },
  { to: '/settings', label: 'Settings' },
]

export function AppShell() {
  const [menuOpen, setMenuOpen] = useState(false)
  const [signingOut, setSigningOut] = useState(false)
  const { signOut } = useSession()
  const navigate = useNavigate()

  const handleSignOut = async () => {
    setSigningOut(true)
    try {
      await signOut()
      navigate('/login', { replace: true })
    } finally {
      setSigningOut(false)
    }
  }

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <header className="topbar">
        <NavLink to="/" className="brand" aria-label="NorthFlux Security overview">
          <span className="brand__mark" aria-hidden="true">N</span>
          <span><strong>NorthFlux</strong><small>Security</small></span>
        </NavLink>
        <button
          type="button"
          className="menu-button"
          aria-expanded={menuOpen}
          aria-controls="primary-navigation"
          onClick={() => setMenuOpen((value) => !value)}
        >
          <span aria-hidden="true">☰</span><span>Menu</span>
        </button>
        <nav id="primary-navigation" className={menuOpen ? 'navigation navigation--open' : 'navigation'} aria-label="Primary navigation">
          {navigation.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              onClick={() => setMenuOpen(false)}
              className={({ isActive }) => isActive ? 'navigation__link navigation__link--active' : 'navigation__link'}
            >
              {item.label}
            </NavLink>
          ))}
          <Button className="navigation__sign-out" variant="ghost" type="button" onClick={handleSignOut} disabled={signingOut}>
            {signingOut ? 'Signing out…' : 'Sign out'}
          </Button>
        </nav>
      </header>
      <main id="main-content" className="main-content" tabIndex={-1}>
        <Outlet />
      </main>
      <footer className="footer">
        <span>NorthFlux Security</span>
        <NavLink to="/privacy">Privacy &amp; data</NavLink>
      </footer>
    </div>
  )
}
