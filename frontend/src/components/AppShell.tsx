import { useEffect, useRef, useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useSession } from '../auth/session-context'
import { BrandMark } from './BrandMark'
import { Icon } from './Icon'
import type { IconName } from './Icon'
import { Button, InlineNotice } from './ui'

const navigation: { to: string; label: string; icon: IconName; end?: boolean }[] = [
  { to: '/', label: 'Overview', icon: 'overview', end: true },
  { to: '/scan', label: 'Scan', icon: 'scan' },
  { to: '/domains', label: 'Domains', icon: 'domains' },
  { to: '/generator', label: 'Generator', icon: 'generator' },
  { to: '/settings', label: 'Settings', icon: 'settings' },
]

export function AppShell() {
  const [menuOpen, setMenuOpen] = useState(false)
  const [signingOut, setSigningOut] = useState(false)
  const [signOutError, setSignOutError] = useState('')
  const headerRef = useRef<HTMLElement>(null)
  const mainRef = useRef<HTMLElement>(null)
  const menuRef = useRef<HTMLButtonElement>(null)
  const { signOut } = useSession()
  const navigate = useNavigate()
  const { pathname } = useLocation()
  const previousPath = useRef(pathname)

  useEffect(() => {
    if (previousPath.current === pathname) return
    previousPath.current = pathname
    mainRef.current?.focus()
  }, [pathname])

  useEffect(() => {
    if (!menuOpen) return
    const dismissOutside = (event: PointerEvent) => {
      if (event.target instanceof Node && !headerRef.current?.contains(event.target)) setMenuOpen(false)
    }
    const dismissEscape = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return
      setMenuOpen(false)
      menuRef.current?.focus()
    }
    document.addEventListener('pointerdown', dismissOutside)
    document.addEventListener('keydown', dismissEscape)
    return () => {
      document.removeEventListener('pointerdown', dismissOutside)
      document.removeEventListener('keydown', dismissEscape)
    }
  }, [menuOpen])

  const handleSignOut = async () => {
    setSigningOut(true)
    setSignOutError('')
    try {
      await signOut()
      navigate('/login', { replace: true })
    } catch {
      setSignOutError('We could not sign you out. Your session may still be active. Check your connection and try again.')
      setMenuOpen(false)
    } finally {
      setSigningOut(false)
    }
  }

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <header className="topbar" ref={headerRef}>
        <NavLink to="/" className="brand" aria-label="NorthFlux Security overview">
          <BrandMark />
          <span><strong>NorthFlux</strong><small>Security</small></span>
        </NavLink>
        <button
          type="button"
          ref={menuRef}
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
              <Icon name={item.icon} /><span>{item.label}</span>
            </NavLink>
          ))}
          <Button className="navigation__sign-out" variant="ghost" type="button" onClick={handleSignOut} disabled={signingOut}>
            {signingOut ? 'Signing out…' : 'Sign out'}
          </Button>
        </nav>
      </header>
      <main id="main-content" className="main-content" ref={mainRef} tabIndex={-1}>
        {signOutError ? <div className="session-notice"><InlineNotice tone="danger">{signOutError}</InlineNotice></div> : null}
        <Outlet />
      </main>
      <footer className="footer">
        <span><strong>NorthFlux Security</strong><span className="footer__separator" aria-hidden="true"> / </span>Clarity for your email security.</span>
        <NavLink to="/privacy">Privacy &amp; data</NavLink>
      </footer>
    </div>
  )
}
