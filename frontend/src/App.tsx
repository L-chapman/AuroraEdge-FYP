import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { SessionProvider, ProtectedRoute } from './auth/SessionProvider'
import { AppShell } from './components/AppShell'
import { GeneratorPage } from './features/generator'
import { DashboardPage } from './pages/DashboardPage'
import { DomainDetailPage } from './pages/DomainDetailPage'
import { DomainsPage } from './pages/DomainsPage'
import { LoginPage } from './pages/LoginPage'
import { NotFoundPage } from './pages/NotFoundPage'
import { PrivacyPage } from './pages/PrivacyPage'
import { ScanPage } from './pages/ScanPage'
import { SettingsPage } from './pages/SettingsPage'

function LegacyScanRedirect() {
  const location = useLocation()
  return <Navigate to={`/scan${location.search}`} replace />
}

export function App() {
  return (
    <SessionProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/privacy" element={<PrivacyPage />} />
        <Route element={<ProtectedRoute />}>
          <Route element={<AppShell />}>
            <Route index element={<DashboardPage />} />
            <Route path="scan" element={<ScanPage />} />
            <Route path="test" element={<LegacyScanRedirect />} />
            <Route path="domains" element={<DomainsPage />} />
            <Route path="domain/:domain" element={<DomainDetailPage />} />
            <Route path="generator" element={<GeneratorPage />} />
            <Route path="settings" element={<SettingsPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Route>
      </Routes>
    </SessionProvider>
  )
}
