import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { App } from './App'
import './styles.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: (failureCount, error) => {
        if (typeof error === 'object' && error !== null && 'status' in error) {
          const status = Number((error as { status: unknown }).status)
          if ([400, 401, 403, 404, 429].includes(status)) return false
        }
        return failureCount < 1
      },
    },
    mutations: { retry: false },
  },
})

const root = document.getElementById('root')
if (!root) throw new Error('NorthFlux application root is missing')

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
)
