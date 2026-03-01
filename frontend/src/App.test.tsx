import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'

import App from './App'
import { AuthProvider } from './features/auth'

const createTestQueryClient = () =>
  new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  })

const renderWithProviders = (component: React.ReactElement) => {
  const queryClient = createTestQueryClient()
  return render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>{component}</AuthProvider>
      </QueryClientProvider>
    </MemoryRouter>
  )
}

describe('App', () => {
  // Fetch mock is configured in test/setup.ts with default healthy response
  // Clerk is mocked in test/setup.ts

  it('renders the main heading', () => {
    renderWithProviders(<App />)
    expect(screen.getByText('OSINT Platform')).toBeInTheDocument()
  })

  it('renders the system status section', () => {
    renderWithProviders(<App />)
    expect(screen.getByText('System Status')).toBeInTheDocument()
  })

  it('renders the getting started section', () => {
    renderWithProviders(<App />)
    expect(screen.getByText('Getting Started')).toBeInTheDocument()
  })
})
