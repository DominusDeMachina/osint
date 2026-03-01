import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

import App from './App'

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
  return render(<QueryClientProvider client={queryClient}>{component}</QueryClientProvider>)
}

describe('App', () => {
  // Fetch mock is configured in test/setup.ts with default healthy response

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
