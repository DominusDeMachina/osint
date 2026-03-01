import '@testing-library/jest-dom'
import { vi } from 'vitest'

// Mock fetch for tests with proper typing
const mockFetch = vi.fn()
global.fetch = mockFetch as unknown as typeof fetch

// Reset mocks between tests
beforeEach(() => {
  vi.clearAllMocks()
  // Default mock implementation for fetch
  mockFetch.mockResolvedValue({
    ok: true,
    json: async () => ({ status: 'healthy', version: '0.1.0', api_version: 'v1' }),
  } as Response)
})
