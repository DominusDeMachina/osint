import '@testing-library/jest-dom'
import { vi, beforeEach } from 'vitest'

// Mock Clerk environment variable
vi.stubEnv('VITE_CLERK_PUBLISHABLE_KEY', 'pk_test_mock_key_for_testing')

// Mock Clerk React SDK
vi.mock('@clerk/clerk-react', () => ({
  ClerkProvider: ({ children }: { children: React.ReactNode }) => children,
  useAuth: () => ({
    isLoaded: true,
    isSignedIn: true,
    getToken: vi.fn().mockResolvedValue('mock-token'),
    signOut: vi.fn(),
  }),
  useUser: () => ({
    user: {
      id: 'user_test123',
      emailAddresses: [{ emailAddress: 'test@example.com' }],
      firstName: 'Test',
      lastName: 'User',
    },
  }),
  SignIn: () => null,
  SignUp: () => null,
  UserButton: () => null,
  RedirectToSignIn: () => null,
}))

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
