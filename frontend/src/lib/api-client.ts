import axios, { type AxiosInstance, type InternalAxiosRequestConfig } from 'axios'

// Create axios instance with base configuration
export const apiClient: AxiosInstance = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
})

// Token getter function - will be set by AuthProvider
let getTokenFn: (() => Promise<string | null>) | null = null

/**
 * Set the token getter function.
 * Called by AuthProvider to inject Clerk's getToken function.
 */
export function setTokenGetter(getter: () => Promise<string | null>): void {
  getTokenFn = getter
}

// Request interceptor to add Authorization header
apiClient.interceptors.request.use(
  async (config: InternalAxiosRequestConfig) => {
    if (getTokenFn) {
      try {
        const token = await getTokenFn()
        if (token) {
          config.headers.Authorization = `Bearer ${token}`
        }
      } catch (error) {
        console.error('Failed to get auth token:', error)
      }
    }
    return config
  },
  error => Promise.reject(error)
)

// Response interceptor to handle 401 errors
apiClient.interceptors.response.use(
  response => response,
  error => {
    if (error.response?.status === 401) {
      // Token expired or invalid - redirect to sign-in
      // The AuthGuard will handle this, but we can also trigger a redirect here
      window.location.href = '/sign-in'
    }
    return Promise.reject(error)
  }
)
