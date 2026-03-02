import { useAuth as useClerkAuth, useUser } from '@clerk/clerk-react'

export function useAuth() {
  const { isLoaded, isSignedIn, getToken, signOut } = useClerkAuth()
  const { user } = useUser()

  return {
    isLoaded,
    isSignedIn,
    user,
    getToken,
    signOut,
  }
}

export function useAuthToken() {
  const { getToken } = useClerkAuth()

  const getAuthToken = async (): Promise<string | null> => {
    try {
      return await getToken()
    } catch {
      return null
    }
  }

  return { getAuthToken }
}
