import { useEffect } from 'react'
import { ClerkProvider as BaseClerkProvider, useAuth } from '@clerk/clerk-react'
import { useNavigate } from 'react-router-dom'

import { setTokenGetter } from '@/lib/api-client'

const PUBLISHABLE_KEY = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY

if (!PUBLISHABLE_KEY) {
  throw new Error('Missing VITE_CLERK_PUBLISHABLE_KEY environment variable')
}

interface AuthProviderProps {
  children: React.ReactNode
}

function TokenInjector({ children }: { children: React.ReactNode }) {
  const { getToken } = useAuth()

  useEffect(() => {
    // Inject the token getter into the API client
    setTokenGetter(getToken)
  }, [getToken])

  return <>{children}</>
}

export function AuthProvider({ children }: AuthProviderProps) {
  const navigate = useNavigate()

  return (
    <BaseClerkProvider
      publishableKey={PUBLISHABLE_KEY}
      routerPush={to => navigate(to)}
      routerReplace={to => navigate(to, { replace: true })}
      signInFallbackRedirectUrl="/"
      signUpFallbackRedirectUrl="/"
    >
      <TokenInjector>{children}</TokenInjector>
    </BaseClerkProvider>
  )
}
