import { useAuth, RedirectToSignIn } from '@clerk/clerk-react'

interface AuthGuardProps {
  children: React.ReactNode
}

function LoadingSkeleton() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="flex flex-col items-center gap-4">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
        <p className="text-sm text-muted-foreground">Loading...</p>
      </div>
    </div>
  )
}

export function AuthGuard({ children }: AuthGuardProps) {
  const { isLoaded, isSignedIn } = useAuth()

  if (!isLoaded) {
    return <LoadingSkeleton />
  }

  if (!isSignedIn) {
    return <RedirectToSignIn />
  }

  return <>{children}</>
}
