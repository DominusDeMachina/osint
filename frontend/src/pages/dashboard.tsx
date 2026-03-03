import { useState, useEffect } from 'react'

import { UserButton } from '../features/auth'
import { apiClient } from '../lib/api-client'

interface HealthStatus {
  status: string
  version?: string
  api_version?: string
}

export function Dashboard() {
  const [health, setHealth] = useState<HealthStatus | null>(null)
  const [apiHealth, setApiHealth] = useState<HealthStatus | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    // Check root health endpoint (public, uses fetch directly)
    fetch('/health')
      .then(res => res.json())
      .then(data => setHealth(data))
      .catch(err => setError(`Health check failed: ${err.message}`))

    // Check API v1 health endpoint (uses apiClient for consistency)
    apiClient
      .get<HealthStatus>('/health')
      .then(res => setApiHealth(res.data))
      .catch(err => setError(`API health check failed: ${err.message}`))
  }, [])

  return (
    <div className="bg-background min-h-screen">
      <header className="bg-card border-b">
        <div className="container mx-auto flex h-16 items-center justify-between px-4">
          <h1 className="text-foreground text-xl font-bold">OSINT Platform</h1>
          <UserButton />
        </div>
      </header>

      <main className="container mx-auto py-10">
        <div className="mx-auto max-w-2xl">
          <div className="space-y-6">
            <div className="bg-card rounded-lg border p-6">
              <h2 className="mb-4 text-xl font-semibold">System Status</h2>

              {error && (
                <div className="bg-destructive/10 text-destructive mb-4 rounded-md p-4">
                  {error}
                </div>
              )}

              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Backend Health:</span>
                  <span
                    className={`font-medium ${
                      health?.status === 'healthy' ? 'text-green-600' : 'text-yellow-600'
                    }`}
                  >
                    {health?.status ?? 'Checking...'}
                  </span>
                </div>

                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">API Version:</span>
                  <span className="font-medium">{apiHealth?.api_version ?? 'Checking...'}</span>
                </div>

                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Backend Version:</span>
                  <span className="font-medium">{health?.version ?? 'Checking...'}</span>
                </div>
              </div>
            </div>

            <div className="bg-card rounded-lg border p-6">
              <h2 className="mb-4 text-xl font-semibold">Getting Started</h2>
              <p className="text-muted-foreground">
                Welcome to the OSINT Platform. This is the initial setup of the monorepo structure.
                Additional features will be implemented in subsequent stories.
              </p>
              <ul className="text-muted-foreground mt-4 space-y-2 text-sm">
                <li>• Backend: FastAPI with Python 3.12</li>
                <li>• Graph Engine: Rust with PyO3 bindings</li>
                <li>• Frontend: React + TypeScript + Vite</li>
                <li>• UI Components: shadcn/ui + Tailwind CSS</li>
              </ul>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
