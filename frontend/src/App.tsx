import { useState, useEffect } from 'react'

interface HealthStatus {
  status: string
  version?: string
  api_version?: string
}

function App() {
  const [health, setHealth] = useState<HealthStatus | null>(null)
  const [apiHealth, setApiHealth] = useState<HealthStatus | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    // Check root health endpoint
    fetch('/health')
      .then(res => res.json())
      .then(data => setHealth(data))
      .catch(err => setError(`Health check failed: ${err.message}`))

    // Check API v1 health endpoint
    fetch('/api/v1/health')
      .then(res => res.json())
      .then(data => setApiHealth(data))
      .catch(err => setError(`API health check failed: ${err.message}`))
  }, [])

  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto py-10">
        <div className="mx-auto max-w-2xl">
          <h1 className="mb-8 text-4xl font-bold text-foreground">OSINT Platform</h1>

          <div className="space-y-6">
            <div className="rounded-lg border bg-card p-6">
              <h2 className="mb-4 text-xl font-semibold">System Status</h2>

              {error && (
                <div className="mb-4 rounded-md bg-destructive/10 p-4 text-destructive">
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

            <div className="rounded-lg border bg-card p-6">
              <h2 className="mb-4 text-xl font-semibold">Getting Started</h2>
              <p className="text-muted-foreground">
                Welcome to the OSINT Platform. This is the initial setup of the monorepo structure.
                Additional features will be implemented in subsequent stories.
              </p>
              <ul className="mt-4 space-y-2 text-sm text-muted-foreground">
                <li>• Backend: FastAPI with Python 3.12</li>
                <li>• Graph Engine: Rust with PyO3 bindings</li>
                <li>• Frontend: React + TypeScript + Vite</li>
                <li>• UI Components: shadcn/ui + Tailwind CSS</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default App
