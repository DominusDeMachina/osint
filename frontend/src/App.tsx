import { Routes, Route } from 'react-router-dom'

import { AuthGuard } from './features/auth'
import { SignInPage, SignUpPage, Dashboard } from './pages'

function App() {
  return (
    <Routes>
      {/* Public routes */}
      <Route path="/sign-in/*" element={<SignInPage />} />
      <Route path="/sign-up/*" element={<SignUpPage />} />

      {/* Protected routes */}
      <Route
        path="/*"
        element={
          <AuthGuard>
            <Dashboard />
          </AuthGuard>
        }
      />
    </Routes>
  )
}

export default App
