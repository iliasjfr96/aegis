import { useState } from 'react'
import { api, auth } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Shield, Loader2, KeyRound } from 'lucide-react'

export default function AuthGate({ onAuth }: { onAuth: () => void }) {
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit() {
    setBusy(true)
    setError('')
    try {
      const { token } = mode === 'login'
        ? await api.login(email, password)
        : await api.register(email, password)
      auth.token = token
      onAuth()
    } catch {
      setError(mode === 'login' ? 'Invalid credentials' : 'Email already registered')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="min-h-screen bg-[#0d1117] flex items-center justify-center px-6">
      <div className="w-full max-w-sm space-y-6">
        <div className="text-center space-y-2">
          <Shield className="w-12 h-12 text-sky-400 mx-auto" />
          <h1 className="text-2xl font-bold text-zinc-50">AEGIS</h1>
          <p className="text-sm text-zinc-500">LLM red team console — sign in to run audits</p>
        </div>
        <div className="bg-[#161b22] border border-zinc-800 rounded-xl p-6 space-y-4">
          <Input type="email" placeholder="email" value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="bg-[#0d1117] border-zinc-700" />
          <Input type="password" placeholder="password (8+ chars)" value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && submit()}
            className="bg-[#0d1117] border-zinc-700" />
          {error && <p className="text-sm text-red-400">{error}</p>}
          <Button onClick={submit} disabled={busy || !email || password.length < 8}
            className="w-full bg-sky-600 hover:bg-sky-500">
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <KeyRound className="w-4 h-4 mr-2" />}
            {mode === 'login' ? 'Sign in' : 'Create account'}
          </Button>
          <button onClick={() => setMode(mode === 'login' ? 'register' : 'login')}
            className="w-full text-center text-xs text-zinc-500 hover:text-sky-400">
            {mode === 'login' ? 'No account? Register' : 'Already registered? Sign in'}
          </button>
        </div>
        <p className="text-center text-xs text-zinc-600">
          Your LLM provider keys (Kimi Code, OpenAI...) stay yours — BYOK, encrypted at rest.
        </p>
      </div>
    </div>
  )
}
