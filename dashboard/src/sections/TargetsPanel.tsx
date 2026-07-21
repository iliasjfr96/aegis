import { useEffect, useState } from 'react'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Globe, Loader2, ShieldCheck, Copy, Check } from 'lucide-react'

interface Target {
  url: string
  token: string
  verified: boolean
}

export default function TargetsPanel() {
  const [targets, setTargets] = useState<Target[]>([])
  const [url, setUrl] = useState('')
  const [busy, setBusy] = useState(false)
  const [verifying, setVerifying] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState<string | null>(null)

  const refresh = () => api.myTargets().then(setTargets).catch(() => {})
  useEffect(() => { refresh() }, [])

  async function add() {
    setBusy(true)
    setError('')
    try {
      await api.addTarget(url)
      setUrl('')
      await refresh()
    } catch {
      setError('Could not register target')
    } finally {
      setBusy(false)
    }
  }

  async function verify(t: Target) {
    setVerifying(t.url)
    setError('')
    try {
      await api.verifyTarget(t.url)
      await refresh()
    } catch {
      setError(`Verification failed for ${t.url} — is the token file served at ${t.url}/.well-known/aegis-verify.txt ?`)
    } finally {
      setVerifying(null)
    }
  }

  return (
    <div className="bg-[#161b22] border border-zinc-800 rounded-xl p-5 space-y-4">
      <h3 className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
        <Globe className="w-4 h-4 text-sky-400" /> My targets — audit your own sites
      </h3>
      <p className="text-xs text-zinc-500">
        To prevent abuse, you can only scan targets you own. Register a site, serve
        the token at <code className="text-sky-400">/.well-known/aegis-verify.txt</code>,
        then verify — it becomes scannable.
      </p>
      <div className="flex gap-2">
        <Input placeholder="https://your-site.com" value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="bg-[#0d1117] border-zinc-700 font-mono text-sm" />
        <Button onClick={add} disabled={busy || !url.startsWith('http')}
          className="bg-sky-600 hover:bg-sky-500 shrink-0">
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Register'}
        </Button>
      </div>
      {error && <p className="text-xs text-red-400">{error}</p>}
      {targets.map((t) => (
        <div key={t.url} className="border border-zinc-800 rounded-lg p-3 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <span className="font-mono text-sm text-zinc-200 truncate">{t.url}</span>
            {t.verified ? (
              <span className="text-xs text-emerald-400 flex items-center gap-1 shrink-0">
                <ShieldCheck className="w-4 h-4" /> verified — scannable
              </span>
            ) : (
              <Button size="sm" variant="outline" onClick={() => verify(t)}
                disabled={verifying === t.url} className="border-zinc-700 shrink-0">
                {verifying === t.url ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Verify'}
              </Button>
            )}
          </div>
          {!t.verified && (
            <div className="flex items-center gap-2 bg-[#0d1117] rounded px-2 py-1.5">
              <code className="text-xs text-yellow-400 truncate flex-1">{t.token}</code>
              <button onClick={() => {
                navigator.clipboard.writeText(t.token)
                setCopied(t.url)
                setTimeout(() => setCopied(null), 1500)
              }}>
                {copied === t.url
                  ? <Check className="w-3.5 h-3.5 text-emerald-400" />
                  : <Copy className="w-3.5 h-3.5 text-zinc-500 hover:text-zinc-300" />}
              </button>
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
