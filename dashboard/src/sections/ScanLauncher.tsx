import { useState } from 'react'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Crosshair, Loader2 } from 'lucide-react'

const NODES = ['scope_guard', 'recon', 'plan', 'attack', 'evaluate', 'report']

export function ProgressRail({ current, done }: { current: string; done: string[] }) {
  return (
    <div className="flex items-center gap-1 flex-wrap">
      {NODES.map((n) => {
        const active = n === current
        const passed = done.includes(n)
        return (
          <span
            key={n}
            className={`text-xs px-2 py-1 rounded-full border font-mono transition-colors ${
              active
                ? 'border-sky-400 text-sky-300 bg-sky-400/10 animate-pulse'
                : passed
                  ? 'border-emerald-600 text-emerald-400'
                  : 'border-zinc-700 text-zinc-500'
            }`}
          >
            {n}
          </span>
        )
      })}
    </div>
  )
}

export default function ScanLauncher({
  onLaunched,
  onDemoLaunch,
  disabled,
  demo,
}: {
  onLaunched: (id: string) => void
  onDemoLaunch?: (url: string) => void
  disabled: boolean
  demo?: boolean
}) {
  const defaultTarget = import.meta.env.VITE_DEFAULT_TARGET ?? 'http://localhost:8100'
  const [url, setUrl] = useState(defaultTarget)
  const [busy, setBusy] = useState(false)

  async function launch() {
    if (demo && onDemoLaunch) {
      onDemoLaunch(url)
      return
    }
    setBusy(true)
    try {
      const { scan_id } = await api.launchScan(url)
      onLaunched(scan_id)
    } catch {
      alert('API unreachable — is the Aegis API running on :8200?')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex gap-3">
      <Input
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="http://localhost:8100"
        className="bg-[#0d1117] border-zinc-700 font-mono text-sm"
      />
      <Button
        onClick={launch}
        disabled={busy || disabled}
        className="bg-sky-600 hover:bg-sky-500 shrink-0"
      >
        {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Crosshair className="w-4 h-4 mr-2" />}
        {busy ? 'Launching…' : 'Launch audit'}
      </Button>
    </div>
  )
}
