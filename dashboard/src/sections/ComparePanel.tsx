import { useEffect, useState } from 'react'
import { api } from '@/lib/api'
import type { Scan } from '@/types/scan'
import { Button } from '@/components/ui/button'
import { GitCompareArrows, Loader2, ShieldCheck, ShieldAlert } from 'lucide-react'

const SEV_COLOR: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-emerald-400',
  info: 'text-emerald-400',
}

export default function ComparePanel({ demo }: { demo: boolean }) {
  const [scans, setScans] = useState<Scan[]>([])
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    try {
      const { scan_ids } = await api.compare([
        'http://localhost:8100',
        'http://localhost:8101',
        'http://localhost:8102',
      ])
      const poll = setInterval(async () => {
        const results = await Promise.all(scan_ids.map((id) => api.getScan(id)))
        setScans(results)
        if (results.every((s) => s.status !== 'running')) {
          clearInterval(poll)
          setBusy(false)
        }
      }, 1000)
    } catch {
      setBusy(false)
      alert('API unreachable — start the 3 target levels + the Aegis API first.')
    }
  }

  useEffect(() => {
    if (demo) {
      // demo data lives in the scan list above; nothing to fetch here
    }
  }, [demo])

  return (
    <section className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-zinc-100 flex items-center gap-2">
          <GitCompareArrows className="w-5 h-5 text-sky-400" />
          Defense-level comparison
        </h2>
        <Button onClick={run} disabled={busy || demo} variant="outline" className="border-zinc-700">
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Scan levels 0 · 1 · 2'}
        </Button>
      </div>
      {scans.length > 0 && (
        <div className="grid md:grid-cols-3 gap-4">
          {scans.map((s, i) => {
            const vulns = s.findings.length
            const worst = s.findings.reduce<string | null>(
              (acc, f) => (['critical', 'high'].includes(f.severity) ? f.severity : acc),
              null,
            )
            return (
              <div key={s.id} className="bg-[#161b22] border border-zinc-800 rounded-xl p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-sm text-zinc-400">level {i}</span>
                  {s.status === 'running' ? (
                    <Loader2 className="w-4 h-4 animate-spin text-sky-400" />
                  ) : vulns > 0 ? (
                    <ShieldAlert className={`w-5 h-5 ${worst ? SEV_COLOR[worst] : 'text-yellow-400'}`} />
                  ) : (
                    <ShieldCheck className="w-5 h-5 text-emerald-400" />
                  )}
                </div>
                <div className="text-2xl font-bold text-zinc-100">
                  {s.status === 'running' ? '…' : vulns}
                  <span className="text-sm font-normal text-zinc-500 ml-2">
                    finding{vulns === 1 ? '' : 's'}
                  </span>
                </div>
                <div className="flex gap-1.5 flex-wrap">
                  {s.findings.map((f) => (
                    <span key={f.attempt_id} className={`text-xs font-mono ${SEV_COLOR[f.severity]}`}>
                      {f.owasp}
                    </span>
                  ))}
                  {s.status !== 'running' && vulns === 0 && (
                    <span className="text-xs text-emerald-400">resisted all techniques</span>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
      {demo && (
        <p className="text-sm text-zinc-500">
          Demo mode — run the API and the 3 target levels locally to use the live comparator.
        </p>
      )}
    </section>
  )
}
