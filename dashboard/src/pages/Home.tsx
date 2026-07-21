import { useCallback, useEffect, useRef, useState } from 'react'
import { api, auth, DEMO_SCANS } from '@/lib/api'
import type { Attempt } from '@/types/scan'
import AuthGate from '@/sections/AuthGate'
import ProviderSettings from '@/sections/ProviderSettings'
import TargetsPanel from '@/sections/TargetsPanel'
import type { Scan } from '@/types/scan'
import ScanLauncher, { ProgressRail } from '@/sections/ScanLauncher'
import FindingCard from '@/sections/FindingCard'
import ComparePanel from '@/sections/ComparePanel'
import AttemptTimeline from '@/sections/AttemptTimeline'
import { Shield, FlaskConical, History } from 'lucide-react'

const NODES = ['scope_guard', 'recon', 'plan', 'attack', 'evaluate', 'report']

function simulateAudit(
  url: string,
  onUpdate: (s: Scan) => void,
  source: Scan,
) {
  const id = `sim-${Date.now()}`
  const base: Scan = {
    id, target_url: url, status: 'running', current_node: 'scope_guard',
    progress: [], findings: [], attempts: [], report_path: '',
    started_at: Date.now() / 1000, kind: 'llm',
  }
  NODES.forEach((node, i) => {
    setTimeout(() => {
      base.progress.push(node)
      base.current_node = node
      if (node === 'attack' && source.attempts) {
        source.attempts.forEach((a: Attempt, j: number) => {
          setTimeout(() => {
            base.attempts = [...(base.attempts ?? []), a]
            onUpdate({ ...base })
          }, 900 * (j + 1))
        })
      }
      if (node === 'evaluate') {
        base.findings = source.findings
      }
      if (node === 'report') {
        base.status = 'done'
      }
      onUpdate({ ...base })
    }, 900 * (i + 1))
  })
}

export default function Home() {
  const [scans, setScans] = useState<Scan[]>([])
  const [demo, setDemo] = useState(false)
  const [authed, setAuthed] = useState(!!auth.token)
  const [selected, setSelected] = useState<string | null>(null)
  const pollers = useRef<Record<string, ReturnType<typeof setInterval>>>({})

  useEffect(() => {
    if (!authed) return
    api
      .listScans()
      .then((s) => setScans(s))
      .catch((e) => {
        if (String(e).includes('401')) {
          setAuthed(false)
          return
        }
        setDemo(true)
        setScans(DEMO_SCANS)
        setSelected(DEMO_SCANS[0].id)
      })
  }, [authed])

  const watch = useCallback((id: string) => {
    pollers.current[id] = setInterval(async () => {
      try {
        const s = await api.getScan(id)
        setScans((prev) => [s, ...prev.filter((p) => p.id !== id)])
        if (s.status !== 'running') clearInterval(pollers.current[id])
      } catch {
        clearInterval(pollers.current[id])
      }
    }, 1000)
  }, [])

  // Early return AFTER all hooks (React rule: hooks must run in the same
  // order every render - putting this before useCallback crashed post-login)
  if (!authed) {
    return <AuthGateWithFallback onAuth={() => setAuthed(true)} onDemo={() => { setDemo(true); setScans(DEMO_SCANS); setSelected(DEMO_SCANS[0].id); setAuthed(true) }} />
  }

  const current = scans.find((s) => s.id === selected) ?? scans[0]

  return (
    <div className="min-h-screen bg-[#0d1117] text-zinc-200">
      <div className="max-w-5xl mx-auto px-6 py-10 space-y-10">
        <header className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-sky-400" />
            <div>
              <h1 className="text-2xl font-bold text-zinc-50 tracking-tight">
                AEGIS <span className="text-zinc-500 font-normal">— LLM red team console</span>
              </h1>
              <p className="text-sm text-zinc-500">Automated multi-agent security auditing</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {demo && (
              <span className="flex items-center gap-2 text-xs text-yellow-400 border border-yellow-800 rounded-full px-3 py-1">
                <FlaskConical className="w-3.5 h-3.5" /> demo data — API offline
              </span>
            )}
            <span className="text-xs font-mono text-zinc-600 border border-zinc-800 rounded-full px-2 py-1">
              build: {import.meta.env.VITE_BUILD_TAG ?? 'static-preview'}
            </span>
          </div>
        </header>

        {!demo && (
          <div className="grid md:grid-cols-2 gap-6">
            <ProviderSettings />
            <TargetsPanel />
          </div>
        )}

        <section className="space-y-4">
          <h2 className="text-lg font-semibold text-zinc-100">New audit</h2>
          <ScanLauncher
            disabled={false}
            demo={demo}
            onDemoLaunch={(url) => {
              const source = url.includes('8102') ? DEMO_SCANS[1] : DEMO_SCANS[0]
              const id = `sim-${Date.now()}`
              simulateAudit(url, (s) => {
                setScans((prev) => [s, ...prev.filter((p) => p.id !== s.id)])
              }, source)
              setSelected(id)
            }}
            onLaunched={(id) => {
              watch(id)
              setSelected(id)
            }}
          />
        </section>

        {scans.length > 0 && (
          <section className="space-y-4">
            <h2 className="text-lg font-semibold text-zinc-100">Audits</h2>
            <h2 className="text-lg font-semibold text-zinc-100 flex items-center gap-2">
              <History className="w-5 h-5 text-zinc-500" /> History
            </h2>
            <div className="flex gap-2 flex-wrap">
              {scans.map((s) => {
                const breached = (s.attempts ?? []).filter((a) => a.judge_verdict === 'success').length
                return (
                  <button
                    key={s.id}
                    onClick={() => setSelected(s.id)}
                    className={`text-xs font-mono px-3 py-1.5 rounded-lg border transition-colors ${
                      current?.id === s.id
                        ? 'border-sky-500 text-sky-300 bg-sky-500/10'
                        : 'border-zinc-700 text-zinc-400 hover:border-zinc-500'
                    }`}
                  >
                    {s.kind === 'websec' ? '🌐' : '🤖'} {s.target_url} · {s.status}
                    {s.status === 'done' && (
                      <span className={breached ? 'text-red-400' : 'text-emerald-400'}>
                        {' '}· {breached ? `${breached} breached` : 'held'}
                      </span>
                    )}
                  </button>
                )
              })}
            </div>
            {current && (
              <div className="space-y-5">
                <ProgressRail current={current.current_node} done={current.progress} />
                {current.status === 'refused' && (
                  <p className="text-red-400 text-sm">Target refused — outside the authorized whitelist.</p>
                )}
                {current.error && (
                  <p className="text-red-400 text-sm border border-red-900 rounded-lg px-4 py-3">{current.error}</p>
                )}
                <AttemptTimeline attempts={current.attempts ?? []} />
                <div className="space-y-4">
                  {current.findings.map((f) => (
                    <FindingCard key={f.attempt_id} finding={f} />
                  ))}
                  {current.status === 'done' && current.findings.length === 0 && (
                    <p className="text-emerald-400 text-sm border border-emerald-900 rounded-lg px-4 py-3">
                      No vulnerabilities confirmed — the target resisted all attempted techniques.
                    </p>
                  )}
                </div>
              </div>
            )}
          </section>
        )}

        <ComparePanel demo={demo} />

        <footer className="text-center text-xs text-zinc-600 pt-6 border-t border-zinc-800">
          Aegis — authorized testing only · targets restricted by whitelist
        </footer>
      </div>
    </div>
  )
}


function AuthGateWithFallback({ onAuth, onDemo }: { onAuth: () => void; onDemo: () => void }) {
  const [apiDown, setApiDown] = useState<boolean | null>(null)
  useEffect(() => {
    fetch(`${import.meta.env.VITE_AEGIS_API ?? 'http://localhost:8200'}/docs`, { method: 'HEAD' })
      .then(() => setApiDown(false))
      .catch(() => setApiDown(true))
  }, [])
  if (apiDown) {
    return (
      <div className="min-h-screen bg-[#0d1117] flex items-center justify-center px-6">
        <div className="text-center space-y-4">
          <p className="text-zinc-400">Aegis API is offline — this is a static preview.</p>
          <button onClick={onDemo}
            className="px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-sm">
            Continue with interactive demo
          </button>
        </div>
      </div>
    )
  }
  return <AuthGate onAuth={onAuth} />
}
