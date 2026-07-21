import { useState } from 'react'
import type { Attempt } from '@/types/scan'
import { ChevronDown, ChevronRight, Swords, ShieldCheck, ShieldAlert, Flame } from 'lucide-react'

const VERDICT = {
  success: { label: 'BREACHED', cls: 'text-red-400 border-red-500 bg-red-500/10', Icon: Flame },
  partial: { label: 'PARTIAL', cls: 'text-yellow-400 border-yellow-500 bg-yellow-500/10', Icon: ShieldAlert },
  failure: { label: 'HELD', cls: 'text-emerald-400 border-emerald-600 bg-emerald-500/10', Icon: ShieldCheck },
  pending: { label: 'RUNNING', cls: 'text-sky-400 border-sky-500 bg-sky-500/10 animate-pulse', Icon: Swords },
} as const

export default function AttemptTimeline({ attempts }: { attempts: Attempt[] }) {
  const [open, setOpen] = useState<string | null>(null)
  if (!attempts.length) return null

  return (
    <div className="space-y-2">
      <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider flex items-center gap-2">
        <Swords className="w-4 h-4 text-orange-400" /> Attack timeline
      </h3>
      {attempts.map((a) => {
        const v = VERDICT[a.judge_verdict] ?? VERDICT.pending
        const expanded = open === a.id
        return (
          <div key={a.id} className="bg-[#161b22] border border-zinc-800 rounded-xl overflow-hidden">
            <button
              onClick={() => setOpen(expanded ? null : a.id)}
              className="w-full flex items-center gap-3 px-4 py-3 hover:bg-zinc-800/40 transition-colors text-left"
            >
              {expanded ? <ChevronDown className="w-4 h-4 text-zinc-500" /> : <ChevronRight className="w-4 h-4 text-zinc-500" />}
              <span className="font-mono text-sm text-zinc-200 flex-1">{a.technique}</span>
              <span className="text-xs font-mono text-sky-500">{a.owasp}</span>
              {a.canary_triggered && (
                <span className="text-xs font-mono text-purple-400 border border-purple-800 rounded-full px-2 py-0.5">canary</span>
              )}
              <span className={`text-xs font-bold px-2 py-0.5 rounded-full border flex items-center gap-1 ${v.cls}`}>
                <v.Icon className="w-3 h-3" /> {v.label}
              </span>
              <span className="text-xs text-zinc-600 font-mono">{a.turns.length / 2}t</span>
            </button>
            {expanded && (
              <div className="border-t border-zinc-800 bg-[#0d1117] p-4 space-y-2 font-mono text-xs max-h-72 overflow-y-auto">
                {a.turns.map((t, i) => (
                  <div key={i} className={`flex ${t.role === 'attacker' ? 'justify-start' : 'justify-end'}`}>
                    <div className={`max-w-[80%] rounded-lg px-3 py-2 ${
                      t.role === 'attacker'
                        ? 'bg-orange-500/10 border border-orange-900 text-orange-200'
                        : 'bg-zinc-800 border border-zinc-700 text-zinc-300'
                    }`}>
                      <span className="text-zinc-600 text-[10px] uppercase">{t.role}</span>
                      <p className="whitespace-pre-wrap">{t.content}</p>
                    </div>
                  </div>
                ))}
                {a.judge_reasoning && (
                  <p className="text-zinc-500 pt-2 border-t border-zinc-800">
                    judge: {a.judge_reasoning}
                  </p>
                )}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
