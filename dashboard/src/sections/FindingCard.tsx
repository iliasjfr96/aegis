import type { Finding } from '@/types/scan'

const SEV_STYLE: Record<string, string> = {
  critical: 'text-red-400 border-red-400',
  high: 'text-orange-400 border-orange-400',
  medium: 'text-yellow-400 border-yellow-400',
  low: 'text-emerald-400 border-emerald-400',
  info: 'text-emerald-400 border-emerald-400',
}

export default function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div className="bg-[#161b22] border border-zinc-800 rounded-xl p-5 space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <span className={`text-xs font-bold uppercase px-2 py-0.5 rounded-full border ${SEV_STYLE[finding.severity]}`}>
          {finding.severity}
        </span>
        <span className="text-xs font-mono text-sky-400 border border-sky-800 px-2 py-0.5 rounded-full">
          {finding.owasp}
        </span>
        <span className="text-sm font-semibold text-zinc-100">{finding.title}</span>
      </div>
      <p className="text-sm text-zinc-400">{finding.impact}</p>
      <div className="bg-[#0d1117] border border-zinc-800 rounded-lg p-3 font-mono text-xs space-y-1.5 max-h-48 overflow-y-auto">
        {finding.evidence.map((t, i) => (
          <div key={i} className={t.role === 'attacker' ? 'text-orange-300' : 'text-zinc-300'}>
            <span className="text-zinc-600">[{t.role}]</span> {t.content}
          </div>
        ))}
      </div>
      <div className="border-l-2 border-emerald-500 bg-emerald-500/5 rounded-r-lg px-3 py-2 text-sm text-zinc-300">
        {finding.remediation}
      </div>
    </div>
  )
}
