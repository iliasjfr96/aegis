import { useEffect, useState } from 'react'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { KeyRound, Loader2, Check } from 'lucide-react'

const PROVIDERS = [
  { id: 'kimi', label: 'Kimi Code (abonnement)', models: 'kimi-for-coding, k3' },
  { id: 'openai', label: 'OpenAI', models: 'gpt-4o-mini, gpt-4o' },
  { id: 'anthropic', label: 'Anthropic', models: 'claude-haiku-4-5, claude-sonnet-4-6' },
]

export default function ProviderSettings() {
  const [provider, setProvider] = useState('kimi')
  const [key, setKey] = useState('')
  const [model, setModel] = useState('kimi-for-coding')
  const [saved, setSaved] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [ok, setOk] = useState(false)

  useEffect(() => {
    api.myProviders().then((p) => setSaved(p.map((x) => x.provider))).catch(() => {})
  }, [])

  async function save() {
    setBusy(true)
    try {
      await api.saveProvider(provider, key, model)
      setSaved((s) => [...new Set([...s, provider])])
      setKey('')
      setOk(true)
      setTimeout(() => setOk(false), 2000)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="bg-[#161b22] border border-zinc-800 rounded-xl p-5 space-y-3">
      <h3 className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
        <KeyRound className="w-4 h-4 text-sky-400" /> Your LLM provider key (BYOK)
      </h3>
      <p className="text-xs text-zinc-500">
        Without a key, audits run in zero-AI scripted mode. Add your own key for full
        agentic attacks — it is encrypted at rest and used only for YOUR scans.
      </p>
      <div className="flex gap-2 flex-wrap">
        {PROVIDERS.map((p) => (
          <button key={p.id} onClick={() => setProvider(p.id)}
            className={`text-xs px-3 py-1.5 rounded-lg border ${
              provider === p.id ? 'border-sky-500 text-sky-300 bg-sky-500/10' : 'border-zinc-700 text-zinc-400'
            }`}>
            {p.label} {saved.includes(p.id) && <Check className="inline w-3 h-3 text-emerald-400 ml-1" />}
          </button>
        ))}
      </div>
      <div className="flex gap-2">
        <Input type="password" placeholder="API key" value={key}
          onChange={(e) => setKey(e.target.value)}
          className="bg-[#0d1117] border-zinc-700 font-mono text-sm" />
        <Input placeholder="model" value={model}
          onChange={(e) => setModel(e.target.value)}
          className="bg-[#0d1117] border-zinc-700 font-mono text-sm w-48" />
        <Button onClick={save} disabled={busy || !key} className="bg-sky-600 hover:bg-sky-500 shrink-0">
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : ok ? <Check className="w-4 h-4" /> : 'Save'}
        </Button>
      </div>
    </div>
  )
}
