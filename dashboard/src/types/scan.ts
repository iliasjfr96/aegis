export interface ConversationTurn {
  role: 'attacker' | 'target'
  content: string
}

export interface Finding {
  title: string
  owasp: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  evidence: ConversationTurn[]
  impact: string
  remediation: string
  attempt_id: string
}

export interface Attempt {
  id: string
  technique: string
  owasp: string
  turns: ConversationTurn[]
  succeeded: boolean | null
  judge_verdict: 'success' | 'partial' | 'failure' | 'pending'
  judge_reasoning: string
  canary_triggered: boolean
}

export interface Scan {
  id: string
  target_url: string
  status: 'running' | 'done' | 'error' | 'refused'
  current_node: string
  progress: string[]
  findings: Finding[]
  attempts?: Attempt[]
  kind?: 'llm' | 'websec'
  finished_at?: number | null
  report_path: string
  started_at: number
  error?: string
}
