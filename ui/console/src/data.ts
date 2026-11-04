// Snapshot types (aig/console.py build_snapshot) and helpers shared by the pages.
import { useCallback, useEffect, useState } from 'react'

export type DecisionRecord = {
  ts: number; agent: string; principal: string; class?: string; instance?: string; device?: string; token?: string
  tool: string; args: Record<string, unknown>; decision: 'allow' | 'require_approval' | 'deny'; outcome: 'allow' | 'deny'
  reasons: string[]; rules: string[]; sink: string | null; session_labels: string[]
  observed?: Array<{ rule: string; would: string; reason: string }>; intents?: string[]; prev: string; hash: string
}
export type AgentInfo = {
  id: string; agent_class: string | null; purpose: string; on_behalf_of: string[]; allow: string[]
  require_approval: string[]; deny: string[]; calls: number; refused: number; approvals: number
  last_ts: number | null; principals: string[]; devices: string[]; instances: number
}
export type ToolInfo = {
  name: string; reads: string[]; writes: string[]; sink: string; risk: string; args: string[] | null
  stores: string | null; loads: string | null; egress_rules: Array<{ args: string[]; pattern: string; sink: string; kind: string }>
}
export type FlowInfo = {
  id: string; from: string; to: string; action: string; precision: string; residual: string | null
  mode: 'enforce' | 'observe'; source: 'base' | 'clarion'; intent_id: string | null; artifact_id: string | null
  approval_ref: string | null; agent_classes: string[]; device_ids: string[]; expires_at_ms: number | null
  hits: number; observed: number
}
export type IntentInfo = {
  intent_id: string; title?: string; artifact_id: string; action_mode: string; blocking_enabled: boolean; scope: string[]
  key_id: string; content_sha256: string; approval_ref: string | null; expires_at_ms: number
  compiled_at_ms: number | null; compiler_version: string | null; rules: string[]; report: string[]
}
export type OutcomeEvent = Record<string, unknown> & {
  event_id: string; event_type: string; timestamp_ms: number; intent_id: string; artifact_id: string
  device_id?: string; approval_ref?: string; blocking_applied: boolean; detail: string; action_mode: string
}
export type ScenarioStep = {
  agent: string; principal: string; tool: string; args: Record<string, unknown>
  decision: string; outcome: string; reasons: string[]; rules: string[]
}
export type ScenarioResult = {
  id: string; kind: 'attack' | 'workload'; technique: string; description: string; verdict: string
  known_issue: string | null; stopped_at: number | null; external_sends: string[]; steps: ScenarioStep[]
}
export type RedteamConfig = {
  key: string; name: string; description: string
  scoreboard: { attacks: { total: number; blocked: number; bypassed: string[] }
    workloads: { total: number; completed: number; false_positives: string[]; known_issues: string[] } }
  results: ScenarioResult[]
}
export type Snapshot = {
  schema: string; generated_ms: number; version: string; commit: string; demo: boolean
  gateway: Record<string, unknown> & { policy_version: string | null; default: string; classes: string[] }
  agents: AgentInfo[]; tools: ToolInfo[]; flows: FlowInfo[]; intents: IntentInfo[]
  decisions: DecisionRecord[]; chain: { ok: boolean; n: number; message: string }
  events: OutcomeEvent[]; redteam: { configs: RedteamConfig[] } | null
}

declare global { interface Window { __AIG_SNAPSHOT__: Snapshot | null } }

/** Embedded snapshot (published demo) or the live gateway's /api/snapshot. */
export function useSnapshot() {
  const [snap, setSnap] = useState<Snapshot | null>(window.__AIG_SNAPSHOT__)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(!window.__AIG_SNAPSHOT__)
  const load = useCallback(async () => {
    if (window.__AIG_SNAPSHOT__) { setSnap(window.__AIG_SNAPSHOT__); return }
    setLoading(true)
    try {
      const res = await fetch('/api/snapshot', { cache: 'no-store' })
      if (!res.ok) throw new Error(`The gateway answered ${res.status}`)
      setSnap(await res.json()); setError(null)
    } catch (e) {
      setError(`Couldn't load gateway state: ${e instanceof Error ? e.message : String(e)}. Check that aig console is running.`)
    } finally { setLoading(false) }
  }, [])
  useEffect(() => { void load() }, [load])
  return { snap, error, loading, reload: load }
}

export type OutcomeKind = 'allowed' | 'refused' | 'approved' | 'not_approved'
export function outcomeKind(r: DecisionRecord): OutcomeKind {
  if (r.decision === 'require_approval') return r.outcome === 'allow' ? 'approved' : 'not_approved'
  return r.outcome === 'allow' ? 'allowed' : 'refused'
}
export const OUTCOME_LABEL: Record<OutcomeKind, string> = {
  allowed: 'Allowed', refused: 'Refused', approved: 'Approved', not_approved: 'Not approved',
}
export const OUTCOME_VARIANT = { allowed: 'success', refused: 'danger', approved: 'info', not_approved: 'warning' } as const

/** The rule that decided a record, in words an operator recognises. */
export function ruleLabel(rule: string | undefined): string {
  if (!rule) return '—'
  if (rule.startsWith('agent:')) {
    const [, agent, kind] = rule.split(':')
    return kind === 'allow' ? 'In scope' : kind === 'deny' ? `Denied for ${agent}` : 'Needs approval'
  }
  if (rule.startsWith('flow:')) return rule.slice(5).replace(/:residual$/, ' (no values sent)')
  if (rule.startsWith('identity:')) return { 'identity:unknown-agent': 'Unknown agent', 'identity:principal': 'Wrong principal',
    'identity:unknown-tool': 'Undeclared tool', 'identity:undeclared-argument': 'Undeclared argument' }[rule] ?? rule
  if (rule.startsWith('class:')) return `Class ${rule.split(':')[1]}`
  return rule === 'default' ? 'Outside purpose' : rule
}
export function isDataFlowRule(rule: string | undefined) { return !!rule && rule.startsWith('flow:') }

export function fmtTime(ts: number | null | undefined, now = Date.now()): string {
  if (!ts) return '—'
  const ms = ts > 1e12 ? ts : ts * 1000
  const d = new Date(ms)
  const sameDay = new Date(now).toDateString() === d.toDateString()
  return sameDay ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}
export function fmtAgo(ts: number | null | undefined, now = Date.now()): string {
  if (!ts) return 'never'
  const s = Math.max(0, (now - (ts > 1e12 ? ts : ts * 1000)) / 1000)
  if (s < 90) return 'just now'
  if (s < 3600) return `${Math.round(s / 60)} min ago`
  if (s < 86400) return `${Math.round(s / 3600)} h ago`
  return `${Math.round(s / 86400)} d ago`
}
export function fmtDate(ms: number | null | undefined): string {
  return ms ? new Date(ms).toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' }) : '—'
}
export function shortHash(h: string, n = 10) { return h ? `${h.slice(0, n)}…` : '—' }
export function argsPreview(args: Record<string, unknown>, max = 90): string {
  const s = JSON.stringify(args)
  if (s === '{}') return ''
  return s.length > max ? `${s.slice(0, max)}…` : s
}
export function plural(n: number, one: string, many = `${one}s`) { return `${n} ${n === 1 ? one : many}` }

/** The "now" the console reasons about: the newest record in a demo, the clock when live. */
export function referenceNow(s: Snapshot): number {
  if (!s.demo || !s.decisions.length) return Date.now()
  return Math.max(...s.decisions.map((d) => d.ts)) * 1000 + 5 * 60 * 1000
}
