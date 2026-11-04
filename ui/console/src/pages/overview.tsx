import { ArrowRight, RefreshCw } from 'lucide-react'
import { useMemo } from 'react'
import { Badge, Card, CardHeader, KpiTile, MainPanel, PageHeader, SummaryStrip } from '../components/ui'
import { fmtAgo, isDataFlowRule, outcomeKind, plural, ruleLabel, type Snapshot } from '../data'
import { go, type RouteId } from '../routes'
import type { Health } from '../components/Shell'

type Item = { id: string; message: string; hint: string; route: RouteId; param?: string; cta: string; tone: 'danger' | 'warning' | 'info' }

export function currentRedteam(s: Snapshot) {
  const cfgs = s.redteam?.configs ?? []
  return cfgs.find((c) => c.key === 'clarion') ?? cfgs.find((c) => c.key === 'current') ?? cfgs[cfgs.length - 1]
}

export function Overview({ s, health, now, onRefresh, loading }: { s: Snapshot; health: Health; now: number; onRefresh: () => void; loading: boolean }) {
  const stats = useMemo(() => {
    const kinds = s.decisions.map(outcomeKind)
    const refused = kinds.filter((k) => k === 'refused').length
    const notApproved = kinds.filter((k) => k === 'not_approved').length
    const approvals = kinds.filter((k) => k === 'approved' || k === 'not_approved').length
    // Data that was on its way out and stopped: data-flow rules that found the data, not "ask a human" fallbacks.
    const flowBlocks = s.decisions.filter((d) => d.outcome === 'deny' && isDataFlowRule(d.rules[0]) && !d.rules[0].endsWith(':residual')).length
    const byRule = new Map<string, number>()
    for (const d of s.decisions) if (d.outcome === 'deny') byRule.set(d.rules[0] ?? '—', (byRule.get(d.rules[0] ?? '—') ?? 0) + 1)
    return { refused, notApproved, approvals, flowBlocks, byRule: [...byRule.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6) }
  }, [s])

  const observed = s.flows.filter((f) => f.mode === 'observe' && f.observed > 0)
  const rt = currentRedteam(s)
  const items: Item[] = []
  if (!s.chain.ok) items.push({ id: 'chain', tone: 'danger', message: 'The decision log failed verification', hint: s.chain.message, route: 'evidence', cta: 'Investigate' })
  if (stats.notApproved) items.push({ id: 'approvals', tone: 'warning', message: `${plural(stats.notApproved, 'call')} refused because no one approved ${stats.notApproved === 1 ? 'it' : 'them'}`,
    hint: 'Legitimate work may be waiting. Review the reasons, then approve similar calls or adjust the rule.', route: 'approvals', cta: 'Review' })
  for (const f of observed) items.push({ id: `obs-${f.id}`, tone: 'info', message: `${f.intent_id ?? f.id} would have blocked ${plural(f.observed, 'call')}`,
    hint: 'This rule is in observe mode. Check what it would block before Clarion switches the intent to enforce.', route: 'rules', param: f.id, cta: 'Review rule' })
  if (rt && rt.scoreboard.attacks.bypassed.length) items.push({ id: 'gaps', tone: 'warning',
    message: `${plural(rt.scoreboard.attacks.bypassed.length, 'attack')} get through the current policy`,
    hint: rt.scoreboard.attacks.bypassed.join(', '), route: 'redteam', cta: 'View' })

  const topAgents = [...s.agents].sort((a, b) => b.calls - a.calls)
  const maxRule = Math.max(1, ...stats.byRule.map(([, n]) => n))

  return (
    <MainPanel>
      <PageHeader title="Overview" subtitle="Agent tool calls, where their data went, and what needs a decision."
        actions={<>
          <span className="text-sm text-slate-500 dark:text-gray-400">{s.demo ? 'Demo snapshot' : `Updated ${new Date(s.generated_ms).toLocaleTimeString()}`}</span>
          <button type="button" className="btn btn-secondary" onClick={onRefresh}><RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />Refresh</button>
        </>} />
      <p className="mb-5 text-sm text-slate-600 dark:text-gray-300"><span className="font-semibold text-slate-800 dark:text-gray-100">{health.label}.</span> {health.text}</p>

      <section className="card mb-5" aria-labelledby="needs-decision">
        <div className="border-b border-slate-100 px-5 py-3 dark:border-gray-700">
          <h2 id="needs-decision" className="text-sm font-semibold text-slate-900 dark:text-gray-100">What needs a decision</h2>
        </div>
        <div className="px-5 py-3">
          {items.length === 0 ? <p className="py-4 text-sm text-emerald-800 dark:text-emerald-300">All clear. Nothing needs a decision right now.</p> : (
            <ul className="divide-y divide-slate-100 dark:divide-gray-700">
              {items.map((it) => (
                <li key={it.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                  <div className="flex min-w-0 items-start gap-3">
                    <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${it.tone === 'danger' ? 'bg-red-500' : it.tone === 'warning' ? 'bg-amber-400' : 'bg-blue-500'}`} />
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-slate-900 dark:text-gray-100">{it.message}</p>
                      <p className="mt-0.5 text-xs text-slate-500 dark:text-gray-400">{it.hint}</p>
                    </div>
                  </div>
                  <button type="button" onClick={() => go(it.route, it.param)} className="btn btn-secondary">{it.cta}<ArrowRight className="h-3.5 w-3.5" /></button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      <SummaryStrip>
        <KpiTile label="Tool calls" value={s.decisions.length} detail={plural(s.agents.filter((a) => a.calls).length, 'agent')} onClick={() => go('decisions')} />
        <KpiTile label="Refused" value={stats.refused + stats.notApproved} tone={stats.refused + stats.notApproved ? 'danger' : undefined}
          detail={`${stats.refused} by policy, ${stats.notApproved} not approved`} onClick={() => go('decisions', 'refused')} />
        <KpiTile label="Data leaving blocked" value={stats.flowBlocks} tone={stats.flowBlocks ? 'danger' : undefined} detail="calls carrying data that may not go there" onClick={() => go('flows')} />
        <KpiTile label="Approval requests" value={stats.approvals} tone={stats.notApproved ? 'warning' : undefined} detail={`${stats.notApproved} not approved`} onClick={() => go('approvals')} />
      </SummaryStrip>

      <div className="grid gap-5 xl:grid-cols-2 [&>*]:min-w-0">
        <Card>
          <CardHeader title="Refusals by rule" subtitle="Which part of the policy is doing the work" />
          <div className="space-y-2.5 px-5 py-4">
            {stats.byRule.length === 0 ? <p className="text-sm text-slate-500">No refusals yet.</p> : stats.byRule.map(([rule, n]) => (
              <button type="button" key={rule} onClick={() => go('decisions', 'refused')} className="block w-full text-left">
                <div className="flex items-baseline justify-between gap-3 text-sm">
                  <span className="truncate font-medium text-slate-800 dark:text-gray-200">{ruleLabel(rule)}</span>
                  <span className="tabular-nums text-slate-500 dark:text-gray-400">{n}</span>
                </div>
                <div className="mt-1 h-1.5 rounded-full bg-slate-100 dark:bg-gray-700">
                  <div className={`h-1.5 rounded-full ${isDataFlowRule(rule) ? 'bg-clarion-blue dark:bg-blue-500' : 'bg-slate-400'}`} style={{ width: `${(100 * n) / maxRule}%` }} />
                </div>
              </button>
            ))}
          </div>
        </Card>

        <Card>
          <CardHeader title="Agents" subtitle="Calls through this gateway" actions={<button type="button" className="text-sm font-medium text-blue-600 hover:text-blue-800 dark:text-blue-400" onClick={() => go('agents')}>All agents</button>} />
          <ul className="divide-y divide-slate-100 dark:divide-gray-700">
            {topAgents.map((a) => (
              <li key={a.id}>
                <button type="button" onClick={() => go('agents', a.id)} className="flex w-full items-center justify-between gap-3 px-5 py-3 text-left hover:bg-slate-50 dark:hover:bg-gray-700/40">
                  <div className="min-w-0">
                    <p className="font-mono text-sm font-semibold text-slate-900 dark:text-gray-100">{a.id}</p>
                    <p className="truncate text-xs text-slate-500 dark:text-gray-400">{a.purpose}</p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2 text-xs">
                    <span className="tabular-nums text-slate-600 dark:text-gray-300">{a.calls} calls</span>
                    {a.refused ? <Badge variant="danger">{a.refused} refused</Badge> : <Badge variant="success">none refused</Badge>}
                    <span className="hidden text-slate-400 sm:inline">{fmtAgo(a.last_ts, now)}</span>
                  </div>
                </button>
              </li>
            ))}
          </ul>
        </Card>

        {rt ? (
          <Card>
            <CardHeader title="Red-team posture" subtitle={rt.name} actions={<button type="button" className="text-sm font-medium text-blue-600 hover:text-blue-800 dark:text-blue-400" onClick={() => go('redteam')}>Details</button>} />
            <div className="grid grid-cols-2 gap-4 px-5 py-4">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-gray-400">Attacks blocked</p>
                <p className="mt-1 text-3xl font-bold tabular-nums text-slate-950 dark:text-white">{rt.scoreboard.attacks.blocked}<span className="text-lg font-medium text-slate-400"> / {rt.scoreboard.attacks.total}</span></p>
              </div>
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-gray-400">Workloads without a human</p>
                <p className="mt-1 text-3xl font-bold tabular-nums text-slate-950 dark:text-white">{rt.scoreboard.workloads.completed}<span className="text-lg font-medium text-slate-400"> / {rt.scoreboard.workloads.total}</span></p>
              </div>
            </div>
          </Card>
        ) : null}

        <Card>
          <CardHeader title="Decision log" subtitle="Hash-chained, so edits and deletions are detectable" actions={<button type="button" className="text-sm font-medium text-blue-600 hover:text-blue-800 dark:text-blue-400" onClick={() => go('evidence')}>Evidence log</button>} />
          <div className="flex flex-wrap items-center gap-3 px-5 py-4 text-sm">
            {s.chain.ok ? <Badge variant="success">Chain intact</Badge> : <Badge variant="danger">Chain broken</Badge>}
            <span className="text-slate-600 dark:text-gray-300">{s.chain.message}</span>
            <span className="text-slate-400">·</span>
            <span className="text-slate-600 dark:text-gray-300">{plural(s.events.length, 'outcome event')} for AegisFlux</span>
          </div>
        </Card>
      </div>
    </MainPanel>
  )
}
