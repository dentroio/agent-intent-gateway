import { Search } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Badge, Card, CardHeader, Chips, Drawer, EmptyState, Field, MainPanel, Notice, PageHeader, Segmented, Table } from '../components/ui'
import {
  OUTCOME_LABEL, OUTCOME_VARIANT, argsPreview, fmtTime, isDataFlowRule, outcomeKind, plural, ruleLabel, shortHash,
  type DecisionRecord, type OutcomeKind, type Snapshot,
} from '../data'
import { go } from '../routes'

type Filter = 'all' | 'refused' | 'approval' | 'allowed'
const PAGE = 60

function matchesFilter(d: DecisionRecord, f: Filter) {
  const k = outcomeKind(d)
  if (f === 'all') return true
  if (f === 'refused') return k === 'refused' || k === 'not_approved'
  if (f === 'approval') return k === 'approved' || k === 'not_approved'
  return k === 'allowed' || k === 'approved'
}

export function Decisions({ s, now, param }: { s: Snapshot; now: number; param: string | null }) {
  const [filter, setFilter] = useState<Filter>(param === 'refused' ? 'refused' : 'all')
  const [agent, setAgent] = useState<string>(param?.startsWith('agent-') ? param.slice(6) : '')
  const [q, setQ] = useState('')
  const [limit, setLimit] = useState(PAGE)
  const [open, setOpen] = useState<DecisionRecord | null>(null)

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return [...s.decisions].reverse().filter((d) => matchesFilter(d, filter) && (!agent || d.agent === agent) &&
      (!needle || [d.tool, d.principal, d.agent, ...d.reasons, ...d.rules].some((x) => x.toLowerCase().includes(needle))))
  }, [s, filter, agent, q])
  const counts = useMemo(() => Object.fromEntries((['all', 'refused', 'approval', 'allowed'] as Filter[])
    .map((f) => [f, s.decisions.filter((d) => matchesFilter(d, f) && (!agent || d.agent === agent)).length])), [s, agent])

  return (
    <MainPanel>
      <PageHeader title="Decisions" subtitle="Every tool call the gateway decided, newest first, with the reason it gave the agent." />
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <Segmented label="Outcome" value={filter} onChange={(v) => { setFilter(v); setLimit(PAGE) }} options={[
          { id: 'all', label: 'All', count: counts.all }, { id: 'refused', label: 'Refused', count: counts.refused },
          { id: 'approval', label: 'Approval', count: counts.approval }, { id: 'allowed', label: 'Allowed', count: counts.allowed }]} />
        <label className="sr-only" htmlFor="agent-filter">Agent</label>
        <select id="agent-filter" className="input w-auto" value={agent} onChange={(e) => { setAgent(e.target.value); setLimit(PAGE) }}>
          <option value="">All agents</option>
          {s.agents.map((a) => <option key={a.id} value={a.id}>{a.id}</option>)}
        </select>
        <div className="relative min-w-[12rem] flex-1 sm:max-w-xs">
          <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-slate-400" />
          <label className="sr-only" htmlFor="decision-search">Search decisions</label>
          <input id="decision-search" className="input pl-8" placeholder="Search tool, principal, reason" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
      </div>
      <Card>
        {rows.length === 0 ? <div className="p-5"><EmptyState title="No decisions match" message="Change the filters to see more." /></div> : (
          <>
            <Table head={['Time', 'Agent', 'Acting for', 'Tool', 'Outcome', 'Decided by']}>
              {rows.slice(0, limit).map((d) => {
                const k = outcomeKind(d)
                return (
                  <tr key={d.hash} tabIndex={0} className="cursor-pointer hover:bg-slate-50 dark:hover:bg-gray-700/40" onClick={() => setOpen(d)} onKeyDown={(e) => e.key === 'Enter' && setOpen(d)}>
                    <td className="td whitespace-nowrap tabular-nums text-slate-500 dark:text-gray-400">{fmtTime(d.ts, now)}</td>
                    <td className="td whitespace-nowrap font-mono text-xs">{d.agent}</td>
                    <td className="td max-w-[12rem] truncate text-xs" title={d.principal}>{d.principal}</td>
                    <td className="td"><span className="font-mono text-xs font-semibold">{d.tool}</span>
                      {argsPreview(d.args) ? <p className="mt-0.5 max-w-[20rem] truncate font-mono text-[11px] text-slate-400" title={argsPreview(d.args, 400)}>{argsPreview(d.args)}</p> : null}</td>
                    <td className="td"><Badge variant={OUTCOME_VARIANT[k]}>{OUTCOME_LABEL[k]}</Badge>{d.observed?.length ? <Badge variant="purple" className="ml-1" title="An observe-mode rule would have tightened this">would block</Badge> : null}</td>
                    <td className="td text-xs">{isDataFlowRule(d.rules[0]) ? <span className="font-medium text-clarion-blue dark:text-blue-300">{ruleLabel(d.rules[0])}</span> : ruleLabel(d.rules[0])}</td>
                  </tr>
                )
              })}
            </Table>
            <div className="flex items-center justify-between border-t border-slate-100 px-5 py-3 text-sm text-slate-500 dark:border-gray-700 dark:text-gray-400">
              <span>Showing {Math.min(limit, rows.length)} of {rows.length}</span>
              {rows.length > limit ? <button type="button" className="btn btn-secondary" onClick={() => setLimit((l) => l + PAGE)}>Show more</button> : null}
            </div>
          </>
        )}
      </Card>
      <DecisionDrawer d={open} onClose={() => setOpen(null)} now={now} />
    </MainPanel>
  )
}

export function DecisionDrawer({ d, onClose, now }: { d: DecisionRecord | null; onClose: () => void; now: number }) {
  if (!d) return null
  const k: OutcomeKind = outcomeKind(d)
  return (
    <Drawer open title={<span className="font-mono">{d.tool}</span>} subtitle={`${d.agent} for ${d.principal} · ${fmtTime(d.ts, now)}`} onClose={onClose}>
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={OUTCOME_VARIANT[k]}>{OUTCOME_LABEL[k]}</Badge>
        {d.sink ? <Badge variant={d.sink === 'internal' ? 'neutral' : 'warning'}>destination: {d.sink}</Badge> : null}
        {d.intents?.map((i) => <Badge key={i} variant="purple">{i}</Badge>)}
      </div>
      <Field label="Reason given to the agent">
        <ul className="space-y-1.5">{d.reasons.map((r, i) => <li key={i} className={k === 'refused' || k === 'not_approved' ? 'text-red-800 dark:text-red-200' : ''}>{r}</li>)}</ul>
      </Field>
      {d.observed?.length ? (
        <Notice tone="info"><b>Observe mode.</b> {d.observed.map((o) => `${o.rule} would ${o.would.replace('_', ' ')}: ${o.reason}`).join(' ')}</Notice>
      ) : null}
      <Field label="Decided by"><Chips items={d.rules} /></Field>
      <Field label="Arguments"><pre className="code-block whitespace-pre-wrap break-all">{JSON.stringify(d.args, null, 2)}</pre></Field>
      <Field label="Data the session held"><Chips items={d.session_labels} empty="none" variant="info" /></Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Agent instance"><span className="font-mono text-xs">{d.instance ?? '—'}</span></Field>
        <Field label="Device"><span className="font-mono text-xs">{d.device ?? '—'}</span></Field>
        <Field label="Policy class"><span className="font-mono text-xs">{d.class ?? '—'}</span></Field>
        <Field label="Token"><span className="font-mono text-xs">{d.token ? shortHash(d.token, 12) : '—'}</span></Field>
      </div>
      <Field label="Log record"><p className="font-mono text-xs break-all text-slate-500 dark:text-gray-400">hash {d.hash}<br />prev {d.prev}</p></Field>
    </Drawer>
  )
}

export function Approvals({ s, now }: { s: Snapshot; now: number }) {
  const [open, setOpen] = useState<DecisionRecord | null>(null)
  const rows = [...s.decisions].reverse().filter((d) => d.decision === 'require_approval')
  const notApproved = rows.filter((d) => d.outcome === 'deny').length
  return (
    <MainPanel>
      <PageHeader title="Approvals" subtitle="Calls the policy sent to a human before they could run." />
      <div className="mb-4"><Notice tone={notApproved ? 'warning' : 'info'}>
        The gateway asks the configured approver while the agent waits. <b>Not approved</b> means no one approved the call, so it was refused.
        {notApproved ? ` ${plural(notApproved, 'call')} ended that way.` : ''}
      </Notice></div>
      <Card>
        {rows.length === 0 ? <div className="p-5"><EmptyState title="No approval requests yet" /></div> : (
          <Table head={['Time', 'Agent', 'Tool', 'Result', 'Why approval was needed']}>
            {rows.map((d) => {
              const k = outcomeKind(d)
              return (
                <tr key={d.hash} tabIndex={0} className="cursor-pointer hover:bg-slate-50 dark:hover:bg-gray-700/40" onClick={() => setOpen(d)} onKeyDown={(e) => e.key === 'Enter' && setOpen(d)}>
                  <td className="td whitespace-nowrap tabular-nums text-slate-500 dark:text-gray-400">{fmtTime(d.ts, now)}</td>
                  <td className="td whitespace-nowrap font-mono text-xs">{d.agent}</td>
                  <td className="td font-mono text-xs font-semibold">{d.tool}</td>
                  <td className="td"><Badge variant={OUTCOME_VARIANT[k]}>{OUTCOME_LABEL[k]}</Badge></td>
                  <td className="td max-w-xl text-xs">{d.reasons[0]}</td>
                </tr>
              )
            })}
          </Table>
        )}
      </Card>
      <DecisionDrawer d={open} onClose={() => setOpen(null)} now={now} />
    </MainPanel>
  )
}

export function Flows({ s }: { s: Snapshot }) {
  const byLabel = useMemo(() => {
    const m = new Map<string, { blocked: number; observed: number }>()
    for (const f of s.flows) {
      const e = m.get(f.from) ?? { blocked: 0, observed: 0 }
      e.blocked += f.hits; e.observed += f.observed; m.set(f.from, e)
    }
    return [...m.entries()].sort((a, b) => b[1].blocked + b[1].observed - (a[1].blocked + a[1].observed))
  }, [s])
  return (
    <MainPanel>
      <PageHeader title="Data flows" subtitle="Where data was stopped on its way out, and which rule stopped it." />
      <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
        {byLabel.map(([label, e]) => (
          <div key={label} className="rounded-lg border border-slate-200 bg-white px-3 py-3 shadow-sm dark:border-gray-700 dark:bg-gray-800">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-gray-400">{label} data</p>
            <p className="mt-1 text-xl font-semibold tabular-nums text-slate-950 dark:text-white">{e.blocked}</p>
            <p className="mt-1 text-xs text-slate-500 dark:text-gray-400">{e.observed ? `${e.observed} more in observe mode` : 'stopped'}</p>
          </div>
        ))}
      </div>
      <Card>
        <CardHeader title="By rule" subtitle="Counts include calls that needed approval." />
        <Table head={['Rule', 'Data', 'Destination', 'Mode', 'Stopped', 'Would stop']}>
          {[...s.flows].sort((a, b) => b.hits + b.observed - (a.hits + a.observed)).map((f) => (
            <tr key={f.id} className="cursor-pointer hover:bg-slate-50 dark:hover:bg-gray-700/40" onClick={() => go('rules', f.id)}>
              <td className="td font-mono text-xs font-semibold">{f.id}</td>
              <td className="td"><Badge variant="info">{f.from}</Badge></td>
              <td className="td font-mono text-xs">{f.to}</td>
              <td className="td">{f.mode === 'enforce' ? <Badge variant="danger">Enforce</Badge> : <Badge variant="purple">Observe</Badge>}</td>
              <td className="td tabular-nums">{f.hits}</td>
              <td className="td tabular-nums">{f.observed || '—'}</td>
            </tr>
          ))}
        </Table>
      </Card>
    </MainPanel>
  )
}
