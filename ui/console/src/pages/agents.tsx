import { useMemo, useState } from 'react'
import { Badge, Card, Chips, Drawer, Field, MainPanel, PageHeader, Table } from '../components/ui'
import { OUTCOME_LABEL, OUTCOME_VARIANT, fmtAgo, fmtTime, outcomeKind, type AgentInfo, type Snapshot } from '../data'
import { go } from '../routes'

export function Agents({ s, now, selected }: { s: Snapshot; now: number; selected: string | null }) {
  const [open, setOpen] = useState<string | null>(selected)
  const agent = s.agents.find((a) => a.id === open) ?? null
  return (
    <MainPanel>
      <PageHeader title="Agents" subtitle="Every agent this gateway knows: what it is for, who it may act for, and what it did." />
      <Card>
        <Table head={['Agent', 'Purpose', 'Acts for', 'Tools', 'Calls', 'Refused', 'Last seen']}>
          {s.agents.map((a) => (
            <tr key={a.id} className="cursor-pointer hover:bg-slate-50 dark:hover:bg-gray-700/40" onClick={() => setOpen(a.id)} tabIndex={0}
              onKeyDown={(e) => e.key === 'Enter' && setOpen(a.id)}>
              <td className="td">
                <p className="font-mono font-semibold text-slate-900 dark:text-gray-100">{a.id}</p>
                {a.agent_class ? <p className="mt-0.5 text-xs text-slate-500 dark:text-gray-400">{a.agent_class}</p> : null}
              </td>
              <td className="td max-w-xs">{a.purpose}</td>
              <td className="td"><Chips items={a.on_behalf_of} /></td>
              <td className="td whitespace-nowrap text-xs">
                <span className="text-emerald-700 dark:text-emerald-300">{a.allow.length} allowed</span>
                {a.require_approval.length ? <span className="text-amber-700 dark:text-amber-300"> · {a.require_approval.length} approval</span> : null}
                {a.deny.length ? <span className="text-red-700 dark:text-red-300"> · {a.deny.length} denied</span> : null}
              </td>
              <td className="td tabular-nums">{a.calls}</td>
              <td className="td">{a.refused ? <Badge variant="danger">{a.refused}</Badge> : <span className="text-slate-400">0</span>}</td>
              <td className="td whitespace-nowrap text-slate-500 dark:text-gray-400">{fmtAgo(a.last_ts, now)}</td>
            </tr>
          ))}
        </Table>
      </Card>
      <AgentDrawer s={s} agent={agent} now={now} onClose={() => { setOpen(null); go('agents') }} />
    </MainPanel>
  )
}

function AgentDrawer({ s, agent, now, onClose }: { s: Snapshot; agent: AgentInfo | null; now: number; onClose: () => void }) {
  const recent = useMemo(() => agent ? s.decisions.filter((d) => d.agent === agent.id).slice(-10).reverse() : [], [s, agent])
  if (!agent) return null
  return (
    <Drawer open title={<span className="font-mono">{agent.id}</span>} subtitle={agent.agent_class ?? 'no agent class'} onClose={onClose}>
      <Field label="Declared purpose">{agent.purpose}</Field>
      <Field label="May act for"><Chips items={agent.on_behalf_of} /></Field>
      <Field label="Allowed tools"><Chips items={agent.allow} variant="success" /></Field>
      <Field label="Needs approval"><Chips items={agent.require_approval} variant="warning" /></Field>
      <Field label="Denied"><Chips items={agent.deny} variant="danger" /></Field>
      <div className="grid grid-cols-3 gap-3">
        <Field label="Calls"><span className="tabular-nums">{agent.calls}</span></Field>
        <Field label="Refused"><span className="tabular-nums">{agent.refused}</span></Field>
        <Field label="Instances"><span className="tabular-nums">{agent.instances}</span></Field>
      </div>
      <Field label="Seen on devices"><Chips items={agent.devices} /></Field>
      <Field label="Recent decisions">
        {recent.length === 0 ? <span className="text-slate-400">None</span> : (
          <ul className="divide-y divide-slate-100 rounded-md border border-slate-200 dark:divide-gray-700 dark:border-gray-700">
            {recent.map((d) => {
              const k = outcomeKind(d)
              return (
                <li key={d.hash} className="flex items-center justify-between gap-2 px-3 py-2 text-xs">
                  <span className="font-mono text-slate-800 dark:text-gray-200">{d.tool}</span>
                  <span className="flex items-center gap-2">
                    <Badge variant={OUTCOME_VARIANT[k]}>{OUTCOME_LABEL[k]}</Badge>
                    <span className="text-slate-400">{fmtTime(d.ts, now)}</span>
                  </span>
                </li>
              )
            })}
          </ul>
        )}
        <button type="button" className="mt-2 text-sm font-medium text-blue-600 hover:text-blue-800 dark:text-blue-400" onClick={() => go('decisions', `agent-${agent.id}`)}>
          All decisions for this agent
        </button>
      </Field>
    </Drawer>
  )
}
