import { useState } from 'react'
import { Badge, Card, CardHeader, Chips, Drawer, EmptyState, Field, MainPanel, Notice, PageHeader, Table } from '../components/ui'
import { fmtDate, shortHash, type FlowInfo, type Snapshot } from '../data'
import { go } from '../routes'

const ACTION = { deny: 'Block', require_approval: 'Ask a human', allow: 'Allow' } as Record<string, string>

function describeFlow(f: FlowInfo) {
  const act = ACTION[f.action] ?? f.action
  if (f.precision === 'value') return `${act} when the call carries ${f.from} values; otherwise ${(ACTION[f.residual ?? ''] ?? f.residual ?? '').toLowerCase()}`
  return `${act} once the session holds ${f.from} data`
}

export function Rules({ s, selected }: { s: Snapshot; selected: string | null }) {
  const [open, setOpen] = useState<string | null>(selected)
  const f = s.flows.find((x) => x.id === open) ?? null
  const fromClarion = s.flows.filter((x) => x.source === 'clarion').length
  return (
    <MainPanel>
      <PageHeader title="Rules" subtitle="Data-flow rules in force. Identity and tool scope are set per agent on the Agents page." />
      <div className="mb-4"><Notice tone="info">
        {fromClarion ? `${fromClarion} of ${s.flows.length} rules come from signed Clarion intents. ` : 'No Clarion intents are loaded; all rules come from the local policy. '}
        Rules can only tighten a decision. An intent can never loosen the local baseline.
      </Notice></div>
      <Card>
        <Table head={['Rule', 'What it does', 'Destination', 'Mode', 'Source', 'Stopped']}>
          {s.flows.map((x) => (
            <tr key={x.id} tabIndex={0} className="cursor-pointer hover:bg-slate-50 dark:hover:bg-gray-700/40" onClick={() => setOpen(x.id)} onKeyDown={(e) => e.key === 'Enter' && setOpen(x.id)}>
              <td className="td font-mono text-xs font-semibold">{x.id}</td>
              <td className="td max-w-md text-xs">{describeFlow(x)}</td>
              <td className="td font-mono text-xs">{x.to}</td>
              <td className="td">{x.mode === 'enforce' ? <Badge variant="danger">Enforce</Badge> : <Badge variant="purple">Observe</Badge>}</td>
              <td className="td">{x.source === 'clarion' ? <Badge variant="info">Clarion intent</Badge> : <Badge>Local policy</Badge>}</td>
              <td className="td tabular-nums">{x.hits}{x.observed ? <span className="text-purple-700 dark:text-purple-300"> +{x.observed}</span> : null}</td>
            </tr>
          ))}
        </Table>
      </Card>
      {f ? (
        <Drawer open title={<span className="font-mono">{f.id}</span>} subtitle={f.source === 'clarion' ? `From Clarion intent ${f.intent_id}` : 'Local policy'} onClose={() => { setOpen(null); go('rules') }}>
          <p className="text-sm text-slate-700 dark:text-gray-200">{describeFlow(f)}, when the destination matches <span className="font-mono">{f.to}</span>.</p>
          {f.mode === 'observe' ? <Notice tone="info">Observe mode: the gateway records what this rule would do and does not block. It would have acted on {f.observed} calls.</Notice> : null}
          <div className="grid grid-cols-2 gap-3">
            <Field label="Data">{f.from}</Field>
            <Field label="Destination"><span className="font-mono">{f.to}</span></Field>
            <Field label="Action">{ACTION[f.action] ?? f.action}</Field>
            <Field label="Precision">{f.precision === 'value' ? 'Values in the call' : 'Whole session'}</Field>
            {f.residual ? <Field label="When no values are found">{ACTION[f.residual] ?? f.residual}</Field> : null}
            <Field label="Expires">{fmtDate(f.expires_at_ms)}</Field>
          </div>
          <Field label="Applies to">{f.agent_classes.length || f.device_ids.length
            ? <Chips items={[...f.agent_classes.map((c) => `class ${c}`), ...f.device_ids.map((d) => `device ${d}`)]} /> : 'Every agent'}</Field>
          {f.source === 'clarion' ? (
            <>
              <Field label="Signed artifact"><span className="font-mono text-xs break-all">{f.artifact_id}</span></Field>
              <Field label="Approval">{f.approval_ref ? <span className="font-mono text-xs">{f.approval_ref}</span> : '—'}</Field>
              <button type="button" className="btn btn-secondary" onClick={() => go('intents')}>View intent</button>
            </>
          ) : null}
        </Drawer>
      ) : null}
    </MainPanel>
  )
}

export function Intents({ s }: { s: Snapshot }) {
  return (
    <MainPanel>
      <PageHeader title="Clarion intents" subtitle="Enterprise intent compiled into signed gateway rules. The gateway checks each signature before loading it." />
      {s.intents.length === 0 ? <EmptyState title="No Clarion intents loaded" message="Compile one with aig compile and load it with --overlay." /> : (
        <div className="grid gap-5 xl:grid-cols-2 [&>*]:min-w-0">
          {s.intents.map((it) => (
            <Card key={it.artifact_id}>
              <CardHeader title={it.title ?? it.intent_id} subtitle={<span className="font-mono">{it.intent_id}</span>}
                actions={it.action_mode === 'observe' ? <Badge variant="purple">Observe</Badge> : <Badge variant="danger">Enforce</Badge>} />
              <div className="space-y-4 px-5 py-4">
                <div className="grid grid-cols-2 gap-3">
                  <Field label="Applies to"><Chips items={it.scope} /></Field>
                  <Field label="Approval"><span className="font-mono text-xs">{it.approval_ref ?? '—'}</span></Field>
                  <Field label="Signed by key"><span className="font-mono text-xs">{it.key_id}</span></Field>
                  <Field label="Content hash"><span className="font-mono text-xs">{shortHash(it.content_sha256, 16)}</span></Field>
                  <Field label="Compiled">{fmtDate(it.compiled_at_ms)}</Field>
                  <Field label="Expires">{fmtDate(it.expires_at_ms)}</Field>
                </div>
                <Field label="Rules it adds">
                  <div className="flex flex-wrap gap-1">{it.rules.map((r) => (
                    <button key={r} type="button" onClick={() => go('rules', r)} className="badge badge-info font-mono hover:underline">{r}</button>))}</div>
                </Field>
                {it.report.length ? (
                  <Field label="Compile report">
                    <ul className="space-y-1 text-xs text-slate-600 dark:text-gray-300">
                      {it.report.map((line, i) => <li key={i} className={line.startsWith('warning') ? 'text-amber-800 dark:text-amber-200' : ''}>{line}</li>)}
                    </ul>
                  </Field>
                ) : null}
              </div>
            </Card>
          ))}
        </div>
      )}
    </MainPanel>
  )
}

export function Tools({ s }: { s: Snapshot }) {
  return (
    <MainPanel>
      <PageHeader title="Tools" subtitle="What each tool returns, what it changes, and where its arguments end up." />
      <Card>
        <Table head={['Tool', 'Returns', 'Changes', 'Sends to', 'Shared store', 'Risk', 'Declared arguments']}>
          {s.tools.map((t) => (
            <tr key={t.name}>
              <td className="td font-mono text-xs font-semibold">{t.name}</td>
              <td className="td"><Chips items={t.reads} variant="info" /></td>
              <td className="td"><Chips items={t.writes} /></td>
              <td className="td text-xs">
                <Badge variant={t.sink === 'internal' ? 'neutral' : 'warning'}>{t.sink}</Badge>
                {t.egress_rules.map((r, i) => <p key={i} className="mt-1 text-slate-500 dark:text-gray-400">{r.sink} if every {r.args.join('/')} is <span className="font-mono">{r.pattern}</span></p>)}
              </td>
              <td className="td text-xs">{t.stores ? <>writes <span className="font-mono">{t.stores}</span></> : null}{t.stores && t.loads ? ' · ' : ''}{t.loads ? <>reads <span className="font-mono">{t.loads}</span></> : null}{!t.stores && !t.loads ? '—' : null}</td>
              <td className="td">{t.risk === 'high' ? <Badge variant="danger">High</Badge> : <span className="text-slate-400">Low</span>}</td>
              <td className="td">{t.args === null ? <span className="text-xs text-amber-700 dark:text-amber-300">not declared (any accepted)</span> : <Chips items={t.args} empty="none" />}</td>
            </tr>
          ))}
        </Table>
      </Card>
    </MainPanel>
  )
}
