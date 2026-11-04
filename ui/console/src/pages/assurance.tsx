import { Copy, ShieldCheck } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { verifyChain } from '../chain.js'
import { Badge, Card, CardHeader, EmptyState, MainPanel, Notice, PageHeader, Segmented, StatCard, Table, cn } from '../components/ui'
import { fmtTime, plural, type Snapshot } from '../data'
import { go } from '../routes'
import { currentRedteam } from './overview'

const VERDICT = {
  blocked: ['Blocked', 'success'], bypass: ['Got through', 'danger'], completed: ['Completed', 'success'], false_positive: ['Needed a human', 'warning'],
} as const

export function RedTeam({ s, selected }: { s: Snapshot; selected: string | null }) {
  const cfgs = s.redteam?.configs ?? []
  const [cfgKey, setCfgKey] = useState(currentRedteam(s)?.key ?? '')
  const [kind, setKind] = useState<'all' | 'attack' | 'workload'>('all')
  const [id, setId] = useState<string | null>(selected)
  const cfg = cfgs.find((c) => c.key === cfgKey) ?? cfgs[0]
  const results = useMemo(() => (cfg?.results ?? []).filter((r) => kind === 'all' || r.kind === kind), [cfg, kind])
  useEffect(() => { if (!id && results.length) setId(results.find((r) => r.verdict !== 'blocked' && r.verdict !== 'completed')?.id ?? results[0].id) }, [results, id])
  if (!cfg) return <MainPanel><PageHeader title="Red team" /><EmptyState title="No red-team results" message="Run aig redteam --json and start the console with --redteam." /></MainPanel>
  const r = cfg.results.find((x) => x.id === id) ?? results[0]
  const sb = cfg.scoreboard
  const techs = [...new Set(cfg.results.filter((x) => x.kind === 'attack').map((x) => x.technique))].sort()

  return (
    <MainPanel>
      <PageHeader title="Red team" subtitle="Attacks and legitimate workloads replayed through the real gateway. Every fixed bypass stays here as a regression test." />
      {cfgs.length > 1 ? <div className="mb-4"><Segmented label="Policy" value={cfg.key} onChange={(k) => { setCfgKey(k); setId(null) }} options={cfgs.map((c) => ({ id: c.key, label: c.name }))} /></div> : null}
      <div className="mb-5 grid gap-3 md:grid-cols-3">
        <StatCard label="Attacks blocked" highlight value={<span className="text-3xl font-bold tabular-nums">{sb.attacks.blocked}<span className="text-lg font-medium text-slate-400"> / {sb.attacks.total}</span></span>}
          detail={sb.attacks.bypassed.length ? `Got through: ${sb.attacks.bypassed.join(', ')}` : 'None got through'} />
        <StatCard label="Workloads without a human" value={<span className="text-3xl font-bold tabular-nums">{sb.workloads.completed}<span className="text-lg font-medium text-slate-400"> / {sb.workloads.total}</span></span>}
          detail={sb.workloads.false_positives.length ? `Needed approval: ${sb.workloads.false_positives.join(', ')}` : 'All ran unattended'} />
        <StatCard label="This policy" value={<span className="text-base font-semibold">{cfg.name}</span>} detail={cfg.description} />
      </div>

      <Card className="mb-5">
        <CardHeader title="By technique" />
        <Table head={['Technique', 'Blocked']}>
          {techs.map((t) => {
            const rs = cfg.results.filter((x) => x.technique === t), b = rs.filter((x) => x.verdict === 'blocked').length
            return (
              <tr key={t}>
                <td className="td">{t.replace('/', ' · ')}</td>
                <td className="td"><Badge variant={b === rs.length ? 'success' : b === 0 ? 'danger' : 'warning'} className="tabular-nums">{b} / {rs.length}</Badge></td>
              </tr>
            )
          })}
        </Table>
      </Card>

      <div className="mb-3"><Segmented label="Scenario kind" value={kind} onChange={setKind} options={[
        { id: 'all', label: 'All', count: cfg.results.length }, { id: 'attack', label: 'Attacks', count: sb.attacks.total }, { id: 'workload', label: 'Workloads', count: sb.workloads.total }]} /></div>
      <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,20rem)_minmax(0,1fr)]">
        <Card className="max-h-[36rem] overflow-y-auto">
          <ul className="divide-y divide-slate-100 dark:divide-gray-700" role="listbox" aria-label="Scenarios">
            {results.map((x) => {
              const [label, variant] = x.known_issue && x.kind === 'attack' ? ['Known gap', 'warning'] as const : VERDICT[x.verdict as keyof typeof VERDICT]
              return (
                <li key={x.id}>
                  <button type="button" role="option" aria-selected={x.id === r?.id} onClick={() => { setId(x.id); go('redteam', x.id) }}
                    className={cn('w-full border-l-[3px] px-4 py-2.5 text-left', x.id === r?.id ? 'border-clarion-blue bg-slate-50 dark:border-blue-400 dark:bg-gray-700/50' : 'border-transparent hover:bg-slate-50 dark:hover:bg-gray-700/30')}>
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs font-semibold text-slate-900 dark:text-gray-100">{x.id}</span>
                      <Badge variant={variant}>{label}</Badge>
                    </div>
                    <p className="mt-0.5 line-clamp-2 text-xs text-slate-500 dark:text-gray-400">{x.description}</p>
                  </button>
                </li>
              )
            })}
          </ul>
        </Card>
        {r ? (
          <Card>
            <CardHeader title={r.description} subtitle={<span className="font-mono">{r.id} · {r.technique}</span>}
              actions={<Badge variant={VERDICT[r.verdict as keyof typeof VERDICT][1]}>{VERDICT[r.verdict as keyof typeof VERDICT][0]}</Badge>} />
            <div className="space-y-4 px-5 py-4">
              {r.known_issue ? <Notice tone="warning"><b>Documented gap.</b> {r.known_issue}</Notice> : null}
              <ol className="space-y-3">
                {r.steps.map((st, i) => {
                  const refused = st.outcome === 'deny'
                  return (
                    <li key={i} className="grid grid-cols-[1.5rem_minmax(0,1fr)] gap-3">
                      <span className="pt-0.5 font-mono text-xs text-slate-400">{i + 1}</span>
                      <div className="min-w-0 space-y-1.5">
                        <p className="text-xs text-slate-500 dark:text-gray-400">{st.agent} for {st.principal}{st.decision === 'require_approval' ? (st.outcome === 'allow' ? ' · approved by a human' : ' · approval not granted') : ''}</p>
                        <pre className="code-block whitespace-pre-wrap break-all"><b>{st.tool}</b> {JSON.stringify(st.args) === '{}' ? '' : JSON.stringify(st.args)}</pre>
                        <div className="flex flex-wrap items-start gap-2">
                          <Badge variant={refused ? 'danger' : 'success'}>{refused ? 'Refused' : 'Allowed'}</Badge>
                          <p className={cn('min-w-0 flex-1 text-sm', refused ? 'text-red-800 dark:text-red-200' : 'text-slate-600 dark:text-gray-300')}>{st.reasons.join('; ')}</p>
                        </div>
                      </div>
                    </li>
                  )
                })}
              </ol>
              {r.kind === 'attack' && r.external_sends.length ? (
                <Notice tone={r.verdict === 'bypass' ? 'danger' : 'warning'}><b>{r.verdict === 'bypass' ? 'Left the company:' : 'Left before the block:'}</b> {r.external_sends.join('; ')}</Notice>
              ) : null}
            </div>
          </Card>
        ) : null}
      </div>
    </MainPanel>
  )
}

export function Evidence({ s, now }: { s: Snapshot; now: number }) {
  const [result, setResult] = useState<{ ok: boolean; reason: string; index: number } | null>(null)
  const [busy, setBusy] = useState(false)
  const [ev, setEv] = useState(0)
  const [copied, setCopied] = useState(false)
  const run = async () => { setBusy(true); setResult(await verifyChain(s.decisions)); setBusy(false) }
  useEffect(() => { void run() }, [s]) // eslint-disable-line react-hooks/exhaustive-deps
  const event = s.events[ev]
  const copy = async () => {
    try { await navigator.clipboard.writeText(JSON.stringify(event, null, 2)); setCopied(true); setTimeout(() => setCopied(false), 1500) } catch { setCopied(false) }
  }
  return (
    <MainPanel>
      <PageHeader title="Evidence log" subtitle="The tamper-evident decision log, and the evidence AegisFlux receives." />
      <Card className="mb-5">
        <CardHeader title="Decision log integrity" subtitle="Each record carries the SHA-256 of the one before it. Editing, reordering or deleting a record breaks the chain from that point."
          actions={<button type="button" className="btn btn-primary" onClick={() => void run()} disabled={busy}><ShieldCheck className="h-4 w-4" />{busy ? 'Verifying…' : 'Verify in browser'}</button>} />
        <div className="px-5 py-4">
          {result ? <Notice tone={result.ok ? 'success' : 'danger'}>{result.ok
            ? <><b>Chain intact.</b> {result.reason}. Nothing was edited, reordered or removed.</>
            : <><b>Tampering detected at record {result.index + 1}.</b> {result.reason}.</>}</Notice> : <p className="text-sm text-slate-500">Verifying…</p>}
          <p className="mt-3 text-xs text-slate-500 dark:text-gray-400">The gateway also checks the chain on the server: {s.chain.message}. Use <span className="font-mono">aig verify-log</span> for the file itself.</p>
        </div>
      </Card>
      <Card>
        <CardHeader title="AegisFlux outcome events" subtitle={`${plural(s.events.length, 'event')} in segmentation_outcome_event.v1 format. They carry no data values; the full reason stays in the local log, referenced by hash.`} />
        {s.events.length === 0 ? <div className="p-5"><EmptyState title="No events yet" message="Events are written for decisions made by rules compiled from Clarion intents." /></div> : (
          <div className="grid gap-0 xl:grid-cols-2">
            <div className="border-b border-slate-100 dark:border-gray-700 xl:border-b-0 xl:border-r">
              <Table head={['Time', 'Event', 'Intent', 'Approval']}>
                {s.events.map((e, i) => (
                  <tr key={e.event_id} tabIndex={0} onClick={() => setEv(i)} onKeyDown={(k) => k.key === 'Enter' && setEv(i)}
                    className={cn('cursor-pointer', i === ev ? 'bg-slate-50 dark:bg-gray-700/50' : 'hover:bg-slate-50 dark:hover:bg-gray-700/30')}>
                    <td className="td whitespace-nowrap tabular-nums text-slate-500 dark:text-gray-400">{fmtTime(e.timestamp_ms, now)}</td>
                    <td className="td"><Badge variant={e.event_type === 'match_blocked' ? 'danger' : 'purple'}>{e.event_type.replace('match_', '')}</Badge></td>
                    <td className="td max-w-[14rem] truncate font-mono text-xs" title={e.intent_id}>{e.intent_id}</td>
                    <td className="td font-mono text-xs">{e.approval_ref ?? '—'}</td>
                  </tr>
                ))}
              </Table>
            </div>
            <div className="min-w-0 p-4">
              <div className="mb-2 flex items-center justify-between">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-gray-400">Selected event</p>
                <button type="button" className="btn btn-secondary" onClick={() => void copy()}><Copy className="h-3.5 w-3.5" />{copied ? 'Copied' : 'Copy JSON'}</button>
              </div>
              <pre className="code-block max-h-[28rem]">{JSON.stringify(event, null, 2)}</pre>
            </div>
          </div>
        )}
      </Card>
    </MainPanel>
  )
}
