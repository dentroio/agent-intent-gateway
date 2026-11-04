import { AlertTriangle } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Shell, type Health } from './components/Shell'
import { MainPanel, Notice } from './components/ui'
import { outcomeKind, plural, referenceNow, useSnapshot, type Snapshot } from './data'
import { readRoute, type RouteId } from './routes'
import { Approvals, Decisions, Flows } from './pages/activity'
import { Agents } from './pages/agents'
import { Evidence, RedTeam } from './pages/assurance'
import { Overview } from './pages/overview'
import { Intents, Rules, Tools } from './pages/policy'
import { Gateway, Integrations } from './pages/settings'

function healthOf(s: Snapshot | null): Health {
  if (!s) return { label: 'Connecting', tone: 'slate', text: 'Waiting for the gateway.' }
  if (!s.chain.ok) return { label: 'Log tampered', tone: 'red', text: `The decision log failed verification: ${s.chain.message}.` }
  const enforced = s.flows.filter((f) => f.mode === 'enforce').length
  const clarion = s.flows.filter((f) => f.source === 'clarion').length
  const observe = s.flows.length - enforced
  const detail = `${plural(enforced, 'data-flow rule')} enforced${observe ? `, ${observe} in observe mode` : ''}${clarion ? `, ${clarion} from Clarion intents` : ''}. Decision log intact.`
  return enforced ? { label: 'Enforcing', tone: 'emerald', text: detail } : { label: 'Observe only', tone: 'amber', text: detail }
}

export default function App() {
  const { snap, error, loading, reload } = useSnapshot()
  const [{ route, param }, setRoute] = useState(readRoute())
  useEffect(() => {
    const on = () => setRoute(readRoute())
    window.addEventListener('hashchange', on)
    return () => window.removeEventListener('hashchange', on)
  }, [])
  useEffect(() => { document.querySelector('main')?.scrollTo({ top: 0 }) }, [route])

  const health = healthOf(snap)
  const now = useMemo(() => (snap ? referenceNow(snap) : Date.now()), [snap])
  const waiting = snap ? snap.decisions.filter((d) => outcomeKind(d) === 'not_approved').length : 0
  const operator = snap?.demo ? 'Demo viewer' : String(snap?.gateway.operator ?? 'local operator')

  return (
    <Shell route={route} health={health} demo={!!snap?.demo} approvalsWaiting={waiting} operator={operator}>
      {error ? <MainPanel><Notice tone="danger"><span className="inline-flex items-center gap-2"><AlertTriangle className="h-4 w-4" />{error}</span></Notice></MainPanel> : null}
      {snap ? <Page route={route} param={param} s={snap} now={now} health={health} reload={reload} loading={loading} />
        : !error ? <MainPanel><p className="text-sm text-slate-500">Loading gateway state…</p></MainPanel> : null}
    </Shell>
  )
}

function Page({ route, param, s, now, health, reload, loading }: {
  route: RouteId; param: string | null; s: Snapshot; now: number; health: Health; reload: () => void; loading: boolean
}) {
  switch (route) {
    case 'agents': return <Agents key={param ?? ''} s={s} now={now} selected={param} />
    case 'decisions': return <Decisions key={param ?? ''} s={s} now={now} param={param} />
    case 'approvals': return <Approvals s={s} now={now} />
    case 'flows': return <Flows s={s} />
    case 'rules': return <Rules key={param ?? ''} s={s} selected={param} />
    case 'intents': return <Intents s={s} />
    case 'tools': return <Tools s={s} />
    case 'redteam': return <RedTeam s={s} selected={param} />
    case 'evidence': return <Evidence s={s} now={now} />
    case 'integrations': return <Integrations s={s} />
    case 'gateway': return <Gateway s={s} />
    default: return <Overview s={s} health={health} now={now} onRefresh={reload} loading={loading} />
  }
}
