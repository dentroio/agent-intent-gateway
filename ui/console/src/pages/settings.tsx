import type { ReactNode } from 'react'
import { Badge, Card, CardHeader, Chips, Field, MainPanel, Notice, PageHeader } from '../components/ui'
import { plural, type Snapshot } from '../data'

function Integration({ name, status, tone, children }: { name: string; status: string; tone: 'success' | 'warning' | 'neutral'; children: ReactNode }) {
  return (
    <Card>
      <CardHeader title={name} actions={<Badge variant={tone}>{status}</Badge>} />
      <div className="space-y-3 px-5 py-4 text-sm">{children}</div>
    </Card>
  )
}

export function Integrations({ s }: { s: Snapshot }) {
  const keys = [...new Set(s.intents.map((i) => i.key_id))]
  return (
    <MainPanel>
      <PageHeader title="Integrations" subtitle="AIG works on its own. Each dentro.io product it connects to upgrades something it already does." />
      <div className="grid gap-5 xl:grid-cols-2 [&>*]:min-w-0">
        <Integration name="Clarion" status={s.intents.length ? 'Connected' : 'Not connected'} tone={s.intents.length ? 'success' : 'neutral'}>
          <p className="text-slate-600 dark:text-gray-300">Enterprise intent compiled into signed gateway rules, and decisions reported back for Clarion's Verify stage.</p>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Intents loaded">{s.intents.length}</Field>
            <Field label="Signing keys"><Chips items={keys} /></Field>
          </div>
          <Field label="Contract"><span className="font-mono text-xs">segmentation_policy_intent.v1 → segmentation_compiled_artifact.v1 (proxy_broker)</span></Field>
        </Integration>
        <Integration name="AegisFlux" status={s.events.length ? 'Sending evidence' : 'Not connected'} tone={s.events.length ? 'success' : 'neutral'}>
          <p className="text-slate-600 dark:text-gray-300">Endpoint-proven agent identity and traffic steering in; outcome events out, joined with host and flow evidence.</p>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Outcome events">{plural(s.events.length, 'event')}</Field>
            <Field label="Identity tokens">{s.decisions.some((d) => d.token) ? 'Per-stream tokens' : 'Not in use'}</Field>
          </div>
          <Field label="Contract"><span className="font-mono text-xs">segmentation_outcome_event.v1 · stream tokens per ADR-GW-002</span></Field>
          <Notice tone="warning">Tokens come from the lab issuer (<span className="font-mono">aig token</span>) until the AegisFlux backend mints them.</Notice>
        </Integration>
        <Integration name="Single sign-on" status="Not configured" tone="neutral">
          <p className="text-slate-600 dark:text-gray-300">Okta or Entra ID for the principal an agent acts for. On the roadmap for the first release.</p>
        </Integration>
        <Integration name="SIEM export" status="Not configured" tone="neutral">
          <p className="text-slate-600 dark:text-gray-300">Stream decisions to Splunk, Sentinel or any syslog collector. On the roadmap for the first release.</p>
        </Integration>
      </div>
    </MainPanel>
  )
}

export function Gateway({ s }: { s: Snapshot }) {
  const g = s.gateway
  return (
    <MainPanel>
      <PageHeader title="Gateway" subtitle="How this gateway is configured." />
      <Card>
        <div className="grid gap-5 px-5 py-5 sm:grid-cols-2 lg:grid-cols-3">
          <Field label="Policy version"><span className="font-mono">{g.policy_version ?? 'unversioned'}</span></Field>
          <Field label="Default for undeclared calls">{g.default === 'deny' ? 'Refuse' : g.default}</Field>
          <Field label="Policy classes"><Chips items={g.classes} empty="not in use" /></Field>
          <Field label="Mode">{s.demo ? 'Demo snapshot' : String(g.transport ?? 'live')}</Field>
          <Field label="Agents">{s.agents.length}</Field>
          <Field label="Tools declared">{s.tools.length}</Field>
          <Field label="Data-flow rules">{s.flows.length}</Field>
          <Field label="AIG version"><span className="font-mono">{s.version}</span></Field>
          <Field label="Build"><span className="font-mono">{s.commit}</span></Field>
        </div>
      </Card>
    </MainPanel>
  )
}
