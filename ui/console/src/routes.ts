// One route table for the sidebar and section tabs, as the AegisFlux console's shared/sections.ts.
import type { LucideIcon } from 'lucide-react'
import { Activity, Bot, LayoutDashboard, ScrollText, Settings, ShieldCheck } from 'lucide-react'

export type RouteId =
  | 'overview' | 'agents' | 'decisions' | 'approvals' | 'flows'
  | 'rules' | 'intents' | 'tools' | 'redteam' | 'evidence' | 'integrations' | 'gateway'

export type Tab = { id: RouteId; label: string }
export type NavItem = { id: string; label: string; icon: LucideIcon; route: RouteId; tabs?: Tab[] }
export type NavGroup = { label: string; items: NavItem[] }

export const NAV: NavGroup[] = [
  {
    label: 'Journey',
    items: [
      { id: 'overview', label: 'Overview', icon: LayoutDashboard, route: 'overview' },
      { id: 'agents', label: 'Agents', icon: Bot, route: 'agents' },
      { id: 'activity', label: 'Activity', icon: Activity, route: 'decisions', tabs: [
        { id: 'decisions', label: 'Decisions' }, { id: 'approvals', label: 'Approvals' }, { id: 'flows', label: 'Data flows' }] },
      { id: 'policy', label: 'Policy', icon: ScrollText, route: 'rules', tabs: [
        { id: 'rules', label: 'Rules' }, { id: 'intents', label: 'Clarion intents' }, { id: 'tools', label: 'Tools' }] },
      { id: 'assurance', label: 'Assurance', icon: ShieldCheck, route: 'redteam', tabs: [
        { id: 'redteam', label: 'Red team' }, { id: 'evidence', label: 'Evidence log' }] },
    ],
  },
  {
    label: 'System',
    items: [
      { id: 'settings', label: 'Settings', icon: Settings, route: 'integrations', tabs: [
        { id: 'integrations', label: 'Integrations' }, { id: 'gateway', label: 'Gateway' }] },
    ],
  },
]

export const ALL_ROUTES = new Set<RouteId>(NAV.flatMap((g) => g.items.flatMap((i) => [i.route, ...(i.tabs ?? []).map((t) => t.id)])))

export function navFor(route: RouteId): NavItem {
  for (const g of NAV) for (const i of g.items) if (i.route === route || i.tabs?.some((t) => t.id === route)) return i
  return NAV[0].items[0]
}
export function tabLabel(route: RouteId): string | undefined {
  return navFor(route).tabs?.find((t) => t.id === route)?.label
}

/** Plain-name hash routing (#decisions), which works both locally and inside a published page. */
export function readRoute(): { route: RouteId; param: string | null } {
  const raw = decodeURIComponent(window.location.hash.replace(/^#/, ''))
  const [name, ...rest] = raw.split('--')
  const route = (ALL_ROUTES.has(name as RouteId) ? name : 'overview') as RouteId
  return { route, param: rest.length ? rest.join('--') : null }
}
export function go(route: RouteId, param?: string) {
  window.location.hash = param ? `${route}--${encodeURIComponent(param)}` : route
}
