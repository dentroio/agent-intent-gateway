// Primitives ported from the AegisFlux console (components/ui, components/workbench/primitives).
import type { HTMLAttributes, ReactNode } from 'react'
import { X } from 'lucide-react'
import { useEffect } from 'react'

export function cn(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ')
}

export function Card({ className, children, ...props }: HTMLAttributes<HTMLDivElement> & { children: ReactNode }) {
  return <div className={cn('card', className)} {...props}>{children}</div>
}

export function CardHeader({ title, actions, subtitle }: { title: ReactNode; actions?: ReactNode; subtitle?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 px-5 py-3 dark:border-gray-700">
      <div className="min-w-0">
        <h2 className="text-sm font-semibold text-slate-900 dark:text-gray-100">{title}</h2>
        {subtitle ? <p className="mt-0.5 text-xs text-slate-500 dark:text-gray-400">{subtitle}</p> : null}
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  )
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-2xl font-bold text-slate-950 dark:text-white">{title}</h1>
        {subtitle ? <p className="mt-1 text-sm text-slate-500 dark:text-gray-400">{subtitle}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  )
}

/** Full-width content area inside the shell, as AegisFlux's ShellMainPanel. */
export function MainPanel({ children }: { children: ReactNode }) {
  return <div className="w-full min-w-0 px-4 py-6 sm:px-5 lg:px-6">{children}</div>
}

export type BadgeVariant = 'success' | 'warning' | 'danger' | 'info' | 'neutral' | 'purple'
// Literal class names, so Tailwind's build keeps them.
const BADGE: Record<BadgeVariant, string> = {
  success: 'badge-success', warning: 'badge-warning', danger: 'badge-danger',
  info: 'badge-info', neutral: 'badge-neutral', purple: 'badge-purple',
}
export function Badge({ variant = 'neutral', className, children, title }: {
  variant?: BadgeVariant; className?: string; children: ReactNode; title?: string
}) {
  return <span title={title} className={cn('badge', BADGE[variant], className)}>{children}</span>
}

export function SummaryStrip({ children }: { children: ReactNode }) {
  return <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-4">{children}</div>
}

export function KpiTile({ label, value, detail, onClick, tone }: {
  label: string; value: ReactNode; detail?: ReactNode; onClick?: () => void; tone?: 'danger' | 'warning'
}) {
  const inner = (
    <>
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-gray-400">{label}</p>
      <p className={cn('mt-1 text-xl font-semibold tabular-nums',
        tone === 'danger' ? 'text-danger-700 dark:text-red-300' : tone === 'warning' ? 'text-warning-700 dark:text-amber-300' : 'text-slate-950 dark:text-white')}>{value}</p>
      {detail ? <p className="mt-1 text-xs text-slate-500 dark:text-gray-400">{detail}</p> : null}
    </>
  )
  const cls = 'rounded-lg border border-slate-200 bg-white px-3 py-3 text-left shadow-sm transition-colors dark:border-gray-700 dark:bg-gray-800'
  return onClick
    ? <button type="button" onClick={onClick} className={cn(cls, 'hover:border-slate-300 hover:bg-slate-50 dark:hover:bg-gray-700/60')}>{inner}</button>
    : <div className={cls}>{inner}</div>
}

export function StatCard({ label, value, detail, highlight }: { label: string; value: ReactNode; detail?: ReactNode; highlight?: boolean }) {
  return (
    <Card className={cn('p-5', highlight && 'border-clarion-blue dark:border-blue-400')}>
      <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500 dark:text-gray-400">{label}</p>
      <div className="mt-2 text-slate-900 dark:text-white">{value}</div>
      {detail ? <div className="mt-2 text-sm text-slate-600 dark:text-gray-300">{detail}</div> : null}
    </Card>
  )
}

export function EmptyState({ title, message }: { title: string; message?: string }) {
  return (
    <div className="rounded-lg border border-dashed border-slate-300 bg-white px-4 py-10 text-center dark:border-gray-600 dark:bg-gray-800">
      <p className="text-sm font-semibold text-slate-700 dark:text-gray-200">{title}</p>
      {message ? <p className="mt-1 text-sm text-slate-500 dark:text-gray-400">{message}</p> : null}
    </div>
  )
}

export function Table({ head, children, fixed }: { head: ReactNode[]; children: ReactNode; fixed?: boolean }) {
  return (
    <div className="overflow-x-auto">
      <table className={cn('w-full text-sm', fixed && 'table-fixed')}>
        <thead className="bg-slate-50 dark:bg-gray-900/40">
          <tr>{head.map((h, i) => <th key={i} scope="col" className="th">{h}</th>)}</tr>
        </thead>
        <tbody className="divide-y divide-slate-100 dark:divide-gray-700">{children}</tbody>
      </table>
    </div>
  )
}

export function Chips({ items, empty = '—', variant = 'neutral' }: { items: string[]; empty?: string; variant?: BadgeVariant }) {
  if (!items.length) return <span className="text-slate-400 dark:text-gray-500">{empty}</span>
  return <div className="flex flex-wrap gap-1">{items.map((t) => <Badge key={t} variant={variant} className="font-mono">{t}</Badge>)}</div>
}

/** Segmented filter, same look as AegisFlux filter chips. */
export function Segmented<T extends string>({ value, options, onChange, label }: {
  value: T; options: Array<{ id: T; label: string; count?: number }>; onChange: (v: T) => void; label: string
}) {
  return (
    <div role="group" aria-label={label} className="inline-flex flex-wrap gap-1 rounded-lg border border-gray-200 bg-white p-1 dark:border-gray-700 dark:bg-gray-800">
      {options.map((o) => (
        <button key={o.id} type="button" aria-pressed={o.id === value} onClick={() => onChange(o.id)}
          className={cn('rounded-md px-2.5 py-1 text-xs font-medium transition-colors',
            o.id === value ? 'bg-clarion-blue text-white dark:bg-blue-600' : 'text-slate-600 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-700')}>
          {o.label}{o.count !== undefined ? <span className="ml-1 opacity-75 tabular-nums">{o.count}</span> : null}
        </button>
      ))}
    </div>
  )
}

/** Right-hand detail panel, the console's pattern for inspecting one record. */
export function Drawer({ open, title, subtitle, onClose, children }: {
  open: boolean; title: ReactNode; subtitle?: ReactNode; onClose: () => void; children: ReactNode
}) {
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])
  if (!open) return null
  return (
    <div className="fixed inset-0 z-40 flex justify-end" role="dialog" aria-modal="true">
      <button type="button" aria-label="Close" className="absolute inset-0 bg-slate-900/30 dark:bg-black/50" onClick={onClose} />
      <div className="relative flex h-full w-full max-w-xl flex-col border-l border-gray-200 bg-white shadow-xl dark:border-gray-700 dark:bg-gray-800"
        style={{ paddingTop: 'env(safe-area-inset-top, 0px)', paddingRight: 'env(safe-area-inset-right, 0px)' }}>
        <div className="flex items-start justify-between gap-3 border-b border-gray-200 px-5 py-4 dark:border-gray-700">
          <div className="min-w-0">
            <h2 className="text-base font-semibold text-slate-950 dark:text-white">{title}</h2>
            {subtitle ? <p className="mt-0.5 text-xs text-slate-500 dark:text-gray-400">{subtitle}</p> : null}
          </div>
          <button type="button" onClick={onClose} aria-label="Close details" className="rounded-md p-1 text-slate-400 hover:bg-gray-100 hover:text-slate-700 dark:hover:bg-gray-700 dark:hover:text-gray-200">
            <X size={18} />
          </button>
        </div>
        <div className="min-h-0 flex-1 space-y-5 overflow-y-auto px-5 py-4">{children}</div>
      </div>
    </div>
  )
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-gray-400">{label}</p>
      <div className="mt-1 text-sm text-slate-800 dark:text-gray-200">{children}</div>
    </div>
  )
}

export function Notice({ tone = 'info', children }: { tone?: 'info' | 'warning' | 'danger' | 'success'; children: ReactNode }) {
  const t = {
    info: 'border-blue-200 bg-blue-50 text-blue-900 dark:border-blue-800 dark:bg-blue-900/20 dark:text-blue-100',
    warning: 'border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-700 dark:bg-amber-900/20 dark:text-amber-100',
    danger: 'border-red-200 bg-red-50 text-red-800 dark:border-red-800 dark:bg-red-900/20 dark:text-red-100',
    success: 'border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-800 dark:bg-emerald-900/20 dark:text-emerald-100',
  }[tone]
  return <div className={cn('rounded-lg border px-4 py-3 text-sm', t)}>{children}</div>
}
