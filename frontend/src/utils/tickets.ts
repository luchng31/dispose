import type { MyTicketsParams, TicketItem } from '../api/tickets'

/** Build query params for GET /api/tickets/my — drops empty filters, page_size default 20. */
export function buildMyTicketsQuery(input: MyTicketsParams): Record<string, string | number> {
  const out: Record<string, string | number> = {}
  if (input.state) out.state = input.state
  const sevRaw = input.severity
  const sevList = Array.isArray(sevRaw) ? sevRaw.filter(Boolean) : sevRaw ? [sevRaw] : []
  if (sevList.length > 0) out.severity = sevList.join(',')
  if (input.q?.trim()) out.q = input.q.trim()
  out.page = input.page && input.page > 0 ? input.page : 1
  out.page_size = input.page_size && input.page_size > 0 ? input.page_size : 20
  return out
}

export interface SlaInfo {
  label: string
  daysLeft: number | null
  overdue: boolean
}

/** Client-side SLA countdown from sla_due_at. Overdue -> red tag downstream. */
export function slaCountdown(slaDueAt?: string | null, now: number = Date.now()): SlaInfo {
  if (!slaDueAt) return { label: '无SLA', daysLeft: null, overdue: false }
  const due = new Date(slaDueAt).getTime()
  if (Number.isNaN(due)) return { label: 'SLA异常', daysLeft: null, overdue: false }
  const diffMs = due - now
  const daysLeft = Math.floor(diffMs / 86_400_000)
  if (diffMs < 0) {
    const over = Math.ceil(-diffMs / 86_400_000)
    return { label: `逾期 ${over} 天`, daysLeft, overdue: true }
  }
  if (diffMs < 86_400_000) {
    const hours = Math.max(1, Math.floor(diffMs / 3_600_000))
    return { label: `剩余 ${hours} 小时`, daysLeft, overdue: false }
  }
  return { label: `剩余 ${daysLeft} 天`, daysLeft, overdue: false }
}

/** Owner/auditor hide ops actions; operator/admin/leader see ops pool buttons (matches router roles). */
export function canShowOpsButton(role: string | undefined | null): boolean {
  return role === 'operator' || role === 'admin' || role === 'leader'
}

/** Audit log readers: admin/operator/auditor (matches GET /api/audit permission). */
export function canShowAuditButton(role: string | undefined | null): boolean {
  return role === 'admin' || role === 'operator' || role === 'auditor'
}

export interface IpSummary {
  ip: string
  total: number
  overdue: number
  severities: Record<string, number>
}

/** Client-side group-by; used as fallback when GET /api/tickets/ip-summary is unreachable. */
export function groupTicketsByIp(tickets: TicketItem[], now: number = Date.now()): IpSummary[] {
  const map = new Map<string, IpSummary>()
  for (const t of tickets) {
    const ip = String(t.ip ?? 'unknown')
    let row = map.get(ip)
    if (!row) {
      row = { ip, total: 0, overdue: 0, severities: {} }
      map.set(ip, row)
    }
    row.total += 1
    row.severities[String(t.severity ?? 'unknown')] = (row.severities[String(t.severity ?? 'unknown')] ?? 0) + 1
    if (slaCountdown(t.sla_due_at, now).overdue) row.overdue += 1
  }
  return [...map.values()].sort((a, b) => b.total - a.total)
}
