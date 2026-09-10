/** Task8 pure helpers: pool query builder, dry-run parser, mapping history grouper. */

export type PoolTab = 'all' | 'orphan' | 'unassigned' | 'overdue' | 'delays'

export interface PoolQueryInput {
  tab?: PoolTab
  state?: string
  severity?: string | string[]
  q?: string
  dept?: string
  dept_prefix?: string
  page?: number
  page_size?: number
}

/**
 * Build query params for GET /api/ops/pool?orphan=&unassigned=&state=&severity=&q=&dept=&dept_prefix=.
 * Tabs: 全部 -> no flags; 无主 -> orphan=true; 未分配 -> unassigned=true; 逾期 -> client-side SLA filter hint (no server flag).
 * 级联：选一级 -> dept_prefix；选二级 -> dept=全称（与 dept_prefix 同传做双保险）。
 * Drops empties; page defaults 1, page_size defaults 20 (max 100).
 */
export function buildPoolQuery(input: PoolQueryInput): Record<string, string | number> {
  const out: Record<string, string | number> = {}
  const tab = input.tab ?? 'all'
  if (tab === 'orphan') out.orphan = 'true'
  else if (tab === 'unassigned') out.unassigned = 'true'
  // 'overdue' has no server flag: backend SLA lives in sla_due_at; view filters client-side.
  if (input.state) out.state = input.state
  const sevRaw = input.severity
  const sevList = Array.isArray(sevRaw) ? sevRaw.filter(Boolean) : sevRaw ? [sevRaw] : []
  if (sevList.length > 0) out.severity = sevList.join(',')
  if (input.q?.trim()) out.q = input.q.trim()
  if (input.dept) out.dept = input.dept
  if (input.dept_prefix) out.dept_prefix = input.dept_prefix
  out.page = input.page && input.page > 0 ? input.page : 1
  const ps = input.page_size && input.page_size > 0 ? input.page_size : 20
  out.page_size = ps > 100 ? 100 : ps
  return out
}

export interface DryRunCounts {
  new: number
  still_open: number
  fixed_unverified: number
  reopened: number
  errors: Array<Record<string, unknown>>
  skipped: boolean
  file_hash: string
}

/**
 * Parse dry-run preview verbatim from POST /api/imports/rsas?dry_run=true.
 * NEVER recompute counts client-side: coerce + pass through exactly.
 * Missing numeric fields default 0; errors default [].
 */
export function parseDryRun(raw: unknown): DryRunCounts {
  const r = (raw ?? {}) as Record<string, unknown>
  const num = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) ? v : 0)
  const errs = Array.isArray(r.errors) ? (r.errors as Array<Record<string, unknown>>) : []
  return {
    new: num(r.new),
    still_open: num(r.still_open),
    fixed_unverified: num(r.fixed_unverified),
    reopened: num(r.reopened),
    errors: errs,
    skipped: r.skipped === true,
    file_hash: typeof r.file_hash === 'string' ? r.file_hash : '',
  }
}

export interface MappingRow {
  wecom_userid?: string
  username?: string
  valid_from?: string | null
  valid_to?: string | null
  [k: string]: unknown
}

export interface MappingHistoryGroup {
  key: string
  username: string
  wecom_userid: string
  periods: MappingRow[]
  current: boolean
}

/**
 * Group GET /api/assets/mapping?ip= history rows by owner (wecom_userid||username).
 * Preserves backend order (newest-first: -valid_from); marks period with valid_to==null as current.
 */
export function groupMappingHistory(history: MappingRow[]): MappingHistoryGroup[] {
  const groups = new Map<string, MappingHistoryGroup>()
  for (const row of history ?? []) {
    const key = String(row.wecom_userid ?? row.username ?? 'unknown')
    let g = groups.get(key)
    if (!g) {
      g = {
        key,
        username: String(row.username ?? ''),
        wecom_userid: String(row.wecom_userid ?? ''),
        periods: [],
        current: false,
      }
      groups.set(key, g)
    }
    g.periods.push(row)
    if (row.valid_to === null || row.valid_to === undefined) g.current = true
  }
  return [...groups.values()]
}
