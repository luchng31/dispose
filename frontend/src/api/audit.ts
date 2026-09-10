import client from './client'

export interface AuditRow {
  id: number | string
  action: string
  actor?: string | null
  ticket_id?: number | null
  entity?: string | null
  entity_id?: string | null
  diff_json?: Record<string, unknown> | null
  created_at?: string | null
}

export interface AuditParams {
  ticket_id?: string
  actor?: string
  page?: number
  page_size?: number
}

/** GET /api/audit?ticket_id=&actor=&page= -> {results[], count} (admin/operator/auditor). */
export async function fetchAuditLogs(params: AuditParams): Promise<{ results: AuditRow[]; count: number }> {
  const clean: Record<string, string | number> = {}
  if (params.ticket_id?.trim()) clean.ticket_id = params.ticket_id.trim()
  if (params.actor?.trim()) clean.actor = params.actor.trim()
  clean.page = params.page && params.page > 0 ? params.page : 1
  clean.page_size = params.page_size && params.page_size > 0 ? params.page_size : 20
  const { data } = await client.get('/api/audit', { params: clean })
  const raw = data as { results?: AuditRow[]; data?: AuditRow[]; count?: number; total?: number }
  const results = raw.results ?? raw.data ?? []
  return { results, count: raw.count ?? raw.total ?? results.length }
}
