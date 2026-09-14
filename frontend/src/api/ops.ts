import client from './client'
import { downloadBlob, todayStamp } from './download'
import type { TicketItem } from './tickets'

export interface OpsPoolResponse {
  results: TicketItem[]
  count: number
  next: string | null
  previous: string | null
}

/** GET /api/ops/pool?orphan=&unassigned=&state= -> paginated {count,next,previous,results} */
export async function fetchOpsPool(params: Record<string, string | number>): Promise<OpsPoolResponse> {
  const { data } = await client.get<OpsPoolResponse>('/api/ops/pool', { params })
  const raw = data as OpsPoolResponse & { data?: TicketItem[]; total?: number }
  return {
    results: raw.results ?? raw.data ?? [],
    count: raw.count ?? raw.total ?? (raw.results ?? raw.data ?? []).length,
    next: raw.next ?? null,
    previous: raw.previous ?? null,
  }
}

/** POST /api/ops/:id/close {note?} -> 待复测→已闭合 */
export async function opsClose(id: string | number, note?: string): Promise<unknown> {
  const { data } = await client.post(`/api/ops/${id}/close`, note ? { note } : {})
  return data
}

/** POST /api/ops/:id/reject {note?} -> 待复测→待修复打回 */
export async function opsReject(id: string | number, note?: string): Promise<unknown> {
  const { data } = await client.post(`/api/ops/${id}/reject`, note ? { note } : {})
  return data
}

/** POST /api/ops/:id/ignore {reason, expires_at?} -> *→已忽略 */
export async function opsIgnore(id: string | number, reason: string, expires_at?: string): Promise<unknown> {
  const { data } = await client.post(`/api/ops/${id}/ignore`, { reason, ...(expires_at ? { expires_at } : {}) })
  return data
}

export interface AssignableUser {
  id: string | number
  username: string
  dept?: string | null
  role: string
}

/** GET /api/ops/users -> {results[{id, username, dept, role}]} */
export async function fetchAssignableUsers(): Promise<AssignableUser[]> {
  const { data } = await client.get<{ results: AssignableUser[] }>('/api/ops/users')
  return data.results ?? []
}

export interface DeptTree {
  first: string[]
  tree: Record<string, string[]>
  count: number
}

/** GET /api/ops/departments -> {first[], tree{一级:[二级...]}, count} 级联筛选数据源 */
export async function fetchDepartments(): Promise<DeptTree> {
  const { data } = await client.get<DeptTree>('/api/ops/departments')
  return { first: data.first ?? [], tree: data.tree ?? {}, count: data.count ?? 0 }
}

/** POST /api/ops/:id/assign {assignee} -> 手工派单/改派 */
export async function opsAssign(id: string | number, assignee: string): Promise<unknown> {
  const { data } = await client.post(`/api/ops/${id}/assign`, { assignee })
  return data
}

export interface EditTicketInput {
  title?: string
  severity?: string
  description?: string
  solution?: string
  cve?: string
  cvss?: number | null
  source?: string
}

/** PATCH /api/ops/:id/edit -> 内容改单（IP/端口不可改；变严重性重算SLA） */
export async function opsEditTicket(id: string | number, payload: EditTicketInput): Promise<TicketItem> {
  const { data } = await client.patch<TicketItem>(`/api/ops/${id}/edit`, payload)
  return data
}

/** DELETE /api/ops/:id -> 硬删工单（仅运营/管理员，任意状态；审计留 ticket.delete 行） */
export async function opsDeleteTicket(id: string | number): Promise<{ deleted: boolean; id: number }> {
  const { data } = await client.delete(`/api/ops/${id}`)
  return data
}

/** POST /api/ops/batch-assign {ids, assignee} -> {assigned, skipped[{id, reason}]} */
export async function opsBatchAssign(ids: Array<string | number>, assignee: string): Promise<{ assigned: number; skipped: Array<{ id: number; reason: string }> }> {
  const { data } = await client.post('/api/ops/batch-assign', { ids, assignee })
  return data
}

export interface RemindResult {
  requested: number
  sent_emails: number
  reminded_tickets: number
  skipped_cooldown: number
  skipped_unassigned: number
}

/** POST /api/ops/remind {ids} -> 手动提醒邮件（按负责人聚合成一封；24h 冷却与无主自动跳过） */
export async function remindTickets(ids: Array<string | number>): Promise<RemindResult> {
  const { data } = await client.post<RemindResult>('/api/ops/remind', { ids })
  return data
}

/** POST /api/ops/batch-close {ids, note?} -> {closed, skipped[{id, reason}]} */
export async function opsBatchClose(
  ids: Array<string | number>,
  note?: string,
): Promise<{ closed: number; skipped: Array<{ id: number; reason: string }> }> {
  const { data } = await client.post('/api/ops/batch-close', note ? { ids, note } : { ids })
  return data
}

/** POST /api/ops/batch-ignore {ids, reason} -> {ignored, skipped[{id, reason}]} */
export async function opsBatchIgnore(
  ids: Array<string | number>,
  reason: string,
): Promise<{ ignored: number; skipped: Array<{ id: number; reason: string }> }> {
  const { data } = await client.post('/api/ops/batch-ignore', { ids, reason })
  return data
}

export interface ManualTicketInput {
  ip: string
  port?: number
  protocol?: string
  severity: string
  title: string
  cve?: string
  description?: string
  solution?: string
  cvss?: number | null
  assignee?: string
  source?: string
}

/** POST /api/ops/tickets -> 201 手工建单（第三方漏洞录入，不填处理人则按IP自动派） */
export async function opsCreateTicket(payload: ManualTicketInput): Promise<TicketItem> {
  const { data } = await client.post<TicketItem>('/api/ops/tickets', payload)
  return data
}

/** GET /api/ops/pool/export?<params> -> CSV 下载（UTF-8 BOM） */
export async function exportPoolCsv(params: Record<string, string | number> = {}): Promise<void> {
  const { data } = await client.get('/api/ops/pool/export', { params, responseType: 'blob' })
  downloadBlob(data as Blob, `pool_export_${todayStamp()}.csv`)
}

export interface DelayRequest {
  id: string | number
  ticket: number
  ticket_ip: string
  ticket_title: string
  requested_by?: string | null
  delay_days?: number | null
  delay_until?: string | null
  reason: string
  status: string
  decided_by?: string | null
  created_at?: string
}

/** GET /api/ops/delay-requests?status= -> 延期申请列表 */
export async function fetchDelayRequests(status?: string): Promise<DelayRequest[]> {
  const { data } = await client.get<{ results: DelayRequest[] }>('/api/ops/delay-requests', {
    params: status ? { status } : {},
  })
  return data.results ?? []
}

/** POST /api/ops/delay-requests/:id/approve|reject */
export async function decideDelayRequest(
  id: string | number,
  action: 'approve' | 'reject',
  note?: string,
): Promise<unknown> {
  const { data } = await client.post(`/api/ops/delay-requests/${id}/${action}`, note ? { note } : {})
  return data
}
