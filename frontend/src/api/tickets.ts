import client from '../api/client'
import { downloadBlob, todayStamp } from './download'

export interface AuthUser {
  id: number | string
  username: string
  role: string // 'owner' | 'operator' | 'auditor' | ...
  display_name?: string
  totp_enrolled?: boolean
}

export interface LocalLoginPayload {
  username: string
  password: string
  totp?: string
}

export interface LocalLoginResponse {
  jwt: string
  refresh_token?: string
  user: AuthUser
}

/** Stable contract (Wave2 landed): POST /api/auth/local {username,password[,totp]} -> {jwt,user} */
export async function postLocalLogin(payload: LocalLoginPayload): Promise<LocalLoginResponse> {
  const { data } = await client.post<LocalLoginResponse>('/api/auth/local', payload)
  return data
}

/** Stable contract: POST /api/auth/wecom/callback {code} -> {jwt,user}（企微扫码重定向带回的code） */
export async function postWecomCallback(code: string): Promise<LocalLoginResponse> {
  const { data } = await client.post<LocalLoginResponse>('/api/auth/wecom/callback', { code })
  return data
}

/** Stable contract (Wave2 landed): GET /api/auth/me (Bearer) */
export async function fetchMe(): Promise<AuthUser> {
  const { data } = await client.get<AuthUser>('/api/auth/me')
  return data
}

/** Stable contract (P1): POST /api/auth/change-password {old_password,new_password} -> {jwt,user} */
export async function changePassword(oldPassword: string, newPassword: string): Promise<LocalLoginResponse> {
  const { data } = await client.post<LocalLoginResponse>('/api/auth/change-password', {
    old_password: oldPassword,
    new_password: newPassword,
  })
  return data
}

/** Best-effort server-side refresh revocation on logout; never throws. */
export async function postLogout(refreshToken: string): Promise<void> {
  try {
    await client.post('/api/auth/logout', { refresh_token: refreshToken })
  } catch {
    /* logout must never fail the client */
  }
}

export interface TicketItem {
  id: number | string
  severity: string
  state: string
  sla_due_at?: string | null
  ip: string
  port?: number | string | null
  title: string
  assignee?: string | null
  first_seen_at?: string | null
  source?: string | null
  [k: string]: unknown
}

export interface MyTicketsParams {
  state?: string
  severity?: string | string[]
  q?: string
  page?: number
  page_size?: number
}

export interface MyTicketsResponse {
  results: TicketItem[]
  count: number
}

/** Stable contract: GET /api/tickets/my?state=&severity=&q=&page= -> {results[], count} */
export async function fetchMyTickets(params: MyTicketsParams): Promise<MyTicketsResponse> {
  const { data } = await client.get<MyTicketsResponse>('/api/tickets/my', { params })
  // Defensive: Task6 may land mid-lane; normalize both paginated shapes.
  const raw = data as unknown as MyTicketsResponse & { results?: TicketItem[]; data?: TicketItem[]; total?: number }
  return {
    results: raw.results ?? raw.data ?? [],
    count: raw.count ?? raw.total ?? (raw.results ?? raw.data ?? []).length,
  }
}

export interface EvidenceEntry {
  content?: string
  author?: string
  created_at?: string
}

const INTERNAL_EVIDENCE_KEYS = new Set([
  'reopen_count',
  'reopened_from',
  'escalation',
  'overdue',
  'retest_status',
  'attachment_ids',
])

export function toEvidenceEntries(src: unknown): EvidenceEntry[] {
  if (Array.isArray(src)) {
    return src.map((e) => {
      const o = e as Record<string, unknown>
      return {
        content: String(o.content ?? o.note ?? JSON.stringify(e)),
        author: String(o.author ?? ''),
        created_at: String(o.created_at ?? ''),
      }
    })
  }
  if (src && typeof src === 'object') {
    return Object.entries(src as Record<string, unknown>)
      .filter(([k]) => !INTERNAL_EVIDENCE_KEYS.has(k))
      .map(([k, v]) => ({ content: `${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}` }))
  }
  return []
}

export interface TimelineRow {
  id: string | number
  action?: string
  actor?: string | null
  created_at?: string
  diff_json?: Record<string, unknown>
}

export interface TicketDetail extends TicketItem {
  fix_evidence?: Array<{ id?: string | number; content?: string; created_at?: string; author?: string }> | Record<string, unknown>
  audit?: TimelineRow[]
  attachments?: Attachment[]
}

/** Stable contract: GET /api/tickets/:id -> detail incl. fix_evidence + timeline[] (backend field name: timeline). */
export async function fetchTicketDetail(id: string | number): Promise<TicketDetail> {
  const { data } = await client.get<TicketDetail>(`/api/tickets/${id}`)
  const d = data as TicketDetail & { fix_evidence?: TicketDetail['fix_evidence']; evidences?: TicketDetail['fix_evidence']; timeline?: TimelineRow[] }
  return {
    ...d,
    fix_evidence: d.fix_evidence ?? d.evidences ?? [],
    audit: d.audit ?? d.timeline ?? [],
  }
}

/** Stable contract: POST /api/tickets/:id/submit {evidence: {note}} — backend merges the object into fix_evidence JSON. */
export async function submitEvidence(
  id: string | number,
  evidence: string,
  attachmentIds: Array<string | number> = [],
): Promise<unknown> {
  const { data } = await client.post(`/api/tickets/${id}/submit`, {
    evidence: { note: evidence, attachment_ids: attachmentIds },
  })
  return data
}

export interface Attachment {
  id: string | number
  url: string | null
  name: string
  uploaded_by?: string | null
  created_at?: string
}

/** Stable contract: POST /api/tickets/:id/attachments (multipart file=) -> 201 {id, url, name}. */
export async function uploadAttachment(id: string | number, file: File): Promise<Attachment> {
  const form = new FormData()
  form.append('file', file)
  const { data } = await client.post<Attachment>(`/api/tickets/${id}/attachments`, form)
  return data
}

export interface DelayPayload {
  delay_until?: string
  delay_days?: number
  reason: string
}

/** Stable contract: POST /api/tickets/:id/delay-request {delay_days|delay_until, reason} -> 201 申请单（运营/负责人审批，待修复 only）. */
export async function requestDelay(id: string | number, payload: DelayPayload): Promise<unknown> {
  const { data } = await client.post(`/api/tickets/${id}/delay-request`, payload)
  return data
}

/** Stable contract: POST /api/tickets/:id/resume {} -> 已延期→待修复 */
export async function resumeTicket(id: string | number): Promise<unknown> {
  const { data } = await client.post(`/api/tickets/${id}/resume`, {})
  return data
}

export interface IpSummaryRow {
  ip: string
  total: number
  overdue: number
  severities: Record<string, number>
}

function cleanTicketFilters(params: MyTicketsParams): Record<string, string> {
  const { state, severity, q } = params
  const clean: Record<string, string> = {}
  if (state) clean.state = state
  const sevRaw = severity
  const sevList = Array.isArray(sevRaw) ? sevRaw.filter(Boolean) : sevRaw ? [sevRaw] : []
  if (sevList.length > 0) clean.severity = sevList.join(',')
  if (q?.trim()) clean.q = q.trim()
  return clean
}

/** GET /api/tickets/my/export?state=&severity=&q= -> 本人 CSV 下载（UTF-8 BOM） */
export async function exportMyTicketsCsv(params: MyTicketsParams): Promise<void> {
  const clean = cleanTicketFilters(params)
  const { data } = await client.get('/api/tickets/my/export', { params: clean, responseType: 'blob' })
  downloadBlob(data as Blob, `my_tickets_${todayStamp()}.csv`)
}
/** GET /api/tickets/ip-summary?state=&severity=&q= -> per-IP rollup over the full filtered set. */
export async function fetchIpSummary(params: MyTicketsParams): Promise<IpSummaryRow[]> {
  const clean = cleanTicketFilters(params)
  const { data } = await client.get<{ results: IpSummaryRow[] }>('/api/tickets/ip-summary', { params: clean })
  return data.results ?? []
}
