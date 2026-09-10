import client from './client'

export interface DeptBucket {
  total: number
  open: number
  closed: number
  overdue: number
}

export interface DashboardData {
  total: number
  by_state: Record<string, number>
  by_severity: Record<string, number>
  sla: { overdue: number; at_risk: number; ok: number; no_due: number }
  by_dept?: Record<string, DeptBucket>
}

/** GET /api/dashboard?dept=&dept_prefix= -> 总量/状态/严重性/SLA/一级部门分布 */
export async function fetchDashboard(params: { dept?: string; dept_prefix?: string } = {}): Promise<DashboardData> {
  const clean: Record<string, string> = {}
  if (params.dept) clean.dept = params.dept
  if (params.dept_prefix) clean.dept_prefix = params.dept_prefix
  const { data } = await client.get<DashboardData>('/api/dashboard', { params: clean })
  return data
}

export interface SlaPolicyRow {
  severity: string
  days: number
  warn_days_before: number
  source: 'table' | 'fallback'
}

/** GET /api/ops/sla-policies -> 4个严重性的SLA策略（admin） */
export async function fetchSlaPolicies(): Promise<SlaPolicyRow[]> {
  const { data } = await client.get<{ results: SlaPolicyRow[] }>('/api/ops/sla-policies')
  return data.results ?? []
}

/** PUT /api/ops/sla-policies/:severity {days, warn_days_before?} -> upsert（admin） */
export async function updateSlaPolicy(severity: string, days: number, warnDaysBefore?: number): Promise<SlaPolicyRow> {
  const { data } = await client.put<SlaPolicyRow>(
    `/api/ops/sla-policies/${encodeURIComponent(severity)}`,
    warnDaysBefore != null ? { days, warn_days_before: warnDaysBefore } : { days },
  )
  return data
}

export interface NotifyStatus {
  enabled: boolean
  configured: boolean
  host: string
  port: number
  from: string
  use_ssl: boolean
  use_tls: boolean
  wecom_configured?: boolean
}

/** GET /api/ops/notify/status -> SMTP 配置状态（无密码） */
export async function fetchNotifyStatus(): Promise<NotifyStatus> {
  const { data } = await client.get<NotifyStatus>('/api/ops/notify/status')
  return data
}

/** POST /api/ops/notify/test {to?, channel?} -> 发一封测试邮件或一条群机器人消息 */
export async function sendNotifyTest(to: string, channel: 'mail' | 'wecom' = 'mail'): Promise<{ sent: number; configured: boolean }> {
  const { data } = await client.post('/api/ops/notify/test', channel === 'wecom' ? { channel } : { to })
  return data as { sent: number; configured: boolean }
}
