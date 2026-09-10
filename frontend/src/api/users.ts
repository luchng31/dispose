import client from './client'

export interface AdminUser {
  id: string | number
  username: string
  dept?: string | null
  email?: string | null
  role: string
  wecom_userid?: string | null
  is_active: boolean
  last_login?: string | null
}

export interface AdminUserList {
  results: AdminUser[]
  count: number
}

/** GET /api/ops/admin/users?q=&role=&active= */
export async function fetchAdminUsers(params: Record<string, string | number> = {}): Promise<AdminUserList> {
  const { data } = await client.get<AdminUserList>('/api/ops/admin/users', { params })
  return data
}

export interface CreateUserPayload {
  username: string
  dept?: string
  email?: string
  role?: string
  wecom_userid?: string
  password?: string
}

/** POST /api/ops/admin/users -> 新建（含一次性临时密码） */
export async function createAdminUser(payload: CreateUserPayload): Promise<AdminUser & { temp_password?: string }> {
  const { data } = await client.post('/api/ops/admin/users', payload)
  return data as AdminUser & { temp_password?: string }
}

/** PATCH /api/ops/admin/users/:username -> 改资料/停用启用 */
export async function patchAdminUser(username: string, payload: Partial<AdminUser>): Promise<AdminUser> {
  const { data } = await client.patch(`/api/ops/admin/users/${username}`, payload)
  return data as AdminUser
}

/** POST /api/ops/admin/users/:username -> 重置密码（不传即生成） */
export async function resetAdminPassword(username: string, password?: string): Promise<{ temp_password?: string }> {
  const { data } = await client.post(
    `/api/ops/admin/users/${username}`,
    password ? { password } : {},
  )
  return data as { temp_password?: string }
}

/** DELETE /api/ops/admin/users/:username -> 硬删用户（仅运营/管理员；在办工单自动退回，审计留痕） */
export async function deleteAdminUser(username: string): Promise<{ deleted: boolean; username: string; unassigned_open_tickets: number }> {
  const { data } = await client.delete(`/api/ops/admin/users/${encodeURIComponent(username)}`)
  return data as { deleted: boolean; username: string; unassigned_open_tickets: number }
}
