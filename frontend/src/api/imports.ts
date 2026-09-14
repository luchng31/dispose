import client from './client'
import type { DryRunCounts } from '../utils/ops'

export interface ScanBatch {
  id: number | string
  file_name: string
  file_hash: string
  source: string
  rsas_version?: string
  stats: Record<string, unknown>
  created_at?: string
}

/** GET /api/imports/batches -> file_hash + stats per batch */
export async function fetchBatches(): Promise<ScanBatch[]> {
  const { data } = await client.get<ScanBatch[] | { results: ScanBatch[] }>('/api/imports/batches')
  if (Array.isArray(data)) return data
  return (data as { results: ScanBatch[] }).results ?? []
}

/** POST /api/imports/rsas?dry_run=&source= (multipart file). dry_run=true -> preview, false -> confirm import.
 * label=batch_name（可选）：手工上传的来源显示名，缺省=文件名。 */
export async function postRsasImport(file: File, dryRun: boolean, source = 'manual', label?: string): Promise<DryRunCounts & { batch_id?: number | string; stats?: Record<string, unknown> }> {
  const form = new FormData()
  form.append('file', file)
  if (label && label.trim()) form.append('batch_name', label.trim())
  const { data } = await client.post('/api/imports/rsas', form, {
    params: { dry_run: dryRun ? 'true' : 'false', source },
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data as DryRunCounts & { batch_id?: number | string; stats?: Record<string, unknown> }
}

export interface AssetImportSummary {
  created_assets: number
  updated_assets: number
  created_users: Array<{ username: string; temp_password: string; role?: string }>
  created_leaders?: number
  upgraded_leaders?: string[]
  leader_dept_maps?: number
  leader_maps_rebuilt?: boolean
  orphaned?: number
  sync?: boolean
  remapped: number
  dispatched: number
  errors: Array<Record<string, unknown>>
  applied?: boolean
  valid?: number
  invalid?: number
  orphaned_preview?: number
}

export interface OwnerEmailImportSummary {
  total_rows: number
  updated: number
  unchanged: number
  changes?: Array<{ user_id: number; username: string; old: string; new: string }>
  missing: Array<{ row: number; name: string }>
  errors: Array<Record<string, unknown>>
  applied?: boolean
  updated_preview?: number
}

/** POST /api/imports/assets?dry_run= (multipart file=, 资产+负责人表 .xlsx/.csv).
 * 服务器资源汇总表格式：内网IP*, 管理人*, 管理人-隶属组织, 资源使用部门, 部门负责人。
 * 汇总表格式=权威全量同步（表外 IP 置无主+部门映射重建，orphaned_preview 预览）；
 * dry_run=true -> preview only. */
export async function postAssetImport(file: File, dryRun: boolean): Promise<AssetImportSummary> {
  const form = new FormData()
  form.append('file', file)
  const { data } = await client.post('/api/imports/assets', form, {
    params: { dry_run: dryRun ? 'true' : 'false' },
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data as AssetImportSummary
}

/** POST /api/imports/owner-emails?dry_run= (multipart file=, 负责人邮箱表：负责人/工号+邮箱).
 * 仅更新已有账号邮箱（不建号），dry_run=true -> preview only。 */
export async function postOwnerEmailImport(file: File, dryRun: boolean): Promise<OwnerEmailImportSummary> {
  const form = new FormData()
  form.append('file', file)
  const { data } = await client.post('/api/imports/owner-emails', form, {
    params: { dry_run: dryRun ? 'true' : 'false' },
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data as OwnerEmailImportSummary
}

/** GET /api/imports/assets/template -> CSV 模板下载（带 JWT，用 blob 落盘） */
export async function downloadAssetTemplate(): Promise<void> {
  const { data } = await client.get<Blob>('/api/imports/assets/template', { responseType: 'blob' })
  const url = URL.createObjectURL(data)
  const a = document.createElement('a')
  a.href = url
  a.download = 'asset_template.csv'
  a.click()
  URL.revokeObjectURL(url)
}

/** GET /api/imports/owner-emails/template -> 负责人邮箱表 CSV 模板下载 */
export async function downloadOwnerEmailTemplate(): Promise<void> {
  const { data } = await client.get<Blob>('/api/imports/owner-emails/template', { responseType: 'blob' })
  const url = URL.createObjectURL(data)
  const a = document.createElement('a')
  a.href = url
  a.download = 'owner_email_template.csv'
  a.click()
  URL.revokeObjectURL(url)
}
