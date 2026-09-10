import client from './client'
import type { MappingRow } from '../utils/ops'

export interface AssetMapping {
  ip: string
  hostname?: string
  current: MappingRow | null
  history: MappingRow[]
}

export interface OrphanAsset {
  ip: string
  hostname?: string
  status?: string
}

export interface AssetOverviewRow {
  ip: string
  hostname: string
  dept: string
  owner: string | null
  owner_dept: string
  dept_leader: string
}

export interface AssetOverview {
  count: number
  scope?: string
  page?: number
  page_size?: number
  results: AssetOverviewRow[]
}

export interface CmdbSyncSummary {
  upserted: number
  remapped: number
  orphaned: number
}

/** GET /api/assets/mapping?ip= -> {ip, current, history} */
export async function fetchAssetMapping(ip: string): Promise<AssetMapping> {
  const { data } = await client.get<AssetMapping>('/api/assets/mapping', { params: { ip } })
  return data
}

/** GET /api/assets/orphans -> {count, results[]} */
export async function fetchOrphans(): Promise<{ count: number; results: OrphanAsset[] }> {
  const { data } = await client.get<{ count: number; results: OrphanAsset[] }>('/api/assets/orphans')
  return data
}

/** GET /api/assets/overview?q=&dept=&page=&page_size= -> 角色裁剪的 IP 分配总览（分页，
 * page_size 默认 20 最大 100；leader=管辖部门全部 IP，owner=自己名下，operator/admin=全量） */
export async function fetchAssetOverview(params?: { q?: string; dept?: string; page?: number; page_size?: number }): Promise<AssetOverview> {
  const { data } = await client.get<AssetOverview>('/api/assets/overview', { params })
  return data
}

/** POST /api/cmdb/sync -> {upserted, remapped, orphaned} */
export async function postCmdbSync(): Promise<CmdbSyncSummary> {
  const { data } = await client.post<CmdbSyncSummary>('/api/cmdb/sync', {})
  return data
}

export interface AssetWriteInput {
  ip: string
  hostname?: string
  os?: string
  biz_system?: string
  level?: string
  owner?: string
}

export interface AssetWriteResult {
  ip: string
  hostname?: string
  owner?: string | null
  remapped: number
}

/** POST /api/assets -> 201 手工新建资产（离线/非CMDB资产） */
export async function createAsset(payload: AssetWriteInput): Promise<AssetWriteResult> {
  const { data } = await client.post<AssetWriteResult>('/api/assets', payload)
  return data
}

/** POST /api/assets/remap {ip, username?} -> 变更负责人并重派单（空用户名则置无主） */
export async function remapAsset(ip: string, username?: string): Promise<AssetWriteResult> {
  const { data } = await client.post<AssetWriteResult>('/api/assets/remap', { ip, username: username ?? '' })
  return data
}
