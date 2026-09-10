import client from './client'

export interface IntegrationField {
  key: string
  label: string
  secret: boolean
  configured: boolean
  value?: string | number | boolean
  hint?: string
}

export interface IntegrationGroup {
  id: string
  label: string
  fields: IntegrationField[]
}

export type IntegrationTestKey = 'smtp' | 'wecom.bot' | 'wecom.login' | 'cmdb'

export interface IntegrationTestResult {
  ok: boolean
  detail: string
}

export interface FieldMapResponse {
  version: string
  mapping?: unknown
  [key: string]: unknown
}

export interface CmdbSyncSummary {
  upserted: number
  remapped: number
  orphaned: number
}

/** GET /api/ops/integrations -> 按组返回外部集成配置（secret 字段无 value，只有 configured） */
export async function fetchIntegrations(): Promise<IntegrationGroup[]> {
  const { data } = await client.get<{ groups: IntegrationGroup[] }>('/api/ops/integrations')
  return data.groups ?? []
}

/** PUT /api/ops/integrations {key, value} -> {key, configured}；空 secret 表示不修改 */
export async function updateIntegrationKey(
  key: string,
  value: string | number | boolean,
): Promise<{ key: string; configured: boolean }> {
  const { data } = await client.put('/api/ops/integrations', { key, value })
  return data as { key: string; configured: boolean }
}

/** POST /api/ops/integrations/test {key, to?} -> {ok, detail} */
export async function testIntegration(key: IntegrationTestKey, to?: string): Promise<IntegrationTestResult> {
  const { data } = await client.post('/api/ops/integrations/test', to ? { key, to } : { key })
  return data as IntegrationTestResult
}

/** GET /api/imports/field-map -> {version, mapping, ...} */
export async function fetchFieldMap(): Promise<FieldMapResponse> {
  const { data } = await client.get<FieldMapResponse>('/api/imports/field-map')
  return data
}

/** POST /api/cmdb/sync -> {upserted, remapped, orphaned} */
export async function triggerCmdbSync(): Promise<CmdbSyncSummary> {
  const { data } = await client.post<CmdbSyncSummary>('/api/cmdb/sync', {})
  return data
}
