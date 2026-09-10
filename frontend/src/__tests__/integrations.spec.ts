import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { AxiosResponse } from 'axios'

vi.mock('../api/client', () => ({
  default: { get: vi.fn(), put: vi.fn(), post: vi.fn() },
}))

import client from '../api/client'
import {
  fetchFieldMap,
  fetchIntegrations,
  testIntegration,
  triggerCmdbSync,
  updateIntegrationKey,
} from '../api/integrations'

function ok<T>(data: T): AxiosResponse<T> {
  return {
    data,
    status: 200,
    statusText: 'OK',
    headers: {},
    config: {} as unknown as AxiosResponse<T>['config'],
  }
}

const mockGet = vi.mocked(client.get)
const mockPut = vi.mocked(client.put)
const mockPost = vi.mocked(client.post)

describe('integrations api', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('fetchIntegrations returns groups verbatim', async () => {
    const groups = [
      {
        id: 'smtp',
        label: 'SMTP',
        fields: [{ key: 'smtp.host', label: '服务器', secret: false, configured: true, value: 'smtp.x.com' }],
      },
    ]
    mockGet.mockResolvedValue(ok({ groups }))
    await expect(fetchIntegrations()).resolves.toEqual(groups)
    expect(mockGet).toHaveBeenCalledWith('/api/ops/integrations')
  })

  it('fetchIntegrations defaults missing groups to []', async () => {
    mockGet.mockResolvedValue(ok({}))
    await expect(fetchIntegrations()).resolves.toEqual([])
  })

  it('updateIntegrationKey PUTs {key, value}', async () => {
    mockPut.mockResolvedValue(ok({ key: 'smtp.host', configured: true }))
    await expect(updateIntegrationKey('smtp.host', 'smtp.x.com')).resolves.toEqual({
      key: 'smtp.host',
      configured: true,
    })
    expect(mockPut).toHaveBeenCalledWith('/api/ops/integrations', { key: 'smtp.host', value: 'smtp.x.com' })
  })

  it('testIntegration posts key only without to', async () => {
    mockPost.mockResolvedValue(ok({ ok: true, detail: 'ok' }))
    await expect(testIntegration('cmdb')).resolves.toEqual({ ok: true, detail: 'ok' })
    expect(mockPost).toHaveBeenCalledWith('/api/ops/integrations/test', { key: 'cmdb' })
  })

  it('testIntegration includes to for smtp', async () => {
    mockPost.mockResolvedValue(ok({ ok: true, detail: 'sent' }))
    await expect(testIntegration('smtp', 'a@b.com')).resolves.toEqual({ ok: true, detail: 'sent' })
    expect(mockPost).toHaveBeenCalledWith('/api/ops/integrations/test', { key: 'smtp', to: 'a@b.com' })
  })

  it('fetchFieldMap returns version + mapping', async () => {
    const payload = { version: 'v3', mapping: { ip: 'ip' } }
    mockGet.mockResolvedValue(ok(payload))
    await expect(fetchFieldMap()).resolves.toEqual(payload)
    expect(mockGet).toHaveBeenCalledWith('/api/imports/field-map')
  })

  it('triggerCmdbSync posts empty body and returns summary', async () => {
    const summary = { upserted: 2, remapped: 1, orphaned: 0 }
    mockPost.mockResolvedValue(ok(summary))
    await expect(triggerCmdbSync()).resolves.toEqual(summary)
    expect(mockPost).toHaveBeenCalledWith('/api/cmdb/sync', {})
  })
})
