import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { AxiosResponse } from 'axios'

vi.mock('../api/client', () => ({
  default: { post: vi.fn() },
}))

import client from '../api/client'
import { confirmTotp, disableTotp, formatTotpSecret, setupTotp } from '../api/mfa'

function ok<T>(data: T): AxiosResponse<T> {
  return {
    data,
    status: 200,
    statusText: 'OK',
    headers: {},
    config: {} as unknown as AxiosResponse<T>['config'],
  }
}

const mockPost = vi.mocked(client.post)

describe('mfa api', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('setupTotp returns secret verbatim', async () => {
    mockPost.mockResolvedValue(ok({ secret: 'ABCDEF', otpauth_url: 'otpauth://totp/x' }))
    const res = await setupTotp()
    expect(mockPost).toHaveBeenCalledWith('/api/auth/totp/setup', {})
    expect(res.secret).toBe('ABCDEF')
  })

  it('confirmTotp posts secret+code', async () => {
    mockPost.mockResolvedValue(ok({ enrolled: true }))
    const res = await confirmTotp('ABCDEF', '123456')
    expect(mockPost).toHaveBeenCalledWith('/api/auth/totp/confirm', { secret: 'ABCDEF', code: '123456' })
    expect(res.enrolled).toBe(true)
  })

  it('disableTotp posts password', async () => {
    mockPost.mockResolvedValue(ok({ enrolled: false }))
    const res = await disableTotp('pw')
    expect(mockPost).toHaveBeenCalledWith('/api/auth/totp/disable', { password: 'pw' })
    expect(res.enrolled).toBe(false)
  })
})

describe('formatTotpSecret', () => {
  it('groups in fours and uppercases', () => {
    expect(formatTotpSecret('abcdefij')).toBe('ABCD EFIJ')
  })
  it('strips whitespace', () => {
    expect(formatTotpSecret('abcd efgh')).toBe('ABCD EFGH')
  })
  it('handles uneven tail', () => {
    expect(formatTotpSecret('abcde')).toBe('ABCD E')
  })
})
