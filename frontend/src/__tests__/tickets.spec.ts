import { describe, expect, it } from 'vitest'
import { buildMyTicketsQuery, canShowAuditButton, canShowOpsButton, groupTicketsByIp, slaCountdown } from '../utils/tickets'

describe('buildMyTicketsQuery', () => {
  it('drops empty filters and defaults page_size 20', () => {
    expect(buildMyTicketsQuery({ state: '', severity: '', q: '  ' })).toEqual({ page: 1, page_size: 20 })
  })
  it('keeps set filters and trims q', () => {
    expect(buildMyTicketsQuery({ state: '待修复', severity: '高', q: ' 10.0.0.1 ', page: 2 })).toEqual({
      state: '待修复',
      severity: '高',
      q: '10.0.0.1',
      page: 2,
      page_size: 20,
    })
  })
})

describe('slaCountdown', () => {
  it('marks overdue red', () => {
    const now = new Date('2026-09-01T00:00:00Z').getTime()
    const info = slaCountdown('2026-08-30T00:00:00Z', now)
    expect(info.overdue).toBe(true)
    expect(info.label).toContain('逾期')
  })
  it('shows remaining days', () => {
    const now = new Date('2026-09-01T00:00:00Z').getTime()
    const info = slaCountdown('2026-09-05T00:00:00Z', now)
    expect(info.overdue).toBe(false)
    expect(info.label).toContain('剩余')
  })
  it('handles missing sla', () => {
    expect(slaCountdown(null).label).toBe('无SLA')
  })
})

describe('canShowOpsButton', () => {
  it('owner hides ops actions', () => {
    expect(canShowOpsButton('owner')).toBe(false)
    expect(canShowOpsButton(undefined)).toBe(false)
  })
  it('operator/admin/leader see ops actions', () => {
    expect(canShowOpsButton('operator')).toBe(true)
    expect(canShowOpsButton('admin')).toBe(true)
    expect(canShowOpsButton('leader')).toBe(true)
    expect(canShowOpsButton('auditor')).toBe(false)
  })
})

describe('canShowAuditButton', () => {
  it('admin/operator/auditor see audit log', () => {
    expect(canShowAuditButton('admin')).toBe(true)
    expect(canShowAuditButton('operator')).toBe(true)
    expect(canShowAuditButton('auditor')).toBe(true)
  })
  it('owner/leader/anonymous hide audit log', () => {
    expect(canShowAuditButton('owner')).toBe(false)
    expect(canShowAuditButton('leader')).toBe(false)
    expect(canShowAuditButton(undefined)).toBe(false)
  })
})

describe('groupTicketsByIp', () => {
  it('groups client-side until server VIEW lands', () => {
    const rows = groupTicketsByIp(
      [
        { id: 1, severity: 'high', state: '待修复', ip: '10.0.0.1', title: 'a' },
        { id: 2, severity: 'low', state: '待修复', ip: '10.0.0.1', title: 'b' },
        { id: 3, severity: 'high', state: '待修复', ip: '10.0.0.2', title: 'c' },
      ],
      new Date('2026-09-01T00:00:00Z').getTime(),
    )
    expect(rows).toHaveLength(2)
    expect(rows[0].ip).toBe('10.0.0.1')
    expect(rows[0].total).toBe(2)
  })
})
