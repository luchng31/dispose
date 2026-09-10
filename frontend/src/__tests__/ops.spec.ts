import { describe, expect, it } from 'vitest'
import { buildPoolQuery, groupMappingHistory, parseDryRun } from '../utils/ops'

describe('buildPoolQuery', () => {
  it('all tab sends no flags with defaults', () => {
    expect(buildPoolQuery({})).toEqual({ page: 1, page_size: 20 })
    expect(buildPoolQuery({ tab: 'all' })).toEqual({ page: 1, page_size: 20 })
  })
  it('orphan/unassigned tabs map to server flags', () => {
    expect(buildPoolQuery({ tab: 'orphan' })).toEqual({ orphan: 'true', page: 1, page_size: 20 })
    expect(buildPoolQuery({ tab: 'unassigned', state: '待复测', page: 2 })).toEqual({
      unassigned: 'true',
      state: '待复测',
      page: 2,
      page_size: 20,
    })
  })
  it('overdue tab has no server flag (client SLA filter)', () => {
    expect(buildPoolQuery({ tab: 'overdue' })).toEqual({ page: 1, page_size: 20 })
  })
  it('severity and q pass through trimmed, blanks dropped', () => {
    expect(buildPoolQuery({ severity: '高', q: ' 10.9.0.1 ' })).toEqual({
      severity: '高',
      q: '10.9.0.1',
      page: 1,
      page_size: 20,
    })
    expect(buildPoolQuery({ severity: '', q: '   ' })).toEqual({ page: 1, page_size: 20 })
  })
  it('severity array joins with comma, empties dropped', () => {
    expect(buildPoolQuery({ severity: ['高', '中'] })).toEqual({
      severity: '高,中',
      page: 1,
      page_size: 20,
    })
    expect(buildPoolQuery({ severity: [] })).toEqual({ page: 1, page_size: 20 })
  })
  it('dept cascade maps to dept_prefix/dept', () => {
    expect(buildPoolQuery({ dept_prefix: '研发中心' })).toEqual({
      dept_prefix: '研发中心',
      page: 1,
      page_size: 20,
    })
    expect(buildPoolQuery({ dept_prefix: '研发中心', dept: '研发中心/一组' })).toEqual({
      dept: '研发中心/一组',
      dept_prefix: '研发中心',
      page: 1,
      page_size: 20,
    })
  })
  it('clamps page_size to 100', () => {
    expect(buildPoolQuery({ page_size: 500 }).page_size).toBe(100)
  })
})

describe('parseDryRun', () => {
  it('passes backend counts through verbatim', () => {
    const raw = {
      new: 5,
      still_open: 3,
      fixed_unverified: 2,
      reopened: 1,
      errors: [{ row: 7, message: 'bad xml' }],
      skipped: false,
      file_hash: 'abc123',
    }
    expect(parseDryRun(raw)).toEqual(raw)
  })
  it('defaults missing fields without recompute', () => {
    expect(parseDryRun({})).toEqual({
      new: 0,
      still_open: 0,
      fixed_unverified: 0,
      reopened: 0,
      errors: [],
      skipped: false,
      file_hash: '',
    })
  })
  it('non-array errors coerces to []', () => {
    expect(parseDryRun({ errors: 'oops' }).errors).toEqual([])
  })
})

describe('groupMappingHistory', () => {
  it('groups periods by owner, marks current', () => {
    const groups = groupMappingHistory([
      { wecom_userid: 'u1', username: 'alice', valid_from: '2026-08-01', valid_to: null },
      { wecom_userid: 'u1', username: 'alice', valid_from: '2026-06-01', valid_to: '2026-08-01' },
      { wecom_userid: 'u2', username: 'bob', valid_from: '2026-01-01', valid_to: '2026-06-01' },
    ])
    expect(groups).toHaveLength(2)
    expect(groups[0].key).toBe('u1')
    expect(groups[0].periods).toHaveLength(2)
    expect(groups[0].current).toBe(true)
    expect(groups[1].current).toBe(false)
  })
  it('empty history -> []', () => {
    expect(groupMappingHistory([])).toEqual([])
  })
})
