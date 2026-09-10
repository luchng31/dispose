import { describe, expect, it, vi } from 'vitest'
import { downloadBlob, todayStamp } from '../api/download'

describe('todayStamp', () => {
  it('formats YYYY-MM-DD', () => {
    expect(todayStamp(new Date('2026-09-09T12:00:00Z'))).toBe('2026-09-09')
  })
})

describe('downloadBlob', () => {
  it('appends anchor, clicks, cleans up', () => {
    const urls = new Map<string, string>()
    vi.stubGlobal('URL', {
      createObjectURL: vi.fn((b: Blob) => {
        const url = `blob:${(b as Blob).size}`
        urls.set(url, url)
        return url
      }),
      revokeObjectURL: vi.fn((url: string) => {
        urls.delete(url)
      }),
    })
    const clicks: string[] = []
    const origCreate = document.createElement.bind(document)
    vi.spyOn(document, 'createElement').mockImplementation(((tag: string, ...rest: unknown[]) => {
      const el = origCreate(tag as 'a', ...(rest as []))
      if (tag === 'a') {
        el.click = () => {
          clicks.push((el as HTMLAnchorElement).href)
        }
      }
      return el
    }) as typeof document.createElement)

    downloadBlob(new Blob(['a,b']), 'x.csv')

    expect(clicks).toHaveLength(1)
    expect(document.querySelector('a[download="x.csv"]')).toBeNull()
    expect(urls.size).toBe(0)
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })
})
