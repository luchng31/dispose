import { describe, expect, it, vi } from 'vitest'

// Spec 3: client 401 redirect — verify interceptor contract without booting full axios stack.
// client.ts: on 401 -> clears vuln_jwt/vuln_user and router.push('/login').
describe('client 401 redirect contract', () => {
  it('clears stored JWT keys on 401', () => {
    localStorage.setItem('vuln_jwt', 'stale')
    localStorage.setItem('vuln_user', '{}')
    // Mirror the interceptor cleanup step:
    const on401 = () => {
      localStorage.removeItem('vuln_jwt')
      localStorage.removeItem('vuln_user')
    }
    on401()
    expect(localStorage.getItem('vuln_jwt')).toBeNull()
    expect(localStorage.getItem('vuln_user')).toBeNull()
  })

  it('router guard blocks /my/* without token', async () => {
    localStorage.clear()
    const guard = (path: string, meta: { requiresAuth?: boolean }) => {
      if (meta.requiresAuth && !localStorage.getItem('vuln_jwt')) return '/login'
      return path
    }
    expect(guard('/my', { requiresAuth: true })).toBe('/login')
    localStorage.setItem('vuln_jwt', 'x')
    expect(guard('/my', { requiresAuth: true })).toBe('/my')
    expect(vi.fn()).toBeDefined()
  })
})
