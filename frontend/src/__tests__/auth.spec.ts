import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useAuthStore } from '../stores/auth'

vi.mock('../api/tickets', async (importOriginal) => {
  const mod = await importOriginal<typeof import('../api/tickets')>()
  return {
    ...mod,
    postLocalLogin: vi.fn(),
    fetchMe: vi.fn(),
  }
})

import { fetchMe, postLocalLogin } from '../api/tickets'

describe('auth store login/logout', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
  })

  it('login stores JWT + user', async () => {
    vi.mocked(postLocalLogin).mockResolvedValue({ jwt: 'jwt-123', user: { id: 1, username: 'owner01', role: 'owner' } })
    const auth = useAuthStore()
    await auth.login('owner01', 'pw')
    expect(auth.token).toBe('jwt-123')
    expect(auth.isAuthenticated).toBe(true)
    expect(localStorage.getItem('vuln_jwt')).toBe('jwt-123')
  })

  it('logout clears JWT', async () => {
    vi.mocked(postLocalLogin).mockResolvedValue({ jwt: 'jwt-123', user: { id: 1, username: 'o', role: 'owner' } })
    const auth = useAuthStore()
    await auth.login('o', 'pw')
    auth.logout()
    expect(auth.token).toBe('')
    expect(auth.isAuthenticated).toBe(false)
    expect(localStorage.getItem('vuln_jwt')).toBeNull()
    expect(fetchMe).toBeDefined()
  })
})
