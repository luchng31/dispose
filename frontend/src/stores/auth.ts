import { defineStore } from 'pinia'
import { fetchMe, postLocalLogin, postLogout, postWecomCallback, type AuthUser } from '../api/tickets'

const JWT_KEY = 'vuln_jwt'
const REFRESH_KEY = 'vuln_refresh'
const USER_KEY = 'vuln_user'

function isJwtExpired(token: string): boolean {
  const parts = token.split('.')
  if (parts.length !== 3) return false
  try {
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')))
    if (typeof payload.exp !== 'number') return false
    return Date.now() / 1000 >= payload.exp
  } catch {
    return true
  }
}

export const useAuthStore = defineStore('auth', {
  state: () => ({
    token: localStorage.getItem(JWT_KEY) ?? '',
    refresh: localStorage.getItem(REFRESH_KEY) ?? '',
    user: null as AuthUser | null,
  }),
  getters: {
    isAuthenticated: (s) => !!s.token && !isJwtExpired(s.token),
    role: (s) => s.user?.role ?? '',
    isOperator: (s) => s.user?.role === 'operator' || s.user?.role === 'admin',
    isOwner: (s) => s.user?.role === 'owner',
  },
  actions: {
    hydrate() {
      const stored = localStorage.getItem(JWT_KEY) ?? ''
      if (stored && isJwtExpired(stored)) {
        localStorage.removeItem(JWT_KEY)
        localStorage.removeItem(USER_KEY)
        this.token = ''
        this.user = null
        return
      }
      this.token = stored
      this.refresh = localStorage.getItem(REFRESH_KEY) ?? ''
      try {
        const raw = localStorage.getItem(USER_KEY)
        this.user = raw ? (JSON.parse(raw) as AuthUser) : null
      } catch {
        this.user = null
      }
    },
    async login(username: string, password: string, totp?: string) {
      const data = await postLocalLogin({ username, password, totp: totp || undefined })
      this.token = data.jwt
      this.user = data.user
      localStorage.setItem(JWT_KEY, data.jwt)
      localStorage.setItem(USER_KEY, JSON.stringify(data.user))
      if (data.refresh_token) {
        this.refresh = data.refresh_token
        localStorage.setItem(REFRESH_KEY, data.refresh_token)
      }
      return data.user
    },
    async loginWecom(code: string) {
      const data = await postWecomCallback(code)
      this.token = data.jwt
      this.user = data.user
      localStorage.setItem(JWT_KEY, data.jwt)
      localStorage.setItem(USER_KEY, JSON.stringify(data.user))
      if (data.refresh_token) {
        this.refresh = data.refresh_token
        localStorage.setItem(REFRESH_KEY, data.refresh_token)
      }
      return data.user
    },
    async refreshMe() {
      if (!this.token) return null
      const me = await fetchMe()
      this.user = me
      localStorage.setItem(USER_KEY, JSON.stringify(me))
      return me
    },
    logout() {
      const staleRefresh = this.refresh || localStorage.getItem(REFRESH_KEY) || ''
      this.token = ''
      this.refresh = ''
      this.user = null
      localStorage.removeItem(JWT_KEY)
      localStorage.removeItem(REFRESH_KEY)
      localStorage.removeItem(USER_KEY)
      if (staleRefresh) {
        void postLogout(staleRefresh)
      }
    },
  },
})
