import axios, { type AxiosError, type InternalAxiosRequestConfig } from 'axios'
import router from '../router'

const baseURL = import.meta.env.VITE_API_BASE ?? 'http://localhost:8000'
const REFRESH_KEY = 'vuln_refresh'

export const client = axios.create({ baseURL, timeout: 15000 })

type RetryableConfig = InternalAxiosRequestConfig & { _retry?: boolean }

/** Single-flight access renewal: concurrent 401s share one refresh call. */
let refreshing: Promise<string | null> | null = null

function refreshAccessToken(): Promise<string | null> {
  if (!refreshing) {
    refreshing = (async () => {
      try {
        const stale = localStorage.getItem(REFRESH_KEY)
        if (!stale) return null
        const { data } = await axios.post<{ jwt: string; refresh_token: string }>(
          `${baseURL}/api/auth/refresh`,
          { refresh_token: stale },
          { timeout: 15000 },
        )
        localStorage.setItem('vuln_jwt', data.jwt)
        localStorage.setItem(REFRESH_KEY, data.refresh_token)
        try {
          const mod = await import('../stores/auth')
          const store = mod.useAuthStore()
          store.token = data.jwt
          store.refresh = data.refresh_token
        } catch {
          /* store not initialized yet */
        }
        return data.jwt
      } catch {
        return null
      } finally {
        refreshing = null
      }
    })()
  }
  return refreshing
}

function hardLogout() {
  localStorage.removeItem('vuln_jwt')
  localStorage.removeItem(REFRESH_KEY)
  localStorage.removeItem('vuln_user')
  void import('../stores/auth')
    .then((m) => {
      try {
        m.useAuthStore().logout()
      } catch {
        /* store not initialized yet */
      }
    })
    .catch(() => {})
  if (router.currentRoute.value.path !== '/login') {
    void router.push({ path: '/login', query: { redirect: router.currentRoute.value.fullPath } })
  }
}

client.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = localStorage.getItem('vuln_jwt')
  if (token) {
    config.headers.set('Authorization', `Bearer ${token}`)
  }
  return config
})

client.interceptors.response.use(
  (res) => res,
  async (err: AxiosError<{ detail?: string }>) => {
    const status = err.response?.status
    if (status === 401) {
      const original = err.config as RetryableConfig | undefined
      const isAuthCall = original?.url?.includes('/api/auth/refresh') ?? false
      if (original && !original._retry && !isAuthCall && localStorage.getItem(REFRESH_KEY)) {
        original._retry = true
        const renewed = await refreshAccessToken()
        if (renewed) {
          original.headers.set('Authorization', `Bearer ${renewed}`)
          return client(original)
        }
      }
      hardLogout()
    }
    // 403 friendly message: attach human-readable hint, views render err detail.
    if (status === 403 && err.response?.data) {
      const e = err as AxiosError<{ detail?: string; friendly?: string }>
      if (e.response?.data && !e.response.data.friendly) {
        e.response.data.friendly = '无权限：该操作需要更高角色（如运营），或该工单不属于你。'
      }
    }
    return Promise.reject(err)
  },
)

export default client
