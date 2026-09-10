import client from './client'

export interface TotpSetup {
  secret: string
  otpauth_url: string
}

/** POST /api/auth/totp/setup -> {secret, otpauth_url} (secret not persisted until confirm). */
export async function setupTotp(): Promise<TotpSetup> {
  const { data } = await client.post<TotpSetup>('/api/auth/totp/setup', {})
  return data
}

/** POST /api/auth/totp/confirm {secret, code} -> {enrolled: true}. */
export async function confirmTotp(secret: string, code: string): Promise<{ enrolled: boolean }> {
  const { data } = await client.post<{ enrolled: boolean }>('/api/auth/totp/confirm', { secret, code })
  return data
}

/** POST /api/auth/totp/disable {password} -> {enrolled: false}. */
export async function disableTotp(password: string): Promise<{ enrolled: boolean }> {
  const { data } = await client.post<{ enrolled: boolean }>('/api/auth/totp/disable', { password })
  return data
}

/** Group a base32 secret in fours for manual entry into an authenticator app. */
export function formatTotpSecret(secret: string): string {
  const clean = secret.replace(/\s+/g, '').toUpperCase()
  const groups: string[] = []
  for (let i = 0; i < clean.length; i += 4) {
    groups.push(clean.slice(i, i + 4))
  }
  return groups.join(' ')
}
