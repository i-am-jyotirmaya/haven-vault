import { startAuthentication, startRegistration } from '@simplewebauthn/browser'
import { callVault, acceptRecoveredSession, verifyRecoveryOwner } from './firebase'
import type { KeyRecord, RecoveryKit } from './keys'
import { signRecovery } from './keys'
export type AccessList = {
  passkeys: { id: string; label: import('./crypto').EncryptedPayload | null; createdAt: number | null; lastUsedAt: number | null; current: boolean }[]
  sessions: { id: string; current: boolean; device: string; createdAt: number; lastActivityAt: number | null; expiresAt: number }[]
}
export async function securityCall<T = { config: KeyRecord; currentRevoked?: boolean }>(action: string, fields: Record<string, unknown> = {}): Promise<T> {
  return callVault('securityOperation', { action, ...fields })
}
export async function reauthenticate() {
  const data = await callVault<{ options: Parameters<typeof startAuthentication>[0]['optionsJSON']; challengeId: string }>('authenticationOptions', { reauth: true })
  const response = await startAuthentication({ optionsJSON: data.options })
  await callVault('verifyAuthentication', { challengeId: data.challengeId, response })
}
export async function addPasskey(check: () => void) {
  await reauthenticate(); check()
  const data = await callVault<{ options: Parameters<typeof startRegistration>[0]['optionsJSON']; challengeId: string }>('registrationOptions', {})
  check()
  const response = await startRegistration({ optionsJSON: data.options }); check()
  // Enrollment normally issues a session. Keep current session and revoke the unused
  // newly issued session by using a dedicated management flag on this endpoint.
  await callVault('verifyRegistration', { challengeId: data.challengeId, response, management: true })
  check()
}
export async function beginRecovery() {
  await verifyRecoveryOwner()
  return callVault<{ options: Parameters<typeof startRegistration>[0]['optionsJSON']; challengeId: string; statement: string; record: KeyRecord }>('beginVaultRecovery', {})
}
export async function finishRecovery(data: Awaited<ReturnType<typeof beginRecovery>>, oldKit: RecoveryKit, next: RecoveryKit, check: () => void) {
  check()
  const response = await startRegistration({ optionsJSON: data.options }); check()
  const signature = await signRecovery(oldKit, data.record, data.statement, response, next.record); check()
  const result = await callVault<Parameters<typeof acceptRecoveredSession>[0]>('completeVaultRecovery', { challengeId: data.challengeId, response, signature, record: next.record }); check()
  await acceptRecoveredSession(result); check()
}
