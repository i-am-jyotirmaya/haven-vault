import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createHash } from 'node:crypto'

const mocks = vi.hoisted(() => ({
  records: new Map<string, Record<string, any>>(),
  minutes: '60', sign: vi.fn(),
}))
vi.mock('firebase-admin/app', () => ({ initializeApp: vi.fn() }))
vi.mock('firebase-admin/auth', () => ({ getAuth: () => ({ createCustomToken: mocks.sign }) }))
vi.mock('firebase-admin/firestore', () => {
  const snapshot = (path: string) => ({ data: () => mocks.records.get(path) })
  const ref = (path: string) => ({
    path, get: async () => snapshot(path),
    create: async (data: Record<string, unknown>) => { mocks.records.set(path, data) },
    delete: async () => { mocks.records.delete(path) },
  })
  return {
    Timestamp: { now: () => ({ toMillis: () => Date.now() }), fromMillis: (ms: number) => ({ toMillis: () => ms }) },
    getFirestore: () => ({
      doc: ref, collection: (path: string) => ({ doc: (id: string) => ref(`${path}/${id}`) }),
      runTransaction: (fn: (tx: unknown) => unknown) => fn({
        get: async (r: { path: string }) => snapshot(r.path),
        set: (r: { path: string }, data: Record<string, unknown>) => mocks.records.set(r.path, data),
        update: (r: { path: string }, data: Record<string, unknown>) => mocks.records.set(r.path, { ...mocks.records.get(r.path), ...data }),
        delete: (r: { path: string }) => mocks.records.delete(r.path),
      }),
    }),
  }
})
vi.mock('firebase-functions/params', () => ({
  defineString: (name: string) => ({ value: () => name === 'AUTH_SESSION_MINUTES' ? mocks.minutes : ({ OWNER_EMAIL: 'owner@example.com', RP_ID: 'localhost', EXPECTED_ORIGIN: 'http://localhost:5173' }[name]) }),
  defineBoolean: () => ({ value: () => false }),
}))
vi.mock('firebase-functions/v2/https', async original => ({
  ...await original<typeof import('firebase-functions/v2/https')>(),
  onCall: (_options: unknown, handler: unknown) => handler,
}))
vi.mock('@simplewebauthn/server', () => ({
  generateAuthenticationOptions: vi.fn(), generateRegistrationOptions: vi.fn(), verifyRegistrationResponse: vi.fn(),
  verifyAuthenticationResponse: async () => ({ verified: true, authenticationInfo: { newCounter: 1 } }),
}))
import { verifyAuthentication, validateVaultSession } from '../src/index'
const verify = verifyAuthentication as unknown as (req: unknown) => Promise<{ token: string; expiresAtMs: number; serverNowMs: number; sessionDurationMinutes: number }>
const validate = validateVaultSession as unknown as (req: unknown) => Promise<Record<string, number>>
const challengeId = 'C'.repeat(43)
const request = { rawRequest: { ip: '127.0.0.1' }, data: { challengeId, response: { id: 'credential', response: { userHandle: 'owner-handle' } } } }
beforeEach(() => {
  vi.useFakeTimers(); vi.setSystemTime(1_700_000_000_000)
  vi.clearAllMocks(); mocks.records.clear(); mocks.minutes = '60'; mocks.sign.mockResolvedValue('token')
  mocks.records.set('_vaultAuth/owner', { uid: 'owner', credentialIds: ['credential'] })
  mocks.records.set(`_vaultChallenges/${challengeId}`, { purpose: 'authentication', challenge: 'challenge', uid: 'owner', webAuthnUserID: 'owner-handle', expiresAt: { toMillis: () => Date.now() + 60_000 } })
  mocks.records.set(`_vaultCredentials/${createHash('sha256').update('credential').digest('hex')}`, {
    uid: 'owner', id: 'credential', webAuthnUserID: 'owner-handle', counter: 0, publicKey: 'AA', transports: [],
  })
})
afterEach(() => vi.useRealTimers())

describe('server-controlled session issuance', () => {
  it.each(['15', '30', '60'])('persists the original %s-minute expiry and returns authoritative metadata', async minutes => {
    mocks.minutes = minutes; const start = Date.now()
    const result = await verify(request)
    expect(result).toMatchObject({ token: 'token', expiresAtMs: start + Number(minutes) * 60_000, serverNowMs: start, sessionDurationMinutes: Number(minutes) })
    const [path, record] = [...mocks.records].find(([path]) => path.startsWith('_vaultSessions/'))!
    expect(record.expiresAt.toMillis()).toBe(result.expiresAtMs)
    expect(record.sessionDurationMinutes).toBe(Number(minutes))
    expect(mocks.sign).toHaveBeenCalledWith('owner', { vaultAccess: true, vaultSession: path.split('/')[1] })
    mocks.minutes = '60'; vi.advanceTimersByTime(60_000)
    const auth = { auth: { uid: 'owner', token: { vaultAccess: true, vaultSession: path.split('/')[1], iat: Date.now() / 1000, exp: Date.now() / 1000 + 3600 } } }
    expect((await validate(auth)).expiresAtMs).toBe(result.expiresAtMs)
    expect(record.expiresAt.toMillis()).toBe(result.expiresAtMs)
    vi.setSystemTime(result.expiresAtMs)
    // Simulate a freshly refreshed Firebase token after the private record expires.
    auth.auth.token.iat = Date.now() / 1000; auth.auth.token.exp = Date.now() / 1000 + 3600
    await expect(validate(auth)).rejects.toMatchObject({ code: 'permission-denied' })
  })
  it.each(['', '0', '90', 'Infinity', '15.0'])('invalid config %j rejects before issuing any session', async minutes => {
    mocks.minutes = minutes
    await expect(verify(request)).rejects.toMatchObject({ code: 'failed-precondition' })
    expect([...mocks.records.keys()].some(path => path.startsWith('_vaultSessions/'))).toBe(false)
    expect(mocks.sign).not.toHaveBeenCalled()
  })
})
