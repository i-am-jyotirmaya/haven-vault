import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  records: new Map<string, unknown>(),
  get: vi.fn(), write: vi.fn(),
  appCheck: false,
}));
vi.mock('firebase-admin/app', () => ({ initializeApp: vi.fn() }));
vi.mock('firebase-admin/auth', () => ({ getAuth: vi.fn() }));
vi.mock('firebase-admin/firestore', () => ({
  Timestamp: { now: vi.fn(), fromMillis: vi.fn() },
  getFirestore: () => ({
    doc: (path: string) => path,
    collection: (path: string) => ({ doc: (id: string) => `${path}/${id}` }),
    runTransaction: (run: (tx: unknown) => unknown) => run({ get: mocks.get, set: mocks.write, update: mocks.write, delete: mocks.write }),
  }),
}));
vi.mock('firebase-functions/params', () => ({
  defineString: () => ({ value: () => '' }),
  defineBoolean: () => ({ value: () => mocks.appCheck }),
}));
vi.mock('firebase-functions/v2/https', async importOriginal => ({
  ...await importOriginal<typeof import('firebase-functions/v2/https')>(),
  onCall: (_options: unknown, handler: unknown) => handler,
}));
import { validateVaultSession } from '../src/index';
const validate = validateVaultSession as unknown as (request: unknown) => Promise<{ serverNowMs: number; expiresAtMs: number }>;
const id = 'A'.repeat(43);
const request = { auth: { uid: 'owner', token: { vaultAccess: true, vaultSession: id } } };

beforeEach(() => {
  vi.clearAllMocks();
  mocks.appCheck = false;
  mocks.records.clear();
  mocks.records.set('_vaultAuth/owner', { uid: 'owner' });
  mocks.records.set(`_vaultSessions/${id}`, { uid: 'owner', revoked: false, expiresAt: { toMillis: () => Date.now() + 900_000 } });
  mocks.get.mockImplementation(async (path: string) => ({ data: () => mocks.records.get(path) }));
});

describe('authoritative vault session validation callable', () => {
  it('returns only enforced expiry and server time, without writes or renewal', async () => {
    const result = await validate(request);
    expect(Object.keys(result).sort()).toEqual(['expiresAtMs', 'serverNowMs']);
    expect(result.expiresAtMs - result.serverNowMs).toBeGreaterThanOrEqual(899_990);
    expect(mocks.get).toHaveBeenCalledWith('_vaultAuth/owner');
    expect(mocks.get).toHaveBeenCalledWith(`_vaultSessions/${id}`);
    expect(mocks.write).not.toHaveBeenCalled();
  });
  it.each([
    undefined,
    { auth: { uid: 'owner', token: {} } },
    { auth: { uid: 'owner', token: { firebase: { sign_in_provider: 'google.com' } } } },
    { auth: { uid: 'owner', token: { vaultAccess: true, vaultSession: 'invalid' } } },
  ])('rejects anonymous, Google-only and malformed session claims', async input => {
    await expect(validate(input || {})).rejects.toMatchObject({ code: 'unauthenticated' });
  });
  it.each(['missing', 'revoked', 'expired', 'different-session-owner', 'different-vault-owner'])('rejects %s authority', async condition => {
    const session = { uid: 'owner', revoked: false, expiresAt: { toMillis: () => Date.now() + 900_000 } };
    if (condition === 'missing') mocks.records.delete(`_vaultSessions/${id}`);
    if (condition === 'revoked') mocks.records.set(`_vaultSessions/${id}`, { ...session, revoked: true });
    if (condition === 'expired') mocks.records.set(`_vaultSessions/${id}`, { ...session, expiresAt: { toMillis: () => Date.now() } });
    if (condition === 'different-session-owner') mocks.records.set(`_vaultSessions/${id}`, { ...session, uid: 'attacker' });
    if (condition === 'different-vault-owner') mocks.records.set('_vaultAuth/owner', { uid: 'attacker' });
    await expect(validate(request)).rejects.toMatchObject({ code: 'permission-denied' });
    expect(mocks.write).not.toHaveBeenCalled();
  });
  it('preserves configured App Check enforcement', async () => {
    mocks.appCheck = true;
    await expect(validate(request)).rejects.toMatchObject({ code: 'unauthenticated' });
    expect(mocks.get).not.toHaveBeenCalled();
  });
});
