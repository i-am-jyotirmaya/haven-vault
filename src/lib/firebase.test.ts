import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => {
  const user = {
    uid: 'owner',
    getIdTokenResult: async () => ({ claims: { vaultAccess: true, vaultSession: 'A'.repeat(43) } }),
  };
  return {
    user, auth: { currentUser: null as null | typeof user },
    initializeAuth: vi.fn(),
    signOut: vi.fn(),
    signIn: vi.fn(),
    authentication: vi.fn(),
    registration: vi.fn(),
    popup: vi.fn(),
    call: vi.fn(),
  };
});
vi.mock('firebase/app', () => ({ getApps: () => [], initializeApp: () => ({}) }));
vi.mock('firebase/auth', () => ({
  GoogleAuthProvider: class { setCustomParameters() {} },
  browserPopupRedirectResolver: {},
  inMemoryPersistence: { type: 'NONE' },
  initializeAuth: mocks.initializeAuth,
  signInWithCustomToken: mocks.signIn,
  signOut: mocks.signOut,
  signInWithPopup: mocks.popup,
}));
vi.mock('firebase/firestore', () => ({ getFirestore: () => ({}) }));
vi.mock('firebase/storage', () => ({ getStorage: () => ({}) }));
vi.mock('firebase/functions', () => ({
  getFunctions: () => ({}),
  httpsCallable: (_instance: unknown, name: string) => (data: unknown) => mocks.call(name, data),
}));
vi.mock('@simplewebauthn/browser', () => ({
  startAuthentication: mocks.authentication,
  startRegistration: mocks.registration,
}));

beforeEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
  vi.stubGlobal('document', { visibilityState: 'visible', hasFocus: vi.fn(() => true) });
  for (const variable of ['API_KEY', 'AUTH_DOMAIN', 'PROJECT_ID', 'STORAGE_BUCKET', 'MESSAGING_SENDER_ID', 'APP_ID']) {
    vi.stubEnv(`VITE_FIREBASE_${variable}`, 'test-project');
  }
  mocks.auth.currentUser = null;
  mocks.initializeAuth.mockImplementation(() => mocks.auth);
  mocks.authentication.mockResolvedValue({ id: 'credential' });
  mocks.registration.mockResolvedValue({ id: 'new-credential' });
  mocks.popup.mockImplementation(async () => { mocks.auth.currentUser = mocks.user; });
  mocks.signIn.mockImplementation(async () => {
    mocks.auth.currentUser = mocks.user;
    return { user: mocks.user };
  });
  mocks.signOut.mockImplementation(async () => { mocks.auth.currentUser = null; });
  mocks.call.mockImplementation(async (name: string) => {
    if (name === 'authenticationOptions' || name === 'registrationOptions') return { data: { options: {}, challengeId: 'challenge' } };
    if (name === 'verifyAuthentication' || name === 'verifyRegistration') return { data: { token: 'server-token' } };
    return { data: { ended: true } };
  });
});
afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('vault authentication lifecycle', () => {
  it('waits for a fresh click after the Google popup and starts registration synchronously from that click', async () => {
    const focused = vi.mocked(document.hasFocus);
    mocks.popup.mockImplementation(async () => {
      mocks.auth.currentUser = mocks.user;
      focused.mockReturnValue(false);
    });
    const session = await import('./firebase');
    let click: (() => void) | undefined;
    const pending = session.enrollPasskey(create => new Promise((resolve, reject) => {
      click = () => { try { resolve(create()); } catch (error) { reject(error); } };
    }));
    await vi.waitFor(() => expect(click).toBeDefined());
    expect(focused()).toBe(false);
    expect(mocks.registration).not.toHaveBeenCalled();
    expect(mocks.signIn).not.toHaveBeenCalled();
    expect(() => session.getVaultUserId()).toThrow();
    focused.mockReturnValue(true);
    click!();
    expect(mocks.registration).toHaveBeenCalledOnce();
    await pending;
    expect(mocks.call).toHaveBeenCalledWith('verifyRegistration', { challengeId: 'challenge', response: { id: 'new-credential' } });
    expect(session.getVaultUserId()).toBe('owner');
  });

  it('does not start registration in an unfocused document and clears the Google session', async () => {
    vi.mocked(document.hasFocus).mockReturnValue(false);
    const session = await import('./firebase');
    await expect(session.enrollPasskey(create => create())).rejects.toThrow('Return to the Haven tab');
    expect(mocks.registration).not.toHaveBeenCalled();
    expect(mocks.call.mock.calls.some(([name]) => name === 'verifyRegistration')).toBe(false);
    expect(mocks.auth.currentUser).toBeNull();
  });

  it('rejects a prepared registration after setup is cancelled', async () => {
    const session = await import('./firebase');
    let click: (() => void) | undefined;
    const pending = session.enrollPasskey(create => new Promise((resolve, reject) => {
      click = () => { try { resolve(create()); } catch (error) { reject(error); } };
    }));
    const rejected = expect(pending).rejects.toThrow('cancelled');
    await vi.waitFor(() => expect(click).toBeDefined());
    await session.signOutVault();
    click!();
    await rejected;
    expect(mocks.registration).not.toHaveBeenCalled();
    expect(mocks.auth.currentUser).toBeNull();
  });

  it('clears the Google session when the confirmation step expires or is dismissed', async () => {
    const session = await import('./firebase');
    await expect(session.enrollPasskey(() => Promise.reject(new Error('Setup expired')))).rejects.toThrow('expired');
    expect(mocks.registration).not.toHaveBeenCalled();
    expect(mocks.auth.currentUser).toBeNull();
  });

  it('accepts only a passkey-issued session and uses memory-only Firebase persistence', async () => {
    const session = await import('./firebase');
    expect(() => session.getVaultUserId()).toThrow();
    await session.signInWithPasskey();
    expect(session.getVaultUserId()).toBe('owner');
    expect(mocks.initializeAuth).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ persistence: { type: 'NONE' } }));
    await session.signOutVault();
    expect(mocks.call).toHaveBeenCalledWith('endVaultSession', {});
    expect(() => session.getVaultUserId()).toThrow();
    expect(mocks.auth.currentUser).toBeNull();
  });

  it('fails closed when custom-token claims do not authorize the vault', async () => {
    mocks.signIn.mockResolvedValue({ user: { uid: 'owner', getIdTokenResult: async () => ({ claims: {} }) } });
    const session = await import('./firebase');
    await expect(session.signInWithPasskey()).rejects.toThrow('did not authorize');
    expect(() => session.getVaultUserId()).toThrow();
    expect(mocks.signOut).toHaveBeenCalled();
  });

  it('does not finish sign-in after locking during a passkey prompt', async () => {
    let finish!: (value: unknown) => void;
    mocks.authentication.mockReturnValue(new Promise(resolve => { finish = resolve; }));
    const session = await import('./firebase');
    const pending = session.signInWithPasskey();
    const rejected = expect(pending).rejects.toThrow('cancelled');
    await vi.waitFor(() => expect(mocks.authentication).toHaveBeenCalled());
    await session.signOutVault();
    finish({ id: 'credential' });
    await rejected;
    expect(mocks.call.mock.calls.some(([name]) => name === 'verifyAuthentication')).toBe(false);
    expect(() => session.getVaultUserId()).toThrow();
  });

  it('clears a token that arrives after locking and prevents overlapping sign-ins', async () => {
    let finish!: () => void;
    mocks.signIn.mockImplementation(() => new Promise(resolve => {
      finish = () => { mocks.auth.currentUser = mocks.user; resolve({ user: mocks.user }); };
    }));
    const session = await import('./firebase');
    const pending = session.signInWithPasskey();
    const rejected = expect(pending).rejects.toThrow('cancelled');
    await vi.waitFor(() => expect(mocks.signIn).toHaveBeenCalled());
    await session.signOutVault();
    await expect(session.signInWithPasskey()).rejects.toThrow('still finishing');
    finish();
    await rejected;
    expect(mocks.auth.currentUser).toBeNull();
    expect(() => session.getVaultUserId()).toThrow();
  });

  it('rejects client access after the absolute session deadline', async () => {
    let now = 10_000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    const session = await import('./firebase');
    await session.signInWithPasskey();
    expect(session.getVaultUserId()).toBe('owner');
    now += session.VAULT_SESSION_DURATION_MS + 1;
    expect(() => session.getVaultUserId()).toThrow('ended');
  });

  it('clears the local account even if server revocation fails', async () => {
    const session = await import('./firebase');
    await session.signInWithPasskey();
    mocks.call.mockRejectedValue(new Error('offline'));
    await session.signOutVault();
    expect(mocks.auth.currentUser).toBeNull();
    expect(() => session.getVaultUserId()).toThrow();
  });
});
