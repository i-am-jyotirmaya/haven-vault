import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => {
  const user = {
    uid: 'owner',
    getIdTokenResult: async () => ({ claims: { vaultAccess: true, vaultSession: 'A'.repeat(43) } }),
  };
  return {
    user, auth: { currentUser: null as null | typeof user },
    initializeAuth: vi.fn(),
    connectAuth: vi.fn(), connectFirestore: vi.fn(), connectFunctions: vi.fn(), connectStorage: vi.fn(),
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
  connectAuthEmulator: mocks.connectAuth,
  signInWithCustomToken: mocks.signIn,
  signOut: mocks.signOut,
  signInWithPopup: mocks.popup,
}));
vi.mock('firebase/firestore', () => ({ getFirestore: () => ({}), connectFirestoreEmulator: mocks.connectFirestore }));
vi.mock('firebase/storage', () => ({ getStorage: () => ({}), connectStorageEmulator: mocks.connectStorage }));
vi.mock('firebase/functions', () => ({
  getFunctions: () => ({}),
  connectFunctionsEmulator: mocks.connectFunctions,
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
    if (name === 'verifyAuthentication' || name === 'verifyRegistration') return { data: { token: 'server-token', serverNowMs: Date.now(), expiresAtMs: Date.now() + 900_000 } };
    if (name === 'validateVaultSession') return { data: { serverNowMs: Date.now(), expiresAtMs: Date.now() + 15 * 60_000 } };
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

  it('does not finish sign-in after signing out during a passkey prompt', async () => {
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

  it('clears a token that arrives after signing out and prevents overlapping sign-ins', async () => {
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
  it('takes a conservative deadline from the server record and never extends it on validation', async () => {
    let now = 10_000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    const session = await import('./firebase');
    await session.signInWithPasskey();
    const original = session.getVaultSessionDeadline();
    now += 200_000;
    await session.validateVaultSession();
    expect(session.getVaultSessionDeadline()).toBe(original);
    // The server's clock can differ; use its remaining lifetime, not an
    // absolute timestamp compared with the client's wall clock.
    mocks.call.mockResolvedValueOnce({ data: { serverNowMs: 5_000_000, expiresAtMs: 5_100_000 } });
    await session.validateVaultSession();
    expect(session.getVaultSessionDeadline()).toBe(now + 85_000);
    await session.validateVaultSession();
    expect(session.getVaultSessionDeadline()).toBe(now + 85_000);
  });

  it('does not give token-exchange latency a fresh full session window', async () => {
    let now = 10_000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    mocks.signIn.mockImplementation(async () => {
      now += 300_000; mocks.auth.currentUser = mocks.user; return { user: mocks.user };
    });
    const session = await import('./firebase');
    await session.signInWithPasskey();
    expect(session.getVaultSessionDeadline()).toBe(10_000 + session.VAULT_SESSION_DURATION_MS);
  });

  it('clears usable local authorization on confirmed server revocation, but not network errors', async () => {
    const session = await import('./firebase');
    await session.signInWithPasskey();
    mocks.call.mockRejectedValueOnce(Object.assign(new Error('offline'), { code: 'functions/unavailable' }));
    await expect(session.validateVaultSession()).rejects.toThrow('offline');
    expect(session.getVaultUserId()).toBe('owner');
    mocks.call.mockRejectedValueOnce(Object.assign(new Error('revoked'), { code: 'functions/permission-denied' }));
    await expect(session.validateVaultSession()).rejects.toThrow('revoked');
    expect(() => session.getVaultUserId()).toThrow('ended');
  });

  it('reports failed remote revocation after clearing local authorization and Firebase', async () => {
    const session = await import('./firebase');
    await session.signInWithPasskey();
    mocks.call.mockRejectedValueOnce(new Error('offline'));
    const pending = session.signOutVault();
    expect(() => session.getVaultUserId()).toThrow('ended');
    await expect(pending).resolves.toEqual({ revoked: false });
    expect(mocks.auth.currentUser).toBeNull();
  });

  it('does not accept session validation that finishes after sign-out', async () => {
    const session = await import('./firebase');
    await session.signInWithPasskey();
    let finish!: (value: unknown) => void;
    mocks.call.mockReturnValueOnce(new Promise(resolve => { finish = resolve; }));
    const pending = session.validateVaultSession();
    const rejected = expect(pending).rejects.toThrow('cancelled');
    await session.signOutVault();
    finish({ data: { serverNowMs: Date.now(), expiresAtMs: Date.now() + 900_000 } });
    await rejected;
    expect(() => session.getVaultUserId()).toThrow('ended');
  });

});


describe('emulator isolation', () => {
  it('connects every service locally even with production browser configuration present', async () => {
    vi.stubEnv('MODE', 'emulator');
    vi.stubEnv('DEV', true);
    vi.stubGlobal('window', { location: { hostname: 'localhost' } });
    const session = await import('./firebase');
    expect(session.isVaultBackendReady).toBe(true);
    expect(mocks.connectAuth).toHaveBeenCalledWith(mocks.auth, 'http://127.0.0.1:9099');
    expect(mocks.connectFirestore).toHaveBeenCalledWith(expect.anything(), '127.0.0.1', 18080);
    expect(mocks.connectStorage).toHaveBeenCalledWith(expect.anything(), '127.0.0.1', 19199);
    expect(mocks.connectFunctions).toHaveBeenCalledWith(expect.anything(), '127.0.0.1', 5001);
    await session.signInWithPasskey();
    expect(session.getVaultUserId()).toBe('owner');
  });

  it('leaves production services untouched in normal mode', async () => {
    await import('./firebase');
    for (const mock of [mocks.connectAuth, mocks.connectFirestore, mocks.connectStorage, mocks.connectFunctions]) expect(mock).not.toHaveBeenCalled();
  });

  it('refuses emulator mode on a deployed origin or in a production build', async () => {
    vi.stubEnv('MODE', 'emulator');
    vi.stubEnv('DEV', true);
    vi.stubGlobal('window', { location: { hostname: 'example.web.app' } });
    await expect(import('./firebase')).rejects.toThrow('local development');
    vi.resetModules();
    vi.stubEnv('DEV', false);
    vi.stubGlobal('window', { location: { hostname: 'localhost' } });
    await expect(import('./firebase')).rejects.toThrow('local development');
    expect(mocks.initializeAuth).not.toHaveBeenCalled();
  });
});
