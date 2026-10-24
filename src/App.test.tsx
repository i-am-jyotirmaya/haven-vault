// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  signIn: vi.fn(), enroll: vi.fn(), signOut: vi.fn(), validate: vi.fn(),
  getConfig: vi.fn(), unlock: vi.fn(), create: vi.fn(), saveConfig: vi.fn(),
  list: vi.fn(), download: vi.fn(), saveNote: vi.fn(),
  deadline: 0, authenticated: false,
  config: { version: 1, salt: 'fictional', iterations: 600000, verifier: {} },
  key: {} as CryptoKey,
}));
vi.mock('./lib/firebase', () => ({
  isFirebaseConfigured: true, isVaultBackendReady: true, isEmulatorMode: false,
  signInWithPasskey: mocks.signIn, enrollPasskey: mocks.enroll, signOutVault: mocks.signOut,
  validateVaultSession: mocks.validate,
  getVaultSessionDeadline: () => mocks.deadline,
  getVaultSessionLifetimeMinutes: () => 15,
  getVaultUserId: () => {
    if (!mocks.authenticated || Date.now() >= mocks.deadline) throw Object.assign(new Error('Session ended'), { code: 'unauthenticated' });
    return 'owner';
  },
  isAuthenticationFailure: (err: { code?: string }) => ['unauthenticated', 'functions/permission-denied', 'permission-denied'].includes(err?.code || ''),
}));
vi.mock('./lib/keys', async original => ({ ...await original<typeof import('./lib/keys')>(), createKeyRecord: mocks.create }));
vi.mock('./lib/crypto', () => ({ unlockVault: mocks.unlock, createVault: mocks.create }));
vi.mock('./lib/vault', () => ({
  getVaultConfig: mocks.getConfig, listVaultItems: mocks.list, downloadVaultFile: mocks.download,
  saveVaultConfig: mocks.saveConfig, saveVaultNote: mocks.saveNote,
  permanentlyDeleteVaultItem: vi.fn(), updateVaultItem: vi.fn(), uploadVaultFile: vi.fn(), MAX_FILE_SIZE: 50 * 1024 * 1024,
}));
import App from './App';

const file = { id: 'fictional-photo', name: 'private-photo.jpg', kind: 'photo', mimeType: 'image/jpeg', size: 10, createdAt: 1000, updatedAt: 1000, favorite: false, trashed: false, collection: 'Secret collection' };
const secret = 'fictional long passphrase';
const flush = async () => { await act(async () => { await Promise.resolve(); }); };
async function authenticate() {
  fireEvent.click(screen.getByRole('button', { name: 'Sign in with passkey' }));
  await flush();
  expect(screen.getByText(/Your session is still active/)).toBeTruthy();
}
async function unlock() {
  fireEvent.change(screen.getByLabelText('Your passphrase'), { target: { value: secret } });
  fireEvent.submit(screen.getByRole('button', { name: 'Unlock my vault' }).closest('form')!);
  await flush();
}
async function openVault() { render(<App />); await authenticate(); await unlock(); }
function hide() {
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
  fireEvent(document, new Event('visibilitychange'));
}
function show() {
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  fireEvent(document, new Event('visibilitychange'));
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(10_000);
  vi.clearAllMocks();
  localStorage.clear();
  mocks.authenticated = false;
  mocks.deadline = Date.now() + 885_000;
  mocks.signIn.mockImplementation(async () => { mocks.authenticated = true; });
  mocks.enroll.mockImplementation(async (confirm: (create: () => Promise<unknown>) => Promise<unknown>) => {
    await confirm(async () => ({})); mocks.authenticated = true;
  });
  mocks.signOut.mockImplementation(async () => { mocks.authenticated = false; return { revoked: true }; });
  mocks.validate.mockImplementation(async () => {
    if (!mocks.authenticated || Date.now() >= mocks.deadline) throw Object.assign(new Error('Session ended'), { code: 'unauthenticated' });
  });
  mocks.getConfig.mockResolvedValue(mocks.config);
  mocks.unlock.mockResolvedValue(mocks.key);
  mocks.create.mockResolvedValue({ key: mocks.key, config: mocks.config });
  mocks.saveConfig.mockResolvedValue(undefined);
  mocks.list.mockResolvedValue([file]);
  mocks.download.mockResolvedValue(new Blob(['private pixels'], { type: 'image/jpeg' }));
  mocks.saveNote.mockResolvedValue({ ...file, kind: 'note', name: 'Late private note', text: 'private contents' });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  HTMLDialogElement.prototype.showModal = vi.fn();
  HTMLDialogElement.prototype.close = vi.fn();
  URL.createObjectURL = vi.fn(() => 'blob:private');
  URL.revokeObjectURL = vi.fn();
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('authentication and local encryption transitions', () => {
  it.each(['functions/permission-denied', 'unauthenticated'])('preserves a sign-in rejection instead of claiming expiry (%s)', async code => {
    mocks.signIn.mockRejectedValueOnce(Object.assign(new Error('Passkey authentication could not be verified. Start again.'), { code }));
    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: 'Sign in with passkey' }));
    await flush();
    expect(screen.getByRole('alert').textContent).toContain('Passkey sign-in failed: Passkey authentication could not be verified. Start again.');
    expect(screen.getByRole('alert').textContent).toContain(code);
    expect(screen.queryByText('Your secure session ended. Sign in again.')).toBeNull();
    expect(screen.getByRole('button', { name: 'Sign in with passkey' })).toBeTruthy();
    expect(mocks.getConfig).not.toHaveBeenCalled();
    expect(mocks.authenticated).toBe(false);
    expect(mocks.signOut).toHaveBeenCalledOnce();
  });

  it('distinguishes a vault-read denial after successful passkey authentication', async () => {
    mocks.getConfig.mockRejectedValueOnce(Object.assign(new Error('Missing or insufficient permissions.'), { code: 'permission-denied' }));
    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: 'Sign in with passkey' }));
    await flush();
    expect(screen.getByRole('alert').textContent).toContain('Your passkey was accepted, but Haven could not load your vault. Missing or insufficient permissions. (permission-denied)');
    expect(screen.queryByText('Your secure session ended. Sign in again.')).toBeNull();
    expect(mocks.authenticated).toBe(false);
    expect(mocks.unlock).not.toHaveBeenCalled();
    expect(mocks.signOut).toHaveBeenCalledOnce();
    // A fresh attempt remains possible; the failure did not leave busy set.
    await authenticate();
    expect(mocks.signIn).toHaveBeenCalledTimes(2);
  });

  it('a late sign-in rejection cannot replace feedback after explicit sign-out', async () => {
    let rejectSignIn!: (error: Error) => void;
    mocks.signIn.mockReturnValueOnce(new Promise<void>((_resolve, reject) => { rejectSignIn = reject; }));
    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: 'Sign in with passkey' }));
    hide();
    fireEvent.click(screen.getByRole('button', { name: 'Sign out now' }));
    await act(async () => rejectSignIn(Object.assign(new Error('Passkey verification failed.'), { code: 'functions/permission-denied' })));
    show(); await flush();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(mocks.getConfig).not.toHaveBeenCalled();
    expect(mocks.authenticated).toBe(false);
    expect(mocks.signOut).toHaveBeenCalledOnce();
  });

  it('passkey authenticates with no decrypted content; local passphrase unlocks without another ceremony', async () => {
    render(<App />); await authenticate();
    expect(screen.queryByText(file.name)).toBeNull();
    expect(mocks.unlock).not.toHaveBeenCalled();
    await unlock();
    expect(screen.getByRole('button', { name: `Preview ${file.name}` })).toBeTruthy();
    expect(mocks.unlock).toHaveBeenCalledWith(secret, mocks.config);
    expect(mocks.signIn).toHaveBeenCalledOnce();
    expect(mocks.enroll).not.toHaveBeenCalled();
  });

  it.each(['manual', 'inactivity', 'visibility'] as const)('%s locking clears content and preserves authentication', async (trigger) => {
    await openVault();
    if (trigger === 'manual') fireEvent.click(screen.getByRole('button', { name: 'Lock vault' }));
    if (trigger === 'inactivity') act(() => vi.advanceTimersByTime(300_000));
    if (trigger === 'visibility') { hide(); act(() => vi.advanceTimersByTime(30_000)); show(); await flush(); }
    expect(screen.getByLabelText('Your passphrase')).toHaveProperty('value', '');
    expect(screen.queryByText(file.name)).toBeNull();
    expect(mocks.signOut).not.toHaveBeenCalled();
    expect(mocks.authenticated).toBe(true);

    await unlock();
    expect(screen.getByRole('button', { name: 'Lock vault' })).toBeTruthy();
    expect(mocks.signIn).toHaveBeenCalledOnce();
  });

  it('repeated lock/unlock cycles keep the original absolute deadline', async () => {
    await openVault();
    for (let count = 0; count < 3; count++) {
      act(() => vi.advanceTimersByTime(240_000));
      fireEvent.click(screen.getByRole('button', { name: 'Lock vault' }));
      await unlock();
    }
    act(() => vi.advanceTimersByTime(165_000));
    expect(screen.getByRole('button', { name: 'Sign in with passkey' })).toBeTruthy();
    expect(mocks.signIn).toHaveBeenCalledOnce();
  });

  it('backgrounding clears a passphrase draft on the authenticated lock screen', async () => {
    render(<App />); await authenticate();
    fireEvent.change(screen.getByLabelText('Your passphrase'), { target: { value: secret } });
    hide(); show(); await flush();
    expect(screen.getByLabelText('Your passphrase')).toHaveProperty('value', '');
    expect(mocks.authenticated).toBe(true);
    expect(mocks.signOut).not.toHaveBeenCalled();
  });

  it('wrong passphrase stays authenticated and locked', async () => {
    render(<App />); await authenticate();
    mocks.unlock.mockRejectedValueOnce(new Error('Incorrect passphrase'));
    await unlock();
    expect(screen.getByRole('alert').textContent).toContain('Incorrect passphrase');
    expect(screen.getByLabelText('Your passphrase')).toHaveProperty('value', '');
    expect(mocks.signOut).not.toHaveBeenCalled();
    expect(mocks.authenticated).toBe(true);
  });

  it.each(['locked', 'unlocked'])('expiry while %s ends authentication', async state => {
    render(<App />); await authenticate();
    if (state === 'unlocked') await unlock();
    // Jump to expiry without running the idle callback first.
    vi.setSystemTime(mocks.deadline);
    act(() => vi.advanceTimersByTime(885_000));
    expect(screen.getByRole('button', { name: 'Sign in with passkey' })).toBeTruthy();
    expect(screen.queryByText(file.name)).toBeNull();
    expect(mocks.signOut).toHaveBeenCalledOnce();
  });

  it('resume checks wall-clock expiry when browser timers were suspended', async () => {
    await openVault(); hide();
    vi.setSystemTime(mocks.deadline + 1);
    show(); await flush();
    expect(screen.getByRole('button', { name: 'Sign in with passkey' })).toBeTruthy();
    expect(mocks.signIn).toHaveBeenCalledOnce();
  });

  it('confirmed revocation on resume signs out; a transient network error permits retry while locked', async () => {
    await openVault(); hide();
    mocks.validate.mockRejectedValueOnce(new Error('offline'));
    show(); await flush();
    expect(screen.getByLabelText('Your passphrase')).toBeTruthy();
    expect(mocks.signOut).not.toHaveBeenCalled();
    mocks.validate.mockRejectedValueOnce(Object.assign(new Error('Revoked'), { code: 'functions/permission-denied' }));
    await unlock();
    expect(screen.getByRole('button', { name: 'Sign in with passkey' })).toBeTruthy();
    expect(screen.queryByText(file.name)).toBeNull();
  });

  it.each(['locked', 'unlocked'])('sign-out from %s clears secrets before failed remote revocation finishes', async state => {
    render(<App />); await authenticate();
    if (state === 'unlocked') await unlock();
    let finish!: (value: { revoked: boolean }) => void;
    mocks.signOut.mockReturnValueOnce(new Promise(resolve => { finish = resolve; }));
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(screen.getByRole('button', { name: 'Sign in with passkey' })).toBeTruthy();
    expect(screen.queryByText(file.name)).toBeNull();
    await act(async () => finish({ revoked: false }));
    expect(screen.getByText(/server session remains valid until/)).toBeTruthy();
  });

  it.each(['lock', 'sign-out'])('late decryption/list work cannot repopulate content after %s', async action => {
    render(<App />); await authenticate();
    let finish!: (value: unknown[]) => void;
    mocks.list.mockReturnValueOnce(new Promise(resolve => { finish = resolve; }));
    await unlock();
    if (action === 'lock') hide();
    else fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    await act(async () => finish([file]));
    expect(screen.queryByText(file.name)).toBeNull();
    expect(screen.queryByRole('button', { name: 'Lock vault' })).toBeNull();
  });

  it('locking closes a preview and synchronously revokes its plaintext URL', async () => {
    await openVault();
    fireEvent.click(screen.getByRole('button', { name: `Preview ${file.name}` }));
    await flush();
    expect(URL.createObjectURL).toHaveBeenCalledOnce();
    hide();
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:private');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(document.documentElement.dataset.havenConcealed).toBe('true');
    act(() => vi.advanceTimersByTime(30_000));
    show(); await flush();
    expect(screen.getByLabelText('Your passphrase')).toBeTruthy();
  });

  it('a pending preview cannot create an object URL after locking', async () => {
    await openVault();
    let finish!: (blob: Blob) => void;
    mocks.download.mockReturnValueOnce(new Promise(resolve => { finish = resolve; }));
    fireEvent.click(screen.getByRole('button', { name: `Preview ${file.name}` }));
    hide();
    await act(async () => finish(new Blob(['private'])));
    expect(URL.createObjectURL).not.toHaveBeenCalled();
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('locking closes note drafts and resets search and collection state', async () => {
    await openVault();
    fireEvent.change(screen.getByPlaceholderText('Find something…'), { target: { value: 'private search' } });
    fireEvent.click(screen.getByRole('button', { name: 'New note' }));
    fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'Private draft' } });
    fireEvent.change(screen.getByPlaceholderText('Some things are just for you…'), { target: { value: 'Private unsaved contents' } });
    fireEvent.keyDown(window, { key: 'L', ctrlKey: true, shiftKey: true });
    expect(screen.queryByRole('dialog')).toBeNull();
    await unlock();
    expect(screen.getByPlaceholderText('Find something…')).toHaveProperty('value', '');
    fireEvent.click(screen.getByRole('button', { name: 'New note' }));
    expect(screen.getByLabelText('Title')).toHaveProperty('value', '');
    expect(screen.getByPlaceholderText('Some things are just for you…')).toHaveProperty('value', '');
  });

  it('a note save completing after lock cannot repopulate private content', async () => {
    await openVault();
    fireEvent.click(screen.getByRole('button', { name: 'New note' }));
    fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'Late private note' } });
    let finish!: (item: unknown) => void;
    mocks.saveNote.mockReturnValueOnce(new Promise(resolve => { finish = resolve; }));
    fireEvent.submit(screen.getByLabelText('Title').closest('form')!);
    await flush(); hide(); act(() => vi.advanceTimersByTime(30_000)); show(); await flush();
    await act(async () => finish({ ...file, name: 'Late private note' }));
    expect(screen.queryByText('Late private note')).toBeNull();
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('sign-out invalidates a pending passphrase derivation', async () => {
    render(<App />); await authenticate();
    let finish!: (key: CryptoKey) => void;
    mocks.unlock.mockReturnValueOnce(new Promise(resolve => { finish = resolve; }));
    await unlock();
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    await act(async () => finish(mocks.key));
    expect(mocks.list).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Sign in with passkey' })).toBeTruthy();
  });

  it('new vault setup remains functional', async () => {
    mocks.getConfig.mockResolvedValueOnce(null).mockResolvedValueOnce(null);
    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: 'Set up my private vault' })); await flush();
    fireEvent.click(screen.getByRole('button', { name: 'Create my passkey' })); await flush();
    fireEvent.change(screen.getByLabelText('Create a passphrase'), { target: { value: secret } });
    fireEvent.change(screen.getByLabelText('Confirm passphrase'), { target: { value: secret } });
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.submit(screen.getByRole('button', { name: 'Create my vault' }).closest('form')!); await flush();
    expect(mocks.saveConfig).toHaveBeenCalledWith(mocks.config);
    expect(screen.getByRole('button', { name: 'Lock vault' })).toBeTruthy();
  });

  it('cancel enrollment cannot restore a session and demo remains separate from authentication', async () => {
    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: 'Set up my private vault' })); await flush();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel setup' })); await flush();
    expect(mocks.authenticated).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: /Take a look around the demo/ })); await flush();
    expect(screen.getByRole('button', { name: 'Lock vault' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Lock vault' }));
    expect(screen.getByRole('button', { name: 'Sign in with passkey' })).toBeTruthy();
  });
});

describe('configurable locking and privacy boundary', () => {
  const concealed = () => document.documentElement.dataset.havenConcealed === 'true';
  const security = () => {
    fireEvent.click(screen.getByRole('button', { name: /Your security/ }));
    fireEvent.click(screen.getByText('Automatic locking settings'));
  };
  it('conceals immediately, gates return on validation, and returns within grace without unlocking', async () => {
    await openVault();
    fireEvent.click(screen.getByRole('button', { name: 'New note' }));
    fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'Private draft' } });
    hide(); expect(concealed()).toBe(true);
    expect(HTMLDialogElement.prototype.close).toHaveBeenCalled();
    expect(mocks.signOut).not.toHaveBeenCalled();
    act(() => vi.advanceTimersByTime(29_999));
    let finish!: () => void;
    mocks.validate.mockReturnValueOnce(new Promise<void>(resolve => { finish = resolve; }));
    show(); expect(concealed()).toBe(true);
    await act(async () => finish());
    expect(concealed()).toBe(false);
    expect(screen.getByLabelText('Title')).toHaveProperty('value', 'Private draft');
    expect(mocks.unlock).toHaveBeenCalledOnce();
    expect(mocks.signIn).toHaveBeenCalledOnce();
  });
  it('return after grace clears drafts and requires only passphrase', async () => {
    await openVault(); hide();
    vi.setSystemTime(Date.now() + 30_000); // Sleeping tab: no timer callbacks.
    show(); await flush();
    expect(concealed()).toBe(false);
    expect(screen.queryByText(file.name)).toBeNull();
    expect(screen.getByLabelText('Your passphrase')).toBeTruthy();
    await unlock();
    expect(mocks.unlock).toHaveBeenCalledTimes(2);
    expect(mocks.signIn).toHaveBeenCalledOnce();
  });
  it('immediate-lock mode clears keys at hide, before any timer', async () => {
    localStorage.setItem('haven.security.v1', JSON.stringify({ backgroundSeconds: 0, inactivityMinutes: 5 }));
    await openVault(); hide();
    expect(concealed()).toBe(true);
    expect(screen.queryByText(file.name)).toBeNull();
    expect(screen.getByLabelText('Your passphrase')).toBeTruthy();
    expect(mocks.signOut).not.toHaveBeenCalled();
    show(); await flush();
    expect(screen.queryByText(file.name)).toBeNull();
  });
  it.each([1, 5, 15])('locks after the configured %s minutes of inactivity', async minutes => {
    mocks.deadline = Date.now() + 3_600_000;
    localStorage.setItem('haven.security.v1', JSON.stringify({ backgroundSeconds: 30, inactivityMinutes: minutes }));
    await openVault();
    act(() => vi.advanceTimersByTime(minutes * 60_000 - 1));
    expect(screen.getByRole('button', { name: 'Lock vault' })).toBeTruthy();
    act(() => vi.advanceTimersByTime(1));
    expect(screen.getByLabelText('Your passphrase')).toBeTruthy();
    expect(mocks.signOut).not.toHaveBeenCalled();
  });
  it.each(['keydown', 'pointerdown', 'pointermove', 'touchstart', 'touchmove', 'wheel'])('%s activity resets inactivity without extending authentication', async type => {
    const listener = vi.spyOn(window, 'addEventListener');
    await openVault();
    act(() => vi.advanceTimersByTime(240_000));
    const callback = listener.mock.calls.find(([name]) => name === type)![1] as EventListener;
    act(() => callback({ isTrusted: true } as Event));
    act(() => vi.advanceTimersByTime(240_000));
    expect(screen.getByRole('button', { name: 'Lock vault' })).toBeTruthy();
    act(() => vi.advanceTimersByTime(60_000));
    expect(screen.getByLabelText('Your passphrase')).toBeTruthy();
    act(() => vi.advanceTimersByTime(mocks.deadline - Date.now()));
    expect(screen.getByRole('button', { name: 'Sign in with passkey' })).toBeTruthy();
  });
  it('network completion and synthetic events do not count as activity', async () => {
    await openVault();
    act(() => vi.advanceTimersByTime(240_000));
    fireEvent.pointerMove(window); fireEvent.wheel(window); await mocks.validate();
    act(() => vi.advanceTimersByTime(60_000));
    expect(screen.getByLabelText('Your passphrase')).toBeTruthy();
  });
  it.each(['focus', 'pageshow', 'resume'])('%s enforces suspended inactivity before revealing', async type => {
    await openVault();
    vi.setSystemTime(Date.now() + 300_000);
    fireEvent(type === 'resume' ? document : window, new Event(type));
    expect(screen.queryByText(file.name)).toBeNull();
    await flush();
    expect(screen.getByLabelText('Your passphrase')).toBeTruthy();
  });
  it('repeated hidden lifecycle events never restart grace', async () => {
    await openVault(); hide(); act(() => vi.advanceTimersByTime(20_000));
    fireEvent(window, new Event('pagehide')); fireEvent(document, new Event('freeze'));
    act(() => vi.advanceTimersByTime(10_000)); show(); await flush();
    expect(screen.getByLabelText('Your passphrase')).toBeTruthy();
  });
  it('authentication expires while hidden even after the vault has locked', async () => {
    await openVault(); hide();
    act(() => vi.advanceTimersByTime(30_000));
    expect(mocks.signOut).not.toHaveBeenCalled();
    act(() => vi.advanceTimersByTime(mocks.deadline - Date.now()));
    expect(mocks.signOut).toHaveBeenCalledOnce();
    expect(concealed()).toBe(true);
    show(); await flush();
    expect(screen.getByRole('button', { name: 'Sign in with passkey' })).toBeTruthy();
  });
  it('expiry during return validation cannot flash or restore content', async () => {
    mocks.deadline = Date.now() + 20_000;
    await openVault(); hide();
    let finish!: () => void;
    mocks.validate.mockReturnValueOnce(new Promise<void>(resolve => { finish = resolve; }));
    show(); expect(concealed()).toBe(true);
    vi.setSystemTime(mocks.deadline);
    await act(async () => finish());
    expect(concealed()).toBe(false);
    expect(screen.queryByText(file.name)).toBeNull();
    expect(screen.getByRole('button', { name: 'Sign in with passkey' })).toBeTruthy();
  });
  it('shortening inactivity and restoring defaults apply time already elapsed', async () => {
    await openVault(); security();
    act(() => vi.advanceTimersByTime(120_000));
    fireEvent.change(screen.getByLabelText('Lock after inactivity'), { target: { value: '1' } });
    expect(screen.getByLabelText('Your passphrase')).toBeTruthy();
    expect(JSON.parse(localStorage.getItem('haven.security.v1')!)).toEqual({ backgroundSeconds: 30, inactivityMinutes: 1 });
    fireEvent.click(screen.getByText('Automatic locking settings'));
    fireEvent.click(screen.getByRole('button', { name: 'Restore defaults' }));
    expect(JSON.parse(localStorage.getItem('haven.security.v1')!)).toEqual({ backgroundSeconds: 30, inactivityMinutes: 5 });
  });
  it('warns before expiry while locked without claiming unfinished work is saved', async () => {
    render(<App />); await authenticate();
    act(() => vi.advanceTimersByTime(825_000));
    expect(screen.getByRole('alert').textContent).toContain('Completed uploads remain saved. Unfinished uploads and unsaved edits may be lost.');
    expect(mocks.signIn).toHaveBeenCalledOnce();
    expect(mocks.signOut).not.toHaveBeenCalled();
  });
  it('backgrounding enrollment does not cancel its passkey ceremony', async () => {
    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: 'Set up my private vault' })); await flush();
    hide(); show(); await flush();
    fireEvent.click(screen.getByRole('button', { name: 'Create my passkey' })); await flush();
    expect(mocks.enroll).toHaveBeenCalledOnce();
    expect(mocks.signOut).not.toHaveBeenCalled();
    expect(screen.getByLabelText('Your passphrase')).toBeTruthy();
  });
  it('reload/unmount never restores keys; only non-sensitive preferences survive', async () => {
    await openVault(); cleanup();
    render(<App />);
    expect(screen.getByRole('button', { name: 'Sign in with passkey' })).toBeTruthy();
    expect(screen.queryByText(file.name)).toBeNull();
    expect(localStorage.length).toBe(0);
  });
});

describe('deadline races', () => {
  it('background grace includes time spent validating on return', async () => {
    await openVault(); hide();
    act(() => vi.advanceTimersByTime(29_000));
    let finish!: () => void;
    mocks.validate.mockReturnValueOnce(new Promise<void>(resolve => { finish = resolve; }));
    show();
    vi.setSystemTime(Date.now() + 2000);
    await act(async () => finish());
    expect(document.documentElement.dataset.havenConcealed).toBeUndefined();
    expect(screen.getByLabelText('Your passphrase')).toBeTruthy();
    expect(screen.queryByText(file.name)).toBeNull();
  });
  it('manual lock during return validation cannot be undone by its late success', async () => {
    await openVault(); hide();
    let finish!: () => void;
    mocks.validate.mockReturnValueOnce(new Promise<void>(resolve => { finish = resolve; }));
    show(); fireEvent.keyDown(window, { key: 'L', ctrlKey: true, shiftKey: true });
    await act(async () => finish());
    expect(screen.getByLabelText('Your passphrase')).toBeTruthy();
    expect(screen.queryByText(file.name)).toBeNull();
    expect(mocks.unlock).toHaveBeenCalledOnce();
  });
  it('a preview completing after suspended inactivity clears content before creating plaintext URLs', async () => {
    await openVault();
    let finish!: (value: Blob) => void;
    mocks.download.mockReturnValueOnce(new Promise(resolve => { finish = resolve; }));
    fireEvent.click(screen.getByRole('button', { name: `Preview ${file.name}` }));
    vi.setSystemTime(Date.now() + 300_000);
    await act(async () => finish(new Blob(['private'])));
    expect(URL.createObjectURL).not.toHaveBeenCalled();
    expect(screen.getByLabelText('Your passphrase')).toBeTruthy();
  });
  it('expired access cannot start new work from an old event handler', async () => {
    await openVault();
    fireEvent.click(screen.getByRole('button', { name: 'New note' }));
    fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'No longer authorized' } });
    const form = screen.getByLabelText('Title').closest('form')!;
    vi.setSystemTime(Date.now() + 300_000);
    fireEvent.submit(form); await flush();
    expect(mocks.saveNote).not.toHaveBeenCalled();
    expect(screen.getByLabelText('Your passphrase')).toBeTruthy();
  });
  it('an async save completed during grace stays concealed and cannot unlock a locked vault', async () => {
    await openVault();
    fireEvent.click(screen.getByRole('button', { name: 'New note' }));
    fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'Saved in background' } });
    let finish!: (value: unknown) => void;
    mocks.saveNote.mockReturnValueOnce(new Promise(resolve => { finish = resolve; }));
    fireEvent.submit(screen.getByLabelText('Title').closest('form')!);
    hide(); await act(async () => finish({ ...file, id: 'background-note', name: 'Saved in background' }));
    expect(document.documentElement.dataset.havenConcealed).toBe('true');
    act(() => vi.advanceTimersByTime(30_000)); show(); await flush();
    expect(screen.queryByText('Saved in background')).toBeNull();
    expect(screen.getByLabelText('Your passphrase')).toBeTruthy();
  });
});

it('privacy-screen lock and sign-out controls remain available during return validation', async () => {
  await openVault(); hide();
  let finish!: () => void;
  mocks.validate.mockReturnValueOnce(new Promise<void>(resolve => { finish = resolve; }));
  show();
  fireEvent.click(screen.getByRole('button', { name: 'Lock now' }));
  expect(screen.queryByText(file.name)).toBeNull();
  expect(mocks.signOut).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Sign out now' }));
  await act(async () => finish());
  expect(screen.getByRole('button', { name: 'Sign in with passkey' })).toBeTruthy();
  expect(mocks.signOut).toHaveBeenCalledOnce();
});

it('unmount cleans lifecycle listeners and scheduled deadline timers', async () => {
  const remove = vi.spyOn(window, 'removeEventListener');
  await openVault(); cleanup();
  // jsdom queues a zero-delay selectionchange when passphrase fields clear.
  act(() => vi.advanceTimersByTime(0));
  expect(vi.getTimerCount()).toBe(0);
  for (const name of ['focus', 'pagehide', 'pageshow', 'keydown', 'pointerdown', 'touchstart', 'wheel']) {
    expect(remove.mock.calls.some(([event]) => event === name)).toBe(true);
  }
  fireEvent(window, new Event('focus'));
  expect(mocks.signOut).not.toHaveBeenCalled();
});

it('trusted interaction inside timeout controls cannot restart elapsed inactivity before shortening it', async () => {
  const listener = vi.spyOn(window, 'addEventListener');
  await openVault();
  fireEvent.click(screen.getByRole('button', { name: /Your security/ }));
  fireEvent.click(screen.getByText('Automatic locking settings'));
  const control = screen.getByLabelText('Lock after inactivity');
  act(() => vi.advanceTimersByTime(120_000));
  const pointer = listener.mock.calls.find(([name]) => name === 'pointerdown')![1] as EventListener;
  act(() => pointer({ isTrusted: true, target: control } as unknown as Event));
  fireEvent.change(control, { target: { value: '1' } });
  expect(screen.getByLabelText('Your passphrase')).toBeTruthy();
});


it('applies configured locking to recovery secrets before authentication and clears them on manual sign-out', async () => {
  render(<App />)
  const details = screen.getByText('Recover vault access or a forgotten passphrase').closest('details')!
  details.open = true; fireEvent(details, new Event('toggle'))
  fireEvent.change(screen.getByLabelText('Recovery kit file contents'), { target: { value: 'fictional recovery secret material' } })
  hide(); act(() => vi.advanceTimersByTime(30_000)); show(); await flush()
  expect(screen.getByLabelText('Recovery kit file contents')).toHaveProperty('value', '')
  const again = screen.getByText('Recover vault access or a forgotten passphrase').closest('details')!
  again.open = true; fireEvent(again, new Event('toggle'))
  fireEvent.change(screen.getByLabelText('Recovery kit file contents'), { target: { value: 'another fictional kit' } })
  hide(); fireEvent.click(screen.getByRole('button', { name: 'Sign out now' })); show(); await flush()
  expect(screen.getByLabelText('Recovery kit file contents')).toHaveProperty('value', '')
})

describe('background focus and native credential UI', () => {
  it('conceals a visible but blurred browser window and validates before showing it again', async () => {
    await openVault()
    fireEvent(window, new Event('blur'))
    expect(document.documentElement.dataset.havenConcealed).toBe('true')
    expect(document.getElementById('sensitive-surface')?.hasAttribute('inert')).toBe(true)
    let finish!: () => void
    mocks.validate.mockReturnValueOnce(new Promise<void>(resolve => { finish = resolve }))
    fireEvent(window, new Event('focus'))
    expect(document.documentElement.dataset.havenConcealed).toBe('true')
    await act(async () => finish())
    expect(document.documentElement.dataset.havenConcealed).toBeUndefined()
    expect(screen.getByRole('button', { name: 'Lock vault' })).toBeTruthy()
  })
  it('focus without a previous background transition does not conceal or start an extra validation', async () => {
    await openVault(); mocks.validate.mockClear()
    fireEvent(window, new Event('focus'))
    expect(document.documentElement.dataset.havenConcealed).toBeUndefined()
    expect(mocks.validate).not.toHaveBeenCalled()
  })
  it('a repeated blur cannot restart the configured background deadline', async () => {
    await openVault(); fireEvent(window, new Event('blur'))
    act(() => vi.advanceTimersByTime(20000)); fireEvent(window, new Event('blur'))
    act(() => vi.advanceTimersByTime(10000)); fireEvent(window, new Event('focus')); await flush()
    expect(screen.getByLabelText('Your passphrase')).toBeTruthy()
  })
  it('ignores only focus changes belonging to native credential UI; actual hiding still conceals and locks', async () => {
    const { runCredentialPrompt, clearCredentialPrompts } = await import('./lib/credentialPrompt')
    await openVault()
    let finish!: () => void
    const pending = runCredentialPrompt(() => new Promise<void>(resolve => { finish = resolve }))
    fireEvent(window, new Event('blur')); fireEvent(window, new Event('focus'))
    expect(document.documentElement.dataset.havenConcealed).toBeUndefined()
    hide(); expect(document.documentElement.dataset.havenConcealed).toBe('true')
    act(() => vi.advanceTimersByTime(30000)); show(); await flush()
    expect(screen.getByLabelText('Your passphrase')).toBeTruthy()
    await act(async () => { finish(); await pending; clearCredentialPrompts() })
  })
})

it('native credential UI does not suspend inactivity or authentication expiry', async () => {
  const { runCredentialPrompt, clearCredentialPrompts } = await import('./lib/credentialPrompt')
  localStorage.setItem('haven.security.v1', JSON.stringify({ backgroundSeconds: 30, inactivityMinutes: 1 }))
  mocks.deadline = Date.now() + 70000
  await openVault()
  let finish!: () => void
  const pending = runCredentialPrompt(() => new Promise<void>(resolve => { finish = resolve }))
  fireEvent(window, new Event('blur'))
  act(() => vi.advanceTimersByTime(60000))
  expect(screen.getByLabelText('Your passphrase')).toBeTruthy()
  act(() => vi.advanceTimersByTime(10000))
  expect(screen.getByRole('button', { name: 'Sign in with passkey' })).toBeTruthy()
  await act(async () => { finish(); await pending; clearCredentialPrompts() })
  expect(screen.queryByText(file.name)).toBeNull()
})

it('retains authenticated recovery drafts only within the configured grace and clears them on lock', async () => {
  render(<App />); await authenticate()
  const details = screen.getByText('Recover vault access or a forgotten passphrase').closest('details')!
  details.open = true; fireEvent(details, new Event('toggle'))
  fireEvent.change(screen.getByLabelText('Recovery kit file contents'), { target: { value: 'fictional recovery material' } })
  hide()
  expect(screen.getByLabelText('Recovery kit file contents')).toHaveProperty('value', 'fictional recovery material')
  act(() => vi.advanceTimersByTime(29000)); show(); await flush()
  expect(screen.getByLabelText('Recovery kit file contents')).toHaveProperty('value', 'fictional recovery material')
  hide(); act(() => vi.advanceTimersByTime(30000)); show(); await flush()
  expect(screen.getByLabelText('Recovery kit file contents')).toHaveProperty('value', '')
  expect(mocks.signOut).not.toHaveBeenCalled()
})
