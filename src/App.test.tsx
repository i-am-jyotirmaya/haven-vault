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
