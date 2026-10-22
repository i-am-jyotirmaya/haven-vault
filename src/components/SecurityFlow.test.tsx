// @vitest-environment jsdom
/** Real local crypto + actual workflow/policy modules; only Firebase and native
 * WebAuthn UI boundaries are fictional. This catches focus/continuation races. */
import { webcrypto } from 'node:crypto'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { useState } from 'react'
const boundary = vi.hoisted(() => ({ record: null as any, call: vi.fn(), authentication: vi.fn(), validate: vi.fn() }))
vi.mock('../lib/firebase', () => ({
  callVault: boundary.call, acceptRecoveredSession: vi.fn(), beginRecoverySessionClock: () => Date.now(), verifyRecoveryOwner: vi.fn(),
}))
vi.mock('@simplewebauthn/browser', () => ({ startAuthentication: boundary.authentication, startRegistration: vi.fn() }))
vi.mock('../lib/vault', () => ({ getVaultConfig: async () => boundary.record }))
vi.mock('../lib/migration', () => ({ migrateVault: vi.fn() }))
import SecurityCenter from './SecurityCenter'
import { createKeyRecord, unlockKeyRecord } from '../lib/keys'
import { encryptJson, decryptJson } from '../lib/crypto'
import { useVaultPolicy } from '../lib/useVaultPolicy'
import { clearCredentialPrompts } from '../lib/credentialPrompt'
const phrase = 'fictional current passphrase orchard', replacement = 'fictional replacement passphrase meadow'
let key: CryptoKey
const failures = vi.fn()
let downloaded: Blob | undefined
let lockHarness: () => void
function Harness() {
  const [config, setConfig] = useState(boundary.record), [unlocked, setUnlocked] = useState(true)
  lockHarness = () => setUnlocked(false)
  const policy = useVaultPolicy({ expiresAt: Date.now() + 3600000, unlocked, authenticated: true, lock: () => setUnlocked(false), expire: () => setUnlocked(false), conceal: () => {}, validate: boundary.validate, failure: failures })
  return <div id="sensitive-surface">{unlocked && <SecurityCenter config={config} vaultKey={key} check={() => {
    if (!policy.evaluate() || document.documentElement.dataset.havenConcealed) throw new Error('Privacy gate is active')
  }} onChanged={next => setConfig(next)} onEndSession={() => setUnlocked(false)} onFailure={failures} />}</div>
}
beforeEach(async () => {
  vi.stubGlobal('crypto', webcrypto); vi.clearAllMocks(); failures.mockClear(); localStorage.clear()
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
  vi.spyOn(document, 'hasFocus').mockReturnValue(true)
  const created = await createKeyRecord(phrase); boundary.record = created.config; key = created.key
  boundary.validate.mockResolvedValue(undefined)
  URL.createObjectURL = vi.fn(blob => { downloaded = blob; return 'blob:fixture' }); URL.revokeObjectURL = vi.fn()
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  boundary.call.mockImplementation(async (name, data) => {
    if (name === 'authenticationOptions') return { options: {}, challengeId: 'fixture' }
    if (name === 'verifyAuthentication') return { verified: true }
    if (name === 'securityOperation' && data.action === 'replaceKeys') { boundary.record = data.record; return { config: data.record } }
    throw new Error('Unexpected fixture operation')
  })
  boundary.authentication.mockImplementation(async () => {
    vi.mocked(document.hasFocus).mockReturnValue(false)
    fireEvent(window, new Event('blur'))
    expect(document.documentElement.dataset.havenConcealed).toBeUndefined()
    await Promise.resolve()
    vi.mocked(document.hasFocus).mockReturnValue(true)
    fireEvent(window, new Event('focus'))
    expect(document.documentElement.dataset.havenConcealed).toBeUndefined()
    return { id: 'fictional-passkey' }
  })
})
afterEach(() => { cleanup(); clearCredentialPrompts(); vi.unstubAllGlobals(); vi.restoreAllMocks() })
it('prepares, downloads, confirms and commits a real recovery kit across credential focus changes', async () => {
  render(<Harness />)
  fireEvent.change(screen.getByLabelText('Current passphrase for recovery setup'), { target: { value: phrase } })
  fireEvent.submit(screen.getByRole('form', { name: 'Prepare recovery kit' }))
  await waitFor(() => expect(screen.getByRole('heading', { name: 'Save your recovery kit' })).toBeTruthy(), { timeout: 10000 })
  expect(boundary.record.recovery).toBeNull()
  fireEvent.click(screen.getByRole('button', { name: 'Download recovery kit' }))
  const text = await new Promise<string>((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(String(reader.result)); reader.onerror = reject; reader.readAsText(downloaded!) })
  const saved = JSON.parse(text)
  fireEvent.change(screen.getByLabelText('Saved recovery secret'), { target: { value: saved.secret } })
  fireEvent.click(screen.getByRole('button', { name: 'Confirm saved kit and commit' }))
  await waitFor(() => expect(screen.getByText(/Recovery kit saved and verified/)).toBeTruthy(), { timeout: 10000 })
  expect(boundary.record.recovery.id).toBe(saved.recoveryId)
  expect(boundary.authentication).toHaveBeenCalledTimes(2)
  expect(JSON.stringify(boundary.call.mock.calls)).not.toContain(saved.secret)
  expect(failures).not.toHaveBeenCalled()
}, 15000)
it('shows verified passphrase feedback after a real rewrap and preserves the existing data key', async () => {
  const ciphertext = await encryptJson(key, { fictional: 'private note' }, 'metadata:fixture')
  render(<Harness />)
  fireEvent.change(screen.getByLabelText('Current passphrase'), { target: { value: phrase } })
  fireEvent.change(screen.getByLabelText('New passphrase'), { target: { value: replacement } })
  fireEvent.change(screen.getByLabelText('Confirm new passphrase'), { target: { value: replacement } })
  fireEvent.submit(screen.getByRole('form', { name: 'Change passphrase' }))
  await waitFor(() => expect(screen.getByText(/Passphrase changed and verified/)).toBeTruthy(), { timeout: 10000 })
  const updated = await unlockKeyRecord(replacement, boundary.record)
  await expect(decryptJson(updated, ciphertext, 'metadata:fixture')).resolves.toEqual({ fictional: 'private note' })
  expect(failures).not.toHaveBeenCalled()
}, 15000)
it('rejects a wrong passphrase locally before asking for a passkey and places feedback next to setup', async () => {
  render(<Harness />)
  fireEvent.change(screen.getByLabelText('Current passphrase for recovery setup'), { target: { value: 'fictional incorrect passphrase' } })
  fireEvent.submit(screen.getByRole('form', { name: 'Prepare recovery kit' }))
  await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('current passphrase is incorrect'), { timeout: 10000 })
  expect(screen.getByRole('alert').closest('[aria-label="Recovery kit settings"]')).toBeTruthy()
  expect(boundary.authentication).not.toHaveBeenCalled(); expect(boundary.record.recovery).toBeNull()
}, 15000)

it('waits for return validation when a mobile credential prompt truly hides the document', async () => {
  let reveal!: () => void
  boundary.validate.mockImplementation(() => new Promise<void>(resolve => { reveal = resolve }))
  boundary.authentication.mockImplementation(async () => {
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' })
    fireEvent(document, new Event('visibilitychange'))
    return { id: 'fixture-passkey' }
  })
  render(<Harness />)
  fireEvent.change(screen.getByLabelText('Current passphrase for recovery setup'), { target: { value: phrase } })
  fireEvent.submit(screen.getByRole('form', { name: 'Prepare recovery kit' }))
  await waitFor(() => expect(document.documentElement.dataset.havenConcealed).toBe('true'), { timeout: 10000 })
  expect(screen.queryByText('Save your recovery kit')).toBeNull()
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
  fireEvent(document, new Event('visibilitychange'))
  expect(document.documentElement.dataset.havenConcealed).toBe('true')
  expect(screen.queryByText('Save your recovery kit')).toBeNull()
  await act(async () => reveal())
  await waitFor(() => expect(screen.getByRole('heading', { name: 'Save your recovery kit' })).toBeTruthy(), { timeout: 10000 })
  expect(failures).not.toHaveBeenCalled()
}, 15000)
it('locking while a credential continuation waits for return cancels it without publishing a kit', async () => {
  boundary.authentication.mockImplementation(async () => {
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' })
    fireEvent(document, new Event('visibilitychange'))
    return { id: 'fixture-passkey' }
  })
  render(<Harness />)
  fireEvent.change(screen.getByLabelText('Current passphrase for recovery setup'), { target: { value: phrase } })
  fireEvent.submit(screen.getByRole('form', { name: 'Prepare recovery kit' }))
  await waitFor(() => expect(document.documentElement.dataset.havenConcealed).toBe('true'), { timeout: 10000 })
  await act(async () => lockHarness())
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
  fireEvent(document, new Event('visibilitychange'))
  await act(async () => { await Promise.resolve() })
  expect(screen.queryByText('Save your recovery kit')).toBeNull()
  expect(boundary.record.recovery).toBeNull()
  expect(boundary.call.mock.calls.filter(([name]) => name === 'securityOperation')).toHaveLength(0)
}, 15000)
