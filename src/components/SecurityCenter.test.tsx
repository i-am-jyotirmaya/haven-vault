// @vitest-environment jsdom
import { webcrypto } from 'node:crypto'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
const mocks = vi.hoisted(() => ({ call: vi.fn(), reauth: vi.fn(), prepare: vi.fn(), get: vi.fn(), change: vi.fn() }))
vi.mock('../lib/security', () => ({ securityCall: mocks.call, reauthenticate: mocks.reauth, addPasskey: vi.fn() }))
vi.mock('../lib/vault', () => ({ getVaultConfig: mocks.get }))
vi.mock('../lib/migration', () => ({ migrateVault: vi.fn() }))
vi.mock('../lib/keys', async original => ({ ...await original<typeof import('../lib/keys')>(), prepareRecovery: mocks.prepare, changePassphrase: mocks.change, unlockRecovery: async () => ({}), unlockKeyRecord: async () => ({}) }))
import SecurityCenter from './SecurityCenter'
const config = { version: 2 as const, vaultId: 'fictional-vault', generation: 'fictional-generation', revision: 1, passphrase: {} as any, recovery: null }
const kit = { version: 2 as const, vaultId: config.vaultId, recoveryId: 'fictional-recovery', secret: 'FICTIONAL_SECRET', record: { ...config, revision: 2, recovery: { id: 'fictional-recovery' } as any }, instructions: 'fixture' }
beforeEach(() => { vi.stubGlobal('crypto', webcrypto); vi.clearAllMocks(); mocks.reauth.mockResolvedValue(undefined); mocks.prepare.mockResolvedValue(kit); mocks.get.mockResolvedValue(config); mocks.call.mockResolvedValue({}); URL.createObjectURL = vi.fn(() => 'blob:fixture'); URL.revokeObjectURL = vi.fn(); vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {}) })
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks() })
const flush = async () => { await act(async () => { await Promise.resolve() }) }
function mount() { const changed = vi.fn(), end = vi.fn(); const view = render(<SecurityCenter config={config} vaultKey={{} as CryptoKey} check={() => {}} onChanged={changed} onEndSession={end} onFailure={() => {}} />); return { ...view, changed, end } }
it('makes incomplete recovery explicit and requires downloaded-kit possession before committing', async () => {
  const { changed } = mount()
  expect(screen.getByText(/INCOMPLETE/)).toBeTruthy()
  fireEvent.change(screen.getByLabelText('Current passphrase for recovery setup'), { target: { value: 'fictional current passphrase' } })
  fireEvent.click(screen.getByRole('button', { name: 'Set up recovery kit' })); await flush()
  const button = screen.getByRole('button', { name: 'Confirm saved kit and commit' })
  expect(button).toHaveProperty('disabled', true)
  expect(mocks.call).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Download recovery kit' }))
  fireEvent.change(screen.getByLabelText('Saved recovery secret'), { target: { value: kit.secret } })
  expect(button).toHaveProperty('disabled', false)
  mocks.get.mockResolvedValue(kit.record)
  fireEvent.click(button); await flush()
  expect(mocks.call).toHaveBeenCalledWith('replaceKeys', { purpose: 'recovery', record: kit.record })
  expect(JSON.stringify(mocks.call.mock.calls)).not.toContain(kit.secret)
  await waitFor(() => expect(changed).toHaveBeenCalledWith(kit.record, expect.anything()))
})
it('does not publish recovery material or continue backend writes after unmount during derivation', async () => {
  let resolve!: (value: typeof kit) => void
  mocks.prepare.mockImplementation(() => new Promise(r => { resolve = r }))
  const view = mount(); fireEvent.change(screen.getByLabelText('Current passphrase for recovery setup'), { target: { value: 'fictional passphrase' } }); fireEvent.click(screen.getByRole('button', { name: 'Set up recovery kit' })); await flush()
  view.unmount(); await act(async () => resolve(kit)); await flush()
  expect(mocks.call).not.toHaveBeenCalled(); expect(view.changed).not.toHaveBeenCalled()
})
it('stale passphrase mutations never report success or update local keys', async () => {
  const { changed } = mount(); mocks.change.mockResolvedValue({ ...config, revision: 2 }); mocks.call.mockRejectedValue(new Error('Concurrent key change'))
  fireEvent.change(screen.getByLabelText('Current passphrase'), { target: { value: 'fictional old passphrase' } })
  fireEvent.change(screen.getByLabelText('New passphrase'), { target: { value: 'fictional next passphrase' } })
  fireEvent.change(screen.getByLabelText('Confirm new passphrase'), { target: { value: 'fictional next passphrase' } })
  fireEvent.click(screen.getByRole('button', { name: 'Change passphrase' })); await flush()
  expect(changed).not.toHaveBeenCalled(); expect(screen.getByRole('alert').textContent).toContain('Concurrent key change')
})
it('current-session revocation requests immediate sign-out after the committed result', async () => {
  const { end } = mount(); mocks.call.mockResolvedValue({ currentRevoked: true })
  fireEvent.click(screen.getByRole('button', { name: 'Revoke all sessions' })); await flush()
  expect(mocks.reauth).toHaveBeenCalled(); expect(end).toHaveBeenCalledOnce()
})

it('requires a dedicated recovery passphrase before opening any passkey prompt', async () => {
  mount()
  fireEvent.click(screen.getByRole('button', { name: 'Set up recovery kit' })); await flush()
  expect(screen.getByRole('alert').textContent).toContain('Enter your current passphrase')
  expect(mocks.reauth).not.toHaveBeenCalled(); expect(mocks.prepare).not.toHaveBeenCalled()
})
it('shows passphrase success beside its form only after the saved result has been verified', async () => {
  const { changed } = mount()
  const nextRecord = { ...config, revision: 2 }
  mocks.change.mockResolvedValue(nextRecord)
  mocks.call.mockImplementation(async () => { mocks.get.mockResolvedValue(nextRecord); return {} })
  fireEvent.change(screen.getByLabelText('Current passphrase'), { target: { value: 'fictional current passphrase' } })
  fireEvent.change(screen.getByLabelText('New passphrase'), { target: { value: 'fictional new passphrase' } })
  fireEvent.change(screen.getByLabelText('Confirm new passphrase'), { target: { value: 'fictional new passphrase' } })
  fireEvent.submit(screen.getByRole('form', { name: 'Change passphrase' }))
  await waitFor(() => expect(screen.getByText(/Passphrase changed and verified/)).toBeTruthy())
  expect(changed).toHaveBeenCalledOnce()
  expect(screen.getByText(/Passphrase changed and verified/).closest('form')).toBe(screen.getByRole('form', { name: 'Change passphrase' }))
  expect(screen.getByLabelText('Current passphrase for recovery setup')).toHaveProperty('value', '')
})

it('does not claim cancellation preserved old settings after an unconfirmed recovery commit', async () => {
  mount()
  fireEvent.change(screen.getByLabelText('Current passphrase for recovery setup'), { target: { value: 'fictional current passphrase' } })
  fireEvent.submit(screen.getByRole('form', { name: 'Prepare recovery kit' })); await flush()
  fireEvent.click(screen.getByRole('button', { name: 'Download recovery kit' }))
  fireEvent.change(screen.getByLabelText('Saved recovery secret'), { target: { value: kit.secret } })
  mocks.get.mockRejectedValue(new Error('offline while checking saved record'))
  fireEvent.click(screen.getByRole('button', { name: 'Confirm saved kit and commit' }))
  await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('may already have succeeded'))
  fireEvent.click(screen.getByRole('button', { name: 'Cancel', exact: true }))
  expect(screen.getByText(/last save outcome is unknown/)).toBeTruthy()
  expect(screen.queryByText(/previous recovery settings are unchanged/)).toBeNull()
})
