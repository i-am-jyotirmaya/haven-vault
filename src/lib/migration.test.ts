import { beforeEach, expect, it, vi } from 'vitest'
import { createVault, encryptJson, decryptJson, encryptFile, type LegacyVaultConfig } from './crypto'
import { unlockKeyRecord, type KeyRecord } from './keys'
const state = vi.hoisted(() => ({ docs: new Map<string, any>(), files: new Map<string, Blob>(), migration: null as any, config: null as any, fail: '', completed: new Set<string>(), uploads: 0, forbiddenWrites: 0 }))
vi.mock('./firebase', () => ({ db: {}, storage: {}, getVaultUserId: () => 'owner', validateVaultSession: async () => {} }))
vi.mock('firebase/firestore', () => ({
  collection: (_db: unknown, ...parts: string[]) => parts.join('/'), doc: (_db: unknown, ...parts: string[]) => parts.join('/'),
  getDocsFromServer: async (path: string) => { const docs = [...state.docs].filter(([p]) => p.startsWith(path + '/') && p.split('/').length === path.split('/').length + 1).map(([p, v]) => ({ id: p.split('/').at(-1), data: () => v })); return { docs, size: docs.length } },
  getDocFromServer: async (path: string) => ({ exists: () => state.docs.has(path), data: () => state.docs.get(path) }),
  setDoc: async (path: string, value: unknown) => { if (path.startsWith('users/owner/items/')) state.forbiddenWrites++; state.docs.set(path, value) },
}))
vi.mock('firebase/storage', () => ({
  ref: (_storage: unknown, path: string) => path,
  getBlob: async (path: string) => { if (!state.files.has(path)) throw { code: 'storage/object-not-found' }; return state.files.get(path) },
  uploadBytes: async (path: string, value: Blob) => { if (state.files.has(path)) throw new Error('Immutable file overwrite'); if (path.startsWith('vaults/')) state.forbiddenWrites++; state.uploads++; state.files.set(path, value) },
}))
vi.mock('./vault', () => ({ listVaultItems: async () => [] }))
vi.mock('./security', () => ({ securityCall: async (action: string, data: any = {}) => {
  if (state.fail === action) { state.fail = ''; throw new Error('Fictional interruption') }
  if (action === 'migrationStatus') return { migration: state.migration, config: state.config, completed: [...state.completed] }
  if (action === 'migrationBegin') { state.migration ??= { phase: 'staging', record: data.record }; return { migration: state.migration } }
  if (action === 'migrationItem') state.completed.add(data.id)
  if (action === 'migrationFinalize') { state.config = state.migration.record; state.migration.phase = 'complete'; return { complete: true } }
  return { saved: true }
} }))
import { migrateVault } from './migration'
const phrase = 'fictional legacy passphrase orchard', id = '11111111-1111-4111-8111-111111111111'
let legacy: LegacyVaultConfig
let original: any
beforeEach(async () => {
  state.docs.clear(); state.files.clear(); state.migration = null; state.completed.clear(); state.fail = ''; state.uploads = 0; state.forbiddenWrites = 0
  const created = await createVault(phrase); legacy = created.config; state.config = legacy
  const item = { id, name: 'fixture.jpg', kind: 'photo', mimeType: 'image/jpeg', size: 7, createdAt: 100, updatedAt: 200, favorite: true, collection: 'Private fixtures', trashed: true, thumbnail: 'data:image/jpeg;base64,AAAA', text: 'private metadata' }
  original = { payload: await encryptJson(created.key, item, `metadata:${id}`) }
  state.docs.set(`users/owner/items/${id}`, original)
  state.files.set(`vaults/owner/${id}`, await encryptFile(created.key, new TextEncoder().encode('fixture').buffer, `file:${id}`))
})
it('migrates exact metadata and file bytes to a genuinely new random key without changing originals', async () => {
  const oldFile = state.files.get(`vaults/owner/${id}`)
  const result = await migrateVault(phrase, legacy, () => {}, () => {})
  expect(result.config.version).toBe(2)
  const key = await unlockKeyRecord(phrase, result.config)
  const staged = state.docs.get(`users/owner/generations/${result.config.generation}/items/${id}`)
  expect(await decryptJson(key, staged.payload, `metadata:${id}`)).toMatchObject({ name: 'fixture.jpg', trashed: true, favorite: true, collection: 'Private fixtures', thumbnail: 'data:image/jpeg;base64,AAAA', createdAt: 100, updatedAt: 200, text: 'private metadata' })
  expect(state.docs.get(`users/owner/items/${id}`)).toEqual(original)
  expect(state.files.get(`vaults/owner/${id}`)).toBe(oldFile)
  expect(state.forbiddenWrites).toBe(0)
})
it('resumes after file staging without overwriting immutable files', async () => {
  state.fail = 'migrationItem'
  await expect(migrateVault(phrase, legacy, () => {}, () => {})).rejects.toThrow('interruption')
  expect(state.config).toBe(legacy)
  expect(state.uploads).toBe(1)
  await migrateVault(phrase, legacy, () => {}, () => {})
  expect(state.uploads).toBe(1)
  expect(state.forbiddenWrites).toBe(0)
})
it('pauses before finalization and resumes a sealed generation after interruption', async () => {
  state.fail = 'migrationFinalize'
  await expect(migrateVault(phrase, legacy, () => {}, () => {})).rejects.toThrow('interruption')
  state.migration.phase = 'verifying'
  const generation = state.migration.record.generation
  const result = await migrateVault(phrase, legacy, () => {}, () => {})
  expect(result.config.generation).toBe(generation)
})
it('a lock during async processing prevents cutover and leaves the rollback generation intact', async () => {
  let calls = 0
  await expect(migrateVault(phrase, legacy, () => { if (++calls > 12) throw new Error('Locked') }, () => {})).rejects.toThrow('Locked')
  expect(state.config).toBe(legacy)
  expect(state.docs.get(`users/owner/items/${id}`)).toEqual(original)
})
it('never falsely completes when staged ciphertext was tampered', async () => {
  state.fail = 'migrationItem'
  await expect(migrateVault(phrase, legacy, () => {}, () => {})).rejects.toThrow()
  const r = state.migration.record as KeyRecord
  state.docs.get(`users/owner/generations/${r.generation}/items/${id}`).payload.ciphertext = 'A'.repeat(64)
  await expect(migrateVault(phrase, legacy, () => {}, () => {})).rejects.toThrow()
  expect(state.config).toBe(legacy)
})

it('reuses verified receipts after a rate-limit-style interruption while rechecking staged ciphertext', async () => {
  state.fail = 'migrationFinalize'
  await expect(migrateVault(phrase, legacy, () => {}, () => {})).rejects.toThrow('interruption')
  expect(state.completed.has(id)).toBe(true)
  state.fail = 'migrationItem'
  await expect(migrateVault(phrase, legacy, () => {}, () => {})).resolves.toHaveProperty('config.version', 2)
  expect(state.fail).toBe('migrationItem')
})
