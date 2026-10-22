import { beforeEach, expect, it, vi } from 'vitest'
import { decryptJson, decryptFile } from './crypto'
import { clearPlaintext } from './plaintext'
const state = vi.hoisted(() => ({ objects: new Map<string, Blob>(), operations: new Map<string, any>(), records: new Map<string, any>(), catalog: null as any, migrationPending: false, failFinalize: false, lostFinalize: false, transferCount: 0, calls: [] as any[] }))
vi.mock('./firebase', () => ({ db: {}, storage: {}, getVaultUserId: () => 'fixture-owner' }))
vi.mock('firebase/firestore', () => ({
  collection: (_db: unknown, ...parts: string[]) => parts.join('/'), doc: (_db: unknown, ...parts: string[]) => parts.join('/'),
  getDocsFromServer: async () => ({ docs: [...state.records].map(([id, value]) => ({ id, data: () => value })) }),
  getDocFromServer: vi.fn(), runTransaction: vi.fn(),
}))
vi.mock('firebase/storage', () => ({
  ref: (_storage: unknown, path: string) => path,
  getBlob: async (path: string) => { const blob = state.objects.get(path); if (!blob) throw { code: 'storage/object-not-found' }; return blob },
  uploadBytesResumable: (path: string, blob: Blob, metadata: any) => {
    state.transferCount++; expect(metadata.contentType).toBe('application/octet-stream');
    let aborted = false
    return { cancel: () => { aborted = true }, on: (_event: string, progress: Function, fail: Function, complete: Function) => { queueMicrotask(() => { if (aborted) fail({ code: 'storage/cancelled' }); else { progress({ bytesTransferred: blob.size, totalBytes: blob.size }); state.objects.set(path, blob); complete() } }) } }
  },
}))
vi.mock('./security', () => ({ securityCall: async (action: string, data: any) => {
  state.calls.push({ action, data })
  if (action === 'files.list') return { catalog: state.catalog, migrationPending: state.migrationPending, operations: [...state.operations].filter(([, o]) => o.status === 'pending').map(([id, o]) => ({ id, ...o })) }
  if (action === 'files.catalog') { if ((state.catalog?.revision || 0) !== data.expectedRevision) throw { code: 'functions/aborted' }; state.catalog = { revision: data.expectedRevision + 1, itemEpoch: 0, payload: data.payload }; return { revision: state.catalog.revision } }
  if (action === 'files.begin') { if (!state.operations.has(data.id)) state.operations.set(data.id, { ...data, status: 'pending' }); return { operation: state.operations.get(data.id) } }
  if (action === 'files.finalize') {
    if (state.failFinalize) { state.failFinalize = false; throw new Error('network failure') }
    const op = state.operations.get(data.id)
    if (op.status !== 'completed') { op.status = 'completed'; op.revision = (op.expectedRevision || 0) + 1; state.records.set(op.itemId, { payload: op.payload, revision: op.revision, staged: op.kind === 'upload', objectBytes: op.bytes || 0 }) }
    if (state.lostFinalize) { state.lostFinalize = false; throw new Error('lost response after commit') }
    return { operation: op }
  }
  if (action === 'files.status') return { operation: state.operations.get(data.id) }
  throw new Error('Unexpected action')
} }))
import { prepareUpload, transferUpload, downloadVaultFile, loadCollections, saveCollections, listVaultItems, saveVaultNote, updateVaultItem, type VaultItem } from './vault'
let key: CryptoKey
const file = () => new File([new Uint8Array([0, 1, 127, 128, 255])], 'fictional-private.txt', { type: 'text/plain' })
beforeEach(async () => {
  state.objects.clear(); state.operations.clear(); state.records.clear(); state.catalog = null; state.migrationPending = false; state.failFinalize = false; state.lostFinalize = false; state.transferCount = 0; state.calls = []
  key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  await loadCollections(key)
})
it('success verifies byte-for-byte download with only ciphertext and opaque state crossing the backend boundary', async () => {
  const source = file(), prepared = await prepareUpload(key, source, 'Personal')
  const states: string[] = []
  const item = await transferUpload(key, prepared, { progress: state => states.push(state) })
  const downloaded = await downloadVaultFile(key, item)
  expect(new Uint8Array(await downloaded.arrayBuffer())).toEqual(new Uint8Array(await source.arrayBuffer()))
  expect(states).toContain('uploading'); expect(states).toContain('finalizing')
  const wire = JSON.stringify(state.calls)
  expect(wire).not.toContain(source.name); expect(wire).not.toContain('Personal'); expect(wire).not.toContain('text/plain')
  expect(state.objects.values().next().value?.size).toBe(source.size + 29)
  expect((await decryptJson<VaultItem>(key, prepared.payload, `metadata:${item.id}`)).name).toBe(source.name)
})
it.each(['failFinalize', 'lostFinalize'] as const)('retries %s idempotently without transferring or duplicating a saved file', async fault => {
  const prepared = await prepareUpload(key, file(), 'Personal'); state[fault] = true
  await expect(transferUpload(key, prepared)).rejects.toThrow()
  const completed = await transferUpload(key, prepared)
  expect(completed.id).toBe(prepared.id); expect(state.transferCount).toBe(1); expect(state.records.size).toBe(1)
})
it('notes reuse an unconfirmed creation receipt after a lost response', async () => {
  const identity = crypto.randomUUID(); state.lostFinalize = true
  await expect(saveVaultNote(key, 'Fictional note', 'private fixture', 'Personal', identity)).rejects.toThrow()
  const item = await saveVaultNote(key, 'Fictional note', 'private fixture', 'Personal', identity)
  expect(state.records.size).toBe(1); expect(item.revision).toBe(1)
  expect(await downloadVaultFile(key, item).catch(e => e.message)).toContain('Notes do not')
})
it('an unconfirmed draft cannot silently become a different edit on retry', async () => {
  const identity = crypto.randomUUID(); state.failFinalize = true
  await expect(saveVaultNote(key, 'Fictional note', 'first contents', 'Personal', identity)).rejects.toThrow()
  await expect(saveVaultNote(key, 'Fictional note', 'different contents', 'Personal', identity)).rejects.toThrow('unconfirmed')
  expect(state.records.size).toBe(0)
})
it('retains independently encrypted empty definitions, maps legacy membership and renames stable identities', async () => {
  const catalog = await loadCollections(key)
  const travel = { id: crypto.randomUUID(), name: 'Fictional empty collection', legacyNames: ['Old collection'] }
  const saved = await saveCollections(key, catalog, [...catalog.entries, travel])
  expect((await loadCollections(key)).entries).toContainEqual(travel)
  const now = Date.now(), id = crypto.randomUUID()
  const item: VaultItem = { id, name: 'fixture', kind: 'note', text: '', size: 0, mimeType: 'text/plain', createdAt: now, updatedAt: now, favorite: false, trashed: false, collection: 'Old collection' }
  const { encryptJson } = await import('./crypto')
  state.records.set(id, { payload: await encryptJson(key, item, `metadata:${id}`) })
  expect((await listVaultItems(key))[0]).toMatchObject({ collectionId: travel.id, collection: travel.name })
  const renamed = { ...travel, name: 'New collection name' }
  await saveCollections(key, saved, [catalog.entries[0], renamed])
  expect((await listVaultItems(key))[0].collection).toBe(renamed.name)
})
it('rejects duplicate/reserved collection names and oversized notes before any write receipt', async () => {
  const catalog = await loadCollections(key)
  await expect(saveCollections(key, catalog, [...catalog.entries, { id: crypto.randomUUID(), name: 'personal', legacyNames: [] }])).rejects.toThrow('unique')
  await expect(saveCollections(key, catalog, [])).rejects.toThrow('Personal')
  const before = state.calls.length
  await expect(saveVaultNote(key, 'fixture', 'a'.repeat(256 * 1024 + 1))).rejects.toThrow('supported size')
  expect(state.calls).toHaveLength(before)
})
it('locking during encryption prevents backend writes and the original transient buffer is wiped', async () => {
  const source = file(), bytes = await source.arrayBuffer()
  const original = source.arrayBuffer.bind(source)
  source.arrayBuffer = async () => { clearPlaintext(); return bytes }
  const before = state.calls.filter(c => c.action === 'files.begin').length
  await expect(prepareUpload(key, source)).rejects.toThrow('locked')
  expect(new Uint8Array(bytes).every(b => b === 0)).toBe(true)
  expect(state.calls.filter(c => c.action === 'files.begin')).toHaveLength(before)
  source.arrayBuffer = original
})
it('readback rejects corrupt or mismatched-size encrypted objects', async () => {
  const prepared = await prepareUpload(key, file()); const item = await transferUpload(key, prepared)
  await expect(downloadVaultFile(key, { ...item, size: item.size + 1 })).rejects.toThrow('does not match')
  const path = `staged/fixture-owner/legacy/${item.id}`; state.objects.set(path, new Blob([new Uint8Array(50)]))
  await expect(downloadVaultFile(key, item)).rejects.toThrow()
  await expect(decryptFile(key, state.objects.get(path)!, `file:${item.id}`)).rejects.toThrow()
})

it('keeps legacy unlock and empty collection reads available during an interrupted key migration without issuing writes', async () => {
  state.catalog = null; state.migrationPending = true
  const before = state.calls.filter(c => c.action === 'files.catalog').length
  const catalog = await loadCollections(key)
  expect(catalog.entries[0].name).toBe('Personal')
  expect(state.calls.filter(c => c.action === 'files.catalog')).toHaveLength(before)
})

it('discards a crypto result completed after lock and clears the original transient array', async () => {
  const source = file(), bytes = await source.arrayBuffer()
  source.arrayBuffer = async () => bytes
  let enter!: () => void, release!: () => void
  const started = new Promise<void>(resolve => { enter = resolve })
  const gate = new Promise<void>(resolve => { release = resolve })
  const original = crypto.subtle.encrypt.bind(crypto.subtle)
  const spy = vi.spyOn(crypto.subtle, 'encrypt').mockImplementationOnce(async (...args) => {
    const result = await original(...args); enter(); await gate; return result
  })
  try {
    const pending = prepareUpload(key, source)
    await started; clearPlaintext(); release()
    await expect(pending).rejects.toThrow('locked')
    expect(new Uint8Array(bytes).every(b => b === 0)).toBe(true)
    expect(state.calls.some(c => c.action === 'files.begin')).toBe(false)
  } finally { release(); spy.mockRestore() }
})

it('deletes an independently persisted empty collection without deleting any item or file', async () => {
  const initial = await loadCollections(key), id = crypto.randomUUID()
  const added = await saveCollections(key, initial, [...initial.entries, { id, name: 'Empty deletion fixture', legacyNames: [] }])
  const before = state.calls.filter(c => c.action === 'files.begin').length
  await saveCollections(key, added, added.entries.filter(c => c.id !== id))
  expect((await loadCollections(key)).entries.some(c => c.id === id)).toBe(false)
  expect(state.calls.filter(c => c.action === 'files.begin')).toHaveLength(before)
  expect(state.objects.size).toBe(0)
})
