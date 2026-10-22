import { plaintextGeneration, plaintextIsCurrent, registerPlaintextCleanup } from './plaintext'
import { keyContext, validateKeyRecord } from './keys'
import { securityCall } from './security'
import {
  collection as firestoreCollection,
  doc,
  getDocFromServer,
  getDocsFromServer,
  runTransaction,
} from 'firebase/firestore'
import { getBlob, ref, uploadBytesResumable } from 'firebase/storage'
import {
  decryptFile,
  decryptJson,
  encryptFile,
  encryptJson,
  type EncryptedPayload,
  type VaultConfig,
} from './crypto'
import { db, getVaultUserId, storage } from './firebase'

export const MAX_FILE_SIZE = 50 * 1024 * 1024
export const MAX_NOTE_BYTES = 256 * 1024
const MAX_ENCRYPTED_FILE_SIZE = MAX_FILE_SIZE + 29
const MAX_METADATA_CIPHERTEXT_CHARS = 700_000
const ITEM_KINDS = new Set(['photo', 'document', 'note', 'other'])
const RASTER_MIME_TYPES = new Set([
  'image/jpeg',
  'image/png',
  'image/webp',
  'image/gif',
  'image/avif',
  'image/bmp',
])
const DOCUMENT_MIME_TYPES = new Set([
  'application/pdf',
  'text/plain',
  'text/csv',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-powerpoint',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',
])

export type VaultItem = {
  id: string
  name: string
  kind: 'photo' | 'document' | 'note' | 'other'
  mimeType: string
  size: number
  createdAt: number
  updatedAt: number
  favorite: boolean
  collection: string
  trashed: boolean
  revision?: number
  objectBytes?: number
  staged?: boolean
  deleting?: string
  collectionId?: string
  text?: string
  thumbnail?: string
}

function sensitiveGuard() {
  const generation = plaintextGeneration()
  return () => { if (!plaintextIsCurrent(generation)) throw new Error('Vault locked. Unlock and reconcile interrupted operations.'); getVaultUserId() }
}
function requireDatabase() {
  if (!db) throw new Error('Firebase is not configured.')
  return db
}

function requireStorage() {
  if (!storage) throw new Error('Firebase is not configured.')
  return storage
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function validateId(id: string) {
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(id)) {
    throw new Error('This vault item has an invalid identifier.')
  }
}

function validatePayload(value: unknown): asserts value is EncryptedPayload {
  if (
    !isRecord(value) ||
    ![1, 2].includes(Number(value.version)) ||
    typeof value.iv !== 'string' ||
    typeof value.ciphertext !== 'string' ||
    value.ciphertext.length > MAX_METADATA_CIPHERTEXT_CHARS
  ) {
    throw new Error('The encrypted vault record is invalid.')
  }
}

function validateItem(value: unknown, expectedId: string): asserts value is VaultItem {
  validateId(expectedId)
  if (
    !isRecord(value) ||
    value.id !== expectedId ||
    typeof value.name !== 'string' ||
    value.name.trim().length === 0 ||
    value.name.length > 1024 ||
    typeof value.kind !== 'string' ||
    !ITEM_KINDS.has(value.kind) ||
    typeof value.mimeType !== 'string' ||
    value.mimeType.length > 255 ||
    typeof value.size !== 'number' ||
    !Number.isSafeInteger(value.size) ||
    value.size < 0 ||
    value.size > MAX_FILE_SIZE ||
    typeof value.createdAt !== 'number' ||
    !Number.isSafeInteger(value.createdAt) ||
    value.createdAt <= 0 ||
    typeof value.updatedAt !== 'number' ||
    !Number.isSafeInteger(value.updatedAt) ||
    value.updatedAt < value.createdAt ||
    typeof value.favorite !== 'boolean' ||
    typeof value.collection !== 'string' ||
    value.collection.length > 120 ||
    typeof value.trashed !== 'boolean' ||
    (value.text !== undefined && typeof value.text !== 'string') ||
    (value.thumbnail !== undefined && (typeof value.thumbnail !== 'string' || value.thumbnail.length > 100_000 || !/^data:image\/jpeg;base64,[A-Za-z0-9+/]+=*$/.test(value.thumbnail))) ||
    (value.kind === 'note' && (typeof value.text !== 'string' || new TextEncoder().encode(value.text).byteLength !== value.size))
  ) {
    throw new Error('An item could not be read safely. Its metadata is invalid.')
  }
  if (typeof value.text === 'string' && new TextEncoder().encode(value.text).byteLength > MAX_NOTE_BYTES) {
    throw new Error('This note exceeds the supported size.')
  }
}

function normalizeCollection(value = 'Personal') {
  const name = value.trim() || 'Personal'
  if (name.length > 120) throw new Error('Collection names must be 120 characters or fewer.')
  return name
}

function classifyFile(mimeType: string): VaultItem['kind'] {
  if (RASTER_MIME_TYPES.has(mimeType)) return 'photo'
  if (DOCUMENT_MIME_TYPES.has(mimeType)) return 'document'
  return 'other'
}

async function makeThumbnail(file: File): Promise<string | undefined> {
  if (typeof createImageBitmap !== 'function' || typeof document === 'undefined') return undefined
  let bitmap: ImageBitmap | undefined
  try {
    bitmap = await createImageBitmap(file, { resizeWidth: 360, resizeQuality: 'medium' })
    const factor = Math.min(1, 360 / Math.max(bitmap.width, bitmap.height))
    const canvas = document.createElement('canvas')
    canvas.width = Math.max(1, Math.round(bitmap.width * factor))
    canvas.height = Math.max(1, Math.round(bitmap.height * factor))
    const context = canvas.getContext('2d')
    if (!context) return undefined
    context.fillStyle = '#f3f5ee'
    context.fillRect(0, 0, canvas.width, canvas.height)
    context.drawImage(bitmap, 0, 0, canvas.width, canvas.height)
    const thumbnail = canvas.toDataURL('image/jpeg', .7)
    canvas.width = 0
    canvas.height = 0
    return thumbnail.length <= 100_000 ? thumbnail : undefined
  } catch {
    // A codec failure must not prevent storing the original encrypted file.
    return undefined
  } finally {
    bitmap?.close()
  }
}

function itemReference(uid: string, id: string, key: CryptoKey) {
  validateId(id)
  const binding = keyContext(key)
  return binding ? doc(requireDatabase(), 'users', uid, 'generations', binding.generation, 'items', id) : doc(requireDatabase(), 'users', uid, 'items', id)
}

function fileReference(uid: string, id: string, key: CryptoKey, staged = false) {
  validateId(id)
  const binding = keyContext(key)
  return ref(requireStorage(), staged ? `staged/${uid}/${binding?.generation || 'legacy'}/${id}` : binding ? `generations/${uid}/${binding.generation}/${id}` : `vaults/${uid}/${id}`)
}

async function encryptMetadata(key: CryptoKey, item: VaultItem): Promise<EncryptedPayload> {
  const payload = await encryptJson(key, item, `metadata:${item.id}`)
  if (payload.ciphertext.length > MAX_METADATA_CIPHERTEXT_CHARS) {
    throw new Error('This item contains too much text for one vault entry.')
  }
  return payload
}

export async function getVaultConfig(): Promise<VaultConfig | null> {
  const uid = getVaultUserId()
  const snapshot = await getDocFromServer(doc(requireDatabase(), 'users', uid, 'vault', 'config'))
  if (!snapshot.exists()) return null
  const config: unknown = snapshot.data()
  if (isRecord(config) && ![1, 2].includes(Number(config.version))) throw new Error('Unsupported vault version. Update Haven to a compatible client; do not reset the configuration. Restore a compatible encrypted generation if needed.')
  if (isRecord(config) && config.version === 2) { validateKeyRecord(config as unknown as import("./keys").KeyRecord); return config as unknown as VaultConfig }
  if (
    !isRecord(config) ||
    config.version !== 1 ||
    typeof config.salt !== 'string' ||
    typeof config.iterations !== 'number' ||
    !Number.isSafeInteger(config.iterations)
  ) {
    throw new Error('The vault encryption configuration is invalid.')
  }
  validatePayload(config.verifier)
  return config as unknown as VaultConfig
}

export async function saveVaultConfig(config: VaultConfig): Promise<void> {
  if (config.version === 2) { await securityCall('createKeys', { record: config }); return }
  const uid = getVaultUserId()
  const database = requireDatabase()
  const configRef = doc(database, 'users', uid, 'vault', 'config')
  // A concurrent setup must never replace the salt/key of an existing vault.
  await runTransaction(database, async (transaction) => {
    const existing = await transaction.get(configRef)
    if (existing.exists()) {
      throw new Error('This vault is already set up. Unlock it with its existing passphrase.')
    }
    transaction.set(configRef, config)
  })
}

export async function listVaultItems(key: CryptoKey): Promise<VaultItem[]> {
  const uid = getVaultUserId()
  const snapshot = await getDocsFromServer(firestoreCollection(requireDatabase(), ...(keyContext(key) ? ['users', uid, 'generations', keyContext(key)!.generation, 'items'] : ['users', uid, 'items']) as [string, ...string[]]))
  const items = await Promise.all(snapshot.docs.map(async (entry) => {
    const record = entry.data()
    validateId(entry.id)
    if (Object.keys(record).some(k => !['payload', 'revision', 'objectBytes', 'staged', 'deleting'].includes(k)) || !('payload' in record)) {
      throw new Error('An encrypted vault record has an unexpected format.')
    }
    validatePayload(record.payload)
    const item = await decryptJson<unknown>(key, record.payload, `metadata:${entry.id}`)
    validateItem(item, entry.id)
    return { ...item, revision: record.revision || 0, objectBytes: record.objectBytes || 0, staged: record.staged || false, deleting: record.deleting } as VaultItem
  }))
  const catalog = await loadCollections(key, items)
  return items.map(item => displayCollection(item, catalog)).sort((a, b) => b.createdAt - a.createdAt)
}

export type FileOperation = { id: string; itemId: string; kind: 'upload' | 'write' | 'delete'; status: 'pending' | 'cancelling' | 'cancelled' | 'deleting' | 'completed' | 'retired'; payload: EncryptedPayload; bytes: number; hash: string | null; revision?: number }
export function fileCall<T = { operation: FileOperation }>(key: CryptoKey, action: string, fields: Record<string, unknown> = {}) {
  return securityCall<T>(`files.${action}`, { generation: keyContext(key)?.generation || 'legacy', ...fields })
}
export type VaultCollection = { id: string; name: string; legacyNames: string[] }
export type CollectionCatalog = { revision: number; itemEpoch: number; entries: VaultCollection[] }
let catalogs = new WeakMap<CryptoKey, CollectionCatalog>()
const PERSONAL_ID = '00000000-0000-4000-8000-000000000001'
export function displayCollection(item: VaultItem, catalog: CollectionCatalog): VaultItem {
  const entry = catalog.entries.find(c => item.collectionId ? c.id === item.collectionId : c.legacyNames.includes(item.collection))
  return entry ? { ...item, collection: entry.name, collectionId: entry.id } : item
}
export async function loadCollections(key: CryptoKey, items: VaultItem[] = []): Promise<CollectionCatalog> {
  const check = sensitiveGuard()
  const data = await fileCall<{ catalog: { payload?: EncryptedPayload; revision?: number; itemEpoch?: number } | null; migrationPending?: boolean }>(key, 'list')
  check()
  const current = data.catalog
  if (current?.payload) {
    const entries = await decryptJson<VaultCollection[]>(key, current.payload, 'collections')
    check(); validateCollections(entries)
    const catalog = { entries, revision: current.revision!, itemEpoch: current.itemEpoch || 0 }; catalogs.set(key, catalog); return catalog
  }
  const entries: VaultCollection[] = [{ id: PERSONAL_ID, name: 'Personal', legacyNames: ['Personal'] }]
  for (const item of items) {
    const name = normalizeCollection(item.collection)
    const same = entries.find(c => c.name.toLocaleLowerCase() === name.toLocaleLowerCase())
    if (same) { if (!same.legacyNames.includes(item.collection)) same.legacyNames.push(item.collection) }
    else entries.push({ id: crypto.randomUUID(), name, legacyNames: [item.collection] })
  }
  const catalog = { entries, revision: current?.revision || 0, itemEpoch: current?.itemEpoch || 0 }
  catalogs.set(key, catalog)
  if (data.migrationPending) return catalog // Read-only unlock remains available so Security can resume migration.
  try { return await saveCollections(key, catalog, entries) }
  catch (error) { catalogs.delete(key); throw error }
}
export function validateCollections(entries: VaultCollection[]) {
  if (!Array.isArray(entries) || entries.length > 500 || !entries.some(c => c.id === PERSONAL_ID && c.name === 'Personal')) throw new Error('Invalid collections. Personal must be retained.')
  const names = new Set<string>(), ids = new Set<string>()
  for (const c of entries) {
    validateId(c.id)
    if (!c.name.trim() || c.name !== c.name.trim()) throw new Error('Collection names cannot be empty or have outer spaces.')
    const name = normalizeCollection(c.name).toLocaleLowerCase()
    if (names.has(name) || ids.has(c.id) || !Array.isArray(c.legacyNames) || c.legacyNames.some(n => typeof n !== 'string' || n.length > 120)) throw new Error('Choose unique collection names (case insensitive).')
    names.add(name); ids.add(c.id)
  }
}
export async function saveCollections(key: CryptoKey, catalog: CollectionCatalog, entries: VaultCollection[]) {
  const check = sensitiveGuard(); validateCollections(entries)
  const payload = await encryptJson(key, entries, 'collections')
  check()
  const result = await fileCall<{ revision: number }>(key, 'catalog', { payload, expectedRevision: catalog.revision, expectedEpoch: catalog.itemEpoch })
  check()
  const next = { ...catalog, revision: result.revision, entries }; catalogs.set(key, next); return next
}
async function collectionFields(key: CryptoKey, name?: string) {
  const catalog = catalogs.get(key) || await loadCollections(key)
  const entry = catalog.entries.find(c => c.name === normalizeCollection(name))
  if (!entry) throw new Error('This collection changed. Reload collections and choose a destination.')
  return { collection: entry.name, collectionId: entry.id }
}
let writes = new WeakMap<CryptoKey, Map<string, { signature: string; id: string; item: VaultItem; payload: EncryptedPayload; catalogRevision: number }>>()
const activeWriteCaches = new Set<Map<string, { signature: string; item: VaultItem }>>()
registerPlaintextCleanup(() => {
  for (const cache of activeWriteCaches) {
    for (const prepared of cache.values()) {
      prepared.signature = ''
      prepared.item.name = ''; prepared.item.collection = ''; prepared.item.text = undefined; prepared.item.thumbnail = undefined
    }
    cache.clear()
  }
  activeWriteCaches.clear(); writes = new WeakMap(); catalogs = new WeakMap()
})
async function writeItem(key: CryptoKey, draft: VaultItem, kind: 'write' | 'delete', identity = draft.id): Promise<FileOperation> {
  const check = sensitiveGuard()
  let pending = writes.get(key)
  if (!pending) { pending = new Map(); writes.set(key, pending); activeWriteCaches.add(pending) }
  const signature = JSON.stringify({ ...draft, updatedAt: 0 })
  let prepared = pending.get(identity)
  if (prepared && prepared.signature !== signature) throw new Error('A previous change is unconfirmed. Reload and reconcile it before changing this draft.')
  if (!prepared) {
    prepared = { signature, id: draft.deleting || (draft.revision ? crypto.randomUUID() : draft.id), item: { ...draft }, payload: await encryptMetadata(key, draft), catalogRevision: catalogs.get(key)?.revision || 0 }; check()
    pending.set(identity, prepared)
  }
  check()
  if (!draft.deleting) {
    try { await fileCall(key, 'begin', { id: prepared.id, itemId: draft.id, kind, payload: prepared.payload, expectedRevision: draft.revision || 0, catalogRevision: prepared.catalogRevision }) }
    catch (error) {
      if (['functions/aborted', 'functions/invalid-argument', 'functions/failed-precondition'].includes((error as { code?: string }).code || '')) pending.delete(identity)
      throw error
    }
  }
  check()
  const result = await fileCall(key, 'finalize', { id: prepared.id }); check()
  if (result.operation.status !== 'completed') throw new Error('Write is unfinished. Reconcile or retry cleanup.')
  pending.delete(identity)
  return result.operation
}
export function validateUpload(file: File) {
  if (file.size > MAX_FILE_SIZE) throw new Error('Each file must be 50 MiB or smaller.')
  if (!file.name.trim() || file.name.length > 1024 || file.type.length > 255) throw new Error('The file name or type is unsupported.')
}
export type UploadControl = { id?: string; signal?: AbortSignal; check?: () => void; progress?: (state: 'encrypting' | 'uploading' | 'finalizing', transferred?: number, total?: number) => void; prepared?: (value: PreparedUpload) => void }
export type PreparedUpload = { id: string; item: VaultItem; encrypted: Blob; hash: string; payload: EncryptedPayload; catalogRevision: number }
function checkUpload(control: UploadControl) {
  control.signal?.throwIfAborted(); control.check?.()
}
export async function prepareUpload(key: CryptoKey, file: File, collection?: string, control: UploadControl = {}): Promise<PreparedUpload> {
  const guard = sensitiveGuard(); const externalCheck = control.check; control = { ...control, check: () => { guard(); externalCheck?.() } }
  validateUpload(file); checkUpload(control)
  const id = control.id || crypto.randomUUID(), now = Date.now()
  const item: VaultItem = { id, name: file.name, kind: classifyFile(file.type), mimeType: file.type || 'application/octet-stream', size: file.size, createdAt: now, updatedAt: now, favorite: false, ...(await collectionFields(key, collection)), trashed: false, staged: true }
  checkUpload(control); control.progress?.('encrypting')
  if (item.kind === 'photo') { const thumbnail = await makeThumbnail(file); checkUpload(control); if (thumbnail) item.thumbnail = thumbnail }
  validateItem(item, id)
  const plaintext = await file.arrayBuffer()
  let encrypted: Blob
  try { checkUpload(control); encrypted = await encryptFile(key, plaintext, `file:${id}`); checkUpload(control) }
  finally { new Uint8Array(plaintext).fill(0) }
  const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', await encrypted.arrayBuffer())), b => b.toString(16).padStart(2, '0')).join('')
  const payload = await encryptMetadata(key, item); checkUpload(control)
  return { id, item, encrypted, hash, payload, catalogRevision: catalogs.get(key)?.revision || 0 }
}
export async function transferUpload(key: CryptoKey, prepared: PreparedUpload, control: UploadControl = {}): Promise<VaultItem> {
  const guard = sensitiveGuard(); const externalCheck = control.check; control = { ...control, check: () => { guard(); externalCheck?.() } }
  const { id, item, encrypted, hash, payload, catalogRevision } = prepared
  checkUpload(control)
  const begun = await fileCall(key, 'begin', { id, itemId: id, kind: 'upload', payload, expectedRevision: 0, catalogRevision, bytes: encrypted.size, hash })
  checkUpload(control)
  if (begun.operation.status === 'completed') return { ...item, revision: begun.operation.revision, objectBytes: encrypted.size }
  if (begun.operation.status !== 'pending') throw new Error('This upload was cancelled. Select the file again to start a new upload.')
  checkUpload(control)
  // Inspect the receipt's immutable object before transferring. A lost upload acknowledgement must never overwrite it.
  let exists = false
  try {
    const stored = await getBlob(fileReference(getVaultUserId(), id, key, true), MAX_ENCRYPTED_FILE_SIZE)
    const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', await stored.arrayBuffer())), b => b.toString(16).padStart(2, '0')).join('')
    if (digest !== hash) throw new Error('Staged encrypted object differs. Cancel and retry with a new operation.')
    exists = true
  } catch (error) { if ((error as { code?: string }).code !== 'storage/object-not-found') throw error }
  checkUpload(control)
  if (!exists) await new Promise<void>((resolve, reject) => {
    const task = uploadBytesResumable(fileReference(getVaultUserId(), id, key, true), encrypted, { contentType: 'application/octet-stream', cacheControl: 'private, no-store, max-age=0' })
    const cancel = () => task.cancel()
    control.signal?.addEventListener('abort', cancel, { once: true })
    task.on('state_changed', snapshot => control.progress?.('uploading', snapshot.bytesTransferred, snapshot.totalBytes), error => { control.signal?.removeEventListener('abort', cancel); reject(error) }, () => { control.signal?.removeEventListener('abort', cancel); resolve() })
    if (control.signal?.aborted) cancel()
  })
  checkUpload(control); control.progress?.('finalizing')
  const result = await fileCall(key, 'finalize', { id }); checkUpload(control)
  if (result.operation.status !== 'completed') throw new Error('Upload is not complete. Retry cleanup or finalization.')
  return { ...item, revision: result.operation.revision, objectBytes: encrypted.size }
}
export async function resumeUploadReceipt(key: CryptoKey, id: string): Promise<VaultItem> {
  const check = sensitiveGuard()
  const result = await fileCall(key, 'finalize', { id }); check()
  if (result.operation.status !== 'completed') throw new Error('Transfer is incomplete. Cancel cleanup, then reselect the original file.')
  const item = await decryptJson<VaultItem>(key, result.operation.payload, `metadata:${id}`); check(); validateItem(item, id)
  return { ...item, revision: result.operation.revision, objectBytes: result.operation.bytes }
}
export async function uploadVaultFile(key: CryptoKey, file: File, collection?: string, control: UploadControl = {}): Promise<VaultItem> {
  const prepared = await prepareUpload(key, file, collection, control); control.prepared?.(prepared)
  return transferUpload(key, prepared, control)
}
async function confirmedItem(key: CryptoKey, operation: FileOperation): Promise<VaultItem> {
  const check = sensitiveGuard()
  const saved = await decryptJson<VaultItem>(key, operation.payload, `metadata:${operation.itemId}`); check(); validateItem(saved, operation.itemId)
  return { ...saved, revision: operation.revision }
}
export async function saveVaultNote(key: CryptoKey, title: string, text: string, collection?: string, identity = crypto.randomUUID()): Promise<VaultItem> {
  const check = sensitiveGuard()
  const cached = writes.get(key)?.get(identity)
  if (cached) {
    if (cached.item.name !== title.trim() || cached.item.text !== text || cached.item.collection !== normalizeCollection(collection)) throw new Error('The previous save is unconfirmed. Reload and reconcile it before changing the draft.');
    const operation = await writeItem(key, cached.item, 'write', identity); check(); return confirmedItem(key, operation)
  }
  const now = Date.now(), item: VaultItem = { id: identity, name: title.trim(), kind: 'note', mimeType: 'text/plain', size: new TextEncoder().encode(text).byteLength, createdAt: now, updatedAt: now, favorite: false, ...(await collectionFields(key, collection)), trashed: false, text }
  check(); validateItem(item, item.id)
  const result = await writeItem(key, item, 'write', identity)
  return confirmedItem(key, result)
}
export async function updateVaultItem(key: CryptoKey, item: VaultItem): Promise<void> {
  const check = sensitiveGuard()
  const updated = { ...item, ...(await collectionFields(key, item.collection)), updatedAt: Math.max(Date.now(), item.createdAt) }
  check(); validateItem(updated, item.id)
  const result = await writeItem(key, updated, 'write')
  Object.assign(item, await confirmedItem(key, result))
}

export async function downloadVaultFile(key: CryptoKey, item: VaultItem): Promise<Blob> {
  const uid = getVaultUserId()
  validateItem(item, item.id)
  if (item.kind === 'note') throw new Error('Notes do not have an attached file.')
  const encrypted = await getBlob(fileReference(uid, item.id, key, item.staged), MAX_ENCRYPTED_FILE_SIZE)
  const plaintext = await decryptFile(key, encrypted, `file:${item.id}`)
  try {
    if (plaintext.byteLength !== item.size) {
      throw new Error('The file does not match its encrypted metadata.')
    }
    return new Blob([plaintext], { type: item.mimeType })
  } finally {
    new Uint8Array(plaintext).fill(0)
  }
}

export async function permanentlyDeleteVaultItem(item: VaultItem, key: CryptoKey): Promise<void> {
  validateItem(item, item.id)
  if (!item.trashed) throw new Error('Move this item to the trash before deleting it permanently.')
  await writeItem(key, item, 'delete')
}
export async function reconcileOperations(key: CryptoKey) {
  const check = sensitiveGuard()
  const { operations } = await fileCall<{ operations: FileOperation[] }>(key, 'list')
  const results: { id: string; state: string }[] = []
  for (const operation of operations) {
    check()
    try { const result = await fileCall(key, 'finalize', { id: operation.id }); results.push({ id: operation.id, state: result.operation.status }) }
    catch { results.push({ id: operation.id, state: operation.status === 'pending' ? 'Reselect original or retry finalization' : 'Cleanup pending; reconnect and retry' }) }
  }
  check()
  const pending = writes.get(key)
  if (pending) for (const [identity, write] of pending) { const status = await fileCall(key, 'status', { id: write.id }); if (!status.operation || ['completed', 'cancelled', 'retired'].includes(status.operation.status)) pending.delete(identity) }
  return results
}
