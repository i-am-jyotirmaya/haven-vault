import { keyContext, validateKeyRecord } from './keys'
import { securityCall } from './security'
import {
  collection as firestoreCollection,
  deleteDoc,
  doc,
  getDocFromServer,
  getDocsFromServer,
  runTransaction,
  setDoc,
} from 'firebase/firestore'
import { deleteObject, getBlob, ref, uploadBytes } from 'firebase/storage'
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
const MAX_NOTE_BYTES = 256 * 1024
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
  text?: string
  thumbnail?: string
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
    (value.kind === 'note' && typeof value.text !== 'string')
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

function fileReference(uid: string, id: string, key: CryptoKey) {
  validateId(id)
  const binding = keyContext(key)
  return ref(requireStorage(), binding ? `generations/${uid}/${binding.generation}/${id}` : `vaults/${uid}/${id}`)
}

function isMissingObject(error: unknown) {
  return isRecord(error) && error.code === 'storage/object-not-found'
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
    if (Object.keys(record).length !== 1 || !('payload' in record)) {
      throw new Error('An encrypted vault record has an unexpected format.')
    }
    validatePayload(record.payload)
    const item = await decryptJson<unknown>(key, record.payload, `metadata:${entry.id}`)
    validateItem(item, entry.id)
    return item
  }))
  return items.sort((a, b) => b.createdAt - a.createdAt)
}

export async function uploadVaultFile(
  key: CryptoKey,
  file: File,
  collection?: string,
): Promise<VaultItem> {
  const uid = getVaultUserId()
  if (file.size > MAX_FILE_SIZE) throw new Error('Choose a file smaller than 50 MB.')
  if (!file.name.trim() || file.name.length > 1024) throw new Error('The file name is invalid.')
  const id = crypto.randomUUID()
  const now = Date.now()
  const item: VaultItem = {
    id,
    name: file.name,
    kind: classifyFile(file.type),
    mimeType: file.type || 'application/octet-stream',
    size: file.size,
    createdAt: now,
    updatedAt: now,
    favorite: false,
    collection: normalizeCollection(collection),
    trashed: false,
  }
  if (item.kind === 'photo') {
    const thumbnail = await makeThumbnail(file)
    if (thumbnail) item.thumbnail = thumbnail
  }
  validateItem(item, id)
  const plaintext = await file.arrayBuffer()
  let encrypted: Blob
  try {
    encrypted = await encryptFile(key, plaintext, `file:${id}`)
  } finally {
    // Best-effort reduction of plaintext lifetime; the browser owns the File.
    new Uint8Array(plaintext).fill(0)
  }
  const payload = await encryptMetadata(key, item)
  const fileRef = fileReference(uid, id, key)
  await uploadBytes(fileRef, encrypted, {
    contentType: 'application/octet-stream',
    cacheControl: 'private, no-store, max-age=0',
  })
  try {
    await setDoc(itemReference(uid, id, key), { payload })
  } catch (metadataError) {
    try {
      await deleteObject(fileRef)
    } catch (cleanupError) {
      if (!isMissingObject(cleanupError)) {
        throw new Error(
          'The upload could not finish and its encrypted file could not be cleaned up. Retry after reconnecting.',
          { cause: metadataError },
        )
      }
    }
    throw metadataError
  }
  return item
}

export async function saveVaultNote(
  key: CryptoKey,
  title: string,
  text: string,
  collection?: string,
): Promise<VaultItem> {
  const uid = getVaultUserId()
  const name = title.trim()
  if (!name || name.length > 1024) throw new Error('Add a title of 1–1024 characters.')
  const size = new TextEncoder().encode(text).byteLength
  if (size > MAX_NOTE_BYTES) throw new Error('Keep notes below 256 KB.')
  const now = Date.now()
  const item: VaultItem = {
    id: crypto.randomUUID(),
    name,
    kind: 'note',
    mimeType: 'text/plain',
    size,
    createdAt: now,
    updatedAt: now,
    favorite: false,
    collection: normalizeCollection(collection),
    trashed: false,
    text,
  }
  const payload = await encryptMetadata(key, item)
  await setDoc(itemReference(uid, item.id, key), { payload })
  return item
}

export async function updateVaultItem(key: CryptoKey, item: VaultItem): Promise<void> {
  const uid = getVaultUserId()
  const updated = { ...item, updatedAt: Math.max(Date.now(), item.createdAt) }
  validateItem(updated, item.id)
  const payload = await encryptMetadata(key, updated)
  await setDoc(itemReference(uid, item.id, key), { payload })
}

export async function downloadVaultFile(key: CryptoKey, item: VaultItem): Promise<Blob> {
  const uid = getVaultUserId()
  validateItem(item, item.id)
  if (item.kind === 'note') throw new Error('Notes do not have an attached file.')
  const encrypted = await getBlob(fileReference(uid, item.id, key), MAX_ENCRYPTED_FILE_SIZE)
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
  const uid = getVaultUserId()
  validateItem(item, item.id)
  if (!item.trashed) throw new Error('Move this item to the trash before deleting it permanently.')
  if (item.kind !== 'note') {
    try {
      await deleteObject(fileReference(uid, item.id, key))
    } catch (error) {
      if (!isMissingObject(error)) throw error
    }
  }
  // Delete metadata last so a partial deletion remains visible and retryable.
  await deleteDoc(itemReference(uid, item.id, key))
}
