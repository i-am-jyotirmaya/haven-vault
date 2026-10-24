import { collection, doc, getDocFromServer, getDocsFromServer, setDoc } from 'firebase/firestore'
import { ref, getBlob, uploadBytes } from 'firebase/storage'
import { db, storage, getVaultUserId, validateVaultSession } from './firebase'
import { decryptFile, decryptJson, encryptFile, encryptJson, unlockVault, type LegacyVaultConfig } from './crypto'
import { createKeyRecord, unlockKeyRecord, type KeyRecord } from './keys'
import { securityCall } from './security'
import { listVaultItems, type VaultItem } from './vault'
export type MigrationState = { phase: 'staging' | 'verifying' | 'complete'; record: KeyRecord; cursor: string; verified: number }
const sameBytes = (a: ArrayBuffer, b: ArrayBuffer) => {
  const left = new Uint8Array(a), right = new Uint8Array(b)
  if (left.length !== right.length) return false
  for (let i = 0; i < left.length; i++) if (left[i] !== right[i]) return false
  return true
}
/** A retained original plus verified Admin-only file copies is the rollback safeguard.
 * No original ciphertext is mutated; progress is encrypted and idempotent. */
export async function migrateVault(passphrase: string, legacy: LegacyVaultConfig, check: () => void, progress: (text: string) => void) {
  const uid = getVaultUserId()
  if (!db || !storage) throw new Error('Firebase is not configured.')
  const database = db, bucket = storage
  const oldKey = await unlockVault(passphrase, legacy); check()
  const status = await securityCall<{ migration: MigrationState | null; config: unknown; completed?: string[] }>('migrationStatus'); check()
  const prepared = status.migration ? null : await createKeyRecord(passphrase); check()
  const { migration } = await securityCall<{ migration: MigrationState }>('migrationBegin', { record: status.migration?.record || prepared!.config }); check()
  const key = await unlockKeyRecord(passphrase, migration.record); check()
  const completed = new Set(status.completed || [])
  if (migration.phase === 'staging') {
    const originals = await getDocsFromServer(collection(database, 'users', uid, 'items')); check()
    for (const [index, source] of originals.docs.entries()) {
      check(); await validateVaultSession(); check()
      progress(`Verifying encrypted item ${index + 1} of ${originals.size}…`)
      const value = await decryptJson<VaultItem>(oldKey, source.data().payload, `metadata:${source.id}`); check()
      if (value.id !== source.id) throw new Error('The legacy item identifier is invalid. Originals were preserved.')
      const destination = doc(database, 'users', uid, 'generations', migration.record.generation, 'items', source.id)
      const staged = await getDocFromServer(destination); check()
      if (!staged.exists()) {
        const payload = await encryptJson(key, value, `metadata:${source.id}`); check()
        await setDoc(destination, { payload }); check()
      }
      const saved = await getDocFromServer(destination); check()
      const decoded = await decryptJson(key, saved.data()!.payload, `metadata:${source.id}`); check()
      if (JSON.stringify(value) !== JSON.stringify(decoded)) throw new Error('Staged metadata failed verification. Originals were preserved.')
      if (value.kind !== 'note') {
        const original = await getBlob(ref(bucket, `vaults/${uid}/${source.id}`), 50 * 1024 * 1024 + 29); check()
        const raw = await decryptFile(oldKey, original, `file:${source.id}`)
        try {
          check()
          if (raw.byteLength !== value.size) throw new Error('Legacy file length mismatch.')
          const file = ref(bucket, `generations/${uid}/${migration.record.generation}/${source.id}`)
          let existing: Blob | null = null
          try { existing = await getBlob(file, 50 * 1024 * 1024 + 29) }
          catch (error) { if ((error as { code?: string }).code !== 'storage/object-not-found') throw error }
          check()
          if (!existing) {
            const encrypted = await encryptFile(key, raw, `file:${source.id}`); check()
            await uploadBytes(file, encrypted, { contentType: 'application/octet-stream', cacheControl: 'private, no-store, max-age=0' }); check()
          }
          const stored = await getBlob(file, 50 * 1024 * 1024 + 29); check()
          const verified = await decryptFile(key, stored, `file:${source.id}`)
          try { check(); if (!sameBytes(raw, verified)) throw new Error('Migrated file failed byte verification.') }
          finally { new Uint8Array(verified).fill(0) }
        } finally { new Uint8Array(raw).fill(0) }
      }
      check()
      if (!completed.has(source.id)) { await securityCall('migrationItem', { id: source.id, hasFile: value.kind !== 'note' }); check() }
    }
  }
  progress('Verifying the manifest and finalizing the active generation…')
  let done = false
  while (!done) {
    check(); await validateVaultSession(); check()
    const result = await securityCall<{ complete: boolean }>('migrationFinalize'); check()
    done = result.complete
  }
  const final = await securityCall<{ config: KeyRecord }>('migrationStatus'); check()
  if (final.config.generation !== migration.record.generation) throw new Error('Cutover could not be confirmed. Reload the latest vault.')
  const loaded = await listVaultItems(key); check()
  return { config: final.config, key, items: loaded }
}
