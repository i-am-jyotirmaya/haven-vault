import { keyContext } from './keys'
import { securityCall } from './security'
import { prepareUpload, transferUpload, resumeUploadReceipt, validateUpload, type PreparedUpload, type VaultItem } from './vault'
export type UploadState = 'queued' | 'encrypting' | 'uploading' | 'finalizing' | 'completed' | 'failed' | 'cancelling' | 'cancelled'
export type QueueEntry = { id: string; name: string; state: UploadState; transferred: number; total: number; error?: string }
export const operationGuidance = (error: unknown) => {
  const code = String((error as { code?: string })?.code || '')
  if (/unauthenticated|permission-denied/.test(code)) return 'Session expired or access denied. Sign in and unlock, then reconcile operations.'
  if (/quota|resource-exhausted/.test(code)) return 'Storage quota rejected the operation. Free capacity with your storage provider, then retry or cancel cleanup.'
  if (/failed-precondition|not-found/.test(code)) return 'Transfer or vault state is incomplete. Reload and reconcile. If the original is needed, cancel its receipt and select the file again; plaintext is never cached.'
  if (/aborted|already-exists/.test(code)) return 'The entry or collections changed. Reload the latest version before retrying; your draft remains until locking.'
  if (typeof navigator !== 'undefined' && !navigator.onLine) return 'Offline. Reconnect and retry. Remote completion or cleanup is not yet confirmed.'
  return 'Operation could not be confirmed. Retry after reconnecting, or reload to reconcile its receipt. No successful files will be uploaded again.'
}
/** One worker bounds full-file AES-GCM memory. Only failed pre-encryption entries retain a File. */
export class UploadQueue {
  entries: QueueEntry[] = []
  private files = new Map<string, File>()
  private encrypted = new Map<string, PreparedUpload>()
  private controllers = new Map<string, AbortController>()
  private destinations = new Map<string, string>()
  private generation: string
  private running = false
  private closed = false
  constructor(private key: CryptoKey | null, private collection: string, private check: () => void, private changed: (entries: QueueEntry[]) => void, private saved: (item: VaultItem) => void) { this.generation = key ? keyContext(key)?.generation || 'legacy' : 'legacy' }
  private emit() { if (!this.closed) this.changed(this.entries.map(e => ({ ...e }))) }
  add(files: File[], collection = this.collection) {
    for (const file of files) {
      const entry: QueueEntry = { id: crypto.randomUUID(), name: file.name, state: 'queued', transferred: 0, total: file.size + 29 }
      try { validateUpload(file); this.files.set(entry.id, file) }
      catch (error) { entry.state = 'failed'; entry.error = error instanceof Error ? error.message : 'Unsupported file.' }
      this.destinations.set(entry.id, collection); this.entries.push(entry)
    }
    this.emit(); void this.pump()
  }
  retry(id: string) {
    const entry = this.entries.find(e => e.id === id)
    if (!entry || entry.state !== 'failed') return
    entry.state = 'queued'; entry.error = undefined; this.emit(); void this.pump()
  }
  async cancel(id: string) {
    const entry = this.entries.find(e => e.id === id)
    if (!entry || ['completed', 'cancelled'].includes(entry.state)) return
    const previous = entry.state
    entry.state = 'cancelling'; this.controllers.get(id)?.abort(); this.files.delete(id); this.emit()
    if (previous === 'queued' && !this.encrypted.has(id)) { entry.state = 'cancelled'; this.emit(); return }
    // Active worker performs cleanup after its in-flight begin/upload/finalize has settled.
    if (this.controllers.has(id)) return
    await this.cleanup(entry)
  }
  cancelRemaining() { for (const entry of this.entries) void this.cancel(entry.id) }
  close() {
    this.closed = true; this.cancelRemaining(); this.files.clear(); this.encrypted.clear(); this.destinations.clear(); this.key = null; this.entries = []
  }
  private async cleanup(entry: QueueEntry) {
    try {
      const result = await securityCall<{ operation: { status: string; revision?: number } }>('files.cancel', { generation: this.generation, id: entry.id })
      const prepared = this.encrypted.get(entry.id)
      if (!this.closed && result.operation.status === 'completed' && prepared) { this.check(); this.saved({ ...prepared.item, revision: result.operation.revision, objectBytes: prepared.encrypted.size }) }
      entry.state = result.operation.status === 'completed' ? 'completed' : 'cancelled'
    } catch (error) {
      if ((error as { code?: string }).code === 'functions/not-found') entry.state = 'cancelled'
      else { entry.state = 'failed'; entry.error = 'Cancellation cleanup pending. Reconnect, unlock and retry cleanup.' }
    }
    this.encrypted.delete(entry.id); this.emit()
  }
  private async pump() {
    if (this.running || this.closed) return
    this.running = true
    try {
      for (;;) {
        const entry = this.entries.find(e => e.state === 'queued')
        if (!entry || this.closed || !this.key) break
        const controller = new AbortController(); this.controllers.set(entry.id, controller)
        const control = { id: entry.id, signal: controller.signal, check: () => { if (this.closed) throw new Error('Locked'); this.check() }, progress: (state: 'encrypting' | 'uploading' | 'finalizing', transferred = 0, total = entry.total) => { if (entry.state !== 'cancelling') { entry.state = state; entry.transferred = transferred; entry.total = total; this.emit() } } }
        try {
          let prepared = this.encrypted.get(entry.id)
          if (!prepared) {
            const file = this.files.get(entry.id)
            if (!file) {
              entry.state = 'finalizing'; this.emit()
              const item = await resumeUploadReceipt(this.key, entry.id)
              control.check(); controller.signal.throwIfAborted()
              entry.state = 'completed'; this.saved(item); continue
            }
            prepared = await prepareUpload(this.key, file, this.destinations.get(entry.id), control)
            control.check(); controller.signal.throwIfAborted()
            // Retain at most one full encrypted retry buffer, even if many files fail.
            for (const oldId of this.encrypted.keys()) {
              this.encrypted.delete(oldId)
              const old = this.entries.find(e => e.id === oldId)
              if (old) old.error = 'Retry buffer released to limit memory. Retry finalization; if transfer is incomplete, cancel cleanup then reselect the original file.'
            }
            this.encrypted.set(entry.id, prepared); this.files.delete(entry.id)
          }
          const item = await transferUpload(this.key, prepared, control)
          control.check(); controller.signal.throwIfAborted()
          entry.state = 'completed'; this.encrypted.delete(entry.id); this.saved(item)
        } catch (error) {
          if (controller.signal.aborted || this.closed) { entry.state = 'cancelling'; await this.cleanup(entry) }
          else { entry.state = 'failed'; entry.error = operationGuidance(error) }
        } finally { this.controllers.delete(entry.id); this.emit() }
      }
    } finally { this.running = false }
  }
}
