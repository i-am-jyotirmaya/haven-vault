import { beforeEach, expect, it, vi } from 'vitest'
const mocks = vi.hoisted(() => ({ prepare: vi.fn(), transfer: vi.fn(), resume: vi.fn(), call: vi.fn() }))
vi.mock('./vault', () => ({ prepareUpload: mocks.prepare, transferUpload: mocks.transfer, resumeUploadReceipt: mocks.resume, validateUpload: (file: File) => { if (file.size > 50 * 1024 * 1024) throw new Error('Too large') } }))
vi.mock('./keys', () => ({ keyContext: () => ({ generation: 'fixture-generation' }) }))
vi.mock('./security', () => ({ securityCall: mocks.call }))
import { UploadQueue, operationGuidance, type QueueEntry } from './uploadQueue'
const deferred = <T>() => { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done }); return { promise, resolve } }
const file = (name: string) => new File(['fictional'], name)
const flush = async () => { for (let i = 0; i < 30; i++) await Promise.resolve() }
let entries: QueueEntry[], saved: ReturnType<typeof vi.fn>, queue: UploadQueue
beforeEach(() => {
  vi.clearAllMocks(); entries = []; saved = vi.fn()
  mocks.prepare.mockImplementation(async (_key, source, _collection, control) => { control.progress('encrypting'); return { id: control.id, item: { id: control.id, name: source.name }, encrypted: new Blob(['encrypted']), hash: 'a' } })
  mocks.transfer.mockImplementation(async (_key, prepared, control) => { control.progress('uploading', 3, 10); control.progress('finalizing'); return prepared.item })
  mocks.resume.mockImplementation(async (_key, id) => ({ id, name: 'reconciled' }))
  mocks.call.mockResolvedValue({ operation: { status: 'cancelled' } })
  queue = new UploadQueue({} as CryptoKey, 'Personal', () => {}, next => { entries = next }, saved)
})
it('bounds encryption concurrency to one, preserves partial successes and targets only failed retry', async () => {
  const gate = deferred<any>(); mocks.transfer.mockImplementationOnce(() => gate.promise).mockRejectedValueOnce({ code: 'storage/retry-limit-exceeded' })
  queue.add([file('one'), file('two'), file('three')]); await flush()
  expect(mocks.prepare).toHaveBeenCalledTimes(1)
  gate.resolve({ id: entries[0].id, name: 'one' }); await flush()
  expect(entries.map(e => e.state)).toEqual(['completed', 'failed', 'completed']); expect(saved).toHaveBeenCalledTimes(2)
  queue.retry(entries[1].id); await flush()
  expect(entries.map(e => e.state)).toEqual(['completed', 'completed', 'completed'])
  expect(mocks.prepare).toHaveBeenCalledTimes(3); expect(mocks.transfer).toHaveBeenCalledTimes(3); expect(mocks.resume).toHaveBeenCalledWith(expect.anything(), entries[1].id)
})
it.each(['encrypting', 'uploading', 'finalizing'] as const)('cancels during %s and reports actual remote completion', async state => {
  const gate = deferred<any>()
  if (state === 'encrypting') mocks.prepare.mockImplementationOnce(async (_key, source, _collection, control) => { control.progress(state); await gate.promise; control.signal.throwIfAborted(); return { item: source } })
  else mocks.transfer.mockImplementationOnce(async (_key, prepared, control) => { control.progress(state, 3, 10); await gate.promise; control.signal.throwIfAborted(); return prepared.item })
  queue.add([file('fixture')]); await flush(); expect(entries[0].state).toBe(state)
  await queue.cancel(entries[0].id); gate.resolve(undefined); await flush()
  expect(entries[0].state).toBe('cancelled'); expect(saved).not.toHaveBeenCalled()
  expect(mocks.call).toHaveBeenCalledWith('files.cancel', expect.objectContaining({ generation: 'fixture-generation' }))
})
it('a finalization that already committed wins cancellation and publishes its saved item once', async () => {
  const gate = deferred<any>()
  mocks.transfer.mockImplementationOnce(async (_key, prepared, control) => { control.progress('finalizing'); await gate.promise; control.signal.throwIfAborted(); return prepared.item })
  mocks.call.mockResolvedValue({ operation: { status: 'completed', revision: 1 } })
  queue.add([file('fixture')]); await flush(); await queue.cancel(entries[0].id); gate.resolve(undefined); await flush()
  expect(entries[0].state).toBe('completed'); expect(saved).toHaveBeenCalledTimes(1)
})
it('offline cancellation stays failed and retryable until cleanup is confirmed', async () => {
  mocks.transfer.mockRejectedValue(new Error('network'))
  mocks.call.mockRejectedValueOnce(new Error('offline'))
  queue.add([file('fixture')]); await flush(); await queue.cancel(entries[0].id)
  expect(entries[0].state).toBe('failed'); expect(entries[0].error).toContain('cleanup pending')
  await queue.cancel(entries[0].id); expect(entries[0].state).toBe('cancelled')
})
it('closing on lock clears queue and prevents late decrypted results or callbacks', async () => {
  const gate = deferred<any>(); mocks.prepare.mockImplementationOnce(() => gate.promise)
  queue.add([file('private-fixture')]); await flush(); queue.close()
  gate.resolve({ id: 'late', item: { name: 'private-fixture' } }); await flush()
  expect(queue.entries).toEqual([]); expect(saved).not.toHaveBeenCalled(); expect(mocks.transfer).not.toHaveBeenCalled()
})
it('validates oversized files before encryption and cancels the remaining queued work', async () => {
  const oversized = file('oversized'); Object.defineProperty(oversized, 'size', { value: 50 * 1024 * 1024 + 1 })
  const gate = deferred<any>(); mocks.prepare.mockImplementationOnce(() => gate.promise)
  queue.add([oversized, file('active'), file('waiting')]); await flush(); queue.cancelRemaining(); await flush()
  expect(mocks.prepare).toHaveBeenCalledTimes(1); expect(entries[2].state).toBe('cancelled')
  gate.resolve({ item: {} }); await flush(); expect(saved).not.toHaveBeenCalled()
})
it('provides useful guidance without interpolating private service errors', () => {
  expect(operationGuidance({ code: 'functions/resource-exhausted', message: 'private-name' })).toContain('quota')
  expect(operationGuidance({ code: 'functions/unauthenticated' })).toContain('Session expired')
  expect(operationGuidance({ code: 'functions/aborted' })).toContain('Reload')
  expect(operationGuidance(new Error('private-name'))).not.toContain('private-name')
})

it('bounds encrypted retry-buffer retention after multiple failures and makes evicted failures retryable through receipts', async () => {
  mocks.transfer.mockRejectedValue(new Error('offline'))
  queue.add([file('large-one'), file('large-two')]); await flush()
  expect(entries.every(e => e.state === 'failed')).toBe(true)
  expect(entries[0].error).toContain('Retry buffer released')
  queue.retry(entries[0].id); await flush()
  expect(mocks.resume).toHaveBeenCalledTimes(1); expect(entries[0].state).toBe('completed')
})
