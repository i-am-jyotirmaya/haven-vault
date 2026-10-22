// Shared by previews/downloads so locking revokes URLs synchronously, before
// React unmount cleanup, and late promises cannot publish new plaintext URLs.
let generation = 0
const cleanups = new Set<() => void>()
export function registerPlaintextCleanup(cleanup: () => void) { cleanups.add(cleanup); return () => { cleanups.delete(cleanup) } }
const urls = new Set<string>()
export const plaintextGeneration = () => generation
export const plaintextIsCurrent = (value: number) => value === generation
export function createPlaintextUrl(blob: Blob): string {
  const url = URL.createObjectURL(blob)
  urls.add(url)
  return url
}
export function revokePlaintextUrl(url: string): void {
  if (urls.delete(url)) URL.revokeObjectURL(url)
}
export function clearPlaintext(): void {
  generation++
  cleanups.forEach(cleanup => cleanup())
  urls.forEach(url => URL.revokeObjectURL(url))
  urls.clear()
}
