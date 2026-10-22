/** V2 encryption hierarchy. Secrets never cross this module's network boundary. */
export type Box = { version: 2; iv: string; ciphertext: string }
export type PassphraseWrapper = { version: 2; kdf: 'PBKDF2-SHA256'; salt: string; iterations: number; box: Box }
export type RecoveryRecord = { version: 2; id: string; master: Box; privateKey: Box; publicKey: string }
export type KeyRecord = { version: 2; vaultId: string; generation: string; revision: number; passphrase: PassphraseWrapper; recovery: RecoveryRecord | null }
export type RecoveryKit = { version: 2; vaultId: string; recoveryId: string; secret: string; record: KeyRecord; instructions: string }
const enc = new TextEncoder()
const contexts = new WeakMap<CryptoKey, Pick<KeyRecord, 'vaultId' | 'generation'>>()
export const keyContext = (key: CryptoKey) => contexts.get(key)
export function bindKey(key: CryptoKey, record: KeyRecord) { contexts.set(key, { vaultId: record.vaultId, generation: record.generation }); return key }
export function b64(bytes: Uint8Array): string { return btoa(Array.from(bytes, c => String.fromCharCode(c)).join('')) }
export function unb64(value: string, max = 8192): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string' || value.length > max * 2 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error('Invalid key encoding.')
  const bytes = Uint8Array.from(atob(value), c => c.charCodeAt(0))
  if (bytes.length > max || b64(bytes) !== value) throw new Error('Invalid key encoding.')
  return bytes
}
export function validatePassphrase(value: string) {
  if (typeof value !== 'string' || [...value].length < 12 || value.length > 1024) throw new Error('Use a passphrase of 12–1,024 characters.')
}
export function validateKeyRecord(r: KeyRecord) {
  if (!r || r.version !== 2 || !/^[a-f0-9-]{36}$/.test(r.vaultId) || !/^[a-f0-9-]{36}$/.test(r.generation) || !Number.isSafeInteger(r.revision) || r.revision < 1 || r.passphrase?.version !== 2 || r.passphrase.kdf !== 'PBKDF2-SHA256' || !Number.isSafeInteger(r.passphrase.iterations) || r.passphrase.iterations < 600000 || r.passphrase.iterations > 2000000 || unb64(r.passphrase.salt, 32).length !== 32 || (r.recovery && (r.recovery.version !== 2 || !/^[a-f0-9-]{36}$/.test(r.recovery.id)))) throw new Error('Unsupported vault key record. Upgrade Haven or restore a compatible encrypted generation.')
}
const aad = (r: KeyRecord, purpose: string) => enc.encode(JSON.stringify(['haven', 2, r.vaultId, r.generation, purpose]))
async function seal(key: CryptoKey, bytes: Uint8Array<ArrayBuffer>, r: KeyRecord, purpose: string): Promise<Box> {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  return { version: 2, iv: b64(iv), ciphertext: b64(new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(r, purpose), tagLength: 128 }, key, bytes))) }
}
async function open(key: CryptoKey, box: Box, r: KeyRecord, purpose: string) {
  if (box?.version !== 2) throw new Error('Unsupported key wrapper version.')
  const iv = unb64(box.iv, 12)
  if (iv.length !== 12) throw new Error('Invalid wrapper nonce.')
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad(r, purpose), tagLength: 128 }, key, unb64(box.ciphertext)))
}
async function passKey(passphrase: string, wrapper: PassphraseWrapper) {
  validatePassphrase(passphrase)
  const bytes = enc.encode(passphrase)
  try {
    const material = await crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveKey'])
    return await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: unb64(wrapper.salt, 32), iterations: wrapper.iterations, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  } finally { bytes.fill(0) }
}
async function recoveryKey(secret: string, r: KeyRecord, purpose: string) {
  const raw = unb64(secret, 32)
  if (raw.length !== 32) throw new Error('Recovery secrets must contain 256 random bits.')
  try {
    const material = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey'])
    return await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: enc.encode(r.vaultId), info: aad(r, `recovery:${r.recovery!.id}:${purpose}`) }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  } finally { raw.fill(0) }
}
async function importMaster(raw: Uint8Array<ArrayBuffer>, r: KeyRecord) {
  if (raw.length !== 32) throw new Error('Invalid master key.')
  return bindKey(await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']), r)
}
async function wrapPass(raw: Uint8Array<ArrayBuffer>, passphrase: string, r: KeyRecord) {
  validatePassphrase(passphrase)
  const wrapper: PassphraseWrapper = { version: 2, kdf: 'PBKDF2-SHA256', salt: b64(crypto.getRandomValues(new Uint8Array(32))), iterations: 600000, box: {} as Box }
  wrapper.box = await seal(await passKey(passphrase, wrapper), raw, r, 'master:passphrase')
  return wrapper
}
export async function createKeyRecord(passphrase: string, identity = crypto.randomUUID()): Promise<{ key: CryptoKey; config: KeyRecord }> {
  const raw = crypto.getRandomValues(new Uint8Array(32))
  const config: KeyRecord = { version: 2, vaultId: identity, generation: crypto.randomUUID(), revision: 1, passphrase: {} as PassphraseWrapper, recovery: null }
  try { config.passphrase = await wrapPass(raw, passphrase, config); return { key: await importMaster(raw, config), config } }
  finally { raw.fill(0) }
}
async function passRaw(passphrase: string, r: KeyRecord) {
  validateKeyRecord(r)
  return open(await passKey(passphrase, r.passphrase), r.passphrase.box, r, 'master:passphrase')
}
export async function unlockKeyRecord(passphrase: string, r: KeyRecord) {
  const raw = await passRaw(passphrase, r)
  try { return await importMaster(raw, r) } finally { raw.fill(0) }
}
export async function changePassphrase(current: string, next: string, r: KeyRecord) {
  const raw = await passRaw(current, r)
  try { return { ...r, revision: r.revision + 1, passphrase: await wrapPass(raw, next, r) } } finally { raw.fill(0) }
}
export async function prepareRecovery(passphrase: string, r: KeyRecord): Promise<RecoveryKit> {
  const raw = await passRaw(passphrase, r)
  try { return await recoveryFromRaw(raw, { ...r, revision: r.revision + 1 }) } finally { raw.fill(0) }
}
async function recoveryFromRaw(raw: Uint8Array<ArrayBuffer>, r: KeyRecord): Promise<RecoveryKit> {
  const secretBytes = crypto.getRandomValues(new Uint8Array(32))
  const secret = b64(secretBytes); secretBytes.fill(0)
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const privateBytes = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey))
  const record: KeyRecord = { ...r, recovery: { version: 2, id: crypto.randomUUID(), master: {} as Box, privateKey: {} as Box, publicKey: b64(new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey))) } }
  try {
    record.recovery!.master = await seal(await recoveryKey(secret, record, 'master'), raw, record, `master:recovery:${record.recovery!.id}`)
    record.recovery!.privateKey = await seal(await recoveryKey(secret, record, 'authentication'), privateBytes, record, `authentication:recovery:${record.recovery!.id}`)
  } finally { privateBytes.fill(0) }
  return { version: 2, vaultId: record.vaultId, recoveryId: record.recovery!.id, secret, record, instructions: 'Protect this kit offline. It can decrypt your vault and, with fresh owner Google verification, replace passkeys. Open Haven → Recover vault. No usable unlock method and no kit means recovery is impossible. Older kits cannot be retracted from stolen encrypted backups.' }
}
export function checkKit(kit: RecoveryKit, r: KeyRecord) {
  validateKeyRecord(r)
  if (kit.version !== 2 || kit.vaultId !== r.vaultId || kit.recoveryId !== r.recovery?.id) throw new Error('This recovery kit is obsolete or belongs to another vault.')
}
async function recoveryRaw(kit: RecoveryKit, r: KeyRecord) {
  checkKit(kit, r)
  return open(await recoveryKey(kit.secret, r, 'master'), r.recovery!.master, r, `master:recovery:${r.recovery!.id}`)
}
export async function unlockRecovery(kit: RecoveryKit, r: KeyRecord) {
  const raw = await recoveryRaw(kit, r)
  try { return await importMaster(raw, r) } finally { raw.fill(0) }
}
export async function prepareRecoveredRecord(kit: RecoveryKit, nextPassphrase: string, r: KeyRecord) {
  const raw = await recoveryRaw(kit, r)
  try {
    const next = { ...r, revision: r.revision + 1, passphrase: await wrapPass(raw, nextPassphrase, r) }
    return await recoveryFromRaw(raw, next)
  } finally { raw.fill(0) }
}
export function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']'
  return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical((value as Record<string, unknown>)[k])).join(',') + '}'
}
export async function hashJson(value: unknown) { return b64(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(canonical(value))))) }
export async function signRecovery(kit: RecoveryKit, r: KeyRecord, challenge: string, response: unknown, replacement: KeyRecord) {
  checkKit(kit, r)
  const bytes = await open(await recoveryKey(kit.secret, r, 'authentication'), r.recovery!.privateKey, r, `authentication:recovery:${r.recovery!.id}`)
  try {
    const key = await crypto.subtle.importKey('pkcs8', bytes, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
    return b64(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(JSON.stringify([challenge, await hashJson(response), await hashJson(replacement)])))))
  } finally { bytes.fill(0) }
}
