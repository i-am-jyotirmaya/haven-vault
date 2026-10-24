import { beforeAll, describe, expect, it } from 'vitest'
import { createKeyRecord, unlockKeyRecord, changePassphrase, prepareRecovery, prepareRecoveredRecord, unlockRecovery, signRecovery, b64, hashJson, type KeyRecord, type RecoveryKit } from './keys'
import { createVault, encryptJson, decryptJson, encryptFile, decryptFile } from './crypto'
import { createPublicKey, verify } from 'node:crypto'
const phrase = 'fictional orchard river bicycle', nextPhrase = 'fictional replacement meadow moon'
let config: KeyRecord, key: CryptoKey, kit: RecoveryKit
beforeAll(async () => {
  ({ config, key } = await createKeyRecord(phrase))
  kit = await prepareRecovery(phrase, config)
})
describe('v2 master hierarchy and recovery', () => {
  it('creates nonextractable random independent masters and versioned data bound to vault, item and purpose', async () => {
    expect(key.extractable).toBe(false)
    await expect(crypto.subtle.exportKey('raw', key)).rejects.toThrow()
    const value = await encryptJson(key, { name: 'fictional secret.pdf', trashed: true, thumbnail: 'fictional' }, 'metadata:one')
    expect(value.version).toBe(2)
    const copy = await unlockKeyRecord(phrase, config)
    await expect(decryptJson(copy, value, 'metadata:one')).resolves.toMatchObject({ trashed: true })
    await expect(decryptJson(copy, value, 'metadata:two')).rejects.toThrow()
    const other = await createKeyRecord(phrase)
    await expect(decryptJson(other.key, value, 'metadata:one')).rejects.toThrow()
    expect(JSON.stringify(config)).not.toContain(phrase)
  })
  it('rewraps without changing file ciphertext and preserves the recovery wrapper', async () => {
    const file = await encryptFile(key, new TextEncoder().encode('fictional content').buffer, 'file:one')
    const changed = await changePassphrase(phrase, nextPhrase, kit.record)
    expect(changed.recovery).toEqual(kit.record.recovery)
    expect(changed.generation).toBe(config.generation)
    expect(changed.passphrase.salt).not.toBe(config.passphrase.salt)
    const unlocked = await unlockKeyRecord(nextPhrase, changed)
    expect(new TextDecoder().decode(await decryptFile(unlocked, file, 'file:one'))).toBe('fictional content')
    await expect(unlockKeyRecord(phrase, changed)).rejects.toThrow()
    // A stolen old wrapper still decrypts old ciphertext: no false key-rotation claim.
    await expect(decryptFile(await unlockKeyRecord(phrase, config), file, 'file:one')).resolves.toBeInstanceOf(ArrayBuffer)
  })
  it('decrypts on a fresh browser using only kit material and rotates both recovery credentials', async () => {
    const restored = JSON.parse(JSON.stringify(kit)) as RecoveryKit
    const master = await unlockRecovery(restored, kit.record)
    const payload = await encryptJson(key, { note: 'fixture' }, 'metadata:fixture')
    await expect(decryptJson(master, payload, 'metadata:fixture')).resolves.toEqual({ note: 'fixture' })
    const replacement = await prepareRecoveredRecord(restored, nextPhrase, kit.record)
    expect(replacement.recoveryId).not.toBe(kit.recoveryId)
    expect(replacement.record.recovery!.publicKey).not.toBe(kit.record.recovery!.publicKey)
    await expect(unlockRecovery(kit, replacement.record)).rejects.toThrow('obsolete')
    await expect(decryptJson(await unlockKeyRecord(nextPhrase, replacement.record), payload, 'metadata:fixture')).resolves.toEqual({ note: 'fixture' })
  })
  it('rejects wrong passphrase, wrong recovery secret, tampered wrapper and cross-vault contexts', async () => {
    await expect(unlockKeyRecord('this is the wrong passphrase', config)).rejects.toThrow()
    await expect(unlockRecovery({ ...kit, secret: b64(crypto.getRandomValues(new Uint8Array(32))) }, kit.record)).rejects.toThrow()
    const tampered = structuredClone(config); tampered.passphrase.box.ciphertext = b64(new Uint8Array(48))
    await expect(unlockKeyRecord(phrase, tampered)).rejects.toThrow()
    await expect(unlockKeyRecord(phrase, { ...config, vaultId: crypto.randomUUID() })).rejects.toThrow()
    await expect(unlockKeyRecord(phrase, { ...config, generation: crypto.randomUUID() })).rejects.toThrow()
  })
  it.each([0, 3, 99])('fails closed on unsupported record version %s', async version => {
    await expect(unlockKeyRecord(phrase, { ...config, version } as unknown as KeyRecord)).rejects.toThrow('Unsupported')
  })
  it('rejects unsafe KDF parameters before expensive work', async () => {
    for (const iterations of [1, Infinity, 2000001, 600000.5]) await expect(unlockKeyRecord(phrase, { ...config, passphrase: { ...config.passphrase, iterations } })).rejects.toThrow('Unsupported')
  })
  it('uses independent signing credentials and binds exact enrollment, key record and challenge', async () => {
    const response = { id: 'fictional-passkey', response: { clientDataJSON: 'fixture' } }
    const statement = JSON.stringify(['fixture', 'owner', config.vaultId, kit.recoveryId, 'nonce', 123])
    const signature = await signRecovery(kit, kit.record, statement, response, kit.record)
    const publicKey = createPublicKey({ key: Buffer.from(kit.record.recovery!.publicKey, 'base64'), format: 'der', type: 'spki' })
    const valid = async (s: string, r: unknown, record: KeyRecord) => verify('sha256', Buffer.from(JSON.stringify([s, await hashJson(r), await hashJson(record)])), { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64'))
    expect(await valid(statement, response, kit.record)).toBe(true)
    expect(await valid(statement + 'replay-on-other-operation', response, kit.record)).toBe(false)
    expect(await valid(statement, { ...response, id: 'substitution' }, kit.record)).toBe(false)
    expect(await valid(statement, response, { ...kit.record, revision: 50 })).toBe(false)
  })
  it('cannot relabel legacy ciphertext as v2', async () => {
    const legacy = await createVault(phrase)
    const payload = await encryptJson(legacy.key, { note: 'original' }, 'metadata:fixture')
    await expect(decryptJson(key, { ...payload, version: 2 }, 'metadata:fixture')).rejects.toThrow()
    await expect(decryptJson(legacy.key, payload, 'metadata:fixture')).resolves.toEqual({ note: 'original' })
  })
  it('compares committed records independent of Firestore field ordering', async () => {
    expect(await hashJson({ ...config, revision: 1 })).toBe(await hashJson(Object.fromEntries(Object.entries(config).reverse())))
  })
})
