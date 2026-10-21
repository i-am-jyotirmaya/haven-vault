// @vitest-environment node
import { beforeAll, describe, expect, it } from 'vitest';
import {
  createVault,
  decryptFile,
  decryptJson,
  encryptFile,
  encryptJson,
  unlockVault,
  type EncryptedPayload,
  type VaultConfig,
} from './crypto';

const PASSPHRASE = 'orchard cabin sunrise river';
const CONTEXT = 'owner:7ea07b6a-6351-4dc8-8ac9-62f424c632ba';
let key: CryptoKey;
let config: VaultConfig;

beforeAll(async () => {
  ({ key, config } = await createVault(PASSPHRASE));
});

describe('vault key derivation', () => {
  it('creates a nonextractable AES-256 key with a random 32-byte salt', async () => {
    expect(key.extractable).toBe(false);
    expect(key.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
    expect(config.iterations).toBe(600_000);
    expect(atob(config.salt)).toHaveLength(32);
    await expect(crypto.subtle.exportKey('raw', key)).rejects.toThrow();
    const other = await createVault(PASSPHRASE);
    expect(other.config.salt).not.toBe(config.salt);
    expect(JSON.stringify(config)).not.toContain(PASSPHRASE);
  });

  it('unlocks the existing ciphertext using the correct passphrase', async () => {
    const encrypted = await encryptJson(key, { title: 'Passport', number: 'secret' }, CONTEXT);
    const unlockedKey = await unlockVault(PASSPHRASE, config);
    await expect(decryptJson(unlockedKey, encrypted, CONTEXT)).resolves.toEqual({
      title: 'Passport',
      number: 'secret',
    });
  });

  it('rejects a wrong passphrase and a substituted verifier', async () => {
    await expect(unlockVault('this passphrase is incorrect', config)).rejects.toThrow(
      'The passphrase is incorrect',
    );
    const verifier = await encryptJson(key, 'a different value', 'vault-verifier');
    await expect(unlockVault(PASSPHRASE, { ...config, verifier })).rejects.toThrow(
      'The passphrase is incorrect',
    );
  });

  it('rejects weak passphrases before creating a vault', async () => {
    await expect(createVault('short')).rejects.toThrow('at least 12');
    await expect(createVault('🪨'.repeat(11))).rejects.toThrow('at least 12');
  });

  it.each([0, 599_999, 2_000_001, Number.MAX_SAFE_INTEGER, 600_000.1, NaN, Infinity])(
    'rejects unsafe KDF iteration count %s',
    async (iterations) => {
      await expect(unlockVault(PASSPHRASE, { ...config, iterations })).rejects.toThrow(
        'Unsupported vault configuration',
      );
    },
  );

  it('rejects invalid salt and malformed configuration', async () => {
    await expect(unlockVault(PASSPHRASE, { ...config, salt: btoa('short') })).rejects.toThrow(
      'Invalid vault salt',
    );
    await expect(unlockVault(PASSPHRASE, { ...config, salt: '*' })).rejects.toThrow(
      'Invalid encrypted data encoding',
    );
    await expect(unlockVault(PASSPHRASE, null as unknown as VaultConfig)).rejects.toThrow();
    await expect(
      unlockVault(PASSPHRASE, { ...config, version: 2 } as unknown as VaultConfig),
    ).rejects.toThrow('Unsupported vault configuration');
  });
});

describe('encrypted metadata', () => {
  it('encrypts filenames and Unicode metadata, with fresh IVs for every operation', async () => {
    const value = { name: '私の旅.jpg', mime: 'image/jpeg', notes: 'My secret travel details 🔐' };
    const first = await encryptJson(key, value, CONTEXT);
    const second = await encryptJson(key, value, CONTEXT);
    expect(atob(first.iv)).toHaveLength(12);
    expect(first.iv).not.toBe(second.iv);
    expect(first.ciphertext).not.toBe(second.ciphertext);
    expect(atob(first.ciphertext)).not.toContain('My secret travel');
    await expect(decryptJson(key, first, CONTEXT)).resolves.toEqual(value);
  });

  it('authenticates item identity and ciphertext integrity', async () => {
    const encrypted = await encryptJson(key, { secret: 'value' }, CONTEXT);
    await expect(decryptJson(key, encrypted, 'a-different-item')).rejects.toThrow();
    const bytes = Uint8Array.from(atob(encrypted.ciphertext), (char) => char.charCodeAt(0));
    bytes[0] ^= 1;
    const tampered = { ...encrypted, ciphertext: btoa(String.fromCharCode(...bytes)) };
    await expect(decryptJson(key, tampered, CONTEXT)).rejects.toThrow();
  });

  it('rejects unknown versions, truncated ciphertext, invalid IVs, and invalid base64', async () => {
    const encrypted = await encryptJson(key, { secret: 'value' }, CONTEXT);
    const mutations = [
      { ...encrypted, version: 2 },
      { ...encrypted, ciphertext: btoa('short') },
      { ...encrypted, iv: btoa('short') },
      { ...encrypted, iv: '*' },
      { ...encrypted, ciphertext: `${encrypted.ciphertext}\n` },
    ];
    for (const mutation of mutations) {
      await expect(decryptJson(key, mutation as EncryptedPayload, CONTEXT)).rejects.toThrow();
    }
  });

  it('requires a context and a JSON-serializable value', async () => {
    await expect(encryptJson(key, {}, '')).rejects.toThrow('context');
    await expect(encryptJson(key, undefined, CONTEXT)).rejects.toThrow('JSON');
  });
});

describe('encrypted files', () => {
  it('round-trips arbitrary file bytes, including an empty file', async () => {
    const bytes = new Uint8Array([0, 255, 1, 200, 127, 0]);
    const encrypted = await encryptFile(key, bytes.buffer, CONTEXT);
    expect(encrypted.type).toBe('application/octet-stream');
    expect(encrypted.size).toBe(1 + 12 + bytes.length + 16);
    expect(new Uint8Array(await decryptFile(key, encrypted, CONTEXT))).toEqual(bytes);
    const empty = await encryptFile(key, new ArrayBuffer(0), CONTEXT);
    expect((await decryptFile(key, empty, CONTEXT)).byteLength).toBe(0);
  });

  it('rejects tampered bytes and a different item context', async () => {
    const encrypted = await encryptFile(key, new Uint8Array([1, 2, 3]).buffer, CONTEXT);
    await expect(decryptFile(key, encrypted, 'another-item')).rejects.toThrow();
    const tampered = new Uint8Array(await encrypted.arrayBuffer());
    tampered[tampered.length - 1] ^= 1;
    await expect(decryptFile(key, new Blob([tampered]), CONTEXT)).rejects.toThrow();
  });

  it('rejects truncated files and unsupported binary headers', async () => {
    const encrypted = await encryptFile(key, new Uint8Array([1, 2, 3]).buffer, CONTEXT);
    await expect(decryptFile(key, encrypted.slice(0, 20), CONTEXT)).rejects.toThrow('file size');
    const wrongVersion = new Uint8Array(await encrypted.arrayBuffer());
    wrongVersion[0] = 2;
    await expect(decryptFile(key, new Blob([wrongVersion]), CONTEXT)).rejects.toThrow(
      'file version',
    );
  });

  it('does not allow JSON ciphertext to masquerade as a file', async () => {
    const metadata = await encryptJson(key, { secret: 'value' }, CONTEXT);
    const iv = Uint8Array.from(atob(metadata.iv), (char) => char.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(metadata.ciphertext), (char) => char.charCodeAt(0));
    const fakeFile = new Blob([new Uint8Array([1]), iv, ciphertext]);
    await expect(decryptFile(key, fakeFile, CONTEXT)).rejects.toThrow();
  });
});
