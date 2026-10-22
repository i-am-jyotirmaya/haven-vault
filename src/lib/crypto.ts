import { keyContext, unlockKeyRecord, type KeyRecord } from './keys';
/** Browser-only encryption. Passphrases and keys must never be persisted or sent to Firebase. */
export type EncryptedPayload = {
  version: 1 | 2;
  iv: string;
  ciphertext: string;
};

export type LegacyVaultConfig = {
  version: 1;
  salt: string;
  iterations: number;
  verifier: EncryptedPayload;
};

export type VaultConfig = LegacyVaultConfig | KeyRecord;

const VERSION = 1;
const ITERATIONS = 600_000;
const MAX_ITERATIONS = 2_000_000;
const SALT_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const MAX_JSON_BYTES = 8 * 1024 * 1024;
const MAX_FILE_BYTES = 100 * 1024 * 1024;
const VERIFIER_CONTEXT = 'vault-verifier';
const VERIFIER_VALUE = 'personal-vault-key-check-v1';
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

function webCrypto(): Crypto {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Secure encryption is unavailable. Open this app over HTTPS.');
  }
  return globalThis.crypto;
}

function toBase64(bytes: Uint8Array): string {
  // Chunking avoids exceeding the function-argument limit for larger metadata.
  const parts: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    parts.push(String.fromCharCode(...bytes.subarray(offset, offset + 0x8000)));
  }
  return btoa(parts.join(''));
}

function fromBase64(value: unknown, maxBytes: number): Uint8Array<ArrayBuffer> {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > Math.ceil(maxBytes / 3) * 4 ||
    value.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]*={0,2}$/.test(value)
  ) {
    throw new Error('Invalid encrypted data encoding.');
  }
  const decoded = atob(value);
  const bytes = Uint8Array.from(decoded, (char) => char.charCodeAt(0));
  if (bytes.length > maxBytes || toBase64(bytes) !== value) {
    throw new Error('Invalid encrypted data encoding.');
  }
  return bytes;
}

function assertPassphrase(passphrase: string): void {
  if (typeof passphrase === 'string' && passphrase.length > 1024) {
    throw new Error('Passphrases must be no longer than 1,024 characters.');
  }
  if (typeof passphrase !== 'string' || [...passphrase].length < 12) {
    throw new Error('Use a passphrase of at least 12 characters.');
  }
}

function additionalData(key: CryptoKey, purpose: 'json' | 'file', context: string): Uint8Array<ArrayBuffer> {
  if (typeof context !== 'string' || context.length === 0 || context.length > 1024) {
    throw new Error('A valid encryption context is required.');
  }
  // Purpose separation prevents a metadata ciphertext being accepted as a file.
  // Callers bind context to the owner and item ID, so items cannot be swapped.
  const binding = keyContext(key);
  if (binding) return encoder.encode(JSON.stringify(['haven', 2, binding.vaultId, binding.generation, purpose, context]));
  return encoder.encode(`personal-vault:${VERSION}:${purpose}:${context}`);
}

function readPayload(payload: EncryptedPayload, maxCiphertextBytes = MAX_JSON_BYTES + TAG_BYTES, version = 1) {
  if (!payload || typeof payload !== 'object' || payload.version !== version) {
    throw new Error('Unsupported encrypted data version.');
  }
  const iv = fromBase64(payload.iv, IV_BYTES);
  const ciphertext = fromBase64(payload.ciphertext, maxCiphertextBytes);
  if (iv.length !== IV_BYTES || ciphertext.length < TAG_BYTES) {
    throw new Error('Invalid encrypted data.');
  }
  return { iv, ciphertext };
}

async function deriveKey(
  passphrase: string,
  salt: Uint8Array<ArrayBuffer>,
  iterations: number,
): Promise<CryptoKey> {
  assertPassphrase(passphrase);
  const crypto = webCrypto();
  const passphraseBytes = encoder.encode(passphrase);
  try {
    const material = await crypto.subtle.importKey(
      'raw',
      passphraseBytes,
      'PBKDF2',
      false,
      ['deriveKey'],
    );
    return await crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  } finally {
    // Best effort only: JS strings and browser internals cannot be securely erased.
    passphraseBytes.fill(0);
  }
}

export async function createVault(
  passphrase: string,
): Promise<{ key: CryptoKey; config: LegacyVaultConfig }> {
  assertPassphrase(passphrase);
  const salt = webCrypto().getRandomValues(new Uint8Array(SALT_BYTES));
  const key = await deriveKey(passphrase, salt, ITERATIONS);
  const verifier = await encryptJson(key, VERIFIER_VALUE, VERIFIER_CONTEXT);
  return {
    key,
    config: { version: VERSION, salt: toBase64(salt), iterations: ITERATIONS, verifier },
  };
}

export async function unlockVault(passphrase: string, config: VaultConfig): Promise<CryptoKey> {
  if (config?.version === 2) return unlockKeyRecord(passphrase, config);
  if (
    !config ||
    typeof config !== 'object' ||
    config.version !== VERSION ||
    !Number.isSafeInteger(config.iterations) ||
    config.iterations < ITERATIONS ||
    config.iterations > MAX_ITERATIONS
  ) {
    throw new Error('Unsupported vault configuration.');
  }
  const salt = fromBase64(config.salt, SALT_BYTES);
  if (salt.length !== SALT_BYTES) throw new Error('Invalid vault salt.');
  // Validate before the expensive derivation, including the small verifier size.
  readPayload(config.verifier, 192);
  const key = await deriveKey(passphrase, salt, config.iterations);
  try {
    const verifier = await decryptJson<unknown>(key, config.verifier, VERIFIER_CONTEXT);
    if (verifier !== VERIFIER_VALUE) throw new Error('Invalid verifier.');
    return key;
  } catch {
    throw new Error('The passphrase is incorrect, or the vault data has been damaged.');
  }
}

export async function encryptJson(
  key: CryptoKey,
  value: unknown,
  context: string,
): Promise<EncryptedPayload> {
  const aad = additionalData(key, 'json', context);
  const json = JSON.stringify(value);
  if (json === undefined) throw new Error('The value cannot be encrypted as JSON.');
  const plaintext = encoder.encode(json);
  if (plaintext.length > MAX_JSON_BYTES) throw new Error('The encrypted metadata is too large.');
  const crypto = webCrypto();
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  try {
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
      key,
      plaintext,
    );
    return { version: keyContext(key) ? 2 : 1, iv: toBase64(iv), ciphertext: toBase64(new Uint8Array(ciphertext)) };
  } finally {
    plaintext.fill(0);
  }
}

export async function decryptJson<T>(
  key: CryptoKey,
  payload: EncryptedPayload,
  context: string,
): Promise<T> {
  const { iv, ciphertext } = readPayload(payload, MAX_JSON_BYTES + TAG_BYTES, keyContext(key) ? 2 : 1);
  const plaintext = await webCrypto().subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: additionalData(key, 'json', context), tagLength: 128 },
    key,
    ciphertext,
  );
  const bytes = new Uint8Array(plaintext);
  try {
    return JSON.parse(decoder.decode(bytes)) as T;
  } finally {
    bytes.fill(0);
  }
}

/** Binary format: version (1 byte), IV (12 bytes), ciphertext with 16-byte GCM tag. */
export async function encryptFile(
  key: CryptoKey,
  bytes: ArrayBuffer,
  context: string,
): Promise<Blob> {
  if (!(bytes instanceof ArrayBuffer) || bytes.byteLength > MAX_FILE_BYTES) {
    throw new Error('Files must be no larger than 100 MB.');
  }
  const crypto = webCrypto();
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: additionalData(key, 'file', context), tagLength: 128 },
    key,
    bytes,
  );
  return new Blob([new Uint8Array([keyContext(key) ? 2 : 1]), iv, ciphertext], {
    type: 'application/octet-stream',
  });
}

export async function decryptFile(
  key: CryptoKey,
  blob: Blob,
  context: string,
): Promise<ArrayBuffer> {
  const headerLength = 1 + IV_BYTES;
  if (
    !(blob instanceof Blob) ||
    blob.size < headerLength + TAG_BYTES ||
    blob.size > MAX_FILE_BYTES + headerLength + TAG_BYTES
  ) {
    throw new Error('Invalid encrypted file size.');
  }
  const data = new Uint8Array(await blob.arrayBuffer());
  if (data[0] !== (keyContext(key) ? 2 : 1)) throw new Error('Unsupported encrypted file version.');
  return webCrypto().subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: data.subarray(1, headerLength),
      additionalData: additionalData(key, 'file', context),
      tagLength: 128,
    },
    key,
    data.subarray(headerLength),
  );
}
