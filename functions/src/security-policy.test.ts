import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validKeyRecord, keyTransition, freshPasskey } from './security-policy.js';
const box = { version: 2, iv: 'A'.repeat(16), ciphertext: 'A'.repeat(64) };
const record = { version: 2, vaultId: '11111111-1111-4111-8111-111111111111', generation: '22222222-2222-4222-8222-222222222222', revision: 1, passphrase: { version: 2, kdf: 'PBKDF2-SHA256', salt: 'A'.repeat(43) + '=', iterations: 600000, box }, recovery: null };
test('strict v2 validation rejects secrets, unsafe parameters, unknown formats and extra fields', () => {
  assert.ok(validKeyRecord(record));
  for (const bad of [{ ...record, version: 3 }, { ...record, secret: 'plaintext' }, { ...record, revision: 0 }, { ...record, passphrase: { ...record.passphrase, iterations: 1 } }, { ...record, passphrase: { ...record.passphrase, plaintext: 'secret' } }]) assert.equal(validKeyRecord(bad), false);
});
test('CAS transitions bind data identity, increment one revision and preserve recovery on passphrase changes', () => {
  const next = { ...record, revision: 2 };
  assert.ok(keyTransition(record, next, 'passphrase'));
  for (const invalid of [{ ...next, revision: 1 }, { ...next, generation: record.vaultId }, { ...next, vaultId: record.generation }]) assert.equal(keyTransition(record, invalid, 'passphrase'), false);
  assert.equal(keyTransition(record, next, 'recovery'), false);
});
test('freshness is based on verified server record and rejects future or stale timestamps', () => {
  assert.equal(freshPasskey({}, 1000000), false);
  for (const at of [699999, 1000001]) assert.equal(freshPasskey({ authenticatedAt: { toMillis: () => at } }, 1000000), false);
  assert.ok(freshPasskey({ authenticatedAt: { toMillis: () => 700000 } }, 1000000));
});
