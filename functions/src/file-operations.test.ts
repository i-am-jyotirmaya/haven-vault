import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertRevision, MAX_OBJECT_BYTES, validMetadata, validOperationId } from './file-operations.js';
test('operation validation bounds IDs, ciphertext and revision CAS', () => {
  assert.equal(MAX_OBJECT_BYTES, 50 * 1024 * 1024 + 29);
  assert.equal(validOperationId('11111111-1111-4111-8111-111111111111'), true);
  for (const id of ['../../elsewhere', 'private-name', '', 5, null]) assert.equal(validOperationId(id), false);
  const box = { version: 2, iv: Buffer.alloc(12).toString('base64'), ciphertext: Buffer.alloc(32).toString('base64') };
  assert.equal(validMetadata(box, 2), true);
  for (const payload of [{ ...box, name: 'private-name' }, { ...box, ciphertext: 'x'.repeat(700001) }, { ...box, iv: 'invalid' }, { ...box, version: 1 }]) assert.equal(validMetadata(payload, 2), false);
  assertRevision(0, 0); assertRevision(12, 12);
  for (const revision of [-1, 11, '12', null, NaN, 12.1]) assert.throws(() => assertRevision(12, revision), /changed/);
});
