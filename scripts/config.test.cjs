const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadConfig } = require('./config.cjs');

test('deployment helpers fail closed for missing, placeholder, or malformed targets', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'haven-config-'));
  const file = path.join(dir, 'config.json');
  const valid = { projectId: 'example-vault', projectNumber: '123456789012', bucket: 'example-vault.firebasestorage.app', origin: 'https://example-vault.web.app', region: 'us-central1' };
  try {
    assert.throws(() => loadConfig(file), /Copy vault/);
    for (const invalid of [null, [], { ...valid, projectId: 'your-project-id' }, { ...valid, projectNumber: 123 }, { ...valid, bucket: 'gs://some-bucket' }, { ...valid, origin: 'http://example.com' }, { ...valid, origin: 'https://example.com/' }, { ...valid, origin: 'https://user:pass@example.com' }, { ...valid, origin: 'https://example.com/path' }, { ...valid, region: 'europe-west1' }]) {
      fs.writeFileSync(file, JSON.stringify(invalid));
      assert.throws(() => loadConfig(file));
    }
    fs.writeFileSync(file, JSON.stringify(valid));
    assert.deepEqual(loadConfig(file), { project: valid.projectId, projectNumber: valid.projectNumber, bucket: valid.bucket, origin: valid.origin, region: valid.region, rpId: 'example-vault.web.app' });
  } finally {
    fs.unlinkSync(file);
    fs.rmdirSync(dir);
  }
});
