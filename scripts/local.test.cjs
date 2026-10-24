const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { setup, validateLocalEnv, localProcessEnv } = require('./local.cjs');

test('local child processes disable metadata discovery without changing the parent environment', () => {
  const parent = { PATH: 'fictional-path', METADATA_SERVER_DETECTION: 'assume-present' };
  const local = localProcessEnv(parent);
  assert.equal(local.METADATA_SERVER_DETECTION, 'none');
  assert.equal(local.PATH, parent.PATH);
  assert.equal(parent.METADATA_SERVER_DETECTION, 'assume-present');
});

test('local setup preserves existing files and rejects production overrides', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'haven-local-'));
  const functions = path.join(dir, 'functions');
  fs.mkdirSync(functions);
  try {
    setup(dir);
    const file = path.join(functions, '.env.demo-haven-vault');
    const first = fs.readFileSync(file, 'utf8');
    assert.doesNotThrow(() => validateLocalEnv(dir, {}));
    fs.appendFileSync(file, '# preserved\n');
    setup(dir);
    assert.equal(fs.readFileSync(file, 'utf8'), `${first}# preserved\n`);
    fs.writeFileSync(path.join(functions, '.env.local'), 'EXPECTED_ORIGIN=https://production.web.app\n');
    assert.throws(() => validateLocalEnv(dir, {}), /EXPECTED_ORIGIN/);
    fs.unlinkSync(path.join(functions, '.env.local'));
    assert.throws(() => validateLocalEnv(dir, { RP_ID: 'production.web.app' }), /RP_ID/);
    assert.doesNotThrow(() => validateLocalEnv(dir, { AUTH_SESSION_MINUTES: '30' }));
    assert.throws(() => validateLocalEnv(dir, { AUTH_SESSION_MINUTES: '90' }), /AUTH_SESSION_MINUTES/);
    fs.writeFileSync(file, first.replace('AUTH_SESSION_MINUTES=60\n', ''));
    assert.doesNotThrow(() => validateLocalEnv(dir, {}));
  } finally { fs.rmSync(dir, { recursive: true }); }
});
