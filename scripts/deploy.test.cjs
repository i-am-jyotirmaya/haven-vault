const { test } = require('node:test');
const assert = require('node:assert/strict');
const { validateDeployment, parseArgs, deploymentSteps } = require('./deploy.cjs');
const config = { project: 'example-vault', projectNumber: '123456789012', bucket: 'example-vault.firebasestorage.app', origin: 'https://example-vault.web.app', rpId: 'example-vault.web.app', region: 'us-central1' };
const browser = { VITE_FIREBASE_PROJECT_ID: config.project, VITE_FIREBASE_STORAGE_BUCKET: config.bucket, VITE_FIREBASE_MESSAGING_SENDER_ID: config.projectNumber, VITE_FIREBASE_FUNCTIONS_REGION: config.region, VITE_FIREBASE_API_KEY: 'configured-key', VITE_FIREBASE_AUTH_DOMAIN: 'example-vault.firebaseapp.com', VITE_FIREBASE_APP_ID: '1:123456789012:web:configured' };
const backend = { OWNER_EMAIL: 'owner@example.com', RP_ID: config.rpId, EXPECTED_ORIGIN: config.origin, ENFORCE_APP_CHECK: 'false' };

test('deployment rejects drift between browser, backend, and target before commands run', () => {
  assert.doesNotThrow(() => validateDeployment(config, browser, backend, {}));
  for (const key of ['PROJECT_ID', 'STORAGE_BUCKET', 'MESSAGING_SENDER_ID', 'FUNCTIONS_REGION', 'APP_ID']) {
    assert.throws(() => validateDeployment(config, { ...browser, [`VITE_FIREBASE_${key}`]: 'other-project' }, backend, {}));
  }
  for (const patch of [{ RP_ID: 'localhost' }, { EXPECTED_ORIGIN: 'http://localhost:5173' }, { OWNER_EMAIL: '' }, { ENFORCE_APP_CHECK: 'true' }]) {
    assert.throws(() => validateDeployment(config, browser, { ...backend, ...patch }, {}));
  }
  assert.throws(() => validateDeployment({ ...config, project: 'demo-haven-vault' }, browser, backend, {}));
  assert.throws(() => validateDeployment(config, browser, backend, { FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9099' }));
});

test('scope parsing rejects unknown arguments and malformed selectors', () => {
  assert.deepEqual(parseArgs([]), { only: 'all', plan: false, configureAccess: false });
  assert.deepEqual(parseArgs(['--only', 'hosting', '--plan']), { only: 'hosting', plan: true, configureAccess: false });
  for (const args of [['--only'], ['--only', 'everything'], ['--project', 'other']]) assert.throws(() => parseArgs(args));
});

test('hosting is published only after backend validation; IAM mutations are explicit', () => {
  const options = parseArgs([]);
  const steps = deploymentSteps(config, options);
  assert.ok(steps.findIndex(([name]) => name === 'Verify backend authorization') < steps.findIndex(([name]) => name === 'Deploy Hosting'));
  assert.ok(steps.filter(([name]) => name.includes('access') || name.includes('CORS')).every(([, args]) => !args.includes('--apply')));
  for (const scope of ['hosting', 'backend']) {
    const scoped = deploymentSteps(config, { ...options, only: scope });
    const deploys = scoped.filter(([, args]) => args.includes('deploy'));
    assert.equal(deploys.length, 1);
    assert.equal(deploys[0][1].at(-1), scope === 'hosting' ? 'hosting' : 'functions,firestore,storage');
    assert.ok(deploys[0][1].includes(config.project));
  }
});
