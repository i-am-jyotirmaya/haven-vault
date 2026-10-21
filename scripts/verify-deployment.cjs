// Public smoke checks: no administrator credentials, passkeys, or real vault data.
const assert = require('node:assert/strict');
const { project, bucket, origin, region, rpId } = require('./config.cjs').loadConfig();
const endpoint = `https://${region}-${project}.cloudfunctions.net`;
const id = '00000000-0000-4000-8000-000000000000';

async function run(name, test) {
  try {
    await test();
    console.log(`PASS ${name}`);
  } catch (error) {
    console.error(`FAIL ${name}: ${error.message}`);
    process.exitCode = 1;
  }
}

async function callable(name) {
  const response = await fetch(`${endpoint}/${name}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: origin },
    body: JSON.stringify({ data: {} }),
    signal: AbortSignal.timeout(60000),
  });
  assert.match(response.headers.get('content-type') || '', /application\/json/, `${name}: infrastructure returned HTTP ${response.status} before the callable handler`);
  return { response, body: await response.json() };
}

(async () => {
  await Promise.all([
    run('Hosting and security headers', async () => {
      const response = await fetch(origin, { signal: AbortSignal.timeout(30000) });
      assert.equal(response.status, 200);
      assert.match(response.headers.get('content-security-policy') || '', /frame-ancestors 'none'/);
      assert.match(response.headers.get('cache-control') || '', /no-store/);
      assert.equal(response.headers.get('x-frame-options'), 'DENY');
      assert.match(await response.text(), /Haven/);
    }),
    run('Unauthenticated Firestore reads denied', async () => {
      const response = await fetch(`https://firestore.googleapis.com/v1/projects/${project}/databases/(default)/documents/users/deployment-probe/vault/config`, { signal: AbortSignal.timeout(30000) });
      assert.equal(response.status, 403);
      assert.equal((await response.json()).error.status, 'PERMISSION_DENIED');
    }),
    run('Unauthenticated Storage reads denied', async () => {
      const object = encodeURIComponent(`vaults/deployment-probe/${id}`);
      const response = await fetch(`https://firebasestorage.googleapis.com/v0/b/${bucket}/o/${object}?alt=media`, { signal: AbortSignal.timeout(30000) });
      assert.ok([401, 403].includes(response.status), `Expected authorization rejection, received ${response.status}`);
    }),
    run('Registration requires authenticated owner', async () => {
      const { response, body } = await callable('registrationOptions');
      assert.equal(response.status, 401);
      assert.equal(body.error.status, 'UNAUTHENTICATED');
      assert.equal(response.headers.get('access-control-allow-origin'), origin);
    }),
    run('Session inspection requires authenticated owner', async () => {
      const { response, body } = await callable('vaultSessionInfo');
      assert.equal(response.status, 401);
      assert.equal(body.error.status, 'UNAUTHENTICATED');
    }),
    run('Registration verification requires authenticated owner', async () => {
      const { response, body } = await callable('verifyRegistration');
      assert.equal(response.status, 401);
      assert.equal(body.error.status, 'UNAUTHENTICATED');
    }),
    run('Session revocation requires authentication', async () => {
      const { response, body } = await callable('endVaultSession');
      assert.equal(response.status, 401);
      assert.equal(body.error.status, 'UNAUTHENTICATED');
    }),
    run('Malformed passkey authentication rejected', async () => {
      const { response, body } = await callable('verifyAuthentication');
      assert.equal(response.status, 400);
      assert.equal(body.error.status, 'INVALID_ARGUMENT');
    }),
    run('Passkey endpoint reaches Firestore and configured backend', async () => {
      const { response, body } = await callable('authenticationOptions');
      if (response.status === 200) {
        assert.equal(body.result.options.rpId, rpId);
        assert.equal(body.result.options.userVerification, 'required');
      } else {
        assert.equal(response.status, 400);
        assert.equal(body.error.status, 'FAILED_PRECONDITION');
        assert.equal(body.error.message, 'This vault has not been set up yet.');
      }
    }),
  ]);
})();
