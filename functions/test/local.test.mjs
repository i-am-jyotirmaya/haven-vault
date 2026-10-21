// End-to-end against disposable emulators. No cloud credentials or auth bypasses.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign, webcrypto } from 'node:crypto';
import { encodeCBOR } from '@levischuck/tiny-cbor';
import { initializeApp, deleteApp } from 'firebase/app';
import { initializeAuth, inMemoryPersistence, connectAuthEmulator, GoogleAuthProvider, signInWithCredential, signInWithCustomToken, signOut } from 'firebase/auth';
import { getFunctions, connectFunctionsEmulator, httpsCallable } from 'firebase/functions';
import { getFirestore, connectFirestoreEmulator, doc, setDoc, getDoc, terminate } from 'firebase/firestore';
import { getStorage, connectStorageEmulator, ref, uploadBytes, getBytes } from 'firebase/storage';

for (const [name, expected] of Object.entries({
  FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9099',
  FIRESTORE_EMULATOR_HOST: '127.0.0.1:18080',
  FIREBASE_STORAGE_EMULATOR_HOST: '127.0.0.1:19199',
})) assert.equal(process.env[name], expected, 'Run pnpm test:local; this suite must never contact live services.');
assert.equal(process.env.GCLOUD_PROJECT, 'demo-haven-vault');

const projectId = 'demo-haven-vault';
const origin = 'http://localhost:5173';
const app = initializeApp({ projectId, apiKey: 'fake-api-key', storageBucket: `${projectId}.appspot.com` }, 'local-integration');
const auth = initializeAuth(app, { persistence: inMemoryPersistence });
const db = getFirestore(app);
const storage = getStorage(app);
const functions = getFunctions(app, 'us-central1');
connectAuthEmulator(auth, 'http://127.0.0.1:9099');
connectFirestoreEmulator(db, '127.0.0.1', 18080);
connectStorageEmulator(storage, '127.0.0.1', 19199);
connectFunctionsEmulator(functions, '127.0.0.1', 5001);
const call = async (name, data = {}) => (await httpsCallable(functions, name)(data)).data;
const hash = bytes => createHash('sha256').update(bytes).digest();
const b64 = bytes => Buffer.from(bytes).toString('base64url');
const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const jwk = publicKey.export({ format: 'jwk' });
const credentialId = randomBytes(32);
const id = b64(credentialId);
const cose = encodeCBOR(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
function clientData(type, challenge) { return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false })); }
function authenticatorData(flags, count) {
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(count);
  return Buffer.concat([hash('localhost'), Buffer.from([flags]), counter]);
}
function registration(challenge) {
  const length = Buffer.alloc(2);
  length.writeUInt16BE(credentialId.length);
  const data = Buffer.concat([authenticatorData(0x45, 0), Buffer.alloc(16), length, credentialId, cose]);
  return { id, rawId: id, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform', response: {
    clientDataJSON: b64(clientData('webauthn.create', challenge)),
    attestationObject: b64(encodeCBOR(new Map([['fmt', 'none'], ['authData', data], ['attStmt', new Map()]]))),
    transports: ['internal'],
  } };
}
function authentication(challenge, userHandle) {
  const client = clientData('webauthn.get', challenge);
  const data = authenticatorData(0x05, 1);
  return { id, rawId: id, type: 'public-key', clientExtensionResults: {}, response: {
    clientDataJSON: b64(client), authenticatorData: b64(data), userHandle,
    signature: b64(sign('sha256', Buffer.concat([data, hash(client)]), privateKey)),
  } };
}

test('local owner enrollment, signed passkey login, encrypted data, and session revocation', { timeout: 120000 }, async () => {
  try {
    await assert.rejects(call('registrationOptions'), { code: 'functions/unauthenticated' });
    // The Auth emulator accepts synthetic Google claims; production Google never does.
    const google = GoogleAuthProvider.credential(JSON.stringify({ sub: 'local-owner', email: 'owner@example.com', email_verified: true }));
    await signInWithCredential(auth, google);
    const uid = auth.currentUser.uid;
    assert.equal((await call('vaultSessionInfo')).enrolled, false);
    const note = doc(db, `users/${uid}/items/local-note`);
    await assert.rejects(getDoc(note), { code: 'permission-denied' });
    const options = await call('registrationOptions');
    assert.equal(options.options.rp.id, 'localhost');
    const response = registration(options.options.challenge);
    const issued = await call('verifyRegistration', { challengeId: options.challengeId, response });
    await assert.rejects(call('verifyRegistration', { challengeId: options.challengeId, response }));
    await signInWithCustomToken(auth, issued.token);
    assert.equal((await auth.currentUser.getIdTokenResult()).claims.vaultAccess, true);

    const key = await webcrypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const iv = randomBytes(12);
    const plaintext = Buffer.from('Fictional local testing fixture');
    const ciphertext = Buffer.from(await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext));
    const payload = { version: 1, iv: iv.toString('base64'), ciphertext: ciphertext.toString('base64') };
    await setDoc(note, { payload });
    assert.deepEqual((await getDoc(note)).data().payload, payload);
    const file = ref(storage, `vaults/${uid}/local-file`);
    await uploadBytes(file, Buffer.concat([iv, ciphertext]), { contentType: 'application/octet-stream' });
    const stored = Buffer.from(await getBytes(file));
    const decrypted = Buffer.from(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: stored.subarray(0, 12) }, key, stored.subarray(12)));
    assert.deepEqual(decrypted, plaintext);

    await call('endVaultSession');
    await assert.rejects(getDoc(note), { code: 'permission-denied' });
    await assert.rejects(getBytes(file), { code: 'storage/unauthorized' });
    await signOut(auth);
    // A fresh Google login cannot bypass the already enrolled passkey.
    await signInWithCredential(auth, google);
    await assert.rejects(call('registrationOptions'), { code: 'functions/permission-denied' });
    await signOut(auth);
    const login = await call('authenticationOptions');
    const signed = authentication(login.options.challenge, options.options.user.id);
    const session = await call('verifyAuthentication', { challengeId: login.challengeId, response: signed });
    await assert.rejects(call('verifyAuthentication', { challengeId: login.challengeId, response: signed }));
    await signInWithCustomToken(auth, session.token);
    assert.deepEqual((await getDoc(note)).data().payload, payload);
    await call('endVaultSession');
  } finally {
    await signOut(auth);
    await terminate(db);
    await deleteApp(app);
  }
});
