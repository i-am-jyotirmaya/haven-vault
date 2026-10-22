// Disposable Firebase emulator authorization with real WebAuthn signatures and real Web Crypto.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { initializeApp as adminApp } from 'firebase-admin/app';
import { getFirestore as adminFirestore, Timestamp } from 'firebase-admin/firestore';
import { initializeApp, deleteApp } from 'firebase/app';
import { initializeAuth, inMemoryPersistence, connectAuthEmulator, GoogleAuthProvider, signInWithCredential, signInWithCustomToken, signOut } from 'firebase/auth';
import { getFunctions, connectFunctionsEmulator, httpsCallable } from 'firebase/functions';
import { getFirestore, connectFirestoreEmulator, doc, setDoc, getDoc, terminate } from 'firebase/firestore';
import { getStorage, connectStorageEmulator, ref, uploadBytes, getBytes, deleteObject } from 'firebase/storage';
import { authenticator } from './webauthn-fixture.mjs';
import { createKeyRecord, unlockKeyRecord, changePassphrase, prepareRecovery, prepareRecoveredRecord, unlockRecovery, signRecovery, hashJson } from '../../src/lib/keys.ts';
for (const [name, expected] of Object.entries({ FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9099', FIRESTORE_EMULATOR_HOST: '127.0.0.1:18080', FIREBASE_STORAGE_EMULATOR_HOST: '127.0.0.1:19199', GCLOUD_PROJECT: 'demo-haven-vault' })) assert.equal(process.env[name], expected, 'Never run this against a real vault');
const projectId = 'demo-haven-vault';
const admin = adminFirestore(adminApp({ projectId, storageBucket: `${projectId}.appspot.com` }, 'security-fixtures'));
function client(name) {
  const app = initializeApp({ projectId, apiKey: 'fake-api-key', storageBucket: `${projectId}.appspot.com` }, name);
  const auth = initializeAuth(app, { persistence: inMemoryPersistence }), db = getFirestore(app), storage = getStorage(app), functions = getFunctions(app, 'us-central1');
  connectAuthEmulator(auth, 'http://127.0.0.1:9099'); connectFirestoreEmulator(db, '127.0.0.1', 18080); connectStorageEmulator(storage, '127.0.0.1', 19199); connectFunctionsEmulator(functions, '127.0.0.1', 5001);
  return { app, auth, db, storage, call: async (name, data = {}) => (await httpsCallable(functions, name, { timeout: 120000 })(data)).data };
}
const ownerGoogle = GoogleAuthProvider.credential(JSON.stringify({ sub: 'security-owner', email: 'owner@example.com', email_verified: true }));
const first = client('security-first'), fresh = client('security-fresh');
const operation = (c, action, data = {}) => c.call('securityOperation', { action, ...data });
let userHandle, uid;
const key1 = authenticator(), key2 = authenticator();
async function login(c, key) { const options = await c.call('authenticationOptions'); const issued = await c.call('verifyAuthentication', { challengeId: options.challengeId, response: key.authentication(options.options.challenge, userHandle) }); await signInWithCustomToken(c.auth, issued.token); return issued; }
async function reauth(c, key) { const options = await c.call('authenticationOptions', { reauth: true }); await c.call('verifyAuthentication', { challengeId: options.challengeId, response: key.authentication(options.options.challenge, userHandle) }); }
async function register(c, key) { const options = await c.call('registrationOptions'); return c.call('verifyRegistration', { challengeId: options.challengeId, response: key.registration(options.options.challenge), management: true }); }
async function clearLimits() { await admin.recursiveDelete(admin.collection('_vaultLimits')); }
const phrase = 'fictional orchard bicycle river', replacement = 'fictional moon meadow lantern';
test('security product workflows against isolated emulators', { timeout: 240000 }, async t => {
  try {
    await admin.doc('_vaultAuth/owner').delete(); await clearLimits();
    await signInWithCredential(first.auth, ownerGoogle); uid = first.auth.currentUser.uid;
    await admin.recursiveDelete(admin.doc(`users/${uid}`));
    await admin.doc(`_vaultAccess/${uid}`).delete();
    const options = await first.call('registrationOptions'); userHandle = options.options.user.id;
    const issued = await first.call('verifyRegistration', { challengeId: options.challengeId, response: key1.registration(options.options.challenge) });
    await signInWithCustomToken(first.auth, issued.token);
    let { config, key } = await createKeyRecord(phrase);
    await t.test('new setup is atomic, versioned, owner-only and cannot reset config', async () => {
      await operation(first, 'createKeys', { record: config });
      await assert.rejects(operation(first, 'createKeys', { record: config }));
      assert.equal((await getDoc(doc(first.db, `users/${uid}/vault/config`))).data().version, 2);
      await assert.rejects(setDoc(doc(first.db, `users/${uid}/vault/config`), config), { code: 'permission-denied' });
    });
    await t.test('passkey limits, duplicate rejection, final-key protection and server freshness', async () => {
      await assert.rejects(operation(first, 'removePasskey', { id: key1.id }), { code: 'functions/failed-precondition' });
      const claims = (await first.auth.currentUser.getIdTokenResult()).claims;
      await admin.doc(`_vaultSessions/${claims.vaultSession}`).update({ authenticatedAt: Timestamp.fromMillis(Date.now() - 400000) });
      await assert.rejects(first.call('registrationOptions'), { code: 'functions/failed-precondition' });
      await assert.rejects(operation(first, 'revokeSessions', { scope: 'others' }), { code: 'functions/failed-precondition' });
      await reauth(first, key1); await register(first, key2);
      await assert.rejects(register(first, key2), { code: 'functions/permission-denied' });
      const more = [authenticator(), authenticator(), authenticator()];
      for (const credential of more) await register(first, credential);
      await assert.rejects(first.call('registrationOptions'), { code: 'functions/permission-denied' });
      for (const credential of more) await operation(first, 'removePasskey', { id: credential.id });
      assert.equal((await operation(first, 'list')).passkeys.length, 2);
    });
    await login(fresh, key2);
    await t.test('passphrase CAS preserves files and revokes other sessions including refreshed tokens', async () => {
      const next = await changePassphrase(phrase, replacement, config);
      const stale = await changePassphrase(phrase, 'fictional concurrent replacement', config);
      await operation(first, 'replaceKeys', { purpose: 'passphrase', record: next });
      await assert.rejects(operation(first, 'replaceKeys', { purpose: 'passphrase', record: stale }), { code: 'functions/aborted' });
      await fresh.auth.currentUser.getIdToken(true);
      await assert.rejects(fresh.call('validateVaultSession'), { code: 'functions/permission-denied' });
      await assert.rejects(unlockKeyRecord(phrase, next));
      key = await unlockKeyRecord(replacement, next); config = next;
    });
    let kit;
    await t.test('confirmed recovery registration and lost-passphrase recovery preserve the master', async () => {
      kit = await prepareRecovery(replacement, config);
      await operation(first, 'replaceKeys', { purpose: 'recovery', record: kit.record }); config = kit.record;
      const restored = await prepareRecoveredRecord(kit, phrase, config);
      await operation(first, 'replaceKeys', { purpose: 'recover', record: restored.record });
      await assert.rejects(unlockRecovery(kit, restored.record)); kit = restored; config = restored.record;
      await unlockKeyRecord(phrase, config);
    });
    await signOut(fresh.auth); await signInWithCredential(fresh.auth, ownerGoogle);
    await t.test('Google-only bypass and unauthenticated key changes are denied', async () => {
      await assert.rejects(fresh.call('registrationOptions'), { code: 'functions/permission-denied' });
      await assert.rejects(operation(fresh, 'list'), { code: 'functions/unauthenticated' });
      await assert.rejects(getDoc(doc(fresh.db, `users/${uid}/vault/config`)), { code: 'permission-denied' });
    });
    await clearLimits();
    await t.test('recovery rejects substitution, expired/replayed challenges and the wrong owner', async () => {
      const ceremony = await fresh.call('beginVaultRecovery');
      const newKey = authenticator();
      const response = newKey.registration(ceremony.options.challenge);
      const next = await prepareRecoveredRecord(kit, replacement, config);
      const signature = await signRecovery(kit, config, ceremony.statement, response, next.record);
      await assert.rejects(fresh.call('completeVaultRecovery', { challengeId: ceremony.challengeId, response: { ...response, id: authenticator().id }, signature, record: next.record }), { code: 'functions/permission-denied' });
      await assert.rejects(fresh.call('completeVaultRecovery', { challengeId: ceremony.challengeId, response, signature, record: next.record }), { code: 'functions/permission-denied' });
      const expired = await fresh.call('beginVaultRecovery');
      await admin.doc(`_vaultChallenges/${expired.challengeId}`).update({ expiresAt: Timestamp.fromMillis(Date.now() - 1) });
      await assert.rejects(fresh.call('completeVaultRecovery', { challengeId: expired.challengeId, response, signature, record: next.record }), { code: 'functions/permission-denied' });
      await signOut(fresh.auth); await signInWithCredential(fresh.auth, GoogleAuthProvider.credential(JSON.stringify({ sub: 'wrong-owner', email: 'attacker@example.com', email_verified: true })));
      await assert.rejects(fresh.call('beginVaultRecovery'), { code: 'functions/permission-denied' });
      await signOut(fresh.auth); await signInWithCredential(fresh.auth, ownerGoogle);
    });
    let recoveredKey;
    await t.test('fresh browser recovers lost passkeys and passphrase; lost final response remains usable', async () => {
      const ceremony = await fresh.call('beginVaultRecovery');
      recoveredKey = authenticator(); const response = recoveredKey.registration(ceremony.options.challenge);
      const next = await prepareRecoveredRecord(kit, replacement, config);
      const signature = await signRecovery(kit, config, ceremony.statement, response, next.record);
      // Deliberately ignore the returned session, simulating an interrupted final response.
      await fresh.call('completeVaultRecovery', { challengeId: ceremony.challengeId, response, signature, record: next.record });
      await assert.rejects(first.call('validateVaultSession'), { code: 'functions/permission-denied' });
      await signOut(fresh.auth); await login(fresh, recoveredKey);
      assert.equal((await operation(fresh, 'list')).passkeys.length, 1);
      await unlockRecovery(next, next.record); await unlockKeyRecord(replacement, next.record);
      await assert.rejects(login(first, key1), { code: 'functions/permission-denied' });
      const snapshot = (await getDoc(doc(fresh.db, `users/${uid}/vault/config`))).data();
      assert.equal(await hashJson(snapshot), await hashJson(next.record));
      kit = next; config = next.record;
    });
    await t.test('session ownership, current-session revocation and authoritative expiry', async () => {
      await assert.rejects(operation(fresh, 'revokeSessions', { scope: 'one', id: 'A'.repeat(43) }), { code: 'functions/not-found' });
      const added = authenticator(); await register(fresh, added); await login(first, added);
      await operation(fresh, 'removePasskey', { id: added.id });
      await assert.rejects(first.call('validateVaultSession'), { code: 'functions/permission-denied' });
      const active = await operation(fresh, 'list'); assert.equal(active.sessions.filter(s => s.current).length, 1);
      const result = await operation(fresh, 'revokeSessions', { scope: 'all' }); assert.equal(result.currentRevoked, true);
      await assert.rejects(fresh.call('validateVaultSession'), { code: 'functions/permission-denied' });
      await login(fresh, recoveredKey);
      const claims = (await fresh.auth.currentUser.getIdTokenResult()).claims;
      await admin.doc(`_vaultSessions/${claims.vaultSession}`).update({ expiresAt: Timestamp.fromMillis(Date.now() - 1) });
      await fresh.auth.currentUser.getIdToken(true);
      await assert.rejects(fresh.call('validateVaultSession'), { code: 'functions/permission-denied' });
    });
    await t.test('legacy staging, conflicting clients, interruption during finalization and retained originals', async () => {
      // Reset only this fictional test vault to a legacy fixture; production has no reset API.
      const uidRef = admin.doc(`users/${uid}/vault/config`);
      const legacy = { version: 1, salt: Buffer.alloc(32, 1).toString('base64'), iterations: 600000, verifier: { version: 1, iv: Buffer.alloc(12).toString('base64'), ciphertext: Buffer.alloc(64).toString('base64') } };
      await uidRef.set(legacy); await admin.doc(`_vaultAccess/${uid}`).delete(); await login(fresh, recoveredKey); await login(first, recoveredKey);
      const id = '33333333-3333-4333-8333-333333333333';
      const source = doc(fresh.db, `users/${uid}/items/${id}`);
      await setDoc(source, { payload: legacy.verifier });
      const originalFile = ref(fresh.storage, `vaults/${uid}/${id}`), bytes = Buffer.alloc(64, 7);
      await uploadBytes(originalFile, bytes, { contentType: 'application/octet-stream' });
      const { config: staged } = await createKeyRecord(phrase);
      await operation(fresh, 'migrationBegin', { record: staged });
      await assert.rejects(setDoc(source, { payload: legacy.verifier }), { code: 'permission-denied' });
      await assert.rejects(deleteObject(originalFile), { code: 'storage/unauthorized' });
      const path = `users/${uid}/generations/${staged.generation}/items/${id}`, object = `generations/${uid}/${staged.generation}/${id}`;
      const payload = { ...legacy.verifier, version: 2 };
      await assert.rejects(setDoc(doc(first.db, path), { payload }), { code: 'permission-denied' });
      await operation(first, 'migrationBegin', { record: staged });
      await assert.rejects(setDoc(doc(fresh.db, path), { payload }), { code: 'permission-denied' });
      await setDoc(doc(first.db, path), { payload });
      await uploadBytes(ref(first.storage, object), bytes, { contentType: 'application/octet-stream' });
      await operation(first, 'migrationItem', { id, hasFile: true });
      const progress = await operation(first, 'migrationFinalize'); assert.equal(progress.complete, false);
      assert.equal((await getDoc(source)).data().payload.version, 1);
      assert.equal((await uidRef.get()).data().version, 1);
      await assert.rejects(setDoc(doc(first.db, path), { payload }), { code: 'permission-denied' });
      // Resume with a new claim after sealing, then ignore the cutover response.
      await operation(fresh, 'migrationBegin', { record: staged });
      await operation(fresh, 'migrationFinalize');
      assert.equal((await operation(fresh, 'migrationFinalize')).complete, true);
      assert.equal((await uidRef.get()).data().generation, staged.generation);
      assert.deepEqual(Buffer.from(await getBytes(originalFile)), bytes);
      assert.deepEqual((await getDoc(source)).data().payload, legacy.verifier);
    });
    void key;
  } finally {
    for (const c of [first, fresh]) { await signOut(c.auth); await terminate(c.db); await deleteApp(c.app); }
  }
});
