import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, createHash } from 'node:crypto';
import { initializeApp as adminApp } from 'firebase-admin/app';
import { getAuth as adminAuth } from 'firebase-admin/auth';
import { getFirestore as adminFirestore, Timestamp } from 'firebase-admin/firestore';
import { getStorage as adminStorage } from 'firebase-admin/storage';
import { initializeApp, deleteApp } from 'firebase/app';
import { initializeAuth, inMemoryPersistence, connectAuthEmulator, signInWithCustomToken } from 'firebase/auth';
import { getFunctions, connectFunctionsEmulator, httpsCallable } from 'firebase/functions';
import { getFirestore, connectFirestoreEmulator, doc, setDoc, getDoc, terminate } from 'firebase/firestore';
import { getStorage, connectStorageEmulator, ref, uploadBytes, getBytes, deleteObject } from 'firebase/storage';
import { createKeyRecord } from '../../src/lib/keys.ts';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
// Node's TypeScript loader requires explicit extensions; the browser source uses bundler resolution.
const temporary = await mkdtemp(`${tmpdir()}/haven-operations-crypto-`);
await writeFile(`${temporary}/crypto.ts`, (await readFile(new URL('../../src/lib/crypto.ts', import.meta.url), 'utf8')).replace("'./keys'", JSON.stringify(new URL('../../src/lib/keys.ts', import.meta.url).href)));
const { encryptJson, encryptFile, decryptFile, decryptJson } = await import(pathToFileURL(`${temporary}/crypto.ts`).href);
import { fileOperation, cleanupStagedObject } from '../lib/file-operations.js';
for (const [name, expected] of Object.entries({ FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9099', FIRESTORE_EMULATOR_HOST: '127.0.0.1:18080', FIREBASE_STORAGE_EMULATOR_HOST: '127.0.0.1:19199', GCLOUD_PROJECT: 'demo-haven-vault' })) assert.equal(process.env[name], expected, 'Disposable emulator suite only');
const projectId = 'demo-haven-vault', uid = 'fictional-operations-owner', session = 'Q'.repeat(43);
const appAdmin = adminApp({ projectId, storageBucket: `${projectId}.appspot.com` }, 'operations-admin');
const admin = adminFirestore(appAdmin), bucket = adminStorage(appAdmin).bucket();
const app = initializeApp({ projectId, apiKey: 'fake-key', storageBucket: `${projectId}.appspot.com` }, 'operations-client');
const auth = initializeAuth(app, { persistence: inMemoryPersistence }), db = getFirestore(app), storage = getStorage(app), functions = getFunctions(app, 'us-central1');
connectAuthEmulator(auth, 'http://127.0.0.1:9099'); connectFirestoreEmulator(db, '127.0.0.1', 18080); connectStorageEmulator(storage, '127.0.0.1', 19199); connectFunctionsEmulator(functions, '127.0.0.1', 5001);
const { key, config } = await createKeyRecord('fictional forest lantern oranges');
const generation = config.generation, root = `users/${uid}/generations/${generation}`;
const call = async (action, data = {}) => (await httpsCallable(functions, 'securityOperation', { timeout: 120000 })({ action: `files.${action}`, generation, ...data })).data;
const digest = data => createHash('sha256').update(data).digest('hex');
const itemRef = id => admin.doc(`${root}/items/${id}`), opRef = id => admin.doc(`${root}/operations/${id}`), objectPath = id => `staged/${uid}/${generation}/${id}`;
let catalogRevision = 0;
async function fixture(kind = 'upload', existing) {
  const id = randomUUID(), itemId = existing?.id || id, now = Date.now();
  const plaintext = Buffer.from('Fictional byte-for-byte file fixture \0\xff');
  const item = existing || { id: itemId, name: 'fictional-private-name.txt', kind: 'document', mimeType: 'text/plain', size: plaintext.length, createdAt: now, updatedAt: now, favorite: false, collection: 'Personal', trashed: false, staged: true };
  const encrypted = await encryptFile(key, plaintext.buffer.slice(plaintext.byteOffset, plaintext.byteOffset + plaintext.byteLength), `file:${itemId}`);
  const bytes = Buffer.from(await encrypted.arrayBuffer());
  const payload = await encryptJson(key, item, `metadata:${itemId}`);
  return { id, itemId, kind, payload, expectedRevision: item.revision || 0, catalogRevision, bytes: bytes.length, hash: digest(bytes), object: bytes, plaintext, item };
}
const input = ({ object, plaintext, item, ...fields }) => fields;
async function begin(f) { return call('begin', input(f)); }
async function upload(f) { await uploadBytes(ref(storage, objectPath(f.id)), f.object, { contentType: 'application/octet-stream' }); }
// Test-only dependency injection lives outside the callable. No production fault switches or auth bypasses.
async function injected(action, data, { failMetadata = false, failDelete = false, quota = false } = {}) {
  const proxyDb = new Proxy(admin, { get(target, name) {
    if (name === 'runTransaction') return cb => target.runTransaction(t => cb(new Proxy(t, { get(tx, field) {
      if (failMetadata && field === 'set') return (reference, ...args) => { if (reference.path.includes('/items/')) throw new Error('Injected metadata failure'); return tx.set(reference, ...args); };
      if (failMetadata && field === 'delete') return () => { throw new Error('Injected metadata deletion failure'); };
      const value = Reflect.get(tx, field); return typeof value === 'function' ? value.bind(tx) : value;
    } })));
    const value = Reflect.get(target, name); return typeof value === 'function' ? value.bind(target) : value;
  } });
  const proxyBucket = new Proxy(bucket, { get(target, name) {
    if (name === 'file') return path => new Proxy(target.file(path), { get(object, field) {
      if (field === 'delete' && failDelete) return async () => { throw new Error('Injected object cleanup failure'); };
      if (field === 'getMetadata' && quota) return async () => { throw Object.assign(new Error('Injected provider quota'), { code: 429 }); };
      const value = Reflect.get(object, field); return typeof value === 'function' ? value.bind(object) : value;
    } });
    const value = Reflect.get(target, name); return typeof value === 'function' ? value.bind(target) : value;
  } });
  return fileOperation({ data: { action: `files.${action}`, generation, ...data } }, async () => ({ uid }), { db: proxyDb, bucket: proxyBucket });
}
test('dependable encrypted file operations and faults', { timeout: 240000 }, async t => {
  try {
    await admin.recursiveDelete(admin.doc(`users/${uid}`));
    await admin.doc('_vaultAuth/owner').set({ uid });
    await admin.doc(`users/${uid}/vault/config`).set(config);
    await admin.doc(`_vaultAccess/${uid}`).set({ generation });
    await admin.doc(`_vaultSessions/${session}`).set({ uid, revoked: false, expiresAt: Timestamp.fromMillis(Date.now() + 3600000) });
    const token = await adminAuth(appAdmin).createCustomToken(uid, { vaultAccess: true, vaultSession: session });
    await signInWithCustomToken(auth, token);
    let good;
    await t.test('encrypted catalog persists empty collections and rejects stale catalog CAS', async () => {
      const payload = await encryptJson(key, [{ id: randomUUID(), name: 'Empty fictional collection', legacyNames: [] }], 'collections');
      const result = await call('catalog', { payload, expectedRevision: 0, expectedEpoch: 0 }); catalogRevision = result.revision;
      assert.equal((await call('list')).catalog.revision, 1);
      assert.equal((await decryptJson(key, (await call('list')).catalog.payload, 'collections'))[0].name, 'Empty fictional collection');
      const stale = await encryptJson(key, [], 'collections');
      await assert.rejects(call('catalog', { payload: stale, expectedRevision: 0, expectedEpoch: 0 }), { code: 'functions/aborted' });
      assert.equal((await call('catalog', { payload, expectedRevision: 0, expectedEpoch: 0 })).revision, 1, 'lost catalog response is idempotent');
    });
    await t.test('multi-file partial success, metadata failure after transfer, targeted retry and lost completion response', async () => {
      good = await fixture(); const failed = await fixture(); await begin(good); await begin(failed); await upload(good); await upload(failed);
      await call('finalize', { id: good.id });
      assert.equal((await opRef(good.id).get()).data().payload, null, 'completed journals retain no private metadata ciphertext');
      await assert.rejects(injected('finalize', { id: failed.id }, { failMetadata: true }), /Injected metadata/);
      assert.equal((await itemRef(good.itemId).get()).exists, true); assert.equal((await itemRef(failed.itemId).get()).exists, false);
      assert.equal((await opRef(failed.id).get()).data().status, 'pending');
      await begin(failed); await call('finalize', { id: failed.id });
      const lost = await call('finalize', { id: good.id }); assert.equal(lost.operation.status, 'completed');
      assert.equal((await admin.collection(`${root}/items`).get()).size, 2);
      const stored = new Blob([await getBytes(ref(storage, objectPath(good.id)))]);
      assert.deepEqual(Buffer.from(await decryptFile(key, stored, `file:${good.itemId}`)), good.plaintext);
      await assert.rejects(upload(good), { code: 'storage/unauthorized' });
    });
    await t.test('cancellation is terminal, orphan cleanup retries, and no late transfer is authorized', async () => {
      const f = await fixture(); await begin(f); await upload(f);
      await assert.rejects(injected('cancel', { id: f.id }, { failDelete: true }), /Injected object/);
      assert.equal((await opRef(f.id).get()).data().status, 'cancelling');
      assert.ok((await call('list')).operations.some(o => o.id === f.id), 'cleanup is still visible until the receipt is reconciled');
      const result = await call('finalize', { id: f.id }); assert.equal(result.operation.status, 'cancelled');
      assert.equal((await bucket.file(objectPath(f.id)).exists())[0], false);
      await assert.rejects(upload(f), { code: 'storage/unauthorized' });
      assert.equal((await call('cancel', { id: good.id })).operation.status, 'completed');
    });
    await t.test('late finalized objects after cancellation are inaccessible and cleaned with generation preconditions', async () => {
      const f = await fixture(); await begin(f); await call('cancel', { id: f.id });
      // Simulate a provider accepting an already initiated resumable session late.
      const object = bucket.file(objectPath(f.id)); await object.save(f.object, { contentType: 'application/octet-stream' });
      await assert.rejects(getBytes(ref(storage, objectPath(f.id))), { code: 'storage/unauthorized' });
      let metadata;
      try { [metadata] = await object.getMetadata(); } catch (error) { if (error.code === 404) return; throw error; } // The actual event may already have cleaned it.
      await cleanupStagedObject(objectPath(f.id), metadata.generation, { db: admin, bucket });
      assert.equal((await object.exists())[0], false);
    });
    await t.test('network-loss receipt reconciliation requires reselection if no encrypted object exists', async () => {
      const f = await fixture(); await begin(f);
      assert.ok((await call('list')).operations.some(o => o.id === f.id));
      await assert.rejects(call('finalize', { id: f.id }), /reselected/);
      await call('cancel', { id: f.id }); assert.equal((await opRef(f.id).get()).data().status, 'cancelled');
    });
    await t.test('concurrent mutable edits reject stale revisions and cannot bypass through direct Firestore writes', async () => {
      const original = { ...good.item, revision: 1, trashed: true };
      const a = await fixture('write', original), b = await fixture('write', { ...original, name: 'concurrent edit' });
      await begin(a); await begin(b);
      const results = await Promise.allSettled([call('finalize', { id: a.id }), call('finalize', { id: b.id })]);
      assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
      assert.equal(results.find(r => r.status === 'rejected').reason.code, 'functions/aborted');
      const loser = results[0].status === 'rejected' ? a : b; await call('cancel', { id: loser.id });
      await assert.rejects(setDoc(doc(db, `${root}/items/${good.itemId}`), { payload: good.payload }), { code: 'permission-denied' });
    });
    await t.test('catalog removal rejects interleaved item writes through an epoch check', async () => {
      const catalog = (await call('list')).catalog;
      const f = await fixture('write'); await begin(f); await call('finalize', { id: f.id });
      await assert.rejects(call('catalog', { payload: catalog.payload, expectedRevision: catalog.revision, expectedEpoch: catalog.itemEpoch }), { code: 'functions/aborted' });
    });
    await t.test('permanent deletion retains metadata on partial failure and blocks overlapping edits', async () => {
      const current = (await itemRef(good.itemId).get()).data();
      const item = await decryptJson(key, current.payload, `metadata:${good.itemId}`);
      const deletion = await fixture('delete', { ...item, trashed: true, revision: current.revision });
      await begin(deletion);
      await assert.rejects(begin(await fixture('write', { ...item, revision: current.revision })), { code: 'functions/aborted' });
      await assert.rejects(injected('finalize', { id: deletion.id }, { failDelete: true }), /Injected object/);
      assert.equal((await itemRef(good.itemId).get()).exists, true);
      await assert.rejects(injected('finalize', { id: deletion.id }, { failMetadata: true }), /Injected metadata deletion/);
      assert.equal((await bucket.file(objectPath(good.id)).exists())[0], false); assert.equal((await itemRef(good.itemId).get()).exists, true);
      assert.equal((await call('finalize', { id: deletion.id })).operation.status, 'completed');
      assert.equal((await itemRef(good.itemId).get()).exists, false);
      assert.equal((await call('finalize', { id: deletion.id })).operation.status, 'completed');
    });
    await t.test('concurrent oversized requests and provider quota failure cannot create completed-looking items', async () => {
      const a = await fixture(), b = await fixture();
      const results = await Promise.allSettled([a, b].map(f => begin({ ...f, bytes: 50 * 1024 * 1024 + 30 })));
      assert.ok(results.every(r => r.status === 'rejected' && r.reason.code === 'functions/invalid-argument'));
      await begin(a); await upload(a);
      await assert.rejects(injected('finalize', { id: a.id }, { quota: true }));
      assert.equal((await itemRef(a.id).get()).exists, false); await call('cancel', { id: a.id });
    });
    await t.test('encrypted object byte usage includes staging and trash, without claiming an aggregate quota', async () => {
      const f = await fixture(); await begin(f); await upload(f);
      const usage = await call('usage'); assert.ok(usage.objectBytes >= f.object.length); assert.equal(usage.aggregateLimit, null); assert.equal(usage.maxObjectBytes, 50 * 1024 * 1024 + 29);
      await call('cancel', { id: f.id });
    });
    await t.test('expired/revoked sessions and wrong owners cannot finalize or clean up', async () => {
      const f = await fixture(); await begin(f); await upload(f);
      await admin.doc(`_vaultSessions/${session}`).update({ revoked: true });
      await assert.rejects(call('finalize', { id: f.id }), { code: 'functions/unauthenticated' });
      await assert.rejects(call('cancel', { id: f.id }), { code: 'functions/unauthenticated' });
      await assert.rejects(getBytes(ref(storage, objectPath(f.id))), { code: 'storage/unauthorized' });
      await admin.doc(`_vaultSessions/${session}`).update({ revoked: false, expiresAt: Timestamp.fromMillis(Date.now() - 1) });
      await assert.rejects(call('finalize', { id: f.id }), { code: 'functions/unauthenticated' });
      await admin.doc(`_vaultSessions/${session}`).update({ expiresAt: Timestamp.fromMillis(Date.now() + 600000) });
      await admin.doc('_vaultAuth/owner').set({ uid: 'different-fictional-owner' });
      await assert.rejects(call('cancel', { id: f.id }), { code: 'functions/unauthenticated' });
      await admin.doc('_vaultAuth/owner').set({ uid }); await call('cancel', { id: f.id });
      await assert.rejects(deleteObject(ref(storage, objectPath(f.id))), { code: 'storage/unauthorized' });
    });
  } finally { await admin.doc('_vaultAuth/owner').delete(); await terminate(db); await deleteApp(app); await rm(temporary, { recursive: true, force: true }); }
});
