import { createHash } from 'node:crypto';
import { getFirestore, type Transaction } from 'firebase-admin/firestore';
import { getStorage } from 'firebase-admin/storage';
import { HttpsError, type CallableRequest } from 'firebase-functions/v2/https';
import { canonical } from './security-policy.js';

export const MAX_OBJECT_BYTES = 50 * 1024 * 1024 + 29;
export function validOperationId(id: unknown): id is string {
  return typeof id === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(id);
}
export function validMetadata(box: any, version: number) {
  return !!box && Object.keys(box).sort().join(',') === 'ciphertext,iv,version' && box.version === version &&
    typeof box.iv === 'string' && /^[A-Za-z0-9+/]{16}$/.test(box.iv) && typeof box.ciphertext === 'string' &&
    box.ciphertext.length >= 24 && box.ciphertext.length <= 700000 && /^[A-Za-z0-9+/]+={0,2}$/.test(box.ciphertext);
}
export function assertRevision(actual: number, expected: unknown) {
  if (!Number.isSafeInteger(expected) || actual !== expected) throw new HttpsError('aborted', 'This entry changed on another device. Reload the latest version before applying your edit. Your draft is still available until locking.');
}
type Authorize = (t: Transaction, r: CallableRequest, recent: boolean) => Promise<{ uid: string }>;
/** Uses the existing authenticated callable and key-generation authority. All private fields are opaque boxes. */
export async function fileOperation(request: CallableRequest, authorize: Authorize, dependencies = { db: getFirestore(), bucket: getStorage().bucket() }) {
  const { db, bucket } = dependencies;
  const data = request.data, action = data.action;
  const context = await db.runTransaction(async t => {
    const auth = await authorize(t, request, false);
    const config = (await t.get(db.doc(`users/${auth.uid}/vault/config`))).data();
    const migration = (await t.get(db.doc(`users/${auth.uid}/vault/migration`))).data();
    if (!config || (migration && migration.phase !== 'complete' && !['files.list', 'files.status', 'files.usage'].includes(action))) throw new HttpsError('failed-precondition', 'Finish vault migration before file operations.');
    if ((config.version === 2 ? config.generation : 'legacy') !== data.generation) throw new HttpsError('aborted', 'The active vault generation changed. Unlock the latest vault.');
    return { uid: auth.uid, version: config.version, generation: data.generation as string, migrationPending: !!migration && migration.phase !== 'complete' };
  });
  const root = `users/${context.uid}` + (context.version === 2 ? `/generations/${context.generation}` : '');
  const ops = db.collection(`${root}/operations`), items = db.collection(`${root}/items`);
  const catalog = db.doc(`${root}/catalog/collections`);
  const staged = (id: string) => bucket.file(`staged/${context.uid}/${context.generation}/${id}`);
  const file = (id: string) => bucket.file(context.version === 2 ? `generations/${context.uid}/${context.generation}/${id}` : `vaults/${context.uid}/${id}`);
  const guarded = async <T>(fn: (t: Transaction) => Promise<T>) => db.runTransaction(async t => {
    await authorize(t, request, false);
    const config = (await t.get(db.doc(`users/${context.uid}/vault/config`))).data();
    const migration = (await t.get(db.doc(`users/${context.uid}/vault/migration`))).data();
    if ((config?.version === 2 ? config.generation : 'legacy') !== context.generation || (migration && migration.phase !== 'complete')) throw new HttpsError('aborted', 'Vault generation changed. Reload before retrying.');
    return fn(t);
  });
  if (action === 'files.list') {
    const [pending, collections] = await Promise.all([ops.where('status', 'in', ['pending', 'cancelling', 'deleting']).get(), catalog.get()]);
    return { operations: pending.docs.map(d => ({ id: d.id, ...d.data() })), catalog: collections.data() || null, migrationPending: context.migrationPending };
  }
  if (action === 'files.usage') {
    // Object listing is Admin-only. Includes trash, abandoned staging and retained migration safeguards.
    let bytes = 0, objects = 0;
    for (const prefix of [`vaults/${context.uid}/`, `generations/${context.uid}/`, `safeguards/${context.uid}/`, `staged/${context.uid}/`]) {
      const [files] = await bucket.getFiles({ prefix });
      for (const object of files) { bytes += Number(object.metadata.size || 0); objects++; }
    }
    return { objectBytes: bytes, objects, maxPlaintextBytes: MAX_OBJECT_BYTES - 29, maxObjectBytes: MAX_OBJECT_BYTES, aggregateLimit: null };
  }
  if (action === 'files.catalog') {
    if (!validMetadata(data.payload, context.version)) throw new HttpsError('invalid-argument', 'Invalid encrypted collections.');
    return guarded(async t => {
      const old = (await t.get(catalog)).data();
      if (old && old.revision === data.expectedRevision + 1 && canonical(old.payload) === canonical(data.payload)) return { revision: old.revision };
      assertRevision(old?.revision || 0, data.expectedRevision);
      if ((old?.itemEpoch || 0) !== data.expectedEpoch) throw new HttpsError('aborted', 'Items changed. Reload collections and retry.');
      const revision = (old?.revision || 0) + 1;
      t.set(catalog, { payload: data.payload, revision, itemEpoch: old?.itemEpoch || 0 }); return { revision };
    });
  }
  if (!validOperationId(data.id)) throw new HttpsError('invalid-argument', 'Invalid operation identifier.');
  const opRef = ops.doc(data.id);
  const completedResult = async (operation: any) => {
    if (operation.status !== 'completed' || operation.kind === 'delete') return { operation };
    const current = (await items.doc(operation.itemId).get()).data();
    if (!current || current.deleting) throw new HttpsError('not-found', 'The saved item has since been removed. Reload the latest vault.');
    return { operation: { ...operation, payload: current.payload, revision: current.revision } };
  };
  if (action === 'files.status') return { operation: (await opRef.get()).data() || null };
  if (action === 'files.begin') {
    if (!validOperationId(data.itemId) || !validMetadata(data.payload, context.version) || !['upload', 'write', 'delete'].includes(data.kind)) throw new HttpsError('invalid-argument', 'Invalid encrypted operation.');
    if (data.kind === 'upload' && (data.itemId !== data.id || !Number.isSafeInteger(data.bytes) || data.bytes < 29 || data.bytes > MAX_OBJECT_BYTES || typeof data.hash !== 'string' || !/^[a-f0-9]{64}$/.test(data.hash))) throw new HttpsError('invalid-argument', 'Encrypted object exceeds the 50 MiB plaintext limit or has an invalid digest.');
    const input = { itemId: data.itemId, payload: data.payload, kind: data.kind, expectedRevision: data.expectedRevision, bytes: data.bytes || 0, hash: data.hash || null, catalogRevision: data.catalogRevision };
    const fingerprint = createHash('sha256').update(canonical(input)).digest('hex');
    return guarded(async t => {
      const old = (await t.get(opRef)).data();
      if (old) { if (old.fingerprint !== fingerprint) throw new HttpsError('already-exists', 'Operation identifier already used. Reconcile before retrying.'); return { operation: old }; }
      const target = items.doc(data.itemId), existing = (await t.get(target)).data();
      const collectionState = (await t.get(catalog)).data();
      assertRevision(collectionState?.revision || 0, data.catalogRevision);
      if (existing?.deleting) throw new HttpsError('aborted', 'Deletion is unfinished. Retry deletion before making changes.');
      assertRevision(existing?.revision || 0, data.expectedRevision);
      if (data.kind === 'upload' && existing) throw new HttpsError('already-exists', 'File already exists.');
      const operation = { ...input, fingerprint, status: data.kind === 'delete' ? 'deleting' : 'pending', createdAt: Date.now(), staged: data.kind === 'upload' || existing?.staged === true };
      if (data.kind === 'delete') {
        if (!existing) throw new HttpsError('not-found', 'The item is already removed.');
        // Keep original ciphertext and revision until object cleanup is confirmed.
        t.update(target, { deleting: data.id });
        // Retire the original transfer receipt immediately: a late resumable commit
        // must never restore read access after deletion has started.
        if (existing.staged) t.update(ops.doc(data.itemId), { status: 'retired' });
      }
      t.create(opRef, operation); return { operation };
    });
  }
  if (!['files.finalize', 'files.cancel'].includes(action)) throw new HttpsError('invalid-argument', 'Unknown file operation.');
  let operation = (await opRef.get()).data();
  if (!operation) throw new HttpsError('not-found', 'Operation not found.');
  if (['completed', 'cancelled', 'retired'].includes(operation.status)) return completedResult(operation);
  if (action === 'files.cancel') {
    operation = await guarded(async t => {
      const latest = (await t.get(opRef)).data()!;
      if (latest.status === 'completed' || latest.status === 'cancelled') return latest;
      if (latest.kind === 'delete') throw new HttpsError('failed-precondition', 'Permanent deletion cannot be cancelled. Retry to finish cleanup.');
      t.update(opRef, { status: 'cancelling' }); return { ...latest, status: 'cancelling' };
    });
    if (['completed', 'cancelled', 'retired'].includes(operation.status)) return completedResult(operation);
  }
  if (operation.status === 'cancelling' || operation.kind === 'delete') {
    await guarded(async () => undefined);
    // The path is derived from the authorized owner and the server receipt, never a supplied path.
    if (operation.kind === 'upload' || operation.kind === 'delete') await (operation.staged ? staged(operation.itemId) : file(operation.itemId)).delete({ ignoreNotFound: true });
    return guarded(async t => {
      const latest = (await t.get(opRef)).data()!;
      const target = items.doc(latest.itemId), existing = (await t.get(target)).data();
      const collectionState = (await t.get(catalog)).data();
      if (latest.kind === 'delete') {
        if (existing && existing.deleting !== data.id) throw new HttpsError('aborted', 'Deletion ownership changed.');
        t.delete(target);
        t.set(catalog, { itemEpoch: (collectionState?.itemEpoch || 0) + 1 }, { merge: true });
      }
      const status = latest.kind === 'delete' ? 'completed' : 'cancelled';
      t.update(opRef, { status, payload: null }); return { operation: { ...latest, status } };
    });
  }
  if (operation.kind === 'upload') {
    const object = staged(operation.itemId);
    let metadata;
    try { [metadata] = await object.getMetadata(); }
    catch (error: any) { if (error.code === 404) throw new HttpsError('failed-precondition', 'Original file must be reselected. No plaintext is retained after reload. Cancel this receipt before selecting it again.'); throw error; }
    if (Number(metadata.size) !== operation.bytes || Number(metadata.size) > MAX_OBJECT_BYTES || metadata.contentType !== 'application/octet-stream') throw new HttpsError('data-loss', 'Encrypted object size did not verify. Cancel and retry.');
    const hash = createHash('sha256');
    for await (const chunk of object.createReadStream()) hash.update(chunk);
    if (hash.digest('hex') !== operation.hash) throw new HttpsError('data-loss', 'Encrypted object digest did not verify. Cancel and retry.');
  }
  return guarded(async t => {
    const latest = (await t.get(opRef)).data()!;
    if (latest.status === 'completed') {
      const saved = (await t.get(items.doc(latest.itemId))).data();
      if (!saved || saved.deleting) throw new HttpsError('not-found', 'The saved item has since been removed.');
      return { operation: { ...latest, payload: saved.payload, revision: saved.revision } };
    }
    if (latest.status !== 'pending') throw new HttpsError('aborted', 'Cancellation is pending. Retry cleanup.');
    const target = items.doc(latest.itemId), existing = (await t.get(target)).data();
    const collectionState = (await t.get(catalog)).data();
    assertRevision(collectionState?.revision || 0, latest.catalogRevision);
    if (existing?.deleting) throw new HttpsError('aborted', 'Deletion in progress.');
    assertRevision(existing?.revision || 0, latest.expectedRevision);
    const revision = latest.expectedRevision + 1;
    t.set(target, { payload: latest.payload, revision, staged: latest.staged, objectBytes: latest.kind === 'upload' ? latest.bytes : existing?.objectBytes || 0 });
    t.set(catalog, { itemEpoch: (collectionState?.itemEpoch || 0) + 1 }, { merge: true });
    t.update(opRef, { status: 'completed', revision, payload: null });
    return { operation: { ...latest, status: 'completed', revision } };
  });
}


/** Eventual cleanup for a transfer which commits after a cancellation/lock race.
 * The event is trusted, the receipt is Admin-owned, and generation preconditions
 * prevent an old event from deleting a later physical object. No trash purge. */
export async function cleanupStagedObject(path: string, objectGeneration?: string, dependencies = { db: getFirestore(), bucket: getStorage().bucket() }) {
  const parts = path.split('/');
  if (parts.length !== 4 || parts[0] !== 'staged' || !parts[1] || !validOperationId(parts[3]) || (parts[2] !== 'legacy' && !validOperationId(parts[2]))) return;
  const [, uid, generation, id] = parts;
  const root = `users/${uid}` + (generation === 'legacy' ? '' : `/generations/${generation}`);
  const op = (await dependencies.db.doc(`${root}/operations/${id}`).get()).data();
  if (!op || op.kind !== 'upload' || op.itemId !== id || !['cancelled', 'cancelling', 'retired'].includes(op.status)) return;
  try { await dependencies.bucket.file(path).delete({ ignoreNotFound: true, ...(objectGeneration ? { ifGenerationMatch: objectGeneration } : {}) }); }
  catch (error: any) { if (error.code !== 412) throw error; } // A newer generation has its own event.
}
