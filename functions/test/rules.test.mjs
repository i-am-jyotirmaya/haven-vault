import { readFile } from "node:fs/promises";
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { initializeTestEnvironment, assertFails, assertSucceeds } from "@firebase/rules-unit-testing";
import { doc, getDoc, setDoc, deleteDoc, Timestamp } from "firebase/firestore";
import { ref, uploadBytes, getBytes, deleteObject } from "firebase/storage";

let environment;
const owner = "owner";
const liveId = "A".repeat(43);
const expiredId = "B".repeat(43);
const revokedId = "C".repeat(43);
const otherId = "D".repeat(43);
const envelope = {
  version: 1,
  iv: Buffer.alloc(12).toString("base64"),
  ciphertext: Buffer.alloc(32, 1).toString("base64"),
};
const configuration = {
  version: 1,
  salt: Buffer.alloc(32).toString("base64"),
  iterations: 600000,
  verifier: envelope,
};
const claims = (id = liveId) => ({ vaultAccess: true, vaultSession: id });
const cipherBytes = new Uint8Array(45).fill(1);
const cipherMetadata = { contentType: "application/octet-stream" };

before(async () => {
  environment = await initializeTestEnvironment({
    projectId: "demo-haven-vault",
    firestore: {
      host: "127.0.0.1",
      port: 18080,
      rules: await readFile(new URL("../../firestore.rules", import.meta.url), "utf8"),
    },
    storage: {
      host: "127.0.0.1",
      port: 19199,
      rules: await readFile(new URL("../../storage.rules", import.meta.url), "utf8"),
    },
  });
  await environment.withSecurityRulesDisabled(async (context) => {
    const firestore = context.firestore();
    const now = Date.now();
    for (const [id, uid, expires, revoked] of [
      [liveId, owner, now + 600000, false],
      [expiredId, owner, now - 1, false],
      [revokedId, owner, now + 600000, true],
      [otherId, "someone-else", now + 600000, false],
    ]) {
      await setDoc(doc(firestore, "_vaultSessions", id), { uid, expiresAt: Timestamp.fromMillis(expires), revoked });
    }
    await setDoc(doc(firestore, "users/owner/items/private"), { payload: envelope });
    await setDoc(doc(firestore, "_vaultAuth/owner"), { uid: owner });
    await uploadBytes(ref(context.storage(), "vaults/owner/private"), cipherBytes, cipherMetadata);
  });
});

after(async () => {
  if (environment) await environment.cleanup();
});

test("unauthenticated and Google-only identities cannot read encrypted data", async () => {
  for (const context of [
    environment.unauthenticatedContext(),
    environment.authenticatedContext(owner, { email: "owner@example.com", email_verified: true }),
  ]) {
    await assertFails(getDoc(doc(context.firestore(), "users/owner/items/private")));
    await assertFails(getBytes(ref(context.storage(), "vaults/owner/private")));
    await assertFails(setDoc(doc(context.firestore(), "users/owner/items/new"), { payload: envelope }));
    await assertFails(uploadBytes(ref(context.storage(), "vaults/owner/new"), cipherBytes, cipherMetadata));
  }
});

test("expired, revoked, missing, and wrong-owner session records deny access", async () => {
  for (const id of [expiredId, revokedId, otherId, "E".repeat(43)]) {
    const context = environment.authenticatedContext(owner, claims(id));
    await assertFails(getDoc(doc(context.firestore(), "users/owner/items/private")));
    await assertFails(getBytes(ref(context.storage(), "vaults/owner/private")));
    await assertFails(setDoc(doc(context.firestore(), "users/owner/items/denied"), { payload: envelope }));
    await assertFails(uploadBytes(ref(context.storage(), "vaults/owner/denied"), cipherBytes, cipherMetadata));
  }
});

test("a copied session identifier cannot authorize another UID", async () => {
  const context = environment.authenticatedContext("attacker", claims());
  await assertFails(getDoc(doc(context.firestore(), "users/owner/items/private")));
  await assertFails(getDoc(doc(context.firestore(), "users/attacker/items/private")));
  await assertFails(getBytes(ref(context.storage(), "vaults/owner/private")));
  await assertFails(uploadBytes(ref(context.storage(), "vaults/attacker/stolen"), cipherBytes, cipherMetadata));
});

test("an active owner session can use encrypted documents and immutable encrypted files", async () => {
  const context = environment.authenticatedContext(owner, claims());
  const item = doc(context.firestore(), "users/owner/items/valid-item");
  const object = ref(context.storage(), "vaults/owner/valid-item");
  await assertFails(setDoc(item, { payload: envelope }));
  await environment.withSecurityRulesDisabled(async admin => { await setDoc(doc(admin.firestore(), "users/owner/items/valid-item"), { payload: envelope }); await uploadBytes(ref(admin.storage(), "vaults/owner/valid-item"), cipherBytes, cipherMetadata); });
  assert.equal((await assertSucceeds(getDoc(item))).data().payload.version, 1);
  await assertFails(uploadBytes(object, cipherBytes, cipherMetadata));
  assert.equal((await assertSucceeds(getBytes(object))).byteLength, cipherBytes.length);
  await assertFails(uploadBytes(object, cipherBytes, cipherMetadata));
  await assertFails(deleteObject(object));
  await assertFails(deleteDoc(item));
});

test("configuration is validated and cannot be replaced or deleted", async () => {
  const context = environment.authenticatedContext(owner, claims());
  const config = doc(context.firestore(), "users/owner/vault/config");
  await assertFails(setDoc(config, { ...configuration, iterations: 1 }));
  await assertFails(setDoc(config, { ...configuration, passphrase: "plaintext" }));
  await assertSucceeds(setDoc(config, configuration));
  await assertSucceeds(getDoc(config));
  await assertFails(setDoc(config, { ...configuration, iterations: 700000 }));
  await assertFails(deleteDoc(config));
});

test("plaintext metadata and malformed ciphertext envelopes are rejected", async () => {
  const context = environment.authenticatedContext(owner, claims());
  const item = doc(context.firestore(), "users/owner/items/invalid-envelope");
  for (const data of [
    { payload: envelope, name: "private.pdf" },
    { payload: { ...envelope, filename: "private.pdf" } },
    { payload: { ...envelope, version: 2 } },
    { payload: { ...envelope, iv: "short" } },
    { payload: { ...envelope, ciphertext: "plaintext!" } },
  ]) await assertFails(setDoc(item, data));
});

test("file validation rejects plaintext types, undersized envelopes, and oversized objects", async () => {
  const context = environment.authenticatedContext(owner, claims());
  await assertFails(uploadBytes(ref(context.storage(), "vaults/owner/plaintext"), cipherBytes, { contentType: "image/jpeg" }));
  await assertFails(uploadBytes(ref(context.storage(), "vaults/owner/short"), new Uint8Array(28), cipherMetadata));
  await assertFails(uploadBytes(ref(context.storage(), "vaults/owner/oversized"), new Uint8Array(50 * 1024 * 1024 + 30), cipherMetadata));
});

test("even an active session cannot read or write backend authority records", async () => {
  const context = environment.authenticatedContext(owner, claims());
  for (const path of [
    `_vaultSessions/${liveId}`,
    "_vaultAuth/owner",
    "_vaultChallenges/fake",
    "_vaultCredentials/fake",
    "_vaultLimits/fake",
    "_vaultAccess/owner",
  ]) {
    await assertFails(getDoc(doc(context.firestore(), path)));
    await assertFails(setDoc(doc(context.firestore(), path), { uid: owner, revoked: false }));
  }
});

test("revocation takes effect without issuing a new Firebase ID token", async () => {
  const session = "F".repeat(43);
  await environment.withSecurityRulesDisabled(async (context) => {
    await setDoc(doc(context.firestore(), "_vaultSessions", session), {
      uid: owner, expiresAt: Timestamp.fromMillis(Date.now() + 600000), revoked: false,
    });
  });
  const context = environment.authenticatedContext(owner, claims(session));
  await assertSucceeds(getDoc(doc(context.firestore(), "users/owner/items/private")));
  await assertSucceeds(getBytes(ref(context.storage(), "vaults/owner/private")));
  await environment.withSecurityRulesDisabled(async (admin) => {
    await setDoc(doc(admin.firestore(), "_vaultSessions", session), {
      uid: owner, expiresAt: Timestamp.fromMillis(Date.now() + 600000), revoked: true,
    });
  });
  await assertFails(getDoc(doc(context.firestore(), "users/owner/items/private")));
  await assertFails(getBytes(ref(context.storage(), "vaults/owner/private")));
});

test("freshly refreshed Firebase claims cannot revive an expired private session", async () => {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const freshToken = environment.authenticatedContext(owner, {
    ...claims(expiredId), iat: nowSeconds, auth_time: nowSeconds, exp: nowSeconds + 3600,
  });
  await assertFails(getDoc(doc(freshToken.firestore(), 'users/owner/items/private')));
  await assertFails(getBytes(ref(freshToken.storage(), 'vaults/owner/private')));
  await assertFails(setDoc(doc(freshToken.firestore(), 'users/owner/items/refreshed'), { payload: envelope }));
});


test("generation authority freezes old clients and restricts staging to its claiming session", async () => {
  const generation = "11111111-1111-4111-8111-111111111111";
  const id = "22222222-2222-4222-8222-222222222222";
  const otherId = "G".repeat(43);
  const context = environment.authenticatedContext(owner, claims());
  const other = environment.authenticatedContext(owner, claims(otherId));
  await environment.withSecurityRulesDisabled(async admin => {
    await setDoc(doc(admin.firestore(), "_vaultSessions", otherId), { uid: owner, expiresAt: Timestamp.fromMillis(Date.now() + 600000), revoked: false });
    await setDoc(doc(admin.firestore(), "users/owner/vault/config"), configuration);
    await setDoc(doc(admin.firestore(), "users/owner/vault/migration"), { phase: "staging", sessionId: liveId, record: { generation } });
    await setDoc(doc(admin.firestore(), "_vaultAccess/owner"), { generation: null, migrationGeneration: generation, migrationPhase: "staging", migrationSessionId: liveId });
  });
  await assertFails(setDoc(doc(context.firestore(), "users/owner/items/frozen"), { payload: envelope }));
  await assertFails(uploadBytes(ref(context.storage(), `vaults/owner/${id}`), cipherBytes, cipherMetadata));
  const path = `users/owner/generations/${generation}/items/${id}`;
  const object = `generations/owner/${generation}/${id}`;
  await assertFails(setDoc(doc(other.firestore(), path), { payload: { ...envelope, version: 2 } }));
  await assertFails(uploadBytes(ref(other.storage(), object), cipherBytes, cipherMetadata));
  await assertSucceeds(setDoc(doc(context.firestore(), path), { payload: { ...envelope, version: 2 } }));
  await assertSucceeds(uploadBytes(ref(context.storage(), object), cipherBytes, cipherMetadata));
  await assertFails(deleteObject(ref(context.storage(), object)));
  await assertFails(setDoc(doc(context.firestore(), path), { payload: { ...envelope, version: 2 } }));
  await environment.withSecurityRulesDisabled(async admin => {
    await setDoc(doc(admin.firestore(), "users/owner/vault/migration"), { phase: "verifying", sessionId: liveId, record: { generation } });
    await setDoc(doc(admin.firestore(), "_vaultAccess/owner"), { generation: null, migrationGeneration: generation, migrationPhase: "verifying", migrationSessionId: liveId });
  });
  await assertSucceeds(getBytes(ref(context.storage(), object)));
  await assertFails(uploadBytes(ref(context.storage(), `generations/owner/${generation}/33333333-3333-4333-8333-333333333333`), cipherBytes, cipherMetadata));
});


test("operation-staged objects require server receipts, enforce sizes and close on cancellation", async () => {
  const id = "44444444-4444-4444-8444-444444444444";
  const context = environment.authenticatedContext(owner, claims());
  const path = `staged/owner/legacy/${id}`;
  const receipt = `users/owner/operations/${id}`;
  await assertFails(uploadBytes(ref(context.storage(), path), cipherBytes, cipherMetadata));
  await environment.withSecurityRulesDisabled(async admin => { await setDoc(doc(admin.firestore(), receipt), { status: 'pending', kind: 'upload', bytes: cipherBytes.length }); });
  await assertFails(uploadBytes(ref(context.storage(), path), new Uint8Array(44), cipherMetadata));
  await assertSucceeds(uploadBytes(ref(context.storage(), path), cipherBytes, cipherMetadata));
  await assertFails(uploadBytes(ref(context.storage(), path), cipherBytes, cipherMetadata));
  await assertFails(deleteObject(ref(context.storage(), path)));
  await environment.withSecurityRulesDisabled(async admin => { await setDoc(doc(admin.firestore(), receipt), { status: 'cancelling', kind: 'upload', bytes: cipherBytes.length }); });
  await assertFails(getBytes(ref(context.storage(), path)));
  await environment.withSecurityRulesDisabled(async admin => { await deleteObject(ref(admin.storage(), path)); });
  await assertFails(uploadBytes(ref(context.storage(), path), cipherBytes, cipherMetadata));
});
