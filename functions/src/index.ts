import { createHash, randomBytes, createPublicKey, verify as verifySignature } from "node:crypto";
import { getStorage } from "firebase-admin/storage";
import { freshPasskey, canonical, validBox, validKeyRecord, keyTransition } from "./security-policy.js";
import { initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore, Timestamp, type Transaction } from "firebase-admin/firestore";
import { defineBoolean, defineString } from "firebase-functions/params";
import { onCall, HttpsError, type CallableRequest } from "firebase-functions/v2/https";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
  type AuthenticatorTransportFuture,
} from "@simplewebauthn/server";
import {
  CHALLENGE_MS,
  sessionDurationMs,
  enrollmentAllowed,
  isCredentialId,
  isFreshOwnerGoogle,
  isOpaqueId,
  validRelyingParty,
  validSession,
  type Principal,
} from "./policy.js";

initializeApp();
const db = getFirestore();
const ownerEmail = defineString("OWNER_EMAIL", {
  description: "The verified Google owner email for initial enrollment and kit-based recovery.",
});
const rpId = defineString("RP_ID", {
  description: "Exact production hostname (without scheme, slash, or port).",
});
const expectedOrigin = defineString("EXPECTED_ORIGIN", {
  description: "Exact production origin, for example https://your-project.web.app.",
});
const authSessionMinutes = defineString("AUTH_SESSION_MINUTES", {
  default: "60",
  description: "Absolute lifetime of newly issued sessions: 15, 30, or 60 minutes.",
});
function configuredSessionDuration(): number {
  try { return sessionDurationMs(authSessionMinutes.value()); }
  catch { throw new HttpsError("failed-precondition", "AUTH_SESSION_MINUTES must be 15, 30, or 60."); }
}
const enforceAppCheck = defineBoolean("ENFORCE_APP_CHECK", { default: false });
const callableOptions = {
  region: "us-central1",
  // Browsers must reach the login handshake; each handler enforces its own
  // owner/session checks or verifies a one-use WebAuthn challenge.
  invoker: "public" as const,
  maxInstances: 10,
  timeoutSeconds: 30,
  memory: "256MiB" as const,
};
const ownerRef = db.doc("_vaultAuth/owner");
const credentials = db.collection("_vaultCredentials");
const challenges = db.collection("_vaultChallenges");
const sessions = db.collection("_vaultSessions");
const limits = db.collection("_vaultLimits");

type Owner = { uid: string; email: string; webAuthnUserID: string; credentialIds: string[] };
type StoredCredential = {
  uid: string;
  id: string;
  publicKey: string;
  counter: number;
  transports: AuthenticatorTransportFuture[];
  webAuthnUserID: string;
};
type Challenge = {
  purpose: "registration" | "authentication" | "recovery";
  challenge: string;
  uid: string;
  webAuthnUserID: string;
  expiresAt: Timestamp;
  bootstrap?: boolean;
  sessionId?: string;
  recoveryId?: string;
  revision?: number;
  statement?: string;
};

function opaqueId(): string {
  return randomBytes(32).toString("base64url");
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function checkApp(request: CallableRequest): void {
  // Callable SDK validates a supplied token and populates request.app. Reading
  // the parameter at invocation avoids freezing its value during deployment.
  if (enforceAppCheck.value() && !request.app) {
    throw new HttpsError("unauthenticated", "A valid App Check token is required.");
  }
}

function configured(request: CallableRequest): { rpID: string; origin: string; email: string } {
  checkApp(request);
  configuredSessionDuration();
  const email = ownerEmail.value().trim().toLowerCase();
  const rpID = rpId.value();
  const origin = expectedOrigin.value();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !validRelyingParty(rpID, origin)) {
    throw new HttpsError(
      "failed-precondition",
      "The vault owner and passkey domain must be configured by the administrator.",
    );
  }
  return { rpID, origin, email };
}

function principal(request: CallableRequest): Principal {
  if (!request.auth) throw new HttpsError("unauthenticated", "Sign in to continue.");
  return {
    uid: request.auth.uid,
    email: request.auth.token.email,
    emailVerified: request.auth.token.email_verified,
    provider: request.auth.token.firebase?.sign_in_provider,
    authTime: request.auth.token.auth_time,
  };
}

function claimSession(request: CallableRequest): string | undefined {
  const value: unknown = request.auth?.token.vaultSession;
  return request.auth?.token.vaultAccess === true && isOpaqueId(value) ? value : undefined;
}

async function sessionValid(
  transaction: Transaction,
  id: string | undefined,
  uid: string,
): Promise<boolean> {
  if (!id) return false;
  const snapshot = await transaction.get(sessions.doc(id));
  const data = snapshot.data();
  return validSession(
    data
      ? {
          uid: data.uid,
          expiresAtMs: data.expiresAt?.toMillis(),
          revoked: data.revoked,
        }
      : undefined,
    uid,
    Date.now(),
  );
}

// Atomic, shared across instances. Raw addresses are never stored.
// A project-wide ceiling supplements per-address throttling against distributed abuse.
async function rateLimit(
  request: CallableRequest,
  action: string,
  perAddress: number,
): Promise<void> {
  const now = Date.now();
  const windowMs = 5 * 60 * 1000;
  const refs = [
    { ref: limits.doc(digest(`${action}:${request.rawRequest.ip || "unknown"}`)), max: perAddress },
    { ref: limits.doc(digest(`global:${action}`)), max: 300 },
  ];
  await db.runTransaction(async (transaction) => {
    const snapshots = await Promise.all(refs.map(({ ref }) => transaction.get(ref)));
    const changes = snapshots.map((snapshot, index) => {
      const previous = snapshot.data();
      const active = previous?.windowEnd?.toMillis() > now;
      const count = active ? Number(previous?.count || 0) : 0;
      if (count >= refs[index].max)
        throw new HttpsError(
          "resource-exhausted",
          "Too many attempts. Wait five minutes and try again.",
        );
      return {
        count: count + 1,
        windowEnd: active ? previous!.windowEnd : Timestamp.fromMillis(now + windowMs),
        expiresAt: Timestamp.fromMillis(now + windowMs * 2),
      };
    });
    changes.forEach((data, index) => transaction.set(refs[index].ref, data));
  });
}

function responseData<T>(request: CallableRequest): { challengeId: string; response: T } {
  const data = request.data;
  if (
    !data ||
    !isOpaqueId(data.challengeId) ||
    !data.response ||
    typeof data.response !== "object" ||
    Array.isArray(data.response) ||
    !data.response.response ||
    typeof data.response.response !== "object" ||
    Array.isArray(data.response.response) ||
    !isCredentialId(data.response.id) ||
    JSON.stringify(data.response).length > 32_768
  ) {
    throw new HttpsError("invalid-argument", "Invalid passkey response.");
  }
  return { challengeId: data.challengeId, response: data.response as T };
}

async function consumeChallenge(
  id: string,
  purpose: Challenge["purpose"],
  uid?: string,
): Promise<Challenge> {
  return db.runTransaction(async (transaction) => {
    const ref = challenges.doc(id);
    const snapshot = await transaction.get(ref);
    const data = snapshot.data() as Challenge | undefined;
    if (
      !data ||
      data.purpose !== purpose ||
      data.expiresAt.toMillis() <= Date.now() ||
      (uid !== undefined && data.uid !== uid)
    ) {
      throw new HttpsError(
        "permission-denied",
        "This passkey request expired or was already used. Start again.",
      );
    }
    // Consume before verification. Even a rejected signature cannot be replayed.
    transaction.delete(ref);
    return data;
  });
}

async function issueSession(uid: string, credentialId: string, device = "Browser"): Promise<{ token: string; expiresAtMs: number; serverNowMs: number; sessionDurationMinutes: number }> {
  const id = opaqueId();
  const ref = sessions.doc(id);
  const durationMs = configuredSessionDuration();
  const expiresAtMs = Date.now() + durationMs;
  await db.runTransaction(async transaction => {
    const owner = (await transaction.get(ownerRef)).data() as Owner | undefined;
    const credential = await transaction.get(credentials.doc(digest(credentialId)));
    const active = await transaction.get(sessions.where("uid", "==", uid).where("revoked", "==", false));
    if (owner?.uid !== uid || !owner.credentialIds.includes(credentialId) || !credential.exists) throw new HttpsError("permission-denied", "Credential was revoked.");
    if (active.docs.filter(d => d.data().expiresAt.toMillis() > Date.now()).length >= 50) throw new HttpsError("resource-exhausted", "Session limit reached. Revoke old sessions first.");
    transaction.create(ref, {
    uid, credentialId, device: device.slice(0, 80), authenticatedAt: Timestamp.now(), lastActivityAt: Timestamp.now(),
    createdAt: Timestamp.now(),
    expiresAt: Timestamp.fromMillis(expiresAtMs),
    sessionDurationMinutes: durationMs / 60_000,
    revoked: false,
  });
  });
  try {
    // Never set persistent custom claims: every successful ceremony gets its own
    // expiring server-side session, independent of Firebase's refresh token.
    const token = await getAuth().createCustomToken(uid, { vaultAccess: true, vaultSession: id });
    return { token, expiresAtMs, serverNowMs: Date.now(), sessionDurationMinutes: durationMs / 60_000 };
  } catch {
    await ref.delete();
    throw new HttpsError("internal", "Could not start a vault session. Please try again.");
  }
}

/** Checks the data-rule authority and records activity without renewing expiry. */
export const validateVaultSession = onCall(callableOptions, async (request) => {
  checkApp(request);
  const user = principal(request);
  const id = claimSession(request);
  if (!id) throw new HttpsError("unauthenticated", "A passkey vault session is required.");
  return db.runTransaction(async (transaction) => {
    const owner = await transaction.get(ownerRef);
    const snapshot = await transaction.get(sessions.doc(id));
    const data = snapshot.data();
    const serverNowMs = Date.now();
    const expiresAtMs = data?.expiresAt?.toMillis();
    if (!data || owner.data()?.uid !== user.uid || !validSession(data ? {
      uid: data.uid, expiresAtMs, revoked: data.revoked,
    } : undefined, user.uid, serverNowMs)) {
      throw new HttpsError("permission-denied", "Your vault session has ended. Sign in again.");
    }
    // Older records already have createdAt and a fixed 15-minute lifetime.
    // Read the issued record, never current deployment settings, on validation.
    const sessionDurationMinutes = data.sessionDurationMinutes ??
      Math.round((expiresAtMs - data.createdAt?.toMillis()) / 60_000);
    if (![15, 30, 60].includes(sessionDurationMinutes)) {
      throw new HttpsError("permission-denied", "Invalid session lifetime. Sign in again.");
    }
    transaction.update(snapshot.ref, { lastActivityAt: Timestamp.now() });
    return { expiresAtMs, serverNowMs, sessionDurationMinutes };
  });
});

export const vaultSessionInfo = onCall(callableOptions, async (request) => {
  const config = configured(request);
  const user = principal(request);
  await rateLimit(request, "sessionInfo", 30);
  if (!isFreshOwnerGoogle(user, config.email, Date.now())) {
    throw new HttpsError(
      "permission-denied",
      "Use the configured owner's Google account to set up this vault.",
    );
  }
  const owner = (await ownerRef.get()).data() as Owner | undefined;
  if (owner && owner.uid !== user.uid)
    throw new HttpsError("permission-denied", "This vault belongs to another account.");
  return { enrolled: (owner?.credentialIds.length || 0) > 0 };
});

export const registrationOptions = onCall(callableOptions, async (request) => {
  const config = configured(request);
  const user = principal(request);
  await rateLimit(request, "register", 12);
  const sessionId = claimSession(request);
  const webAuthnUserID = createHash("sha256").update(`haven-vault:${user.uid}`).digest("base64url");
  const id = opaqueId();
  const state = await db.runTransaction(async (transaction) => {
    const owner = (await transaction.get(ownerRef)).data() as Owner | undefined;
    const session = await sessionValid(transaction, sessionId, user.uid);
    const count = owner?.credentialIds.length || 0;
    const bootstrap = count === 0;
    if (
      !enrollmentAllowed(
        owner?.uid,
        count,
        user.uid,
        bootstrap,
        isFreshOwnerGoogle(user, config.email, Date.now()),
        session,
      )
    ) {
      throw new HttpsError(
        "permission-denied",
        count > 0
          ? "Unlock with an existing passkey before adding another."
          : "Use the configured owner's verified Google account to set up this vault.",
      );
    }
    if (!bootstrap) await requireRecent(transaction, request);
    return { owner, bootstrap };
  });
  const options = await generateRegistrationOptions({
    rpName: "Haven Vault",
    rpID: config.rpID,
    userName: config.email,
    userDisplayName: "Vault owner",
    userID: Buffer.from(webAuthnUserID, "base64url"),
    attestationType: "none",
    excludeCredentials: (state.owner?.credentialIds || []).map((credentialId) => ({
      id: credentialId,
    })),
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required",

    },
    timeout: 60_000,
  });
  await challenges.doc(id).create({
    purpose: "registration",
    challenge: options.challenge,
    uid: user.uid,
    webAuthnUserID,
    bootstrap: state.bootstrap,
    ...(sessionId ? { sessionId } : {}),
    expiresAt: Timestamp.fromMillis(Date.now() + CHALLENGE_MS),
  } satisfies Challenge);
  return { options, challengeId: id };
});

export const verifyRegistration = onCall(callableOptions, async (request) => {
  const config = configured(request);
  const user = principal(request);
  await rateLimit(request, "verifyRegister", 15);
  const { challengeId, response } = responseData<RegistrationResponseJSON>(request);
  const challenge = await consumeChallenge(challengeId, "registration", user.uid);
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: config.origin,
      expectedRPID: config.rpID,
      requireUserVerification: true,
    });
  } catch {
    throw new HttpsError(
      "permission-denied",
      "Passkey registration could not be verified. Start again.",
    );
  }
  if (!verification.verified || !verification.registrationInfo) {
    throw new HttpsError("permission-denied", "Passkey verification failed.");
  }
  const { credential } = verification.registrationInfo;
  await db.runTransaction(async (transaction) => {
    const owner = (await transaction.get(ownerRef)).data() as Owner | undefined;
    const ref = credentials.doc(digest(credential.id));
    const existing = await transaction.get(ref);
    const sessionId = claimSession(request);
    const session =
      challenge.sessionId === sessionId && (await sessionValid(transaction, sessionId, user.uid));
    const count = owner?.credentialIds.length || 0;
    if (!challenge.bootstrap) await requireRecent(transaction, request);
    if (
      !enrollmentAllowed(
        owner?.uid,
        count,
        user.uid,
        challenge.bootstrap === true,
        isFreshOwnerGoogle(user, config.email, Date.now()),
        session,
      ) ||
      existing.exists
    ) {
      throw new HttpsError(
        "permission-denied",
        "Enrollment state changed. Unlock with your existing passkey and try again.",
      );
    }
    transaction.create(ref, {
      uid: user.uid,
      id: credential.id,
      publicKey: Buffer.from(credential.publicKey).toString("base64url"),
      counter: credential.counter,
      transports: credential.transports || [],
      webAuthnUserID: challenge.webAuthnUserID,
      createdAt: Timestamp.now(),
    });
    transaction.set(ownerRef, {
      uid: user.uid,
      email: config.email,
      webAuthnUserID: challenge.webAuthnUserID,
      credentialIds: [...(owner?.credentialIds || []), credential.id],
    } satisfies Owner);
  });
  if (!challenge.bootstrap && request.data.management === true) return { registered: true };
  return issueSession(user.uid, credential.id, deviceDescription(request));
});

export const authenticationOptions = onCall(callableOptions, async (request) => {
  const config = configured(request);
  await rateLimit(request, "authenticate", 30);
  const owner = (await ownerRef.get()).data() as Owner | undefined;
  if (!owner || owner.credentialIds.length === 0) {
    throw new HttpsError("failed-precondition", "This vault has not been set up yet.");
  }
  const reauthSession = request.data?.reauth === true ? claimSession(request) : undefined;
  if (request.data?.reauth === true && !reauthSession) throw new HttpsError("unauthenticated", "Sign in first.");
  const options = await generateAuthenticationOptions({
    rpID: config.rpID,
    // Discoverable credentials keep the credential IDs out of this public endpoint.
    allowCredentials: [],
    userVerification: "required",
    timeout: 60_000,
  });
  const id = opaqueId();
  await challenges.doc(id).create({
    purpose: "authentication",
    ...(reauthSession ? { sessionId: reauthSession } : {}),
    challenge: options.challenge,
    uid: owner.uid,
    webAuthnUserID: owner.webAuthnUserID,
    expiresAt: Timestamp.fromMillis(Date.now() + CHALLENGE_MS),
  } satisfies Challenge);
  return { options, challengeId: id };
});

export const verifyAuthentication = onCall(callableOptions, async (request) => {
  const config = configured(request);
  await rateLimit(request, "verifyAuthenticate", 30);
  const { challengeId, response } = responseData<AuthenticationResponseJSON>(request);
  const challenge = await consumeChallenge(challengeId, "authentication");
  const ref = credentials.doc(digest(response.id));
  const snapshot = await ref.get();
  const credential = snapshot.data() as StoredCredential | undefined;
  if (
    !credential ||
    credential.uid !== challenge.uid ||
    credential.webAuthnUserID !== challenge.webAuthnUserID ||
    response.response.userHandle !== challenge.webAuthnUserID
  ) {
    throw new HttpsError("permission-denied", "This passkey does not belong to this vault.");
  }
  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: config.origin,
      expectedRPID: config.rpID,
      requireUserVerification: true,
      credential: {
        id: credential.id,
        publicKey: Buffer.from(credential.publicKey, "base64url"),
        counter: credential.counter,
        transports: credential.transports,
      },
    });
  } catch {
    throw new HttpsError(
      "permission-denied",
      "Passkey authentication could not be verified. Start again.",
    );
  }
  if (!verification.verified)
    throw new HttpsError("permission-denied", "Passkey verification failed.");
  await db.runTransaction(async (transaction) => {
    const current = (await transaction.get(ref)).data() as StoredCredential | undefined;
    const owner = (await transaction.get(ownerRef)).data() as Owner | undefined;
    if (
      !current ||
      current.uid !== challenge.uid ||
      current.counter !== credential.counter ||
      owner?.uid !== challenge.uid ||
      !owner.credentialIds.includes(credential.id)
    ) {
      throw new HttpsError(
        "permission-denied",
        "Passkey state changed. Please authenticate again.",
      );
    }
    if (challenge.sessionId) {
      if (challenge.sessionId !== claimSession(request) || !(await sessionValid(transaction, challenge.sessionId, credential.uid))) throw new HttpsError("permission-denied", "Reauthentication session ended.");
      transaction.update(sessions.doc(challenge.sessionId), { authenticatedAt: Timestamp.now() });
    }
    transaction.update(ref, {
      counter: verification.authenticationInfo.newCounter,
      lastUsedAt: Timestamp.now(),
    });
  });
  if (challenge.sessionId) return { verified: true };
  return issueSession(credential.uid, credential.id, deviceDescription(request));
});

export const endVaultSession = onCall(callableOptions, async (request) => {
  checkApp(request);
  const user = principal(request);
  const id = claimSession(request);
  if (!id) return { ended: true };
  await db.runTransaction(async (transaction) => {
    const ref = sessions.doc(id);
    const session = await transaction.get(ref);
    if (session.data()?.uid === user.uid) transaction.update(ref, { revoked: true });
  });
  return { ended: true };
});

function deviceDescription(request: CallableRequest) {
  const ua = request.rawRequest.get?.('user-agent') || '';
  const platform = /Android/i.test(ua) ? 'Android' : /iPhone|iPad/i.test(ua) ? 'iOS' : /Windows/i.test(ua) ? 'Windows' : /Macintosh/i.test(ua) ? 'macOS' : /Linux/i.test(ua) ? 'Linux' : 'Device';
  const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  return `${browser} on ${platform}`;
}
async function requireRecent(transaction: Transaction, request: CallableRequest, recent = true) {
  const user = principal(request);
  const id = claimSession(request);
  const owner = (await transaction.get(ownerRef)).data();
  const record = id ? (await transaction.get(sessions.doc(id))).data() : undefined;
  if (owner?.uid !== user.uid || !record || !validSession({ uid: record.uid, revoked: record.revoked, expiresAtMs: record.expiresAt?.toMillis() }, user.uid, Date.now())) throw new HttpsError('unauthenticated', 'Your vault session has ended.');
  if (recent && !freshPasskey(record)) throw new HttpsError('failed-precondition', 'Verify your passkey again before continuing.');
  return { uid: user.uid, id: id!, record };
}
async function sessionRecords(transaction: Transaction, uid: string) {
  const snapshot = await transaction.get(sessions.where('uid', '==', uid).where('revoked', '==', false));
  return { docs: snapshot.docs.filter(d => d.data().expiresAt?.toMillis() > Date.now()) };
}
function validPublicRecovery(record: any) {
  if (!validKeyRecord(record)) throw new HttpsError('invalid-argument', 'Unsupported key record.');
  if (record.recovery) {
    try {
      const key = createPublicKey({ key: Buffer.from(record.recovery.publicKey, 'base64'), format: 'der', type: 'spki' });
      if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw new Error();
    } catch { throw new HttpsError('invalid-argument', 'Invalid recovery public verifier.'); }
  }
}
const configFor = (uid: string) => db.doc(`users/${uid}/vault/config`);
const migrationFor = (uid: string) => db.doc(`users/${uid}/vault/migration`);

/** Owner-only administration. No action accepts plaintext encryption secrets. */
export const securityOperation = onCall({ ...callableOptions, timeoutSeconds: 120 }, async request => {
  configured(request);
  const action = request.data?.action;
  if (typeof action !== 'string') throw new HttpsError('invalid-argument', 'Choose a security operation.');
  await rateLimit(request, 'security', 120);
  if (['migrationItem', 'migrationFinalize'].includes(action)) return migrationOperation(request);
  return db.runTransaction(async transaction => {
    const auth = await requireRecent(transaction, request, !['list', 'createKeys', 'migrationStatus'].includes(action));
    const configRef = configFor(auth.uid);
    const current = (await transaction.get(configRef)).data();
    const migrationRef = migrationFor(auth.uid);
    const migration = (await transaction.get(migrationRef)).data();
    if (action === 'migrationStatus') {
      const receipts = migration ? await transaction.get(migrationRef.collection('receipts').select()) : null;
      return { migration: migration || null, config: current || null, completed: receipts?.docs.map(d => d.id) || [] };
    }
    if (action === 'list') {
      const owner = (await transaction.get(ownerRef)).data() as Owner;
      const creds = await Promise.all(owner.credentialIds.map(id => transaction.get(credentials.doc(digest(id)))));
      const active = await sessionRecords(transaction, auth.uid);
      transaction.update(sessions.doc(auth.id), { lastActivityAt: Timestamp.now() });
      return {
        passkeys: creds.filter(c => c.exists).map(c => ({ id: c.data()!.id, label: c.data()!.label || null, createdAt: c.data()!.createdAt?.toMillis() || null, lastUsedAt: c.data()!.lastUsedAt?.toMillis() || null, current: auth.record.credentialId === c.data()!.id })),
        sessions: active.docs.filter(d => d.data().expiresAt.toMillis() > Date.now()).map(d => ({ id: d.id, current: d.id === auth.id, device: d.data().device || 'Older browser session', createdAt: d.data().createdAt.toMillis(), lastActivityAt: d.data().lastActivityAt?.toMillis() || null, expiresAt: d.data().expiresAt.toMillis() })),
      };
    }
    if (action === 'createKeys') {
      validPublicRecovery(request.data.record);
      if (current || request.data.record.revision !== 1 || request.data.record.recovery !== null) throw new HttpsError('already-exists', 'Vault already exists or setup record is invalid.');
      transaction.create(configRef, request.data.record);
      transaction.set(db.doc(`_vaultAccess/${auth.uid}`), { generation: request.data.record.generation, migrationGeneration: null, migrationPhase: null, migrationSessionId: null });
      return { config: request.data.record };
    }
    if (action === 'replaceKeys') {
      const next = request.data.record;
      validPublicRecovery(next);
      const purpose = request.data.purpose;
      if (!['passphrase', 'recovery', 'recover'].includes(purpose) || !keyTransition(current, next, purpose)) throw new HttpsError('aborted', 'Key record changed. Reload and unlock the latest vault before retrying.');
      const active = await sessionRecords(transaction, auth.uid);
      transaction.set(configRef, next);
      // Current session keeps its original deadline. Every other session ends.
      active.docs.forEach(d => { if (d.id !== auth.id) transaction.update(d.ref, { revoked: true }); });
      return { config: next };
    }
    if (action === 'renamePasskey' || action === 'removePasskey') {
      const owner = (await transaction.get(ownerRef)).data() as Owner;
      const id = request.data.id;
      if (!isCredentialId(id) || !owner.credentialIds.includes(id)) throw new HttpsError('not-found', 'Passkey does not belong to this vault.');
      const ref = credentials.doc(digest(id));
      if (action === 'renamePasskey') {
        if (!validBoxLabel(request.data.label)) throw new HttpsError('invalid-argument', 'Encrypt the private passkey label first.');
        transaction.update(ref, { label: request.data.label });
      } else {
        if (owner.credentialIds.length <= 1) throw new HttpsError('failed-precondition', 'Register a replacement before removing your final passkey.');
        const active = await sessionRecords(transaction, auth.uid);
        transaction.update(ownerRef, { credentialIds: owner.credentialIds.filter(value => value !== id) });
        transaction.delete(ref);
        active.docs.forEach(d => { if (d.data().credentialId === id) transaction.update(d.ref, { revoked: true }); });
      }
      return { currentRevoked: action === 'removePasskey' && auth.record.credentialId === id };
    }
    if (action === 'revokeSessions') {
      const scope = request.data.scope;
      const active = await sessionRecords(transaction, auth.uid);
      if (!['all', 'others', 'one'].includes(scope)) throw new HttpsError('invalid-argument', 'Invalid revocation scope.');
      if (scope === 'one' && !active.docs.some(d => d.id === request.data.id)) throw new HttpsError('not-found', 'Session does not belong to this vault.');
      let currentRevoked = false;
      active.docs.forEach(d => {
        if (scope === 'all' || (scope === 'others' && d.id !== auth.id) || (scope === 'one' && d.id === request.data.id)) {
          transaction.update(d.ref, { revoked: true });
          if (d.id === auth.id) currentRevoked = true;
        }
      });
      return { currentRevoked };
    }
    if (action === 'migrationBegin') {
      if (migration) {
        if (migration.phase === 'complete') return { migration, config: current };
        // An explicit, freshly verified owner claim invalidates the previous client.
        transaction.update(migrationRef, { sessionId: auth.id });
        transaction.set(db.doc(`_vaultAccess/${auth.uid}`), { generation: null, migrationGeneration: migration.record.generation, migrationPhase: migration.phase, migrationSessionId: auth.id });
        return { migration: { ...migration, sessionId: auth.id }, config: current };
      }
      const next = request.data.record;
      validPublicRecovery(next);
      if (current?.version !== 1 || next.revision !== 1 || next.recovery !== null) throw new HttpsError('failed-precondition', 'Only unlocked legacy vaults can migrate.');
      const value = { version: 2, phase: 'staging', sessionId: auth.id, record: next, originalConfig: current, cursor: '', verified: 0, createdAt: Timestamp.now() };
      transaction.create(migrationRef, value);
      transaction.set(db.doc(`_vaultAccess/${auth.uid}`), { generation: null, migrationGeneration: next.generation, migrationPhase: 'staging', migrationSessionId: auth.id });
      return { migration: value, config: current };
    }
    throw new HttpsError('invalid-argument', 'Unknown security operation.');
  });
});
function validBoxLabel(b: any) { return validBox(b) && b.ciphertext.length <= 2048; }

async function ciphertextHash(file: { createReadStream(): AsyncIterable<Buffer> }): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of file.createReadStream()) hash.update(chunk);
  return hash.digest('base64');
}

async function migrationOperation(request: CallableRequest) {
  const action = request.data.action;
  const uid = principal(request).uid;
  const migrationRef = migrationFor(uid);
  // Read authority in a transaction for each step, never trust a client claim.
  const state = await db.runTransaction(async t => {
    const auth = await requireRecent(t, request, false);
    const migration = (await t.get(migrationRef)).data();
    if (!migration || migration.sessionId !== auth.id) throw new HttpsError('aborted', 'Another client owns migration. Reauthenticate and resume explicitly.');
    return migration;
  });
  const generation = state.record.generation;
  const source = db.collection(`users/${uid}/items`);
  const target = db.collection(`users/${uid}/generations/${generation}/items`);
  const receipts = migrationRef.collection('receipts');
  if (state.phase === 'complete') return { complete: true, config: (await configFor(uid).get()).data() };
  if (action === 'migrationItem') {
    const id = request.data.id;
    if (typeof id !== 'string' || !/^[a-f0-9-]{36}$/.test(id)) throw new HttpsError('invalid-argument', 'Invalid migration item.');
    const original = await source.doc(id).get();
    const staged = await target.doc(id).get();
    if (!original.exists || !staged.exists) throw new HttpsError('failed-precondition', 'Both generations must be present.');
    // Copy the original ciphertext to an Admin-only immutable safeguard before receipt.
    const file = getStorage().bucket().file(`vaults/${uid}/${id}`);
    const backup = getStorage().bucket().file(`safeguards/${uid}/${generation}/${id}`);
    let fileInfo: any = null;
    try {
      const [metadata] = await file.getMetadata();
      const [exists] = await backup.exists();
      if (!exists) await file.copy(backup, { preconditionOpts: { ifGenerationMatch: 0 } });
      const [saved] = await backup.getMetadata();
      const [newFile] = await getStorage().bucket().file(`generations/${uid}/${generation}/${id}`).getMetadata();
      const sourceHash = await ciphertextHash(file);
      const backupHash = await ciphertextHash(backup);
      const stagedHash = await ciphertextHash(getStorage().bucket().file(`generations/${uid}/${generation}/${id}`));
      if (sourceHash !== backupHash || metadata.size !== saved.size) throw new Error('Snapshot mismatch');
      fileInfo = { original: metadata.generation, backup: saved.generation, staged: newFile.generation, originalHash: backupHash, stagedHash };
    } catch (error: any) { if (error.code !== 404 || request.data.hasFile !== false) throw new HttpsError('failed-precondition', 'Encrypted file safeguard could not be verified. Retry without removing originals.'); }
    if ((fileInfo !== null) !== (request.data.hasFile === true)) throw new HttpsError('failed-precondition', 'File manifest does not match ciphertext.');
    return db.runTransaction(async t => {
      const auth = await requireRecent(t, request, false);
      const latest = (await t.get(migrationRef)).data();
      const oldNow = await t.get(original.ref); const newNow = await t.get(staged.ref);
      if (latest?.phase !== 'staging' || latest.sessionId !== auth.id || canonical(oldNow.data()) !== canonical(original.data()) || canonical(newNow.data()) !== canonical(staged.data())) throw new HttpsError('aborted', 'Migration state changed.');
      t.set(receipts.doc(id), { source: original.data(), staged: staged.data(), fileInfo, clientVerified: true });
      return { saved: true };
    });
  }
  // Seal first: after this transaction even the claiming client cannot change staging.
  await db.runTransaction(async t => {
    const auth = await requireRecent(t, request, false);
    const latest = (await t.get(migrationRef)).data();
    if (latest?.sessionId !== auth.id) throw new HttpsError('aborted', 'Migration claim changed.');
    if (latest.phase === 'staging') {
      t.update(migrationRef, { phase: 'verifying' });
      t.update(db.doc(`_vaultAccess/${uid}`), { migrationPhase: 'verifying' });
    }
  });
  return db.runTransaction(async t => {
    const auth = await requireRecent(t, request, false);
    const latest = (await t.get(migrationRef)).data()!;
    const current = (await t.get(configFor(uid))).data();
    if (latest.sessionId !== auth.id) throw new HttpsError('aborted', 'Migration claim changed.');
    if (latest.phase === 'complete') return { complete: true, config: current };
    if (current?.version !== 1) throw new HttpsError('aborted', 'Source generation changed.');
    const ordered = source.orderBy('__name__');
    const query = (latest.cursor ? ordered.startAfter(latest.cursor) : ordered).limit(10);
    const entries = await t.get(query);
    const targets = await Promise.all(entries.docs.map(d => t.get(target.doc(d.id))));
    const saved = await Promise.all(entries.docs.map(d => t.get(receipts.doc(d.id))));
    entries.docs.forEach((d, i) => {
      const receipt = saved[i].data();
      if (!receipt?.clientVerified || canonical(receipt.source) !== canonical(d.data()) || canonical(receipt.staged) !== canonical(targets[i].data())) throw new HttpsError('failed-precondition', 'Migration verification is incomplete. Originals remain intact.');
    });
    if (entries.empty) {
      // Source and staged document counts must agree; no injected extra records.
      const allSource = await t.get(source.select());
      const allTarget = await t.get(target.select());
      if (allSource.size !== allTarget.size || allSource.size !== latest.verified) throw new HttpsError('failed-precondition', 'Migration manifest mismatch.');
      t.set(configFor(uid), latest.record);
      t.update(migrationRef, { phase: 'complete', completedAt: Timestamp.now() });
      t.update(db.doc(`_vaultAccess/${uid}`), { generation: latest.record.generation, migrationPhase: 'complete' });
      return { complete: true, config: latest.record };
    }
    t.update(migrationRef, { cursor: entries.docs.at(-1)!.id, verified: latest.verified + entries.size });
    return { complete: false, verified: latest.verified + entries.size };
  });
}

/** Google identity has no data authority here: only a scoped recovery ceremony. */
export const beginVaultRecovery = onCall(callableOptions, async request => {
  const config = configured(request);
  const user = principal(request);
  await rateLimit(request, 'recoveryBegin', 6);
  const owner = (await ownerRef.get()).data() as Owner | undefined;
  if (!isFreshOwnerGoogle(user, config.email, Date.now()) || owner?.uid !== user.uid) throw new HttpsError('permission-denied', 'Fresh verification of the registered owner Google identity is required.');
  const record = (await configFor(user.uid).get()).data();
  if (!validKeyRecord(record) || !record?.recovery) throw new HttpsError('failed-precondition', 'Recovery was not completed for this vault. Google alone cannot recover it.');
  const options = await generateRegistrationOptions({ rpName: 'Haven Vault recovery', rpID: config.rpID, userName: config.email, userID: Buffer.from(owner.webAuthnUserID, 'base64url'), attestationType: 'none', authenticatorSelection: { residentKey: 'required', userVerification: 'required' }, excludeCredentials: owner.credentialIds.map(id => ({ id })), timeout: 60000 });
  const challengeId = opaqueId();
  const expiresAt = Date.now() + CHALLENGE_MS;
  const statement = JSON.stringify(['haven-recovery', 2, user.uid, record.vaultId, record.recovery.id, 'replace-passkeys-and-keys', config.origin, challengeId, options.challenge, expiresAt]);
  await challenges.doc(challengeId).create({ purpose: 'recovery', challenge: options.challenge, uid: user.uid, webAuthnUserID: owner.webAuthnUserID, recoveryId: record.recovery.id, revision: record.revision, statement, expiresAt: Timestamp.fromMillis(expiresAt) } satisfies Challenge);
  return { options, challengeId, statement, record };
});
export const completeVaultRecovery = onCall(callableOptions, async request => {
  const config = configured(request); const user = principal(request);
  await rateLimit(request, 'recoveryComplete', 8);
  if (!isFreshOwnerGoogle(user, config.email, Date.now())) throw new HttpsError('permission-denied', 'Verify the owner Google identity again.');
  const { challengeId, response } = responseData<RegistrationResponseJSON>(request);
  const challenge = await consumeChallenge(challengeId, 'recovery', user.uid);
  const current = (await configFor(user.uid).get()).data();
  const next = request.data.record;
  validPublicRecovery(next);
  if (!current?.recovery || current.recovery.id !== challenge.recoveryId || current.revision !== challenge.revision || !keyTransition(current, next, 'recover')) throw new HttpsError('aborted', 'Recovery material changed. Start again.');
  const message = JSON.stringify([challenge.statement, createHash('sha256').update(canonical(response)).digest('base64'), createHash('sha256').update(canonical(next)).digest('base64')]);
  let possession = false;
  try { possession = verifySignature('sha256', Buffer.from(message), { key: createPublicKey({ key: Buffer.from(current.recovery.publicKey, 'base64'), type: 'spki', format: 'der' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(request.data.signature, 'base64')); } catch { /* fail closed */ }
  if (!possession) throw new HttpsError('permission-denied', 'Recovery possession could not be verified.');
  let verification;
  try { verification = await verifyRegistrationResponse({ response, expectedChallenge: challenge.challenge, expectedOrigin: config.origin, expectedRPID: config.rpID, requireUserVerification: true }); }
  catch { throw new HttpsError('permission-denied', 'Replacement passkey could not be verified.'); }
  if (!verification.verified || !verification.registrationInfo) throw new HttpsError('permission-denied', 'Replacement passkey verification failed.');
  const credential = verification.registrationInfo.credential;
  await db.runTransaction(async t => {
    const owner = (await t.get(ownerRef)).data() as Owner;
    const latest = (await t.get(configFor(user.uid))).data();
    const duplicate = await t.get(credentials.doc(digest(credential.id)));
    const active = await sessionRecords(t, user.uid);
    if (owner.uid !== user.uid || latest?.revision !== challenge.revision || latest?.recovery?.id !== challenge.recoveryId || duplicate.exists || owner.credentialIds.includes(credential.id)) throw new HttpsError('aborted', 'Recovery state changed. Start again.');
    t.create(credentials.doc(digest(credential.id)), { uid: user.uid, id: credential.id, publicKey: Buffer.from(credential.publicKey).toString('base64url'), counter: credential.counter, transports: credential.transports || [], webAuthnUserID: owner.webAuthnUserID, createdAt: Timestamp.now() });
    owner.credentialIds.forEach(id => t.delete(credentials.doc(digest(id))));
    t.update(ownerRef, { credentialIds: [credential.id] });
    active.docs.forEach(d => t.update(d.ref, { revoked: true }));
    t.set(configFor(user.uid), next);
  });
  return issueSession(user.uid, credential.id, deviceDescription(request));
});
