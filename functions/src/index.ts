import { createHash, randomBytes } from "node:crypto";
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
  SESSION_MS,
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
  description: "The verified Google email allowed to enroll the first passkey.",
});
const rpId = defineString("RP_ID", {
  description: "Exact production hostname (without scheme, slash, or port).",
});
const expectedOrigin = defineString("EXPECTED_ORIGIN", {
  description: "Exact production origin, for example https://your-project.web.app.",
});
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
  purpose: "registration" | "authentication";
  challenge: string;
  uid: string;
  webAuthnUserID: string;
  expiresAt: Timestamp;
  bootstrap?: boolean;
  sessionId?: string;
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

async function issueSession(uid: string): Promise<{ token: string; expiresAtMs: number; serverNowMs: number }> {
  const id = opaqueId();
  const ref = sessions.doc(id);
  const expiresAtMs = Date.now() + SESSION_MS;
  await ref.create({
    uid,
    createdAt: Timestamp.now(),
    expiresAt: Timestamp.fromMillis(expiresAtMs),
    revoked: false,
  });
  try {
    // Never set persistent custom claims: every successful ceremony gets its own
    // expiring server-side session, independent of Firebase's refresh token.
    const token = await getAuth().createCustomToken(uid, { vaultAccess: true, vaultSession: id });
    return { token, expiresAtMs, serverNowMs: Date.now() };
  } catch {
    await ref.delete();
    throw new HttpsError("internal", "Could not start a vault session. Please try again.");
  }
}

/** Read-only check of the same owner/session policy enforced by data rules. */
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
    if (owner.data()?.uid !== user.uid || !validSession(data ? {
      uid: data.uid, expiresAtMs, revoked: data.revoked,
    } : undefined, user.uid, serverNowMs)) {
      throw new HttpsError("permission-denied", "Your vault session has ended. Sign in again.");
    }
    return { expiresAtMs, serverNowMs };
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
      authenticatorAttachment: "platform",
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
  return issueSession(user.uid);
});

export const authenticationOptions = onCall(callableOptions, async (request) => {
  const config = configured(request);
  await rateLimit(request, "authenticate", 30);
  const owner = (await ownerRef.get()).data() as Owner | undefined;
  if (!owner || owner.credentialIds.length === 0) {
    throw new HttpsError("failed-precondition", "This vault has not been set up yet.");
  }
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
    transaction.update(ref, {
      counter: verification.authenticationInfo.newCounter,
      lastUsedAt: Timestamp.now(),
    });
  });
  return issueSession(credential.uid);
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
