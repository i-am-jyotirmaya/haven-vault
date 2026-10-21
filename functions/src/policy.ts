export const SESSION_MS = 15 * 60 * 1000;
export const CHALLENGE_MS = 5 * 60 * 1000;
export const MAX_PASSKEYS = 5;

export type Principal = {
  uid: string;
  email?: unknown;
  emailVerified?: unknown;
  provider?: unknown;
  authTime?: unknown;
};

export type Session = {
  uid: string;
  expiresAtMs: number;
  revoked: boolean;
};

export function isFreshOwnerGoogle(
  principal: Principal,
  ownerEmail: string,
  now: number,
): boolean {
  const configured = ownerEmail.trim().toLowerCase();
  return configured.length > 3 &&
    typeof principal.email === "string" &&
    principal.email.trim().toLowerCase() === configured &&
    principal.emailVerified === true &&
    principal.provider === "google.com" &&
    typeof principal.authTime === "number" &&
    principal.authTime * 1000 <= now + 30_000 &&
    principal.authTime * 1000 > now - CHALLENGE_MS;
}

export function validSession(session: Session | undefined, uid: string, now: number): boolean {
  return !!session && session.uid === uid && session.revoked === false &&
    Number.isFinite(session.expiresAtMs) && session.expiresAtMs > now;
}

export function enrollmentAllowed(
  ownerUid: string | undefined,
  passkeyCount: number,
  uid: string,
  bootstrap: boolean,
  freshOwnerGoogle: boolean,
  sessionValid: boolean,
): boolean {
  if (passkeyCount >= MAX_PASSKEYS || (ownerUid && ownerUid !== uid)) return false;
  // A Google session must never become a replacement for an existing passkey.
  return bootstrap
    ? passkeyCount === 0 && freshOwnerGoogle
    : passkeyCount > 0 && !!ownerUid && sessionValid;
}

export function isOpaqueId(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}

export function isCredentialId(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{1,2048}$/.test(value);
}

export function validRelyingParty(rpId: string, expectedOrigin: string): boolean {
  try {
    const url = new URL(expectedOrigin);
    const localhost = rpId === "localhost" && url.hostname === "localhost";
    return url.origin === expectedOrigin &&
      !url.username && !url.password &&
      (url.protocol === "https:" || (localhost && url.protocol === "http:")) &&
      rpId.length > 0 &&
      (url.hostname === rpId || url.hostname.endsWith(`.${rpId}`)) &&
      !rpId.includes("/") &&
      !rpId.includes(":");
  } catch {
    return false;
  }
}
