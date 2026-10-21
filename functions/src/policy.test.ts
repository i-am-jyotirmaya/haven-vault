import { test } from "node:test";
import assert from "node:assert/strict";
import {
  enrollmentAllowed,
  isFreshOwnerGoogle,
  validRelyingParty,
  validSession,
} from "./policy.js";

test("an owner Google login cannot replace an enrolled passkey", () => {
  assert.equal(enrollmentAllowed("owner", 1, "owner", true, true, false), false);
  assert.equal(enrollmentAllowed("owner", 1, "owner", false, true, false), false);
  assert.equal(enrollmentAllowed("owner", 1, "owner", false, false, true), true);
});

test("bootstrap is restricted to the configured fresh verified Google identity", () => {
  const now = 1_700_000_000_000;
  const principal = {
    uid: "owner", email: "Owner@example.com", emailVerified: true,
    provider: "google.com", authTime: now / 1000,
  };
  assert.equal(isFreshOwnerGoogle(principal, "owner@example.com", now), true);
  assert.equal(isFreshOwnerGoogle(principal, "", now), false);
  assert.equal(isFreshOwnerGoogle(principal, "attacker@example.com", now), false);
  assert.equal(isFreshOwnerGoogle({ ...principal, emailVerified: false }, "owner@example.com", now), false);
  assert.equal(isFreshOwnerGoogle({ ...principal, provider: "password" }, "owner@example.com", now), false);
  assert.equal(isFreshOwnerGoogle({ ...principal, authTime: (now - 301_000) / 1000 }, "owner@example.com", now), false);
  assert.equal(isFreshOwnerGoogle({ ...principal, authTime: (now + 60_000) / 1000 }, "owner@example.com", now), false);
});

test("enrollment fails for a second owner, at the key limit, or with changed enrollment state", () => {
  assert.equal(enrollmentAllowed(undefined, 0, "owner", true, true, false), true);
  assert.equal(enrollmentAllowed("owner", 0, "attacker", true, true, false), false);
  assert.equal(enrollmentAllowed("owner", 5, "owner", false, false, true), false);
  assert.equal(enrollmentAllowed("owner", 0, "owner", false, false, true), false);
  // Two bootstrap ceremonies are valid initially; only the one committing first is eligible.
  assert.equal(enrollmentAllowed("owner", 1, "owner", true, true, false), false);
});

test("expired, revoked, missing and different-owner sessions never authorize data access", () => {
  const session = { uid: "owner", expiresAtMs: 20_000, revoked: false };
  assert.equal(validSession(session, "owner", 19_999), true);
  assert.equal(validSession(session, "owner", 20_000), false);
  assert.equal(validSession(session, "attacker", 19_999), false);
  assert.equal(validSession({ ...session, revoked: true }, "owner", 19_999), false);
  assert.equal(validSession({ ...session, expiresAtMs: NaN }, "owner", 19_999), false);
  assert.equal(validSession(undefined, "owner", 19_999), false);
});

test("RP configuration requires an exact secure origin and correctly bounded domain", () => {
  assert.equal(validRelyingParty("vault.example.com", "https://vault.example.com"), true);
  assert.equal(validRelyingParty("localhost", "http://localhost:5173"), true);
  assert.equal(validRelyingParty("vault.example.com", "http://vault.example.com"), false);
  assert.equal(validRelyingParty("example.com", "https://evilexample.com"), false);
  assert.equal(validRelyingParty("vault.example.com", "https://vault.example.com/path"), false);
  assert.equal(validRelyingParty("vault.example.com", "https://vault.example.com/"), false);
  assert.equal(validRelyingParty("", ""), false);
});
