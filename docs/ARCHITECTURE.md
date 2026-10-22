> V2 key, migration and access design: [KEYS_RECOVERY_DESIGN.md](KEYS_RECOVERY_DESIGN.md).
> Operational recovery, upgrade and rollback: [RECOVERY_UPGRADE.md](RECOVERY_UPGRADE.md).
> The sections below describing v1 encryption remain the legacy compatibility specification.

# Architecture and integration

Haven is a complete single-owner application, not a multi-tenant vault SDK. The browser, Functions, and security rules must be integrated together.

## Modules

| Path | Responsibility |
| --- | --- |
| `src/App.tsx` | Setup/unlock, items, collections, and locking lifecycle |
| `src/lib/crypto.ts` | Key derivation, AES-GCM envelopes, encrypted verifier |
| `src/lib/firebase.ts` | SDK initialization, memory-only auth, passkey ceremonies, server session validation |
| `src/lib/lockPolicy.ts`, `useVaultPolicy.ts` | Validated device preferences, conservative clock, absolute lock deadlines, privacy gate and browser lifecycle |
| `src/lib/vaultState.ts` | Explicit signed-out, authenticated/locked, authenticated/unlocked, and demo states |
| `src/lib/plaintext.ts` | Plaintext URL ownership and synchronous lock invalidation |
| `src/lib/vault.ts` | Encrypted item operations, validation, thumbnails |
| `src/components/Preview.tsx` | Image, PDF, and text previews |
| `src/components/PdfPreview.tsx` | Local PDF.js renderer and bundled worker |
| `functions/src/index.ts` | Enrollment, challenges, verification, session tokens |
| `functions/src/policy.ts` | Pure authorization predicates and policy tests |
| `firestore.rules`, `storage.rules` | Session-bound server authorization |
| `scripts/` | Deployment checks and opt-in access configuration |

## Authentication lifecycle

First enrollment requires a fresh, verified Google identity matching `OWNER_EMAIL`. A transaction binds the vault to the first successfully enrolled UID. After enrollment, adding a passkey requires a current vault session; changing the email does not transfer ownership.

Registration waits for a fresh click after Google's popup closes. WebAuthn checks the configured origin, relying party, challenge, and required user verification. A device PIN may substitute for biometrics. Challenges are single-use and expire after five minutes. Backend limits apply per hashed IP address and project-wide.

Successful verification issues a Firebase custom token containing `vaultAccess` and a random `vaultSession`, plus enforced expiry, server time, and issued `sessionDurationMinutes`. `AUTH_SESSION_MINUTES` uses existing Firebase deployment parameter conventions: default 60; only literal 15, 30, or 60 accepted. Validation fails closed on invalid configuration before a new session can be issued. Each private record persists its absolute `expiresAt` and original lifetime. Validation reads the original record, so configuration changes cannot renew or extend existing sessions. Old records derive their issued lifetime from `createdAt` and `expiresAt` without modifying either.

The client derives its local deadline from the server's remaining lifetime at verification-request start, minus 15 seconds for conservative latency handling. There is no fixed 15-minute ceiling. Later validation may shorten but never extend this deadline. Firebase token refresh, local activity, passphrase entry, and device settings cannot renew it. Only a fresh passkey ceremony can issue another session.

| State | Backend authorization | Local key/content |
| --- | --- | --- |
| Signed out | No usable application session | Unavailable |
| Authenticated, locked | Valid passkey session, original deadline | Unavailable; encryption configuration is public |
| Authenticated, unlocked | Same session and deadline | Non-extractable key and decrypted content in memory |

Passkey authentication enters the locked state; existing vaults require their passphrase, and new vaults retain setup. Successful local decryption enters the unlocked state. A wrong passphrase leaves authentication intact. Google remains restricted to enrollment.

**Lock vault** (manual/shortcut, configured inactivity, or expired background grace) clears the key, passphrase fields, decrypted items, notes/drafts, search/collection state, sensitive dialogs, previews, and application-managed plaintext URLs. It retains the backend session and absolute deadline. It does not call Firebase sign-out or revoke the session. An encryption-work generation and a shared plaintext generation prevent late decryption, listing, preview, and download results from restoring sensitive state. Preview unmount cancels rendering; the PDF worker is destroyed and its canvas cleared. Crypto promises already in progress cannot be forcibly erased; their results are invalidated.

**Sign out** is separate and available when locked or unlocked. It performs the same local cleanup immediately, invalidates authentication work, then attempts remote revocation with the existing four-second callable timeout before clearing Firebase tokens. Failed remote revocation is reported: the server session remains valid until enforced expiry. Local cleanup never waits for the network. Enrollment cancellation explicitly signs out; demo state never grants backend authorization.

Absolute authentication expiry applies even while locked or concealed. Confirmed authorization failures sign out; transient validation failures lock and allow an explicit retry. Firestore/Storage rules independently enforce each data request. Revocation does not push an instant notification to an idle foreground browser: the next server access/validation discovers it, and the original deadline always applies.

### Concealment and automatic locking

| Policy | Default | Choices / owner |
| --- | --- | --- |
| Conceal when backgrounded | Immediately | Always enabled |
| Lock after backgrounding | 30 seconds | Immediately, 30 seconds, 1 minute; device preference |
| Lock after visible inactivity | 5 minutes | 1, 5, 15 minutes; device preference |
| Absolute backend authentication lifetime | 60 minutes | 15, 30, 60 minutes; deployment only |

These are product policies, not a security-standard compliance claim. Nonzero grace deliberately retains the key and decrypted data in memory. The opaque privacy screen conceals the entire sensitive surface and all top-layer dialogs/backdrops, and makes the surface inert. It does not reliably prevent browser/OS screenshots. The screen offers immediate lock and sign-out controls while validation is pending. Concealed dialogs temporarily leave the modal top layer so they cannot make those controls inert; drafts stay in memory during grace. Preview URLs are revoked and previews closed at concealment; passphrase work/drafts on the locked screen are invalidated without cancelling a passkey ceremony. Upload/save results may finish behind the gate but cannot remove it or count as activity. Only completed uploads are saved; unfinished uploads or drafts may be lost on lock/expiry.

`LockPolicy` stores original last-activity/background timestamps. Trusted keyboard, pointer, touch, and wheel interaction counts only while visible and unlocked. Event handling updates refs without React activity renders or timer recreation on every movement. Network requests, animations, synthetic events, and async completion never move inactivity. The earliest of authentication, inactivity, and background deadlines wins. Setting changes use elapsed time from the existing origins; interaction inside the timeout controls does not reset inactivity, including Restore defaults. Missing/invalid local preference fields fall back to 30 seconds/5 minutes; Restore defaults uses the same re-evaluation. Only these two non-sensitive preferences are written to local storage.

Timers schedule checks; timestamps are authoritative. A conservative clock takes the greater of elapsed wall and monotonic time: forward wall jumps fail closed early, and backward changes cannot move deadlines later. Wall time catches device sleep on platforms whose monotonic clock pauses. Visibility changes, focus, pagehide/pageshow (including BFCache), freeze/resume, and async publication recheck deadlines. Repeated hide/focus events cannot restart grace or inactivity. Return keeps the privacy gate up while the private server session is validated, rechecks all deadlines after validation, and commits any cleanup before revealing. A short return may restore the existing unlocked view; a locked vault never automatically regains a key. A reload starts signed out with memory-only Firebase authentication; no keys are restored.

A one-minute authentication warning appears in locked and unlocked states. Reauthentication uses the normal fresh passkey flow after expiry and still requires local passphrase unlocking. No timer is broadly disabled for WebAuthn/Google prompts; concealment during enrollment does not cancel those independent authentication generations.

Firebase Auth uses `inMemoryPersistence`, and Firestore has no persistent offline cache. No service worker or analytics is included.

## Callable API

Use the Firebase callable SDK/protocol. None of these functions receives a vault passphrase.

| Function | Purpose |
| --- | --- |
| `registrationOptions` | Registration challenge for the bootstrap owner or current vault session |
| `verifyRegistration` | Consume challenge, verify credential, bind owner, issue session |
| `authenticationOptions` | Rate-limited passkey authentication challenge |
| `verifyAuthentication` | Verify response, consume challenge, issue session |
| `vaultSessionInfo` | Google-only enrollment status inspection; not vault-session validation |
| `validateVaultSession` | Read-only owner/session validation; returns original enforced expiry, server time, and issued lifetime |
| `endVaultSession` | Revoke the current authenticated session |

**Upgrade order:** deploy Functions (including `validateVaultSession` and verification/validation timing and lifetime metadata) before Hosting. Update invocation access with the supplied helper if needed. No ciphertext, rules, or stored vault data migration is required.

The Security screen manages up to five credentials with private labels and server-enforced recent authentication. Recovery has a separate kit-possession plus Google-owner enrollment path; see the v2 design above.

## Encryption and data model

The browser derives a non-extractable AES-256-GCM key using PBKDF2-HMAC-SHA-256, 600,000 iterations, and a random 32-byte salt. Every encryption uses a fresh 12-byte IV and 128-bit authentication tag. An encrypted verifier detects a wrong passphrase. The salt and derivation settings are public.

JSON envelopes contain `{ version: 1, iv, ciphertext }` with Base64 IV/ciphertext. Binary files contain a one-byte version, 12-byte IV, then ciphertext including the 16-byte tag. Authenticated additional data separates JSON/file purposes and binds item payloads to context. Consult `vault.ts` for exact owner/item contexts before interoperability work; changing IDs or contexts without re-encrypting breaks authentication.

| Location | Contents |
| --- | --- |
| Firestore `users/{uid}/vault/config` | Immutable salt, iterations, version, encrypted verifier |
| Firestore `users/{uid}/items/{uuid}` | Encrypted names, metadata, notes, and thumbnails |
| Storage `vaults/{uid}/{uuid}` | Encrypted binary objects, `application/octet-stream` |
| `_vaultAuth`, `_vaultCredentials` | Owner binding and public credential material |
| `_vaultChallenges`, `_vaultSessions`, `_vaultLimits` | Private backend authorization and abuse-control records |

Rules require an owner-bound, unexpired, unrevoked session. Google-only tokens are insufficient. Backend collections are inaccessible to browser clients. Storage object overwrites and listing are denied. Authenticated blob reads and local object URLs support previews without public download links.

The application limits files to 50 MiB even though the crypto primitive can accept larger buffers. Encryption is not streaming; files/previews consume browser memory. PDF, raster-image, and text previews run locally; unsupported documents remain downloadable.

## Integrate into another UI

1. Deploy the backend and both rule sets in a dedicated project. Visual components alone do not provide authorization.
2. Reuse `firebase.ts` for sessions and `vault.ts` for data access. Derive keys only after explicit passphrase entry.
3. Preserve memory-only keys, cancellation guards, locking timers, cleanup, and object URL revocation. Never send plaintext, keys, or passphrases to logs, analytics, localStorage, or URLs.
4. Preserve encryption formats and contexts. Changes require versioned migrations and compatibility tests.
5. Keep previews restricted. Do not render decrypted HTML/SVG as trusted markup or send documents to remote preview services.
6. Run authorization tests and device-level sign-in/upload/download checks.

Sharing, multi-user tenancy and account transfers remain out of scope. The linked v2 design covers key recovery and passphrase changes. The singleton `_vaultAuth/owner` record is intentional.

## Local development and emulators

Use `pnpm dev` with `?demo=1` for local UI work. `pnpm test:rules` starts Firestore and Storage emulators with disposable fixtures.

`pnpm dev:local` starts all four service emulators against fictional project `demo-haven-vault`, builds/watches Functions, and starts Vite at `http://localhost:5173`. The browser connects every SDK before issuing requests; local mode ignores production Firebase configuration and cannot be built for deployment. `pnpm test:local` exercises real handlers and rules in a fresh disposable stack. See [local development](LOCAL_DEVELOPMENT.md) for synthetic Google enrollment, passkeys, persistence, reset, and runtime prerequisites.

Production bootstrap and signature checks remain active in local integration. `localhost` and `127.0.0.1` are distinct passkey identities. Normal `pnpm dev` still contacts the configured Firebase project.

Alternatively, deploy a separate staging Firebase project and hostname with its own passkeys, using non-sensitive fixtures. Production credentials will not work on the staging hostname.

## Dependable item and collection operations

See [FILE_OPERATIONS.md](FILE_OPERATIONS.md) for the encrypted receipt lifecycle,
immutable staging and late-object cleanup, item/catalog CAS and item epochs,
collection-name migration, deletion ordering, memory bounds, usage and limits.
The existing `securityOperation` callable, private-session authority and active
key generation are reused. No parallel authentication or encryption format is
introduced. Direct active item writes are denied so stale clients cannot bypass
revision checks; migration-only inactive generation creation remains supported.
