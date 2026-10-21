# Architecture and integration

Haven is a complete single-owner application, not a multi-tenant vault SDK. The browser, Functions, and security rules must be integrated together.

## Modules

| Path | Responsibility |
| --- | --- |
| `src/App.tsx` | Setup/unlock, items, collections, and locking lifecycle |
| `src/lib/crypto.ts` | Key derivation, AES-GCM envelopes, encrypted verifier |
| `src/lib/firebase.ts` | SDK initialization, memory-only auth, passkey ceremonies, server session validation |
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

Successful verification issues a Firebase custom token containing `vaultAccess` and a random `vaultSession`, plus the enforced expiry and server time. Its server record still expires after 15 minutes; token refresh cannot extend it. The client retains its existing conservative maximum of 14 minutes 45 seconds and caps it using the server's remaining lifetime, measured from the verification request start. Clock differences and request latency cannot give the client a new full session window.

| State | Backend authorization | Local key/content |
| --- | --- | --- |
| Signed out | No usable application session | Unavailable |
| Authenticated, locked | Valid passkey session, original deadline | Unavailable; encryption configuration is public |
| Authenticated, unlocked | Same session and deadline | Non-extractable key and decrypted content in memory |

Passkey authentication enters the locked state; existing vaults require their passphrase, and new vaults retain setup. Successful local decryption enters the unlocked state. A wrong passphrase leaves authentication intact. Google remains restricted to enrollment.

**Lock vault** (manual/shortcut, five minutes idle, or immediate tab hiding) clears the key, passphrase fields, decrypted items, notes/drafts, search/collection state, sensitive dialogs, previews, and application-managed plaintext URLs. It retains the backend session and absolute deadline. It does not call Firebase sign-out or revoke the session. An encryption-work generation and a shared plaintext generation prevent late decryption, listing, preview, and download results from restoring sensitive state. Preview unmount cancels rendering; the PDF worker is destroyed and its canvas cleared. Crypto promises already in progress cannot be forcibly erased; their results are invalidated.

**Sign out** is separate and available when locked or unlocked. It performs the same local cleanup immediately, invalidates authentication work, then attempts remote revocation with the existing four-second callable timeout before clearing Firebase tokens. Failed remote revocation is reported: the server session remains valid until enforced expiry. Local cleanup never waits for the network. Enrollment cancellation explicitly signs out; demo state never grants backend authorization.

An absolute authentication timer remains active while locked and never restarts on unlock. Visibility return, window focus, and restored pages check session validity; any retained unlocked state is locked before that check. Unlock checks the private server session before deriving a key and again after loading, and checks the wall clock before publishing results. Confirmed authorization failures sign out; transient network errors leave the vault locked for retry. Firestore/Storage rules independently enforce every data request, including revoked sessions. Revocation does not push an instant notification to an idle foreground browser: it is discovered on the next server access/validation, and the original deadline always applies.

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
| `validateVaultSession` | Read-only owner/session validation; returns enforced expiry and server time |
| `endVaultSession` | Revoke the current authenticated session |

**Upgrade order:** deploy Functions (including `validateVaultSession` and verification response metadata) before Hosting. Update invocation access with the supplied helper if needed. No ciphertext, rules, or stored vault data migration is required.

The backend supports up to five credentials, but the UI does not expose adding/removing passkeys. This is not a completed recovery workflow.

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

Sharing, multi-user tenancy, key recovery, passphrase changes, and account transfers require a new security design. The singleton `_vaultAuth/owner` record is intentional.

## Local development and emulators

Use `pnpm dev` with `?demo=1` for local UI work. `pnpm test:rules` starts Firestore and Storage emulators with disposable fixtures.

`pnpm dev:local` starts all four service emulators against fictional project `demo-haven-vault`, builds/watches Functions, and starts Vite at `http://localhost:5173`. The browser connects every SDK before issuing requests; local mode ignores production Firebase configuration and cannot be built for deployment. `pnpm test:local` exercises real handlers and rules in a fresh disposable stack. See [local development](LOCAL_DEVELOPMENT.md) for synthetic Google enrollment, passkeys, persistence, reset, and runtime prerequisites.

Production bootstrap and signature checks remain active in local integration. `localhost` and `127.0.0.1` are distinct passkey identities. Normal `pnpm dev` still contacts the configured Firebase project.

Alternatively, deploy a separate staging Firebase project and hostname with its own passkeys, using non-sensitive fixtures. Production credentials will not work on the staging hostname.
