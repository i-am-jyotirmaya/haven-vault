# Architecture and integration

Haven is a complete single-owner application, not a multi-tenant vault SDK. The browser, Functions, and security rules must be integrated together.

## Modules

| Path | Responsibility |
| --- | --- |
| `src/App.tsx` | Setup/unlock, items, collections, and locking lifecycle |
| `src/lib/crypto.ts` | Key derivation, AES-GCM envelopes, encrypted verifier |
| `src/lib/firebase.ts` | SDK initialization, memory-only auth, passkey ceremonies |
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

Successful verification issues a Firebase custom token containing `vaultAccess` and a random `vaultSession`. Its server record expires after 15 minutes; token refresh cannot extend it. The browser locks shortly before that deadline, after five minutes idle, or when hidden. Generation guards prevent late async operations restoring a locked session. Sign-out attempts server revocation and clears local state even offline.

Firebase Auth uses `inMemoryPersistence`, and Firestore has no persistent offline cache. No service worker or analytics is included.

## Callable API

Use the Firebase callable SDK/protocol. None of these functions receives a vault passphrase.

| Function | Purpose |
| --- | --- |
| `registrationOptions` | Registration challenge for the bootstrap owner or current vault session |
| `verifyRegistration` | Consume challenge, verify credential, bind owner, issue session |
| `authenticationOptions` | Rate-limited passkey authentication challenge |
| `verifyAuthentication` | Verify response, consume challenge, issue session |
| `vaultSessionInfo` | Inspect the authenticated owner's session |
| `endVaultSession` | Revoke the current authenticated session |

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

The frontend does not currently call `connectAuthEmulator`, `connectFunctionsEmulator`, `connectFirestoreEmulator`, or `connectStorageEmulator`. Starting emulators alone does not route browser SDK traffic to them. A configured frontend normally contacts its configured Firebase project.

Full local integration requires explicit development-only emulator connections after initialization, a disposable `demo-*` project, the exact local origin in backend configuration, and a test owner-bootstrap strategy that accurately models Google claims. Do not weaken production bootstrap checks to facilitate testing. `localhost` and `127.0.0.1` are distinct passkey identities.

Alternatively, deploy a separate staging Firebase project and hostname with its own passkeys, using non-sensitive fixtures. Production credentials will not work on the staging hostname.
