# Haven Vault security and deployment

This is a single-owner personal vault with a client encryption layer and a separate server-enforced passkey gate. It has not received an independent security audit. Test the deployed application, its rules, and your recovery arrangements before storing irreplaceable originals.

## Security model

The browser derives the encryption key from the passphrase. It encrypts file bytes, filenames, descriptions, notes, and item metadata before sending them to Firebase. The backend receives ciphertext and an encrypted verifier, not the passphrase or plaintext encryption key. Anyone obtaining a database or storage copy can attempt offline passphrase guessing; use a long, unique passphrase. Encryption does not conceal account identity, object counts, ciphertext lengths, or access times.

The browser first completes a WebAuthn ceremony with user verification required. On supported devices this uses Face ID, Touch ID, Windows Hello, or another platform authenticator. WebAuthn cannot guarantee biometric-only verification: the operating system may allow its device PIN or password. See [SimpleWebAuthn's passkey guidance](https://simplewebauthn.dev/docs/advanced/passkeys/). A synced passkey's availability also depends on the device's passkey provider.

Successful passkey verification issues a Firebase custom token carrying `vaultAccess` and a random `vaultSession` identifier. The associated server record lasts 15 minutes. Firestore and Storage rules require this record to be unexpired, unrevoked, and bound to the requesting UID. Refreshing or replaying a Firebase token cannot extend the record. Logging out revokes the current session when connectivity is available; an offline logout still clears client state, while the server record expires on schedule. Locking cannot retract copies already downloaded or opened by an authorized session.

The passphrase is a separate encryption factor. A passkey alone allows retrieval of ciphertext during an authorized session but does not decrypt the vault. Conversely, the passphrase does not bypass the deployed Firebase access rules. A stolen passphrase and a stolen encrypted backup are enough to decrypt that backup.

## Owner enrollment and recovery

`OWNER_EMAIL` is a server-side deployment parameter. Initial enrollment requires a Google sign-in authenticated within the previous five minutes, a verified email that matches this setting, and no existing vault passkey. The successful enrollment transaction binds the vault to that Firebase UID. Competing enrollment attempts cannot both initialize the owner record.

After a passkey is enrolled, Google sign-in alone cannot add or replace one. Adding a passkey requires a current passkey-authenticated vault session and the same owner UID. The backend supports up to five registered passkeys. There is no automatic Google-only recovery or reset API, and changing `OWNER_EMAIL` does not transfer the vault.

If the passphrase is lost, the encrypted data cannot be recovered through Firebase or this application. Keep a separate offline record of the passphrase and independent originals or an encrypted backup. If all passkeys are lost, recovery requires carefully controlled administrator intervention; the application intentionally provides no bypass. Never delete backend records merely to troubleshoot a login problem. The vault configuration is immutable because replacing its salt or verifier without re-encrypting every item would strand existing data.

## Deployment

1. Use a dedicated Firebase project. Enable the default Firestore database, Cloud Storage, Google sign-in, Hosting, and Cloud Functions. Deploying Cloud Functions requires a billing-enabled project. Keep administrative credentials outside the browser and repository.
2. Configure the frontend's Firebase environment variables as described in the project README. These public web configuration values are identifiers, not administrative credentials.
3. Copy `functions/.env.example` to `functions/.env.<project-id>` and set:

   ```dotenv
   OWNER_EMAIL=your-verified-google-email@example.com
   RP_ID=your-project.web.app
   EXPECTED_ORIGIN=https://your-project.web.app
   ENFORCE_APP_CHECK=false
   ```

   `RP_ID` is the exact chosen hostname, without a scheme, slash, or port. `EXPECTED_ORIGIN` must be an exact origin with no trailing slash. Use one canonical production origin. A credential registered for another hostname will not silently transfer. Full local emulation requires explicit SDK connections and a test bootstrap strategy; see docs/ARCHITECTURE.md. Merely changing these parameters does not connect the frontend to emulators.
4. Install frontend and backend dependencies, run both builds and the tests, then deploy Hosting, Functions, Firestore rules/indexes, and Storage rules together. Callable functions use `us-central1`.
5. Storage rules read the session record in Firestore. On deployment, grant the cross-service permission requested by Firebase. These rule evaluations incur Firestore reads; see [Firebase's Storage authorization guide](https://firebase.google.com/docs/storage/security/rules-conditions#enhance_with_firestore).
6. If Firebase reports that the Functions service account cannot sign custom tokens, give that specific runtime service account the service-account-token-creator permission required for signing, using the least scope available. See [Firebase custom token setup](https://firebase.google.com/docs/auth/admin/create-custom-tokens).
7. Enable TTL for the `expiresAt` fields declared in `firestore.indexes.json`. Expired records are denied immediately by checks in code and rules even when TTL cleanup is delayed.
8. Configure Cloud Storage CORS for the exact production origin if browser `getBlob` requests are rejected. Permit `GET`, `HEAD`, and `OPTIONS` as needed; do not use public object ACLs or public download links as a workaround. Firebase SDK upload calls use their normal authenticated endpoints. See [Firebase direct browser downloads](https://firebase.google.com/docs/storage/web/download-files#download_data_directly_from_the_sdk).
9. Verify the published flow on your actual devices: first owner enrollment, sign-out, passkey login, wrong passphrase, correct passphrase, upload/download, previews, and expiry. A Google-only account, unauthenticated browser, expired session, and different UID must fail both database and storage reads.

## App Check and abuse controls

Functions apply atomic per-address and project-wide rate limits to challenge issuance and verification. IP addresses are hashed before storage. Limits reduce casual automated abuse but cannot prevent every distributed attack or denial of service. A project-wide limit can temporarily block legitimate login during an attack.

For production, register the web app with Firebase App Check, initialize App Check in the frontend, then set `ENFORCE_APP_CHECK=true` and redeploy Functions. Also enable enforcement for Firestore and Storage after validating real traffic. Do not turn on enforcement until the client sends valid App Check tokens. App Check complements authentication; it does not replace WebAuthn, encryption, or security rules. See [Firebase callable functions and App Check](https://firebase.google.com/docs/functions/callable).

Set billing alerts and review quota usage. Firestore TTL cleanup is asynchronous. Challenges expire after five minutes and are consumed atomically before cryptographic verification. Incorrect or reused responses must start a new ceremony.

## Validation and dependency review

The test suites cover browser encryption/authentication lifecycle, backend authorization policy, deployment-target validation, and Firestore/Storage rules. Public smoke checks validate Hosting headers, denied anonymous reads, and callable authorization. These checks do not replace device-level WebAuthn enrollment, live encrypted upload/download, or an independent security audit.

Review dependency advisories before deployment and after upgrades. An initial backend scan found no high/critical reports and moderate reports related to [UUID buffer bounds](https://github.com/advisories/GHSA-w5hq-g745-h8pq). The inspected upstream call sites used v4 without caller-provided buffers, while the advisory concerned other UUID variants with that option. Haven's security identifiers use Node crypto random bytes. This historical observation is not a current clean bill of health; reassess your locked dependency tree.

The original deployment also received an unresolved mobile Chrome Safe Browsing report. TLS and file integrity passed checks, but the private Search Console report had not been reviewed. See [troubleshooting](docs/TROUBLESHOOTING.md); a valid TLS certificate is not evidence that a reputation warning can be ignored.

## Reporting a vulnerability

Use this repository's GitHub **Security → Report a vulnerability** option if private reporting is enabled. If it is unavailable, contact the maintainer through a contact method listed on their GitHub profile to arrange a private channel. Do not post exploit details, credentials, passphrases, private files, or deployment logs in public issues. There is no guaranteed response time or formal support SLA.

## Browser and administrator limitations

Encryption protects stored data, not an already compromised browser, malicious extension, screen capture, or malware on an unlocked device. A person able to deploy malicious JavaScript to this origin could steal the passphrase or plaintext during a future unlock. Protect the Firebase project, source control, deployment accounts, DNS, and domain ownership with strong authentication. Firebase administrators can delete, corrupt, or replace ciphertext even though they do not have the passphrase.

Previewing and downloading produces plaintext in browser memory. Downloaded files may remain in the operating system's Downloads folder and backups. PDF or image parsing uses the browser's capabilities. Keep the browser and device current. Client key clearing and object URL revocation reduce exposure but cannot guarantee forensic erasure from a managed runtime.

The server validates encrypted envelope shapes and sizes; it cannot prove that a client actually encrypted a payload without receiving the key. Encrypted files have immutable opaque object names, an `application/octet-stream` content type, and a maximum plaintext size of 50 MiB. The application does not need persistent Firebase download URLs. Do not share such URLs, grant public bucket access, or loosen the supplied rules.

The default Hosting configuration supplies restrictive framing, script, referrer, and caching headers. If you add third-party scripts, analytics, remote preview services, or a service worker, review the effect on vault confidentiality first. A production security assessment should include dependency review, rules emulator tests, WebAuthn integration tests, and adversarial testing of the complete deployed app.
