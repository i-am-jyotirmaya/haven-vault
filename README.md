# Haven Vault

A self-hosted, single-owner vault for photos, documents, and notes. A device passkey controls access to Firebase; a separate passphrase decrypts your data in the browser.

Built with React, TypeScript, Vite, Firebase, SimpleWebAuthn, and the Web Crypto API. Released under the [MIT license](LICENSE); bundled third-party images retain their own license.

## Features

- Client-side encryption of files, filenames, notes, metadata, and thumbnails.
- Owner-only Google verification for initial enrollment, then passkey sign-in.
- Photo pinch/wheel zoom and panning, local PDF rendering, and text previews. Office files can be stored and downloaded but have no inline preview.
- Collections, search, favorites, grid/list layouts, trash, and encrypted notes.
- Memory-only authentication, separate Lock vault / Sign out actions, automatic locking, and expiring server sessions.
- Files up to 50 MiB and notes up to 256 KiB.
- A fictional demo that cannot upload real files.

**Security scope:** this is an unaudited personal-vault implementation, not a managed backup service. WebAuthn may use a device PIN instead of biometrics. There is no passphrase reset, passkey-management UI, or built-in backup/export workflow. Read [SECURITY.md](SECURITY.md) and keep independent originals.

## Try it locally

Use Node.js 22.12+ within the Node 22 release line and pnpm 12.0.0.

```sh
git clone https://github.com/i-am-jyotirmaya/haven-vault.git
cd haven-vault
pnpm install --frozen-lockfile
pnpm dev
```

Open **http://127.0.0.1:5173/?demo=1**. No Firebase account or environment file is required for the demo. It is not a local encrypted vault and does not persist your files. To test the real encrypted vault without deploying infrastructure, use the local Firebase emulators:

```sh
npm --prefix functions ci
pnpm dev:local
```

Requires Java 21+ in addition to Node/pnpm. Open **http://localhost:5173**, enroll the synthetic owner `owner@example.com`, and create a localhost passkey and test passphrase. See [local development](docs/LOCAL_DEVELOPMENT.md) for setup, test data, persistence/reset, and automated integration tests.

## Deploy your own vault

Follow the [Firebase setup guide](docs/FIREBASE_SETUP.md). You need a dedicated Firebase project with Blaze billing, Firestore, Storage, Authentication, Hosting, and Cloud Functions. No production credentials or project binding are distributed. Changing frontend variables alone does not configure the security backend. Once configured, use `pnpm deploy:plan` to review the target and `pnpm deploy:cloud` to validate, deploy, and smoke check from your terminal. No pipeline is required.

| Guide | Contents |
| --- | --- |
| [Local development](docs/LOCAL_DEVELOPMENT.md) | Full emulator stack, hot reload, encrypted tests, persistence/reset |
| [Firebase setup](docs/FIREBASE_SETUP.md) | Installation, environment files, permissions, deployment, and first use |
| [Architecture and integration](docs/ARCHITECTURE.md) | Modules, authentication, storage format, and customization |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Passkeys, permissions, CORS, and browser warnings |
| [Security](SECURITY.md) | Threat model, recovery limits, and vulnerability reporting |
| [Contributing](CONTRIBUTING.md) | Development and validation |
| [Third-party notices](THIRD_PARTY_NOTICES.md) | Image and dependency licenses |

## Two security layers

```mermaid
sequenceDiagram
    participant You
    participant Browser
    participant Auth as Firebase + WebAuthn
    participant Store as Firestore + Storage
    You->>Browser: Verify with device passkey
    Browser->>Auth: Signed single-use challenge
    Auth-->>Browser: Firebase token + absolute session expiry
    You->>Browser: Enter vault passphrase
    Browser->>Store: Request encrypted data
    Store-->>Browser: Ciphertext (valid session required)
    Browser->>Browser: Derive key and decrypt locally
```

First enrollment additionally requires the configured owner's verified Google account. The passphrase never goes to Firebase. A stolen database copy can still be subjected to offline passphrase guessing. An administrator who can deploy malicious JavaScript could capture future unlocks. Protect deployment access as carefully as the vault itself.

Routine locking keeps your authenticated session active: enter only the passphrase to unlock locally. Signing out ends access on this device and attempts server revocation. New server sessions default to 60 minutes, configurable by the administrator to 15, 30, or 60 (the client signs out slightly earlier). Activity, locking, unlocking, and Firebase token refresh never renew them. Content is concealed immediately on backgrounding; the default key-clearing deadlines are 30 seconds away or 5 minutes inactive. Change device timings in Security → Automatic locking settings. Deploy the updated Functions before Hosting when upgrading; see [the lifecycle and upgrade notes](docs/ARCHITECTURE.md#authentication-lifecycle).

## Development checks

```sh
npm --prefix functions ci
pnpm test
pnpm test:config
pnpm test:backend
pnpm test:rules
pnpm build
```

Rules tests require Java 21+ and download Firebase emulators on first use. They use the disposable demo-haven-vault project. Use `pnpm test:local` for the complete disposable emulator integration suite; `pnpm dev:local` connects the frontend automatically.

Tests cover encryption, authentication lifecycle, backend policy, deployment configuration, and Firestore/Storage authorization. Verify real passkey enrollment and live encrypted upload/download on your own devices. Passing tests is not an independent security audit.

## License

Haven source, documentation, and original fixtures are MIT licensed. Demo photographs are from Unsplash and are excluded from the MIT grant. Dependencies retain their respective licenses; see [third-party notices](THIRD_PARTY_NOTICES.md).
