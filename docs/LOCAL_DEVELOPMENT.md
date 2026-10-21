# Test the real vault locally

The Firebase Local Emulator Suite runs Auth, Functions, Firestore, and Storage on your computer. You do not need a Firebase account, billing, a cloud project, or infrastructure deployment. The existing `?demo=1` tour remains a separate fictional preview; this workflow exercises the encrypted vault and its actual authorization handlers.

## Start

Install Node 22.12+ within the Node 22 release line, pnpm 12.0.0, and Java 21+. Check `node --version` and `java -version` in the terminal you will use.

```sh
pnpm install --frozen-lockfile
npm --prefix functions ci
pnpm setup:local
pnpm dev:local
```

`setup:local` creates the ignored `functions/.env.demo-haven-vault` with fictional owner `owner@example.com`, RP ID `localhost`, origin `http://localhost:5173`, and App Check disabled. It preserves existing files. `dev:local` also runs setup automatically, checks the runtime/configuration, builds Functions, starts the emulators, then starts Vite and the Functions TypeScript watcher. Frontend changes hot reload; successfully compiled backend changes reload in the Functions emulator. Compilation errors must be fixed before changed backend code runs.

The first run downloads Firebase emulator binaries and needs internet access. Subsequent runs use the cache. No global Firebase CLI is required.

Open **http://localhost:5173** exactly. Use localhost rather than `127.0.0.1`: passkeys are bound to the configured RP and origin. The port is fixed and startup fails if occupied rather than silently choosing another origin. The emulator services bind to loopback only.

| Service | Address |
| --- | --- |
| App with hot reload | http://localhost:5173 |
| Emulator UI | http://127.0.0.1:4000 |
| Authentication | 127.0.0.1:9099 |
| Functions | 127.0.0.1:5001 |
| Firestore | 127.0.0.1:18080 |
| Storage | 127.0.0.1:19199 |

### First enrollment

1. Choose **Set up my private vault** in the app.
2. In the emulated Google popup, add/select `owner@example.com`. This is a synthetic identity; no real Google password is needed. Ensure the synthetic account is marked email verified if your emulator popup exposes that field.
3. Return to the focused vault tab and click **Create my passkey**. Use your real platform authenticator, or Chrome DevTools → More tools → WebAuthn → enable virtual authenticator, with CTAP2, internal transport, resident keys, user verification, and automatic presence simulation enabled.
4. Create a test passphrase and upload fictional fixtures. Test photos, PDFs, notes, preview/download, locking, and later passkey sign-in.

The emulator simulates Google identity, but the backend still verifies WebAuthn challenges, signatures, user verification, owner identity, and session expiry. No test login endpoint or production authentication bypass is added. Your browser still performs encryption and decryption.

A virtual authenticator's credentials may disappear when DevTools/browser sessions end. If you keep emulator data but lose the matching local passkey, reset the disposable data and enroll again. Localhost credentials cannot sign in to your deployed vault.

### Stop, persist, reset

Press Ctrl+C to stop the local stack. Auth/Firestore/Storage emulator data exports into ignored `.emulator-data/`; the next development run imports it. An unclean termination may lose changes since the previous export. Saved data contains encrypted test files, authentication records, and public passkey material; use fictional data and keep it out of Git. Browser decrypted state and the encryption key are not exported.

To reset, stop the stack, then delete `.emulator-data/` (PowerShell: `Remove-Item -Recurse -Force .emulator-data`; macOS/Linux: `rm -rf .emulator-data`). Remove the corresponding localhost test passkey or virtual authenticator if needed, then restart and enroll again. Resetting does not touch cloud resources.

### Automated integration checks

```sh
pnpm test
pnpm test:config
pnpm test:backend
pnpm test:local
pnpm build
```

`test:local` starts a fresh disposable stack without importing/exporting development data. It runs a software WebAuthn ceremony through the actual callable handlers: synthetic Google enrollment, challenge replay rejection, signed passkey login, encrypted Firestore/Storage roundtrip, rejection of Google-only access after enrollment, and revocation. It then runs the existing Firestore/Storage rules suite sequentially. It stops the emulators on completion and returns a failing exit code on failure. Stop `dev:local` first so the ports are free.

These tests do not replace device checks for platform passkey UX, touch gestures, or browser-specific preview behavior. They do not validate production IAM, billing, TLS, Cloud Run scaling, or bucket CORS; use the [deployment checks](FIREBASE_SETUP.md#local-deployment-commands) for those.

## Isolation and troubleshooting

- Local mode hardcodes `demo-haven-vault` and connects all four browser SDKs before requests. Production `.env.local` values do not select a cloud project in this mode. The Functions region is fixed to `us-central1`.
- `functions/.env.local` takes precedence over the project environment file in emulators. Startup rejects conflicting owner/RP/origin/App Check values instead of silently using cloud settings. Move or correct that override if startup reports a mismatch.
- Do not manually run a partial emulator stack with a real project ID. Use `dev:local` or `test:local` so all required services use the same fictional project.
- Production builds cannot use `--mode emulator`. `pnpm dev` keeps its existing behavior: it uses your configured cloud project, or the demo preview if unconfigured.
- If your terminal sets HTTP(S) proxy variables, the locked Firebase CLI can route its internal Storage-to-Firestore session lookups through that proxy. If uploads are denied while Firestore works, download the emulators first, then run locally with those proxy variables unset.
- A wrong or unfocused passkey origin, lost local credentials, wrong synthetic owner email, occupied ports, old Java, or stale Functions compilation can each prevent login. Check terminal output and Emulator UI. Keep the app tab focused for passkey prompts.

Firebase references: [demo projects and Auth](https://firebase.google.com/docs/emulator-suite/connect_auth), [Firestore](https://firebase.google.com/docs/emulator-suite/connect_firestore), [Storage](https://firebase.google.com/docs/emulator-suite/connect_storage), [Functions environment precedence](https://firebase.google.com/docs/functions/config-env#emulator_support).


## Test automatic locking

The emulator uses the same server lifetime parameter as production: omitted `AUTH_SESSION_MINUTES` defaults to `60`; set it to `15`, `30`, or `60` in the local Functions environment to test different new sessions, then restart the emulator. Existing issued records keep their expiry. Invalid values reject authentication rather than producing unbounded sessions.

Security → Automatic locking settings controls device-only background grace (default 30 seconds) and inactivity (default 5 minutes). Background concealment is immediate and mandatory. Try returning within grace, returning after grace, immediately locking, and changing to a shorter inactivity value after time has elapsed. Restore defaults resets those two preferences only. Reloads always discard authentication and encryption keys.

`pnpm test` uses fake clocks for lifecycle/expiry, sleep-style clock jumps, trusted interaction wiring, invalid preferences, stale async races, and server issuance/authorization tests. `pnpm test:rules` includes an expired private record with fresh Firebase token claims. `pnpm test:local` covers signed synthetic WebAuthn enrollment/login and encrypted emulator roundtrips. Real device sleep, BFCache behavior, OS screenshots, platform passkeys, and mobile app switching still require device verification; DOM timing tests cannot prove them.
