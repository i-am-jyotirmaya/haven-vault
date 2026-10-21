# Deploy Haven with Firebase

This guide installs one owner's vault in a dedicated Firebase project. Run commands from the repository root. Deploying these rules into another application replaces its access policy; use a dedicated project and bucket.

## 1. Tools and dependencies

Use Node.js 22.12+ within the Node 22 release line, pnpm 12.0.0, and Java 21+ for emulator tests. Use npm 10 (bundled with Node 22) when changing the backend lockfile.

```sh
pnpm install --frozen-lockfile
npm --prefix functions ci
pnpm firebase login
```

`pnpm firebase` runs the CLI installed and locked under `functions`; no global Firebase CLI is needed. Complete authorization locally. Never commit CLI credentials or paste authorization codes into issues.

## 2. Prepare Firebase

In [Firebase Console](https://console.firebase.google.com/):

1. Create/select a dedicated project and register a Web app. Analytics is unnecessary.
2. Enable Blaze billing. Functions, Storage, builds, reads, and traffic can incur charges. Configure budget alerts; alerts do not cap spending.
3. Create the default Firestore database in Native mode. Choose its location deliberately and start with production access rules.
4. Initialize Cloud Storage and record its exact bucket name. Older and newer projects may use different suffixes.
5. Enable Authentication → Sign-in method → Google using your own support email and app name. Add your Hosting hostname and Firebase auth domain to Authentication → Settings → Authorized domains.
6. Record the project ID, numeric project number, and Web app configuration from Project settings.

Choose one canonical origin before enrolling, normally `https://YOUR_PROJECT_ID.web.app`. Its passkey relying-party ID is `YOUR_PROJECT_ID.web.app`. Credentials do not automatically transfer between hostnames. Custom domains also require deliberate Firebase Auth and CSP configuration.

References: [Functions prerequisites](https://firebase.google.com/docs/functions/get-started), [Google sign-in](https://firebase.google.com/docs/auth/web/google-signin), [Storage setup](https://firebase.google.com/docs/storage/web/start).

## 3. Three local configuration files

Replace all example values with your own project values. The files below are ignored by Git. `my-haven-project` is only an example.

PowerShell:

```powershell
Copy-Item .env.example .env.local
Copy-Item functions/.env.example functions/.env.my-haven-project
Copy-Item vault.config.example.json vault.config.local.json
```

macOS/Linux:

```sh
cp .env.example .env.local
cp functions/.env.example functions/.env.my-haven-project
cp vault.config.example.json vault.config.local.json
```

### Browser: `.env.local`

```dotenv
VITE_FIREBASE_API_KEY=your-firebase-web-api-key
VITE_FIREBASE_AUTH_DOMAIN=my-haven-project.firebaseapp.com
VITE_FIREBASE_PROJECT_ID=my-haven-project
VITE_FIREBASE_STORAGE_BUCKET=my-haven-project.firebasestorage.app
VITE_FIREBASE_MESSAGING_SENDER_ID=your-project-number
VITE_FIREBASE_APP_ID=your-firebase-web-app-id
VITE_FIREBASE_FUNCTIONS_REGION=us-central1
VITE_VAULT_BACKEND_READY=false
```

Every `VITE_*` value becomes public browser code. Firebase web configuration identifies your app; authentication and rules authorize data access. Never put passphrases, service-account keys, or administrative tokens here. Restart Vite after changes; production changes require rebuilding.

### Backend: `functions/.env.my-haven-project`

The filename must end with your actual project ID.

```dotenv
OWNER_EMAIL=your-verified-google-email@example.com
RP_ID=my-haven-project.web.app
EXPECTED_ORIGIN=https://my-haven-project.web.app
ENFORCE_APP_CHECK=false
```

`RP_ID` is a hostname without a scheme or port. `EXPECTED_ORIGIN` has a scheme and no trailing slash. Functions deploy in `us-central1`; changing a browser variable alone does not move them. App Check initialization is not included: keep enforcement false until you implement and validate the client integration described in [SECURITY.md](../SECURITY.md).

### Operational scripts: `vault.config.local.json`

```json
{
  "projectId": "my-haven-project",
  "projectNumber": "123456789012",
  "bucket": "my-haven-project.firebasestorage.app",
  "origin": "https://my-haven-project.web.app",
  "region": "us-central1"
}
```

Helpers reject missing or placeholder configuration. They never default to the author's project. This file configures scripts only, not Firebase CLI, the browser, or Functions; keep all three files consistent. The cloud-access helper also verifies that the project ID and number match Google Cloud before changing permissions.

## 4. Validate and deploy the backend

```sh
pnpm test
pnpm test:config
pnpm test:backend
pnpm test:rules
pnpm build
pnpm firebase deploy --project my-haven-project --only functions,firestore,storage
```

For Functions discovery timeouts, set `FUNCTIONS_DISCOVERY_TIMEOUT=60`: PowerShell uses `$env:FUNCTIONS_DISCOVERY_TIMEOUT = '60'`; Unix shells use `export FUNCTIONS_DISCOVERY_TIMEOUT=60`.

Review Firebase's permission prompts, including Storage's cross-service Firestore access. The configuration includes indexes and TTL fields. Expired sessions are denied immediately even before TTL cleanup. Google sign-in is enabled in Console rather than by this command.

The seven callable services permit public HTTP invocation so browsers can begin authentication. Handlers still enforce owner identity, passkey signatures, challenges, and sessions. This does not make database or bucket data public. Public endpoints may receive unsolicited traffic and consume quota.

## 5. Inspect and configure cloud access

Once Functions are deployed, inspect without changing IAM or CORS:

```sh
node scripts/project-status.cjs
node scripts/configure-cloud-access.cjs
node scripts/configure-callable-access.cjs
```

These helpers use your Firebase CLI session and internal CLI APIs pinned by the backend lockfile. Review compatibility when upgrading the CLI. They print selected status fields, not credentials or full provider configuration.

If required access is absent, review these changes and explicitly apply them:

```sh
node scripts/configure-cloud-access.cjs --apply
node scripts/configure-callable-access.cjs --apply
```

| Helper | Changes |
| --- | --- |
| Cloud access | Enables IAM Credentials API if needed; grants runtime `roles/iam.serviceAccountTokenCreator` on itself; adds `roles/datastore.user` if no recognized Firestore role exists; grants Storage service agent `roles/firebaserules.firestoreServiceAgent`; configures exact-origin GET/HEAD/OPTIONS CORS |
| Callable access | Adds `allUsers` with `roles/run.invoker` to only the seven vault services, preserving other bindings |

**The cloud-access helper replaces the bucket's current CORS list.** Use a dedicated bucket. Neither helper grants public object access or relaxes vault rules. The callable helper repairs private invocation policies that can remain after a failed initial deployment.

References: [token signing](https://firebase.google.com/docs/auth/admin/create-custom-tokens), [Storage rules using Firestore](https://firebase.google.com/docs/storage/security/rules-conditions#enhance_with_firestore), [browser downloads and CORS](https://firebase.google.com/docs/storage/web/download-files#download_data_directly_from_the_sdk).

## 6. Publish Hosting

After verifying the backend and rules, set `VITE_VAULT_BACKEND_READY=true` in `.env.local`:

```sh
pnpm build
pnpm firebase deploy --project my-haven-project --only hosting
node scripts/verify-deployment.cjs
```

The readiness flag is a UI indicator, not an authorization control. Smoke checks require no administrator credentials. They check Hosting headers, unauthorized reads, and callable authorization. After enrollment, the login-options probe may create a short-lived challenge/rate-limit entry, but no credential or vault file.

Optionally configure function build-image retention with Firebase's `functions:artifacts:setpolicy` command. Choose a period deliberately: old image deletion reduces storage costs but removes those rollback copies. It is separate from vault files.

## 7. First use

1. Open the canonical HTTPS URL on your device with no unresolved security warning.
2. Choose **Set up my private vault**, then verify the configured Google owner.
3. Return to the vault tab, click **Create my passkey**, and finish the device prompt while the page stays focused.
4. Create and confirm a strong unique passphrase, at least 12 characters. Keep an independent secure copy.
5. Upload a non-sensitive fixture. Verify preview, download, Lock vault, and passphrase-only unlock on each intended device. Verify Sign out from both the locked and unlocked screens, expiry while locked, and background/resume behavior.

After signing out, visits use **Sign in with passkey**, then the passphrase. The OS may synchronize passkeys; Haven does not manage synchronization. Google alone cannot replace a registered passkey. Losing the passphrase strands ciphertext, and losing every usable passkey blocks normal sign-in. There is no recovery UI.

## Updates and backups

Keep independent originals. This version has no complete encrypted export/import tool. A manually designed backup must preserve vault configuration, encrypted metadata, encrypted Storage objects, and the identifiers used by encryption contexts. Copying files alone is insufficient. Test restores before relying on them.

For upgrades, review changes, install from both lockfiles, run checks, and deploy changed components explicitly. For separate locking/sign-out, deploy Functions first: verification now returns authoritative session timing and the frontend uses `validateVaultSession` for read-only owner/expiry/revocation checks. Deploy Hosting afterward; no vault-data migration is needed. Changes to encryption formats, context strings, salts, or hostnames need a migration plan. Never reset backend records as routine troubleshooting.

## Local deployment commands

After the project and three configuration files above are ready, deploy directly from your terminal:

```sh
pnpm firebase login
pnpm deploy:plan
pnpm deploy:cloud
```

`deploy:plan` validates local files and prints the exact project ID, canonical origin, scope, and planned stages. It makes no cloud requests or changes. `deploy:cloud` checks browser project/bucket/region/project number and Functions owner/RP/origin consistency, runs frontend/script/backend tests, builds Functions, deploys backend/rules, checks cloud access, verifies callable/data authorization, builds the production frontend, publishes Hosting, and verifies the published site. It always passes the configured project explicitly rather than relying on `firebase use` or a current alias. The frontend readiness flag is set for that build only, after backend smoke checks succeed; your environment file is preserved.

The command expects `functions/.env.<projectId>`, not an alias-named Functions file. Vite production mode loads its normal `.env*` precedence, including `.env.production.local`, so update those files if preflight reports drift. Functions deployment loads `.env` and `.env.<projectId>`; emulator `.env.local` overrides are not deployed.

For a first deployment or a permissions repair, review section 5 and then opt into the existing access helpers:

```sh
pnpm deploy:plan --configure-access
pnpm deploy:cloud --configure-access
```

That option applies the documented IAM grants, callable invocation access, and replacement of the dedicated bucket's CORS list with the canonical origin. Without it, access helpers only check and fail on missing configuration. Deployment stops before publishing Hosting when access or backend smoke checks fail. There is no automatic rollback: a failure after backend deployment leaves those backend changes applied. Fix the reported stage and rerun.

For a scoped update:

```sh
pnpm deploy:cloud --only backend
pnpm deploy:cloud --only hosting
pnpm deploy:plan --only hosting
pnpm deploy:verify
```

Backend scope deploys Functions, Firestore rules/indexes, and Storage rules without publishing Hosting. Hosting scope validates the existing backend before publishing the newly built frontend. Both run the local unit/config/policy checks. Run `pnpm test:local` before releases for integration and rules checks; Java/emulator downloads are not required by the cloud deployment command itself.

These commands reuse the locally installed, locked Firebase CLI and your own signed-in account. Cloud infrastructure provisioning (billing, databases, bucket, Google provider, domains) still follows section 2; deployment does not silently create accounts, choose billing, or change domains. No live deployment is needed for [local development](LOCAL_DEVELOPMENT.md).


## Configure authentication lifetime

Set `AUTH_SESSION_MINUTES=60` in `functions/.env.<project-id>` (see `functions/.env.example`). The only supported values are `15`, `30`, and `60`; omitted means `60`. Invalid values fail deployment-plan validation and new session issuance. Redeploy Functions to apply it to **new** passkey sessions. Existing sessions retain their original persisted expiry and issued lifetime, even if the new value is longer.

Deploy **Functions before Hosting** when upgrading this version: verification and `validateVaultSession` now return the issued lifetime alongside server time/expiry. Rules continue to check the original server record independently of refreshed Firebase tokens. No encryption/data migration or rule relaxation is needed.

Use `pnpm deploy:plan` to validate the environment, then `pnpm deploy:cloud` for the checked local-command deployment. Local Security settings affect only background/inactivity locking, never the backend lifetime. The effective issued lifetime appears after authentication; the client ends access approximately 15 seconds early, plus request latency, rather than extending it.
