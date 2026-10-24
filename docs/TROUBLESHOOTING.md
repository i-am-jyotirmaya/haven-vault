# Troubleshooting

## Chrome says “Dangerous site”

This is a Safe Browsing warning, separate from HTTPS certificate validity. A working laptop does not establish that a mobile warning is harmless. Do not disable Safe Browsing or proceed through the warning to enter a passphrase.

Record the exact URL, warning text, browser/device, and whether it happens before the app or during Google sign-in. Check [Google's public site-status tool](https://transparencyreport.google.com/safe-browsing/search) and the property's Search Console **Security Issues** report. “No available data” is not an all-clear. Inspect deployed files and account access, fix reported issues, then follow [Google's review process](https://support.google.com/webmasters/answer/9044101). Report a false positive only after investigation; do not rotate domains to evade a warning.

At the initial open-source release, a mobile Chrome warning on the original deployment remained unresolved. TLS and file-integrity checks passed, but its owner-only Search Console report had not been inspected. This repository does not claim that warning was cleared; the personal deployment is not offered as a public service.

## “Document is not in focus” or passkey prompt fails

Return to the vault tab after Google sign-in, click **Create my passkey**, and keep it active through the device prompt. Cancel and restart if the prepared challenge expires. Use the canonical HTTPS hostname; embedded browsers may have limited passkey support. The app must not automatically start registration while Google's popup still has focus.

Confirm `RP_ID` matches the hostname and `EXPECTED_ORIGIN` the exact origin. Credentials from another hostname do not transfer by changing configuration. Do not delete owner/credential records to troubleshoot prompts.

## Backend not ready

Supply all browser configuration values, deploy Functions and both rule sets, verify permissions, then set `VITE_VAULT_BACKEND_READY=true`, rebuild, and redeploy Hosting. Vite embeds configuration at build time.

## Fingerprint succeeds, then sign-in fails

The device accepting a fingerprint means it authorized the passkey locally;
Haven still has to verify the signed response, exchange the session token and
read the encrypted vault configuration. Older clients report every permission
denial during these steps as “Your secure session ended. Sign in again.” That
message alone does not establish that the session expired.

Updated clients keep the failing stage, server reason and error code visible:

- **Passkey sign-in failed:** use the passkey registered for this vault on the
  original canonical hostname. Check `RP_ID` and `EXPECTED_ORIGIN` if verification
  fails. Do not delete passkeys, owner records or encryption configuration.
- **Your passkey was accepted, but Haven could not load your vault:** check that
  Hosting, Functions, Auth and Firestore use the same Firebase project and that
  the matching session-aware rules and Functions are deployed. Inspect the
  specific failure through the project administrator; do not make rules public.

The client still clears local authorization on a bootstrap authorization failure.
Existing-session expiry and revocation retain their normal sign-out behavior.
When reporting a failure, share the displayed stage/code and browser/device,
never tokens, passphrases, vault contents or credential responses. This feedback
fix does not repair an unverified production configuration or deploy changes.

## Google sign-in or owner verification fails

Enable the Google provider and add Hosting/auth hostnames to authorized domains. Confirm `OWNER_EMAIL` in `functions/.env.<actual-project-id>` and redeploy Functions. First enrollment requires a recent verified matching Google identity; after enrollment, Google alone intentionally cannot add a passkey.

## Callable returns HTML/403 before its handler

Run `node scripts/configure-callable-access.cjs`. A failed first deployment may leave Cloud Run invocation private. Review the setup guide before applying the six-service invocation repair. Never make Firestore or Storage public to fix a callable.

## Token signing or Firestore errors

Run `node scripts/configure-cloud-access.cjs` to inspect runtime identity, IAM Credentials API, signing, and database roles. Verify the target project before applying changes. Token-creator permission should be scoped to the runtime account itself.

## Preview, upload, or CORS failure

Confirm the vault session is active; hidden tabs and inactivity lock it. Check the exact bucket name, origin CORS, and Storage's Firestore session-lookup permission. CORS does not grant authorization. The configuration helper replaces the dedicated bucket's CORS list. Public object ACLs or persistent download links are not a repair.

## Build or deployment failure

Use Node 22 and npm 10 for the backend lockfile. Install with `npm --prefix functions ci`. For local Functions discovery timeouts, set `FUNCTIONS_DISCOVERY_TIMEOUT=60`. Inspect actual Cloud Build errors. Keep the Firebase app-package overrides until their removal has been tested with the emulator SDK.

## Emulator failures

Use Node 22, Java 21+, free the configured emulator ports, and run `pnpm test:local` from the repository root. Use `pnpm dev:local` for the app with live emulators; see [local development](LOCAL_DEVELOPMENT.md). First use requires network access to download emulator binaries. Keep the project `demo-haven-vault`; never target a production database with tests.

## Wrong passphrase or damaged ciphertext

The app cannot distinguish every incorrect passphrase from corrupted authenticated ciphertext. Check your saved passphrase and keyboard layout. Replacing the salt/configuration does not decrypt existing data. There is no reset API. Restore only through a tested complete backup procedure preserving IDs and encryption contexts.

## File queues, collections and partial deletion

Use **Reload latest / retry reconciliation** after reconnecting or reauthenticating.
A lost response can mean the operation already committed. Successful files are
not reuploaded. A missing original requires cancelling its receipt and selecting
it again: Haven does not persist plaintext or resumable File handles. The queue
keeps at most one encrypted retry buffer; other failed transfers can still
retry finalization from their receipts.

Never remove a visible failed deletion's metadata manually. Retry cleanup from
Trash; object deletion happens before metadata deletion, with a durable marker
blocking conflicting edits. Trash remains until explicit deletion and includes
storage usage. Downloaded copies, exported backups and retained migration
safeguards are independent copies.

See [FILE_OPERATIONS.md](FILE_OPERATIONS.md) for state definitions, conflict and
collection-migration rules, quota/offline guidance and measurement limitations,
and [VALIDATION_FILE_OPERATIONS.md](VALIDATION_FILE_OPERATIONS.md) for checks.
