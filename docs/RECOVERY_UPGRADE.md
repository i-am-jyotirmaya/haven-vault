# Recovery, upgrade and rollback guide

This remains a single-owner self-hosted application. Requirements 1/2 remain in
force: authentication, local unlock and sign-out are separate; content conceals
immediately on backgrounding; configured lock/session deadlines still apply.

## Before upgrading

Use Node 22, pnpm 12 and Java 21+. Run `pnpm install --frozen-lockfile`,
`npm --prefix functions ci`, `pnpm test`, `pnpm test:config`,
`pnpm test:backend`, `pnpm test:local`, and `pnpm build`.
The local integration suite uses fictional Google identities and signed synthetic
WebAuthn authenticators only inside Firebase emulators. It has no production
identity bypass. Real platform and USB/NFC key checks remain device work.

Review [the key/recovery design](KEYS_RECOVERY_DESIGN.md) and arrange independent
security review before relying on this as irreplaceable primary storage. Test
upgrade, interruption, recovery and rollback with disposable data first. Keep
independent originals. No automatic vault migration happens during deployment.

`pnpm deploy:plan` previews infrastructure changes. When the operator chooses to
deploy, publish updated Functions, Firestore/Storage rules and indexes before the
new Hosting build. The existing `deploy:cloud` ordering does this; its public
callable-access helper now includes the three new endpoints. No new environment
secret or owner reset is needed. Preserve the original Firebase UID, RP_ID and
EXPECTED_ORIGIN. Changing OWNER_EMAIL does not transfer an existing vault.

Storage authorization reads two private documents: the session and `_vaultAccess`
generation authority. Only server transactions can create/change that authority;
it freezes legacy writes during migration and authorizes precisely one staging
claim. This respects Storage's two-Firestore-document evaluation limit. An absent
authority represents a pre-v2 vault. Do not delete it to troubleshoot permissions.

## New and legacy vaults

New vaults use random master keys and v2 contexts. Recovery starts explicitly
**INCOMPLETE**; visit Security immediately to save/confirm a kit. The application
does not silently substitute a recovery method or imply that Google alone helps.

Legacy vaults unlock with their original passphrase. Open **Security → Migrate or
resume safely**, confirm that passphrase, and verify a passkey. Other devices
cannot write while migration is in progress. If a server rate limit pauses a large vault, wait for the stated window and resume; verified receipts are reused, so retries progress instead of consuming the limit on old items again. The original config/metadata and
original files stay intact; Admin-only encrypted file copies under `safeguards/`
plus ciphertext receipts provide the rollback safeguard. New data is staged
under `generations/`. Plan for roughly three copies of file ciphertext (original,
safeguard and new generation); this release does not automatically reclaim them. The client decrypts and compares metadata and file bytes
before recording each receipt. Server file safeguards are verified by streaming SHA-256 over the original and copied ciphertext. The server seals staging, verifies the manifest
in batches and atomically switches the active config/authority. It never deletes
originals. Object IDs, notes, thumbnails, collections, timestamps, favorites and
trash state are preserved. Empty collections have always been local UI state,
not persisted vault records; this release does not invent missing legacy data.

If interrupted, reconnect, sign in, unlock with the original passphrase and resume
from Security. A newly verified session can reclaim the migration, invalidating
the old staging claim. Locking stops further local work; it does not unfreeze the
source generation. No lease expiry silently re-enables legacy writes. A sealed
finalization resumes without restaging. If cutover committed but its response was
lost, a normal unlock reads the committed v2 config and works with the same
passphrase. Do not reset the config, delete receipts or remove original objects.

Unsupported versions fail with an upgrade/restore message. Old clients cannot
write a frozen or retired legacy generation. Reload every client after upgrade.

## Passphrase changes

Unlock, open Security, enter the current passphrase and matching new passphrases
(12–1,024 characters), then select Change passphrase. A server-verified passkey
ceremony is required. The existing master is rewrapped using a fresh salt/nonce;
files and the recovery wrapper stay unchanged. The server rejects stale revisions
and the UI reads back the committed record before showing success. Other sessions
are revoked; the current session keeps its original expiry. If the response is
lost, lock/reload and try the new passphrase against the authoritative config;
if the update never committed, the old passphrase still works. Do not retry an
old revision blindly.

This does not rotate the master key, invalidate stolen wrappers/backups, or repair
a compromised master. Full data-key rotation is outside this release's UI.

## Recovery kit setup and replacement

With an unlocked v2 vault, enter the current passphrase and select Set up recovery
kit or Replace recovery kit. Download the text kit, print the downloaded file if
wanted, and enter its `secret` from the saved copy. Commit only after saving it.
The downloaded JSON text includes the version, vault/recovery IDs, a random
256-bit secret, encrypted wrappers/private signing material and instructions.
It contains no plaintext contents or unprotected master key. Keep it offline
and protected; do not email it or place it beside a publicly accessible backup.

A cancelled/interrupted preparation leaves the old registration unchanged. A
committed replacement invalidates the old recovery verifier immediately for
future backend recovery. Old kit/backup copies already obtained cannot be revoked.
If the response is lost, preserve the replacement kit and sign in again to check
the recovery identifier before retrying. Never discard a replacement kit just
because an acknowledgement was lost.

## Recover on an existing or new device

| Situation | Procedure |
| --- | --- |
| Passphrase lost, passkey usable | Sign in with the passkey; expand Recover vault on the lock screen, paste the saved kit, choose a new passphrase, save/confirm a replacement kit, and commit. |
| All passkeys lost, passphrase known | On a fresh browser expand Recover vault, supply the kit, verify the registered owner Google identity, choose a new passphrase, save/confirm a replacement kit, then register a replacement passkey. |
| Passphrase and passkeys lost | Follow the same fresh-browser recovery flow; the kit unwraps the master locally and separately signs the scoped enrollment operation. |
| All usable unlock methods and kits lost | Recovery of the content is impossible. Firebase, Google or the administrator cannot reconstruct the key. |

The fresh-browser Google step has no vault-data session. Its five-minute one-use
challenge is bound to owner/vault/recovery version, origin, purpose and WebAuthn
registration; the recovery-authentication signature additionally binds the exact
replacement credential response and replacement key record. The replacement
passkey is cryptographically verified before old credentials/sessions are retired
and the replacement key/recovery record is installed in the same transaction.
A separate session is issued afterward. Opening recovery before sign-in activates the configured background/inactivity cleanup policy for its drafts and kit material; privacy-screen Lock and Sign out also clear it. If the browser closes or the final
response is lost, sign in using the newly registered passkey and new passphrase
or newly saved kit. Old passkeys remain revoked. A timeout before commit keeps
the old recovery method valid; start again with fresh owner verification.

## Passkeys and sessions

Security lists credentials and active sessions only to the authenticated owner.
Passkey labels are encrypted under the v2 master. Add supports compatible
platform and roaming authenticators; at most five credentials are allowed. A
passkey may use a device PIN or be synced by its provider. Never remove the last
credential; register/verify its replacement first. Removing a passkey revokes
sessions established by it. Older sessions without credential attribution cannot
be reliably mapped; revoke all other sessions during upgrade if needed.

Sensitive mutations require passkey authentication within five minutes according
to the server session record, not a client timestamp. Reauthentication does not
renew absolute session expiry. Session device descriptions are coarse browser/OS
families; creation, last validation and expiry are shown without full user agents
or raw IPs. The current session is marked. New session issuance caps simultaneous unexpired sessions at 50; revoke unused sessions before reaching that ceiling.

Revoked/expired private session records deny all subsequent server operations,
even with refreshed Firebase ID tokens. Foreground clients validate every 30
seconds (normally detected within 35 seconds including the four-second request
timeout); lifecycle return checks cover background/suspended clients. Offline or
failed validation locks retained plaintext. Browser scheduling/suspension is not
a hard real-time guarantee. Revocation cannot erase downloaded plaintext or force
an offline adversarial client to clear memory. Current-session revocation clears
local state and returns to sign-in as soon as its committed result is received.

## Rollback

Before cutover, do not downgrade code to bypass the freeze. Resume using this
version. If a corrupt source/stage fails verification, stop and retain all
ciphertext; do not force a completion flag. There is no destructive abort button.

After cutover, old config/metadata remain in the migration record/legacy paths
and original encrypted files plus Admin-only safeguards remain. An operator may
restore a *disposable/staging copy* to the pre-cutover generation using its saved
original config and ciphertext. Never blindly downgrade a live vault: new writes
to v2 would be absent from the old generation. Preserve both generations and
reconcile those writes in an offline reviewed recovery procedure first. An app
rollback to v1 cannot read v2 ciphertext; it must not overwrite the config. This
release deliberately implements no original-generation deletion or automatic
rollback and is not a full backup/export system.

### Privacy while verifying a passkey

Haven conceals on browser blur as well as actual hidden/pagehide/freeze events.
Focus changes from Haven's own credential UI are scoped so an otherwise visible
passkey prompt does not conceal or abort the operation. A real background event
still conceals and uses your existing grace period; on return, a sensitive
operation waits for session validation before continuing. Locking or signing out
cancels the waiting operation. No prompt renews inactivity or session expiry.
Some browsers keep tab-switcher thumbnails or omit browser-chrome lifecycle
signals. Haven cannot guarantee erasing those snapshots; verify your device.
