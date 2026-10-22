# Version 2 keys, recovery, migration, and access design

Status: implementation design, 22 October 2026. This is not an independent audit.
Requirements 1 and 2 are present in main at d2b3855. No real vault or deployment
is changed by this work.

## Keys and formats

A new vault has a random UUID vault identifier and data generation and a random
256-bit master key from crypto.getRandomValues. AES-256-GCM uses fresh 96-bit
nonces and 128-bit tags. PBKDF2-HMAC-SHA-256 (600,000 iterations, random 32-byte
salt, bounded input parameters) protects the master under the passphrase. A
separate random 256-bit recovery secret uses HKDF-SHA-256 with domain-separated
info to protect a second master wrapper and a separately generated ECDSA P-256
recovery-authentication private key (PKCS8). Only its SPKI public verifier is
server-readable. Recovery encryption never signs authentication challenges.

Operational AES/private signing keys are imported non-extractable. Temporary
raw master/PKCS8/decoded secret buffers are zeroed in finally blocks; JavaScript
strings, copies and browser internals cannot promise forensic memory erasure.
No secrets or plaintext enter persistent browser storage or application logs.
Version 2 key records have a monotonically increasing revision, generation,
vault ID, explicitly versioned wrappers and optional recovery registration.
AES authenticated data binds vault ID, generation, purpose and format version;
item contexts also bind immutable item ID. Formats are rejected when unknown.
Legacy v1 contexts and ciphertext remain readable only with a legacy key.

## Passphrase and recovery changes

Passphrase changes confirm the existing passphrase locally, unwrap the existing
master, and rewrap it with a new salt. No file re-encryption occurs. The server
requires a live owner session and passkey verification within five minutes,
compares revisions transactionally, preserves the recovery registration, revokes
other sessions and returns the committed record for client verification. Failure
before commit preserves the previous wrapper. Lost responses are reconciled by
reading the authoritative record; do not blindly retry a stale revision.
Changing a passphrase is not data-key rotation and does not invalidate stolen
old wrappers/backups or remedy a compromised master.

Recovery kits contain a high-entropy secret, vault ID, recovery ID, format version,
encrypted recovery material and instructions. They are powerful bearer material:
with the ciphertext they decrypt locally, and with owner Google verification they
can replace backend access. Users must download/print and re-enter the secret
before a registration is committed. Incomplete setup is explicit. Replacing a
registration invalidates its old server verifier, not copies of old backups.

A usable passkey with a lost passphrase retrieves the record normally and uses
the kit locally to unwrap the master, choose a new passphrase and replace recovery.
With all passkeys lost, fresh verified Google owner identity can request only a
recovery challenge and WebAuthn replacement registration options. It grants no
vault data session. The random, expiring, single-use challenge binds owner UID,
vault ID, recovery ID, purpose, origin and intended enrollment. The recovery
private key signs the challenge plus SHA-256 hashes of the exact replacement
registration response and replacement key record. Verification consumes the
challenge, verifies ECDSA and the WebAuthn ceremony, rechecks owner/revision and
recovery ID transactionally, installs the verified replacement credential and
new confirmed recovery registration, revokes old sessions/credentials, then
issues access. A lost response can be retried by signing in with the new passkey
and new passphrase/kit. Old passkeys are never automatically trusted again.
No raw secret, master, or passphrase is sent to the server. Google alone cannot
recover. If all usable unlock methods and recovery material are lost, content
recovery is impossible. Owner email configuration changes do not transfer a UID.

## Migration and interruption

Legacy passphrase-derived keys cannot be relabeled as random masters. Migration
requires authentication, successful local unlock, current passphrase confirmation
and recent passkey verification. A server-owned migration record freezes legacy
writes across clients before staging starts. Its immutable original config and
original ciphertext are the rollback generation: no original is overwritten or
deleted. Client verification reads/decrypts every original and verifies staged
metadata/files by reading them back, including byte comparisons; a ciphertext
manifest records original/staged hashes without plaintext. Metadata keeps exact
IDs, names, notes, collections, thumbnails, favorite/trash state and timestamps.

New generation paths are isolated. Only the currently claimed migration session
can stage immutable files and metadata. A fresh session can explicitly reclaim
the migration after recent authentication, invalidating the previous claim.
Progress is per item; retry checks existing staged data rather than duplicating
or replacing immutable objects. Lock/sign-out cancels client publication and
further work; the server freeze and encrypted progress remain for resumption.
Finalization checks the complete source/staged manifest and configured generation
before atomically changing the authoritative config pointer. Repeated finalization
reconciles the committed generation, including response loss. Originals remain
available after cutover; no automatic deletion is implemented. Unsupported clients
cannot write to a retired generation. There is no automatic rollback after new
writes to the new generation: operator rollback must preserve both generations
and reconcile later writes. This safeguard is not the backup/export product.

## Passkeys and sessions

Passkey credentials are private owner-only callable results, maximum five. Labels
are encrypted under the master where possible. Adding/removing requires recent
server-verified passkey authentication; registration rechecks freshness and
ownership at commit and never reruns Google bootstrap. Both compatible platform
and roaming authenticators are accepted. The final passkey cannot be removed.
Removing a credential atomically revokes its sessions. Sessions record credential,
created/expiry/last validation times and a coarse browser/platform description;
no raw user-agent/IP directory is exposed. Current/all-other/all revocation uses
server authority. Firestore/Storage check the private revoked/expiry record on
every operation despite otherwise valid refreshed Firebase tokens. Clients poll
validation every 30 seconds while foregrounded and validate on return; offline
validation failure locks retained plaintext. Revocation cannot erase downloaded
plaintext or an offline client's memory. In-flight work may complete before
revocation commits; late results cannot restore locked state.

## Deployment, compatibility, threats and review

Deploy Functions and restrictive rules before Hosting. Keep legacy reads and
legacy creation validation for existing installations, but the new UI creates v2.
Never reset owner/config records manually. Emulator-only setup remains isolated.
Use a disposable fictional vault for upgrade, interrupted migration, recovery and
rollback exercises. Retain originals until a separately reviewed retention policy.
Old clients fail writes during migration/after cutover and must reload to upgrade.

Threats include XSS/malicious served JavaScript, malicious administrators replacing
the web client, compromised extensions/OS, offline guessing of stolen passphrase
wrappers, stolen recovery kits, Google compromise combined with kit compromise,
rollback of a whole backend snapshot, traffic/size/count metadata and denial of
service. Encryption does not protect a compromised unlocked browser. Server-side
rate limits supplement one-use challenge expiry. Firebase administrators can deny
service or roll back ciphertext; no external rollback transparency is claimed.
Independent review is still needed for protocol composition, key lifecycle,
migration races, Firebase rules and real device/browser behavior. Automated tests
are neither an audit nor a recommendation for irreplaceable primary storage.

## Primary API references consulted

- https://www.w3.org/TR/webcrypto/ (AES-GCM, PBKDF2, HKDF, ECDSA and key extractability)
- https://simplewebauthn.dev/docs/13.3.x/packages/server (pinned major 13 ceremonies)
- https://firebase.google.com/docs/firestore/manage-data/transactions (atomic CAS)
- https://nodejs.org/docs/latest-v22.x/api/crypto.html (P-256 IEEE-P1363 verification)

Storage rules use a private `_vaultAccess/{uid}` generation authority, transactionally
updated with config/migration state, alongside the private session. This keeps
requests within Storage's two-Firestore-document access limit. See
https://firebase.google.com/docs/storage/security/rules-conditions#enhance_with_cloud_firestore.
