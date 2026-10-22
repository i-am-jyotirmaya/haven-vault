# Everyday encrypted operations (Requirement 7)

This implementation depends on the versioned-key, recovery and session work in
PR #6 (`feat/key-recovery-access-management`). It incorporates current main,
including the configured Firebase preview-test isolation. Until #6 merges, this
PR targets that branch; retarget to main after its merge and recheck the diff.
No deployment or real-vault mutation is part of this change.

## Trust boundaries and operation states

The existing `securityOperation` callable now dispatches `files.*` actions. Its
existing owner, issued private-session, revocation, absolute-expiry, App Check
and rate-limit checks remain authoritative. File operations do **not** require
recent passkey reauthentication, update user interaction, or renew session
lifetimes. Key changes and migration retain their separate freshness checks.
The existing key-generation/migration authority is checked on each mutation.

A server-owned journal resides beside the existing item namespace:

- Legacy: `users/{uid}/operations/{operationId}`.
- V2: `users/{uid}/generations/{generation}/operations/{operationId}`.

UUIDs, revisions, timestamps, encrypted byte lengths, ciphertext hashes and
operation states are non-secret operational data. Names, MIME types, note text,
collection definitions/membership and thumbnails remain inside authenticated
ciphertext. No plaintext file, passphrase, key, persistent browser draft, logging
of private fields, or upload-session URI is added.

| UI state | Meaning / durable state |
| --- | --- |
| Queued | Validated File handle in memory, awaiting the single worker |
| Encrypting | Thumbnail/AES-GCM processing; bytes are not being transferred |
| Uploading | SDK resumable **encrypted** upload; progress is actual transferred/total encrypted bytes |
| Finalizing | Callable streams and verifies object size, type and SHA-256, then atomically commits item metadata/revision and journal completion |
| Completed | The required commit is acknowledged, or its previous completion is reconciled |
| Failed | No success is assumed; the row or durable receipt remains retryable |
| Cancelling | Local cancellation requested; remote cleanup may still be unconfirmed |
| Cancelled | Cancellation receipt closed after the cleanup attempt succeeds; rules deny access and late-write cleanup remains installed |

Server states are `pending`, `cancelling`, `cancelled`, `deleting`, `completed`
and `retired`. `retired` closes a completed upload receipt when permanent
item deletion starts. Pending receipts hold encrypted metadata needed to finish.
**Completed/cancelled receipts redact that payload**; successful retries obtain
current ciphertext from the active item. Thus deleted notes and old revisions
are not retained as readable ciphertext in a permanent operation history.
Fingerprints and terminal receipts remain for deduplication and orphan cleanup.
Migration safeguards intentionally remain separate retained copies.

## Upload lifetime, retries and cancellation

Validation precedes thumbnails, reading file bytes and encryption. The worker
processes one file at a time, using the current whole-file format. There is at
most one retained full encrypted retry buffer across failures. Queued Files are
handles, not eagerly read arrays. Transient plaintext arrays are cleared on
exit; browser-managed File data, JavaScript strings and WebCrypto internals
cannot be reliably zeroized. A 50 MiB file still needs multiple transient
allocations; this is bounded concurrency, not streaming encryption.

Each upload uses one UUID as its operation ID, item ID and immutable object ID.
Its exact encrypted metadata, object digest/size and expected revisions form an
immutable begin fingerprint. A repeated begin cannot redefine the receipt.
A retry checks whether the immutable object already exists, verifies its digest,
and skips transfer if possible. The server independently streams the object
before committing the item. Upload success followed by metadata failure leaves
`pending` plus the encrypted object, not a completed-looking item. Retrying or
reopening finalizes it. Lost final responses cannot create another item.

Files use **new** `staged/{uid}/{generation-or-legacy}/{UUID}` object paths;
existing files and migration objects are never overwritten. Active item writes
and physical deletion now go through the callable to prevent old clients from
bypassing CAS or racing object cleanup. Storage rules remain immutable and
check exactly two Firestore documents: the private session and the Admin-owned
upload receipt. Migration's existing inactive-generation creates stay available.

Cancel stops the SDK task and waits for the worker's in-flight begin/upload/
finalize to settle before cleanup. A finalization transaction which won the race
is reported as completed. Otherwise a transaction closes upload authorization,
then owner-derived object cleanup runs. A failed/offline cleanup stays visible
and retryable. Cancelling a queued entry avoids processing the file.

The Storage finalize trigger `cleanupAbandonedUpload` covers an already-started
resumable transfer that arrives **after** cancellation or permanent deletion.
It only removes objects with an owned cancelled/cancelling/retired receipt in
`staged/`; it does not purge trash or migration backups. It uses the event's
physical generation as a delete precondition. Stale events cannot delete a
newer generation; other failures retry. Rules immediately deny reads after a
receipt is cancelled/retired, while physical late-object cleanup is eventual.
Cloud-provider event delivery, availability, versioning and retention policies
still affect physical reclamation; no instantaneous erasure guarantee is made.

Receipts reconcile after authentication and local unlock, and via **Reload
latest**. Encryption buffers and Files are not persisted. After reload, an
unfinished transfer requires cancelling its old receipt, then reselecting the
original file. Within a session, eviction of a failed encrypted buffer has the
same limitation: targeted retry first attempts finalization, then explains
reselection if no complete object exists. Successful files are never requeued.
There is no claim of persistent byte-level resume after reload.

## Locking and session changes

The authenticated/locked/unlocked separation and automatic policy remain intact.
Lock and sign-out invalidate generations, abort the queue, clear File/buffer
maps, decrypted items, drafts, dialogs, searches and managed plaintext URLs.
Checks around async crypto/transfers/writes prevent late results from restoring
content or initiating the next sensitive step. A currently executing WebCrypto
call cannot be interrupted, but its result is discarded and raw arrays cleared.
During background grace the existing privacy surface conceals all these views;
plaintext-generation checks stop affected work. Reconciliation resolves a remote
commit whose local result was discarded. Revoked/expired credentials cannot
finalize or clean up; authenticate again to retry. No operation activity counts
as trusted user interaction or extends the server deadline.

## Items, conflicts and deletion

Rename, move, note edit, favorite, trash and restore encrypt the complete revised
metadata and use the **same** revision-CAS journal mechanism. New notes retain a
stable creation identity across an unconfirmed save. Saved metadata and the
completed receipt commit in one Firestore transaction. Existing records without
a revision start at revision zero; the first confirmed mutation sets revision
one. Mutable note contents never use last-write-wins. Direct active item writes
are denied by rules, including from obsolete clients.

Overlapping local work is guarded; competing sessions can stage edits but only
one expected revision can finalize. Conflicts expose a reload action and keep
the open draft in memory until the editor is closed or the vault locks. Reload
keeps that draft; close/reopen the latest item and review the current contents
before explicitly applying changes. Failed receipts can be cancelled from the
operation panel. No automatic merge or silent stale-note replacement occurs.

Permanent deletion requires confirmation, first freezes the item with a durable
deletion owner, and retires the initial transfer receipt to deny file reads.
The object is deleted before metadata. Object failure retains the metadata and
receipt; object success followed by metadata failure retains enough state to
retry the missing-object-safe cleanup. Rename/move/edit/restore cannot race that
marker. Success is returned only after the metadata transaction succeeds.
Empty trash reports individual outcomes and retains failed items for retry.
A repeated completion is idempotent. Downloaded copies, exported backups,
retained migration originals/safeguards, or provider-retained historical versions
are not erased by deleting the active item.

Trash has **manual retention**. It consumes storage until explicit permanent
deletion. No automatic purge, retention scheduler or aggregate quota is added.
Unknown preview formats remain downloadable. Individual downloads check the
authenticated ciphertext and expected plaintext size before creating a managed
URL; the URL is revoked on policy cleanup or shortly after download dispatch.

## Collections and membership migration

The catalog is an independently encrypted document at
`{item-namespace}/catalog/collections`. It has a revision and a server-owned
`itemEpoch`; its payload contains stable collection UUIDs, names and legacy-name
aliases. Empty definitions survive reload. Personal has a fixed reserved ID and
cannot be removed or renamed. Names are trimmed, length limited and compared
case-insensitively for duplicates. The catalog is limited to 500 definitions.

On first unlocked read, exact legacy names become aliases under stable IDs.
Case-insensitive historical variants are grouped while every exact alias is
retained. Items are resolved through aliases without rewriting the whole vault.
The next item mutation stores its collection UUID in encrypted metadata. A
collection rename changes the definition rather than rewriting each file;
legacy aliases still resolve. No membership or file ciphertext is lost.

Deleting a non-empty collection requires choosing another destination. Each
move has its own revision/receipt and per-item result; the definition remains
until a fresh read shows no remaining members (including trash). A catalog
revision protects against concurrent collection edits. The `itemEpoch` captured
**before** the membership read must still match when the definition is removed;
a concurrent move/upload/note write/delete aborts removal. Uploads staged against
an older catalog cannot finalize after its revision changes. On interruption,
completed moves remain and the source definition remains usable; retry moves
only remaining members. There is no inaccessible half-deleted folder.

Legacy-key migration is read-only for these mutations. List/unlock/catalog reads
remain available so Security can resume an interrupted migration. Its existing
claim, verification and cutover protocol now also re-encrypts/reads back the
catalog (including empty definitions) and understands legacy operation-staged
objects. Source catalog and ciphertext remain safeguards. Unfinished legacy
file receipts must be resolved before starting migration.

## Limits and usage

| Limit / measurement | Enforcement and meaning |
| --- | --- |
| Plaintext file | 50 MiB = 52,428,800 bytes, validated before crypto |
| Binary encrypted file | Plaintext + 29 bytes; callable and Storage rules independently reject larger objects |
| Note text | 256 KiB UTF-8, validated before encrypting/saving; editing uses the same check |
| Encrypted metadata/catalog | 700,000 ciphertext base64 characters, backend validated; no plaintext field allowed |
| Collection name / item name | 120 / 1,024 characters; client validation before writes |
| User content total | Current metadata sizes, including trash and notes |
| Encrypted object snapshot | Admin listing sizes for active files, trash, completed staged objects, retained generations and safeguards; UI formatting is rounded |
| Additional usage | Firestore ciphertext/journal storage and incomplete provider resumable fragments are **not** included in the object sum |
| Remaining capacity | Unknown; no app aggregate quota is configured and provider limits are not inferred |

The object snapshot is measured on unlock or explicit reload; it is not atomic
with ongoing uploads. The misleading decorative capacity bar is removed.
Provider quota failures leave a failed/pending receipt, not a saved item. No
client-only aggregate accounting or abandoned quota reservation is introduced.

## Operator rollout and troubleshooting

No deployment has been performed. A later operator rollout must include the
updated callable, Storage cleanup trigger, rules and client as a coordinated
release using the existing deployment workflow. Old clients' direct item writes
are intentionally denied; reload the updated client. Do not remove the cleanup
trigger while resumable cancelled receipts may still arrive. Default bucket
configuration must be present for the Storage trigger; ensure its location is
compatible with the configured Functions region before deployment.

| Symptom | Action |
| --- | --- |
| Offline / unknown completion | Reconnect, then Reload latest; do not assume failure means the server did not commit |
| Original file needed | Cancel/confirm cleanup of the receipt, then reselect the original; no plaintext was cached |
| Quota rejected | Check provider capacity; retry or cancel cleanup after space is available |
| Session ended | Passkey sign-in, local unlock, then reconcile; a refreshed Firebase token cannot revive a revoked private session |
| Entry/collection changed | Reload current revisions and review drafts; cancel stale pending receipts before a new operation |
| Deletion unfinished | Keep the visible trashed entry and retry deletion/reconciliation; do not manually discard its receipt |
| Migration in progress | Security → Migrate or resume safely; preserve source generations and safeguards |
| Storage bytes higher than content | Trash, encryption overhead, staging, retained generations/safeguards and provider policies can explain differences |

Only non-sensitive operation IDs and error categories should be used in any
additional diagnostics. Never add filenames, note text, raw exception request
bodies, keys, recovery secrets or passphrases to logs.
