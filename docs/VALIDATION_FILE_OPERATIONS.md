# Requirement 7 validation

All fixtures are fictional. No real vault, deployment, cloud migration or real
file selection was used. The implementation includes current main (`fcba8d4`)
and the updated PR #6 dependency (`1cf1284`), including its recovery-feedback and
native credential/privacy follow-ups.

## Executed checks

- Configured frontend/backend-handler unit and UI tests: **213 tests / 15
  suites**, using Node **22.23.0**, all six fictional Firebase configuration
  values and `VITE_VAULT_BACKEND_READY=true`.
- Compiled backend policy tests: **10 passed**.
- Repository configuration/deployment-script tests: **6 passed**.
- Full `test:local` Auth, Functions, Firestore and Storage emulators:
  **35 passed**, including real production callable/rules paths and synthetic
  WebAuthn signature/recovery tests from the dependency.
- Frontend and backend TypeScript checks, production Vite build and
  `git diff --check`: passed.
- Chromium browser UI with fictional API fixtures: queue/progress and summary,
  confirmed rename, existing-note editing, move between collections, trash and
  restore, keyboard activation, byte-exact download of an unsupported preview
  format. Layout and reachable modal controls checked at **1280×600, 390×600,
  844×390**, with no horizontal overflow or page runtime errors.

The browser UI check uses fictional API fixtures; the emulator suite separately
executes real Firebase auth/authorization, encrypted upload/download and backend
transactions. Neither is evidence of physical-device platform behavior.

## Fault and regression coverage

| Scenario | Evidence |
| --- | --- |
| Multi-file partial success, targeted retry | UploadQueue tests; a failed buffer is retried or finalized without processing successful entries again |
| Mobile memory pressure from repeated failures | Single worker and at most one full encrypted retry buffer; eviction leaves a receipt-based finalization/reselection path |
| Cancel during encryption/upload/finalization | Deferred task fault tests, result-after-lock test, exact plaintext-array cleanup assertions |
| Finalization wins cancellation | Completed response is shown and the saved item published once |
| Upload success then metadata failure | Injected Firestore item write failure leaves a pending receipt plus object; retry commits exactly one item |
| Lost completion response | Client and emulator tests discard acknowledgement, then retry the same receipt; no duplicate transfer/item |
| Reload with incomplete transfer | Missing-object finalization requires reselection, while an uploaded object can finalize from its encrypted receipt |
| Offline/failed cleanup | Failed cancellation remains visible and cleanup is retryable |
| Late provider upload after cancel | Real Storage finalize trigger can clean the late object; explicit generation-precondition helper also tested; reads denied by rules |
| Permanent deletion: object failure | Metadata/marker retained and edits rejected |
| Permanent deletion: metadata failure after object deletion | Missing-object-safe retry preserves the record until the transaction succeeds |
| Private revision history | Completed journal payloads are redacted; active item ciphertext supplies idempotent retry reads |
| Wrong owner / expired or revoked private session | Real callable and Storage rejection; refreshed Firebase token does not restore access |
| Concurrent note/item writes | Two edits from one revision, exactly one successful finalization; direct Firestore CAS bypass denied |
| Collection races | Stale catalog revisions and an interleaved item-epoch write reject removal; UI fault tests retain the source after one failed move and verify successful deletion preserves destination items |
| Empty collections, aliases, rename | Encrypted catalog reload, stable IDs and legacy-name aliases tested without rewriting files |
| Interrupted key migration | Read-only legacy unlock remains possible, source writes blocked; empty definitions and operation-staged files migrate and read back; already completed cutover retries safely |
| Size/quota failures | Concurrent oversized begin requests rejected by backend; Storage size/type/receipt rules; injected provider quota failure cannot produce a completed item |
| Download integrity | Actual Web Crypto plaintext bytes match byte for byte after emulator transfer; corrupted/wrong-sized objects fail |
| Existing product behavior | Preview/PDF/gesture, session/locking, key/recovery/passkey and retained migration-safeguard regressions run in the combined suites |

Fault injection is a module dependency wrapper in the test process, not a
production request switch or authorization bypass. Existing legacy setup fixtures
now seed historical records with emulator Admin SDK because direct active
writes are intentionally denied by the new rules.

## Runtime details and limitations

Local emulator execution used Node 22.23.0 and extracted OpenJDK 21.0.12.
The managed host forbids Unix sockets. Only ignored installed Firebase Tools
files were temporarily changed to use loopback TCP for its worker transport,
and proxy environment variables were omitted for emulator-to-emulator requests.
No dependency patch, sandbox relaxation or auth/rules bypass is committed.
CI provisions standard Node 22 / Java 21 and runs the unmodified emulator tools.

Physical iOS/Android suspension, phone tab-switcher snapshots, large-file memory
on actual mobile hardware, assistive technology on devices, real platform/
roaming passkey prompts, production bucket-region compatibility and live provider
quota/retention behavior remain **unexecuted device/provider checks**. The
browser layout checks do not establish those outcomes. No backup/export product
is added; the dependency's encrypted key records and retained migration backups
remain intact and their regression tests pass.

See [FILE_OPERATIONS.md](FILE_OPERATIONS.md) for the guarantees and deliberate
limitations: whole-file AES-GCM, reselect after reload, eventual late-object
cleanup, manually retained trash, retained independent copies, unknown provider
remaining capacity, and no new aggregate quota.
