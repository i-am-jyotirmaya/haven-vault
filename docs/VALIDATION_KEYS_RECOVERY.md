# Requirements 3–5 validation — 22 October 2026

Base: main d2b3855 (Requirements 1 and 2 merged). PR #5 is an unrelated open
preview-test isolation fix; the same Firebase boundary isolation is included here
for configured test collection. No runtime dependency on an unmerged branch.

Executed with isolated Node 22.23.4 and Java 21.0.7 runtimes:

| Check | Result |
| --- | --- |
| Frozen frontend dependency installation | Passed |
| Backend `npm ci` | Passed |
| Vitest with all six fictional Firebase values and backend-ready enabled | 163 tests passed, 11 suites |
| Script/config tests | 6 passed |
| Compiled backend policy tests | 9 passed |
| Full Auth/Functions/Firestore/Storage emulator suite | 22 passed |
| Frontend/backend TypeScript compilation | Passed |
| Vite production build | Passed |
| `git diff --check` | Passed |

Vitest covers real Web Crypto v2 master wrapping, wrong passphrases/secrets,
AEAD tampering/context substitution, unsupported versions, unchanged file bytes
across rewrapping, independent recovery signatures, wrapper rotation and legacy
format separation. Client migration fixtures cover exact metadata preservation,
interrupted file staging, sealed finalization resumption, lock cancellation,
tampered staging and receipt reuse after a rate-limit-style interruption.
Security UI tests cover possession confirmation, no raw kit secret in callable
arguments, stale update rejection, current-session revocation and late derivation
after unmount. Existing app/preview suites cover lock/sign-out, drafts, plaintext
URLs, concealment, configured deadlines, enrollment and preview regressions.
Additional tests cover recovery-request timing and a token arriving after sign-out,
and cleanup of recovery drafts opened before authentication.

The full-stack suite exercises real SimpleWebAuthn verification of signed P-256
synthetic authenticators, including roaming-style enrollment; it does not emulate
a person's OS biometric/PIN interaction. Real Web Crypto records exercise new
setup, passphrase revision CAS, recovery setup/replacement, lost-passphrase and
combined passkey/passphrase loss on a separate in-memory Firebase client. It tests
Google-only denial, wrong-owner denial, enrollment substitution, expired/replayed
recovery challenges, a lost final recovery response followed by new-passkey login,
credential limits, duplicate/final-passkey protections, stale recent-auth
records, ownership, credential-linked revocation and refreshed-token rejection.
Server migration authorization uses fictional ciphertext fixtures; actual local
re-encryption and byte comparisons are separately covered by client crypto tests.
The suite checks claims, immutable staging, manifest completion, interruption
across sealing/cutover, idempotent completion and retained originals/safeguards.

Local environment limitation: installed Firebase Tools uses Unix-domain sockets,
which this execution host disallows. For this test run only, installed ignored
node_modules was adapted to use loopback TCP, and HTTP proxy variables were
removed from the emulator subprocess environment. This is not a production rule
change or a committed dependency patch. CI runs the normal dependency installation
on Node 22/Java 21 and now executes the full `test:local` suite.

Unexecuted: real browser/OS passkey prompts, physical USB/NFC authenticators, mobile
suspension/BFCache, production Google verification and live deployment. Playwright
Chromium installation was attempted; downloads returned truncated zip archives.
No cloud deployment, live-vault migration or real owner/config reset was performed.

Independent review remains required for protocol composition, key lifetimes,
Firebase generation authorization, migration interleavings and operational
recovery/rollback. These are automated checks plus implementation review by its
author; they are not an independent security audit or a basis for recommending
irreplaceable primary storage.
