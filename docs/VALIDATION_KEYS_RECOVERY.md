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

## Follow-up: recovery setup, feedback and privacy events

User testing found that recovery setup appeared to stop after a passkey prompt,
passphrase success feedback was hard to find, and the privacy screen reacted to
credential focus changes while missing ordinary visible-window backgrounding.
Confirmed causes were a shared passphrase field validated only after the prompt,
feedback located away from the action, unconditionally concealing on every focus,
no window-blur listener, and a missing `sensitive-surface` ID on the actual roots.

The follow-up gives recovery its own current-passphrase form and validates the
passphrase locally before asking for a passkey. Progress/error/verified-success
feedback is scoped to each action and brought into view. The downloaded kit must
still be confirmed, committed and read back before recovery is reported saved.

Both rendered roots are now synchronously hidden and inert behind the privacy
screen. Focus by itself does not start a conceal/validation cycle; window blur
starts the original configured background deadline. App-initiated credential UI
has a bounded focus-only exception (at most 75 seconds while open, then at most
250 ms for a closing focus transition). Actual hidden/pagehide/freeze events,
inactivity, absolute session expiry and manual lock/sign-out are never exempt.
On platforms that truly hide a page during native UI, sensitive continuations
wait for return validation and are cancelled if their component locks/unmounts.

New committed tests combine the real local key/recovery cryptography, actual
security workflow and privacy hook with mocked Firebase/native-UI boundaries.
They verify successful kit preparation/download/confirmation/commit, real
passphrase rewrapping, early wrong-passphrase rejection, blur/focus ordering,
true-hidden native prompts, validation before resumption and cancellation on
lock. Separate tests cover bounded prompt state and unchanged inactivity/session
expiry while a prompt is open.

A Chromium 153.0.8010.0 browser check also completed setup, kit download/confirmation
and passphrase change using real WebAuthn assertions from a CDP virtual resident
P-256 authenticator. Firebase calls used fictional browser fixtures and native
popup focus events were simulated. Actual CSS visibility and inert behavior,
privacy overlays and screenshots were checked at 1280×900 and 390×844. No page
errors occurred. This supersedes the earlier inability to install a browser:
a locally available serverless Chromium distribution was used for the follow-up.
Physical phone tab-switcher/app-switcher snapshots and real OS biometric UI remain
unexecuted device checks. Browsers do not expose every browser-chrome transition
and may retain an earlier thumbnail; this is not screenshot prevention.

Primary platform references consulted:
- https://html.spec.whatwg.org/multipage/interaction.html#page-visibility
- https://developer.chrome.com/docs/web-platform/page-lifecycle-api
- https://simplewebauthn.dev/docs/13.3.x/packages/browser

No backend cryptographic format, authorization rule, deployed infrastructure or
real-vault data was changed by this follow-up. Main's merged #5 test-isolation
changes are integrated, preserving the full emulator CI step.

Follow-up final checks: the configured Node 22 unit/UI suite passes, including
an interrupted recovery acknowledgement that must not later be described as an
unchanged cancellation. Recovery kit IDs are visible in Security so the saved
file can be compared after an unconfirmed save. Backend policy/configuration
checks, TypeScript and the production build pass. No deployment was performed.
