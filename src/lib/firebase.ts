import { initializeApp, getApps } from 'firebase/app'
import {
  GoogleAuthProvider,
  connectAuthEmulator,
  browserPopupRedirectResolver,
  initializeAuth,
  inMemoryPersistence,
  signInWithCustomToken,
  signInWithPopup,
  signOut,
} from 'firebase/auth'
import { connectFirestoreEmulator, getFirestore } from 'firebase/firestore'
import { connectFunctionsEmulator, getFunctions, httpsCallable } from 'firebase/functions'
import { connectStorageEmulator, getStorage } from 'firebase/storage'
import { startAuthentication, startRegistration } from '@simplewebauthn/browser'
import { createSecurityClock } from './lockPolicy'
import { localFirebaseConfig, emulatorPorts } from './local-config'

export const isEmulatorMode = import.meta.env.MODE === 'emulator'
if (isEmulatorMode && (!import.meta.env.DEV || window.location.hostname !== 'localhost')) {
  throw new Error('Emulator mode requires the local development server at localhost.')
}
const firebaseConfig = isEmulatorMode ? localFirebaseConfig : {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID,
  appId: import.meta.env.VITE_FIREBASE_APP_ID,
}

export const isFirebaseConfigured = Object.values(firebaseConfig).every(
  (value) => typeof value === 'string' && value.trim().length > 0,
)
// A readiness indicator only; access control always remains server-enforced.
export const isVaultBackendReady = isFirebaseConfigured && (isEmulatorMode || import.meta.env.VITE_VAULT_BACKEND_READY === 'true')

const app = isFirebaseConfigured
  ? (getApps()[0] ?? initializeApp(firebaseConfig))
  : null

// Initialize directly with memory persistence: no previous browser session is
// restored, and no Firebase refresh token is written to local storage.
const auth = app
  ? initializeAuth(app, {
      persistence: inMemoryPersistence,
      popupRedirectResolver: browserPopupRedirectResolver,
    })
  : null

// Firestore uses its default memory cache. Do not enable IndexedDB persistence.
export const db = app ? getFirestore(app) : null
export const storage = app ? getStorage(app) : null
const functions = app
  ? getFunctions(app, isEmulatorMode ? 'us-central1' : import.meta.env.VITE_FIREBASE_FUNCTIONS_REGION || 'us-central1')
  : null

// Connect every service before any authentication, callable, or data request.
// This mode uses a demo project even when .env.local contains production values.
if (isEmulatorMode && auth && db && storage && functions) {
  connectAuthEmulator(auth, `http://127.0.0.1:${emulatorPorts.auth}`)
  connectFirestoreEmulator(db, '127.0.0.1', emulatorPorts.firestore)
  connectStorageEmulator(storage, '127.0.0.1', emulatorPorts.storage)
  connectFunctionsEmulator(functions, '127.0.0.1', emulatorPorts.functions)
}

// Server timing is authoritative; this is only a conservative client margin.
const SESSION_SAFETY_MARGIN_MS = 15_000
let sessionNow = createSecurityClock()
let sessionDurationMinutes: number | null = null
export function getVaultSessionLifetimeMinutes() { return sessionDurationMinutes }
let activeVaultUid: string | null = null
let localSessionExpiresAt = 0
let authenticationPending = false
let authenticationGeneration = 0
let logoutPending: Promise<void> = Promise.resolve()

function checkAuthenticationGeneration(generation: number) {
  if (generation !== authenticationGeneration) {
    throw new Error('Sign-in was cancelled. Start again to open your vault.')
  }
}

type RegistrationOptions = Parameters<typeof startRegistration>[0]['optionsJSON']
type AuthenticationOptions = Parameters<typeof startAuthentication>[0]['optionsJSON']
type ChallengeResponse<T> = { options: T; challengeId: string }
type SessionTiming = { expiresAtMs: number; serverNowMs: number; sessionDurationMinutes: number }
type TokenResponse = SessionTiming & { token: string }
function validTiming(data: SessionTiming) {
  const remaining = data.expiresAtMs - data.serverNowMs
  return Number.isFinite(remaining) && remaining > 0 &&
    [15, 30, 60].includes(data.sessionDurationMinutes) && remaining <= data.sessionDurationMinutes * 60_000
}
type ConfirmRegistration = (
  createPasskey: () => ReturnType<typeof startRegistration>,
) => ReturnType<typeof startRegistration>

function requireFocusedDocument() {
  if (document.visibilityState !== 'visible' || !document.hasFocus()) {
    throw new Error('Return to the Haven tab and try again. Keep this page active while creating or using your passkey.')
  }
}

function requireServices() {
  if (!auth || !functions) {
    throw new Error('Connect your Firebase project before opening your private vault.')
  }
  return { auth, functions }
}

function clearLocalSession() {
  activeVaultUid = null
  localSessionExpiresAt = 0
  sessionDurationMinutes = null
}

export class VaultAuthenticationError extends Error {}

export function isAuthenticationFailure(error: unknown): boolean {
  if (error instanceof VaultAuthenticationError) return true
  const code = (error as { code?: string } | null)?.code
  return ['functions/unauthenticated', 'functions/permission-denied', 'permission-denied',
    'unauthenticated', 'storage/unauthorized', 'auth/user-token-expired',
    'auth/invalid-user-token', 'auth/user-disabled'].includes(code || '')
}

export function getVaultSessionDeadline(): number {
  getVaultUserId()
  return localSessionExpiresAt
}

/** Validate against the private server record, without issuing or refreshing a session. */
export async function validateVaultSession(): Promise<void> {
  const uid = getVaultUserId()
  const generation = authenticationGeneration
  const startedAt = sessionNow()
  const { functions } = requireServices()
  const check = httpsCallable<Record<string, never>, SessionTiming>(
    functions, 'validateVaultSession', { timeout: 4000 },
  )
  let data: SessionTiming
  try {
    ;({ data } = await check({}))
  } catch (error) {
    if (generation === authenticationGeneration && isAuthenticationFailure(error)) clearLocalSession()
    throw error
  }
  checkAuthenticationGeneration(generation)
  if (getVaultUserId() !== uid) throw new VaultAuthenticationError('Your vault session has ended.')
  if (!validTiming(data) || data.sessionDurationMinutes !== sessionDurationMinutes) {
    throw new Error('The server could not confirm your session. Please try again.')
  }
  // Request start is conservative about latency. Never move the deadline later,
  // even if this check is repeated or the server clock differs from this device.
  localSessionExpiresAt = Math.min(localSessionExpiresAt,
    startedAt + data.expiresAtMs - data.serverNowMs - SESSION_SAFETY_MARGIN_MS)
  getVaultUserId()
}

async function acceptVaultToken(response: TokenResponse, verificationStartedAt: number) {
  const { token, expiresAtMs, serverNowMs } = response
  const services = requireServices()
  if (typeof token !== 'string' || token.length === 0 || !validTiming(response)) {
    throw new Error('The server did not return a valid vault session.')
  }
  const credential = await signInWithCustomToken(services.auth, token)
  const { claims } = await credential.user.getIdTokenResult()
  if (
    claims.vaultAccess !== true ||
    typeof claims.vaultSession !== 'string' ||
    !/^[A-Za-z0-9_-]{43}$/.test(claims.vaultSession)
  ) {
    throw new Error('The server did not authorize this vault session.')
  }
  activeVaultUid = credential.user.uid
  // Rules and callable functions independently enforce the server session
  // deadline; this deadline only makes the client fail closed sooner.
  sessionDurationMinutes = response.sessionDurationMinutes
  localSessionExpiresAt = verificationStartedAt + expiresAtMs - serverNowMs - SESSION_SAFETY_MARGIN_MS
  getVaultUserId()
}

/** First-time setup requires the owner's verified Google identity. */
export async function enrollPasskey(confirmRegistration: ConfirmRegistration): Promise<void> {
  const services = requireServices()
  if (authenticationPending) throw new Error('A passkey request is still finishing. Please try again in a moment.')
  authenticationPending = true
  sessionNow = createSecurityClock()
  const generation = ++authenticationGeneration
  clearLocalSession()
  try {
    await logoutPending
    checkAuthenticationGeneration(generation)
    const provider = new GoogleAuthProvider()
    provider.setCustomParameters({ prompt: 'select_account' })
    await signInWithPopup(services.auth, provider)
    checkAuthenticationGeneration(generation)
    const optionsCall = httpsCallable<Record<string, never>, ChallengeResponse<RegistrationOptions>>(
      services.functions,
      'registrationOptions',
    )
    const { data } = await optionsCall({})
    checkAuthenticationGeneration(generation)
    // The Google popup may resolve before this document regains focus. The UI
    // calls this prepared operation directly from a fresh click in the vault.
    const response = await confirmRegistration(() => {
      checkAuthenticationGeneration(generation)
      requireFocusedDocument()
      return startRegistration({ optionsJSON: data.options })
    })
    checkAuthenticationGeneration(generation)
    const verifyCall = httpsCallable<
      { challengeId: string; response: typeof response },
      TokenResponse
    >(services.functions, 'verifyRegistration')
    const verificationStartedAt = sessionNow()
    const result = await verifyCall({ challengeId: data.challengeId, response })
    checkAuthenticationGeneration(generation)
    await acceptVaultToken(result.data, verificationStartedAt)
    checkAuthenticationGeneration(generation)
  } catch (error) {
    clearLocalSession()
    await signOut(services.auth).catch(() => undefined)
    throw error
  } finally {
    authenticationPending = false
  }
}

/** Must be initiated from a user gesture for platform passkey prompts. */
export async function signInWithPasskey(): Promise<void> {
  const services = requireServices()
  if (authenticationPending) throw new Error('A passkey request is still finishing. Please try again in a moment.')
  authenticationPending = true
  sessionNow = createSecurityClock()
  const generation = ++authenticationGeneration
  clearLocalSession()
  try {
    await logoutPending
    checkAuthenticationGeneration(generation)
    const optionsCall = httpsCallable<Record<string, never>, ChallengeResponse<AuthenticationOptions>>(
      services.functions,
      'authenticationOptions',
    )
    const { data } = await optionsCall({})
    checkAuthenticationGeneration(generation)
    requireFocusedDocument()
    const response = await startAuthentication({ optionsJSON: data.options })
    checkAuthenticationGeneration(generation)
    const verifyCall = httpsCallable<
      { challengeId: string; response: typeof response },
      TokenResponse
    >(services.functions, 'verifyAuthentication')
    const verificationStartedAt = sessionNow()
    const result = await verifyCall({ challengeId: data.challengeId, response })
    checkAuthenticationGeneration(generation)
    await acceptVaultToken(result.data, verificationStartedAt)
    checkAuthenticationGeneration(generation)
  } catch (error) {
    clearLocalSession()
    await signOut(services.auth).catch(() => undefined)
    throw error
  } finally {
    authenticationPending = false
  }
}

export async function signOutVault(): Promise<{ revoked: boolean }> {
  authenticationGeneration++
  clearLocalSession()
  if (!auth) return { revoked: true }
  let revoked = true
  const activeAuth = auth
  const previousLogout = logoutPending
  logoutPending = (async () => {
    await previousLogout
    try {
      if (activeAuth.currentUser && functions) {
        const endSession = httpsCallable<Record<string, never>, unknown>(functions, 'endVaultSession', { timeout: 4000 })
        await endSession({}).catch(() => { revoked = false })
      }
    } finally {
      // A bounded revocation request must not indefinitely retain local tokens.
      await signOut(activeAuth)
    }
  })().catch(() => undefined)
  await logoutPending
  return { revoked }
}

export function getVaultUserId(): string {
  if (
    !auth?.currentUser ||
    !activeVaultUid ||
    auth.currentUser.uid !== activeVaultUid ||
    sessionNow() >= localSessionExpiresAt
  ) {
    clearLocalSession()
    throw new VaultAuthenticationError('Your vault session has ended. Verify your identity again.')
  }
  return activeVaultUid
}

/** Callables share in-memory Firebase auth; no encryption secrets are arguments. */
export async function callVault<T>(name: string, data: Record<string, unknown>): Promise<T> {
  const services = requireServices()
  const generation = authenticationGeneration
  const result = await httpsCallable<Record<string, unknown>, T>(services.functions, name, { timeout: 120000 })(data)
  checkAuthenticationGeneration(generation)
  return result.data
}
export async function verifyRecoveryOwner() {
  const services = requireServices()
  const generation = authenticationGeneration
  const provider = new GoogleAuthProvider()
  provider.setCustomParameters({ prompt: 'select_account' })
  await signInWithPopup(services.auth, provider)
  checkAuthenticationGeneration(generation)
}
export function beginRecoverySessionClock() { sessionNow = createSecurityClock(); return sessionNow() }
export async function acceptRecoveredSession(result: TokenResponse, verificationStartedAt: number) {
  const generation = authenticationGeneration
  await acceptVaultToken(result, verificationStartedAt)
  if (generation !== authenticationGeneration) {
    clearLocalSession()
    await signOut(requireServices().auth)
    throw new Error('Recovery was cancelled. Sign in with the replacement passkey.')
  }
}
