/** A narrow focus-only exception for UI opened by our own credential APIs.
 * Actual hidden/pagehide/freeze events and all lock/session deadlines still apply. */
import { createSecurityClock } from './lockPolicy'
export const CREDENTIAL_PROMPT_EVENT = 'haven-credential-prompt'
const MAX_PROMPT_MS = 75_000
const CLOSING_FOCUS_MS = 250
const prompts = new Set<{ expiresAt: number; close: () => void }>()
const now = createSecurityClock()
const notify = () => window.dispatchEvent(new Event(CREDENTIAL_PROMPT_EVENT))
export function credentialPromptActive() { return [...prompts].some(prompt => prompt.expiresAt > now()) }
export function clearCredentialPrompts() { [...prompts].forEach(prompt => prompt.close()) }

export async function runCredentialPrompt<T>(operation: () => Promise<T>): Promise<T> {
  let settled = false
  let closed = false
  let timer: ReturnType<typeof setTimeout>
  const close = () => {
    if (closed) return
    closed = true
    clearTimeout(timer)
    window.removeEventListener('focus', focus)
    prompts.delete(prompt)
    notify()
  }
  const focus = () => { if (settled) close() }
  const prompt = { expiresAt: now() + MAX_PROMPT_MS, close }
  prompts.add(prompt)
  window.addEventListener('focus', focus)
  timer = setTimeout(close, MAX_PROMPT_MS)
  notify()
  try { return await operation() }
  finally {
    settled = true
    // Some browsers settle credentials before returning document focus. Keep only
    // that closing focus transition scoped; the fixed maximum cannot be renewed.
    if (document.visibilityState !== 'visible' || document.hasFocus()) close()
    else if (!closed) {
      clearTimeout(timer)
      prompt.expiresAt = Math.min(prompt.expiresAt, now() + CLOSING_FOCUS_MS)
      timer = setTimeout(close, Math.max(0, prompt.expiresAt - now()))
    }
  }
}

export const PRIVACY_READY_EVENT = 'haven-privacy-ready'
/** A platform may actually hide the document during native UI. Do not publish
 * its continuation until the lifecycle hook has validated and removed the gate. */
export async function waitForPrivacyReturn(signal?: AbortSignal): Promise<void> {
  const ready = () => document.visibilityState === 'visible' && !document.documentElement?.dataset.havenConcealed
  if (signal?.aborted) throw new DOMException('The security workflow was cancelled.', 'AbortError')
  if (ready()) return
  await new Promise<void>((resolve, reject) => {
    const clear = () => {
      clearTimeout(timer)
      window.removeEventListener(PRIVACY_READY_EVENT, check)
      document.removeEventListener('visibilitychange', check)
      signal?.removeEventListener('abort', abort)
    }
    const abort = () => { clear(); reject(new DOMException('The security workflow was cancelled.', 'AbortError')) }
    const check = () => { if (ready()) { clear(); resolve() } }
    const timer = setTimeout(() => { clear(); reject(new Error('Return to Haven and retry this step. Your change was not confirmed.')) }, 75000)
    window.addEventListener(PRIVACY_READY_EVENT, check)
    document.addEventListener('visibilitychange', check)
    signal?.addEventListener('abort', abort, { once: true })
    check()
  })
}
