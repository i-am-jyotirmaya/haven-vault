import { flushSync } from 'react-dom'
import { useCallback, useLayoutEffect, useRef, useState } from 'react'
import { LockPolicy, readLockPreferences, writeLockPreferences, parseLockPreferences, type LockPreferences } from './lockPolicy'

export function useVaultPolicy(options: {
  expiresAt: number; unlocked: boolean; authenticated: boolean
  lock: (message?: string) => void; expire: (message?: string) => void
  conceal: (background: boolean) => void; validate: () => Promise<void>; failure: (error: unknown) => void
}) {
  const [preferences, setPreferences] = useState(readLockPreferences)
  const [warning, setWarning] = useState(false)
  const [storageFailed, setStorageFailed] = useState(false)
  const [concealed, setConcealed] = useState(document.visibilityState !== 'visible')
  const policy = useRef<LockPolicy>(null)
  policy.current ??= new LockPolicy(preferences)
  const callbacks = useRef(options)
  useLayoutEffect(() => { callbacks.current = options })
  const scheduler = useRef<() => void>(() => {})
  const evaluate = useCallback(() => {
    const result = policy.current!.evaluate()
    if (result === 'expire') { policy.current!.session(0, false); callbacks.current.expire('Your secure session ended. Sign in again.') }
    else if (result === 'lock') { policy.current!.unlocked = false; callbacks.current.lock('Your vault locked automatically. Enter your passphrase to unlock it.') }
    return result === null
  }, [])
  useLayoutEffect(() => {
    const model = policy.current!
    model.session(options.expiresAt, options.unlocked)
    evaluate()
    scheduler.current()
  }, [options.expiresAt, options.unlocked, evaluate])

  useLayoutEffect(() => {
    const model = policy.current!
    let timer: ReturnType<typeof setTimeout> | undefined
    let resumeGeneration = 0
    let disposed = false
    let checking = false
    const conceal = () => {
      // Synchronous CSS/inert gate includes top-layer dialogs, before React commits.
      document.documentElement.dataset.havenConcealed = 'true'
      document.getElementById('sensitive-surface')?.setAttribute('inert', '')
      setConcealed(true)
    }
    const reveal = () => {
      if (disposed || document.visibilityState !== 'visible') return
      delete document.documentElement.dataset.havenConcealed
      document.getElementById('sensitive-surface')?.removeAttribute('inert')
      setConcealed(false)
    }
    const schedule = () => {
      clearTimeout(timer)
      if (disposed) return
      const remaining = model.expiresAt - model.now()
      setWarning(remaining > 0 && remaining <= 60_000)
      const next = Math.min(model.deadline(), remaining > 60_000 ? model.expiresAt - 60_000 : Infinity)
      if (Number.isFinite(next)) timer = setTimeout(() => { evaluate(); schedule() }, Math.max(1, next - model.now()))
    }
    scheduler.current = schedule
    const hide = () => {
      ++resumeGeneration
      checking = false
      conceal()
      model.hide()
      callbacks.current.conceal(true)
      evaluate()
      schedule()
    }
    const resume = async () => {
      if (disposed || document.visibilityState !== 'visible' || checking) return
      conceal()
      let valid = true
      flushSync(() => { valid = evaluate() })
      if (!valid) { model.returned(); reveal(); schedule(); return }
      if (!callbacks.current.authenticated) { model.returned(); reveal(); return }
      callbacks.current.conceal(false)
      checking = true
      const generation = ++resumeGeneration
      try {
        await callbacks.current.validate()
      } catch (error) {
        if (disposed || generation !== resumeGeneration) return
        // Transient validation failure keeps plaintext locked for an explicit retry.
        flushSync(() => {
          if (model.unlocked) callbacks.current.lock()
          callbacks.current.failure(error)
        })
      } finally {
        if (!disposed && generation === resumeGeneration) {
          checking = false
          flushSync(() => { evaluate() }) // Commit cleanup before removing the privacy gate.
          model.returned()
          reveal()
          schedule()
        }
      }
    }
    const visibility = () => { if (document.visibilityState !== 'visible') hide(); else void resume() }
    const pagehide = () => hide()
    const focus = () => { void resume() }
    const pageshow = () => { void resume() }
    const activity = (event: Event) => {
      if (document.visibilityState !== 'visible' || document.documentElement.dataset.havenConcealed) return
      // Editing timeout controls must not give a shorter setting a fresh budget.
      const editingPolicy = event.target instanceof Element && !!event.target.closest('.security-settings')
      // Reject overdue access before allowing this interaction to move inactivity.
      if (evaluate() && event.isTrusted && !editingPolicy) model.activity()
    }
    let polling = false
    const poll = setInterval(async () => {
      if (disposed || polling || !callbacks.current.authenticated || document.visibilityState !== 'visible' || checking) return
      polling = true
      const generation = resumeGeneration
      try { await callbacks.current.validate() }
      catch (error) {
        if (!disposed && generation === resumeGeneration) {
          if (model.unlocked) callbacks.current.lock('Session validation failed. Unlock after reconnecting.')
          callbacks.current.failure(error)
        }
      } finally { polling = false; evaluate() }
    }, 30_000)
    const events = ['keydown', 'pointerdown', 'pointermove', 'touchstart', 'touchmove', 'wheel']
    events.forEach(event => window.addEventListener(event, activity, { passive: true, capture: true }))
    document.addEventListener('visibilitychange', visibility)
    document.addEventListener('freeze', hide)
    document.addEventListener('resume', focus)
    window.addEventListener('focus', focus)
    window.addEventListener('pagehide', pagehide)
    window.addEventListener('pageshow', pageshow)
    if (document.visibilityState !== 'visible') hide()
    else { reveal(); schedule() }
    return () => {
      disposed = true
      ++resumeGeneration
      clearTimeout(timer)
      clearInterval(poll)
      scheduler.current = () => {}
      events.forEach(event => window.removeEventListener(event, activity, true))
      document.removeEventListener('visibilitychange', visibility)
      document.removeEventListener('freeze', hide)
      document.removeEventListener('resume', focus)
      window.removeEventListener('focus', focus)
      window.removeEventListener('pagehide', pagehide)
      window.removeEventListener('pageshow', pageshow)
      delete document.documentElement.dataset.havenConcealed
      document.getElementById('sensitive-surface')?.removeAttribute('inert')
    }
  }, [evaluate])

  const updatePreferences = (value: LockPreferences) => {
    const next = parseLockPreferences(value)
    policy.current!.preferences = next
    setPreferences(next)
    setStorageFailed(!writeLockPreferences(next))
    evaluate()
    scheduler.current()
  }
  return { preferences, updatePreferences, warning, storageFailed, concealed, evaluate }
}
