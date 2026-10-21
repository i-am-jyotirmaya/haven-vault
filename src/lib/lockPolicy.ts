export type LockPreferences = { backgroundSeconds: 0 | 30 | 60; inactivityMinutes: 1 | 5 | 15 }
export const DEFAULT_LOCK_PREFERENCES: LockPreferences = { backgroundSeconds: 30, inactivityMinutes: 5 }
export const LOCK_PREFERENCES_KEY = 'haven.security.v1'

export function parseLockPreferences(value: unknown): LockPreferences {
  const input = value && typeof value === 'object' ? value as Record<string, unknown> : {}
  return {
    backgroundSeconds: [0, 30, 60].includes(input.backgroundSeconds as number)
      ? input.backgroundSeconds as LockPreferences['backgroundSeconds'] : 30,
    inactivityMinutes: [1, 5, 15].includes(input.inactivityMinutes as number)
      ? input.inactivityMinutes as LockPreferences['inactivityMinutes'] : 5,
  }
}
export function readLockPreferences(): LockPreferences {
  try { return parseLockPreferences(JSON.parse(localStorage.getItem(LOCK_PREFERENCES_KEY) || 'null')) }
  catch { return { ...DEFAULT_LOCK_PREFERENCES } }
}
export function writeLockPreferences(value: LockPreferences): boolean {
  try { localStorage.setItem(LOCK_PREFERENCES_KEY, JSON.stringify(parseLockPreferences(value))); return true }
  catch { return false }
}

/** Wall time catches sleep; monotonic elapsed time prevents backward clock changes
 * from extending access. A forward jump may end access early (fail closed). */
export function createSecurityClock() {
  let wall = Date.now()
  let monotonic = performance.now()
  return () => {
    const next = performance.now()
    wall = Math.max(Date.now(), wall + Math.max(0, next - monotonic))
    monotonic = next
    return wall
  }
}

/** No keys, tokens or React state. Deadlines are derived from original activity
 * and background timestamps, never from a timer callback or repeated focus. */
export class LockPolicy {
  expiresAt = 0
  unlocked = false
  lastActivity = 0
  hiddenSince: number | null = null
  constructor(public preferences: LockPreferences, public now = createSecurityClock()) {}
  session(expiresAt: number, unlocked: boolean) {
    if (unlocked && !this.unlocked) this.lastActivity = this.now()
    this.unlocked = unlocked
    this.expiresAt = expiresAt
  }
  hide() { this.hiddenSince ??= this.now() }
  returned() { this.hiddenSince = null }
  activity() { if (this.unlocked && this.hiddenSince === null) this.lastActivity = this.now() }
  deadline() {
    return Math.min(this.expiresAt || Infinity,
      this.unlocked ? this.lastActivity + this.preferences.inactivityMinutes * 60_000 : Infinity,
      this.unlocked && this.hiddenSince !== null ? this.hiddenSince + this.preferences.backgroundSeconds * 1000 : Infinity)
  }
  evaluate(): 'expire' | 'lock' | null {
    const now = this.now()
    if (this.expiresAt && now >= this.expiresAt) return 'expire'
    if (this.unlocked && now >= this.deadline()) return 'lock'
    return null
  }
}
