// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { LockPolicy, createSecurityClock, readLockPreferences, parseLockPreferences, writeLockPreferences, LOCK_PREFERENCES_KEY } from './lockPolicy'

beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(10_000); localStorage.clear() })
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks() })
const policy = () => {
  const model = new LockPolicy({ backgroundSeconds: 30, inactivityMinutes: 5 })
  model.session(Date.now() + 3_600_000, true)
  return model
}
describe('absolute lock policy', () => {
  it.each([0, 30, 60] as const)('enforces %s second background grace without repeated lifecycle renewal', seconds => {
    const model = policy(); model.preferences.backgroundSeconds = seconds
    model.hide(); const origin = model.hiddenSince
    if (seconds) {
      vi.advanceTimersByTime(seconds * 1000 - 1)
      model.hide(); expect(model.hiddenSince).toBe(origin)
      expect(model.evaluate()).toBeNull()
      vi.advanceTimersByTime(1)
    }
    expect(model.evaluate()).toBe('lock')
  })
  it.each([1, 5, 15] as const)('enforces %s minute inactivity', minutes => {
    const model = policy(); model.preferences.inactivityMinutes = minutes
    vi.advanceTimersByTime(minutes * 60_000 - 1); expect(model.evaluate()).toBeNull()
    vi.advanceTimersByTime(1); expect(model.evaluate()).toBe('lock')
  })
  it('visible user activity moves only inactivity; hidden activity and server work cannot renew access', () => {
    const model = policy(); const expiry = model.expiresAt
    vi.advanceTimersByTime(240_000); model.activity()
    expect(model.deadline()).toBe(550_000)
    model.hide(); const lastActivity = model.lastActivity
    vi.advanceTimersByTime(20_000); model.activity()
    expect(model.lastActivity).toBe(lastActivity)
    expect(model.expiresAt).toBe(expiry)
    model.returned(); vi.advanceTimersByTime(60_000); expect(model.evaluate()).toBeNull()
  })
  it('shortening settings uses existing timestamps, including while hidden', () => {
    const model = policy()
    model.preferences.backgroundSeconds = 60; model.hide()
    vi.advanceTimersByTime(40_000); model.preferences.backgroundSeconds = 30
    expect(model.evaluate()).toBe('lock')
    model.returned(); model.preferences.inactivityMinutes = 1
    vi.advanceTimersByTime(20_000); expect(model.evaluate()).toBe('lock')
  })
  it('applies authentication first, even while locked, and never extends on unlocking', () => {
    const model = policy(); const expiry = model.expiresAt
    model.session(expiry, false); vi.setSystemTime(expiry)
    expect(model.evaluate()).toBe('expire')
    model.session(expiry, true); expect(model.evaluate()).toBe('expire')
  })
  it('catches sleep without timers and backward clock changes cannot extend deadlines', () => {
    const model = policy(); model.hide()
    vi.setSystemTime(Date.now() + 60_000); expect(model.evaluate()).toBe('lock')
    const clock = createSecurityClock(); const initial = clock()
    vi.setSystemTime(1000); vi.advanceTimersByTime(50_000)
    expect(clock()).toBeGreaterThanOrEqual(initial + 50_000)
  })
  it('returning or restoring cannot resurrect an already cleared unlocked state', () => {
    const model = policy(); model.hide(); vi.advanceTimersByTime(30_000)
    expect(model.evaluate()).toBe('lock'); model.session(model.expiresAt, false)
    model.returned(); expect(model.unlocked).toBe(false)
  })
})
describe('device preferences', () => {
  it.each([null, [], 'garbage', { backgroundSeconds: '30', inactivityMinutes: 0 }, { backgroundSeconds: -1, inactivityMinutes: Infinity }])('rejects invalid values: %j', value => {
    expect(parseLockPreferences(value)).toEqual({ backgroundSeconds: 30, inactivityMinutes: 5 })
  })
  it('handles missing, corrupted, mixed-validity, and inaccessible storage', () => {
    expect(readLockPreferences()).toEqual({ backgroundSeconds: 30, inactivityMinutes: 5 })
    localStorage.setItem(LOCK_PREFERENCES_KEY, '{broken')
    expect(readLockPreferences()).toEqual({ backgroundSeconds: 30, inactivityMinutes: 5 })
    localStorage.setItem(LOCK_PREFERENCES_KEY, JSON.stringify({ backgroundSeconds: 0, inactivityMinutes: 4, key: 'discard' }))
    expect(readLockPreferences()).toEqual({ backgroundSeconds: 0, inactivityMinutes: 5 })
    writeLockPreferences({ backgroundSeconds: 60, inactivityMinutes: 15 })
    expect(JSON.parse(localStorage.getItem(LOCK_PREFERENCES_KEY)!)).toEqual({ backgroundSeconds: 60, inactivityMinutes: 15 })
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('blocked') })
    expect(readLockPreferences()).toEqual({ backgroundSeconds: 30, inactivityMinutes: 5 })
  })
})
