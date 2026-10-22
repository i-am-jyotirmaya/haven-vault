// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { clearCredentialPrompts, credentialPromptActive, runCredentialPrompt } from './credentialPrompt'
beforeEach(() => { vi.useFakeTimers(); vi.spyOn(document, 'hasFocus').mockReturnValue(true); Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' }) })
afterEach(() => { clearCredentialPrompts(); vi.useRealTimers(); vi.restoreAllMocks() })
it('scopes focus exceptions to a credential API call and cleans up success and cancellation', async () => {
  await runCredentialPrompt(async () => { expect(credentialPromptActive()).toBe(true); return 'fixture' })
  expect(credentialPromptActive()).toBe(false)
  await expect(runCredentialPrompt(async () => { throw new Error('cancelled') })).rejects.toThrow('cancelled')
  expect(credentialPromptActive()).toBe(false)
})
it('keeps only the closing focus transition when credentials settle before focus returns', async () => {
  vi.mocked(document.hasFocus).mockReturnValue(false)
  await runCredentialPrompt(async () => 'fixture')
  expect(credentialPromptActive()).toBe(true)
  vi.mocked(document.hasFocus).mockReturnValue(true)
  window.dispatchEvent(new Event('focus'))
  expect(credentialPromptActive()).toBe(false)
})
it('cannot renew or retain the focus exception indefinitely', async () => {
  let finish!: () => void
  const pending = runCredentialPrompt(() => new Promise<void>(resolve => { finish = resolve }))
  vi.advanceTimersByTime(75000)
  expect(credentialPromptActive()).toBe(false)
  finish(); await pending
  expect(credentialPromptActive()).toBe(false)
})
it('sign-out clears the exception even when a native prompt is unresolved', async () => {
  let finish!: () => void
  const pending = runCredentialPrompt(() => new Promise<void>(resolve => { finish = resolve }))
  clearCredentialPrompts(); expect(credentialPromptActive()).toBe(false)
  finish(); await pending; expect(credentialPromptActive()).toBe(false)
})

it('bounds a closing prompt to 250ms instead of extending a missing-focus exception', async () => {
  vi.mocked(document.hasFocus).mockReturnValue(false)
  await runCredentialPrompt(async () => 'fixture')
  expect(credentialPromptActive()).toBe(true)
  vi.advanceTimersByTime(250)
  expect(credentialPromptActive()).toBe(false)
})
