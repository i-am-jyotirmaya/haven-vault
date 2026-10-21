import { DEFAULT_LOCK_PREFERENCES, type LockPreferences } from '../lib/lockPolicy'

export default function SecuritySettings({ preferences, onChange, lifetimeMinutes, storageFailed }: {
  preferences: LockPreferences; onChange: (next: LockPreferences) => void
  lifetimeMinutes: number | null; storageFailed: boolean
}) {
  return <details className="security-settings">
    <summary>Automatic locking settings</summary>
    <p>Content is always concealed immediately when Haven is backgrounded. Concealment covers filenames, thumbnails, notes, search, and dialogs. It cannot reliably prevent screenshots captured by your browser or operating system.</p>
    <p>During a nonzero background grace period, the encryption key and decrypted vault data remain in memory so you can return without another prompt. Locking clears the key and decrypted state. Choose Immediately to clear them as soon as you leave.</p>
    <label>Lock after backgrounding
      <select value={preferences.backgroundSeconds} onChange={event => onChange({ ...preferences, backgroundSeconds: Number(event.target.value) as LockPreferences['backgroundSeconds'] })}>
        <option value={0}>Immediately</option><option value={30}>30 seconds (default)</option><option value={60}>1 minute</option>
      </select>
    </label>
    <label>Lock after inactivity
      <select value={preferences.inactivityMinutes} onChange={event => onChange({ ...preferences, inactivityMinutes: Number(event.target.value) as LockPreferences['inactivityMinutes'] })}>
        <option value={1}>1 minute</option><option value={5}>5 minutes (default)</option><option value={15}>15 minutes</option>
      </select>
    </label>
    <p><strong>Authentication lifetime: {lifetimeMinutes ? `${lifetimeMinutes} minutes` : 'shown after sign-in'}</strong> · Administrator-controlled (15, 30, or 60 minutes; default 60). The client ends access slightly early for network latency. Activity, unlocking, and these device preferences never renew authentication.</p>
    <p>Only these two non-sensitive device preferences are saved locally. Missing or invalid values use 30 seconds and 5 minutes. Shorter settings apply to time already elapsed.</p>
    <button className="button secondary" type="button" onClick={() => onChange({ ...DEFAULT_LOCK_PREFERENCES })}>Restore defaults</button>
    {storageFailed && <p role="status">This browser could not save your preferences. They apply until you reload.</p>}
  </details>
}
