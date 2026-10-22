import { useEffect, useRef, useState } from 'react'
import { decryptJson, encryptJson, type VaultConfig } from '../lib/crypto'
import { changePassphrase, prepareRecovery, prepareRecoveredRecord, unlockRecovery, unlockKeyRecord, hashJson, type KeyRecord, type RecoveryKit } from '../lib/keys'
import { getVaultConfig } from '../lib/vault'
import { securityCall, reauthenticate, addPasskey, type AccessList } from '../lib/security'
import { migrateVault } from '../lib/migration'
import { createPlaintextUrl, revokePlaintextUrl } from '../lib/plaintext'

export function RecoveryKitConfirmation({ kit, onConfirm, onCancel, busy }: { kit: RecoveryKit; onConfirm: () => void; onCancel: () => void; busy: boolean }) {
  const [proof, setProof] = useState('')
  const [downloaded, setDownloaded] = useState(false)
  return <section className="recovery-confirm">
    <h3>Save your replacement recovery kit</h3>
    <p>This kit can decrypt your vault and replace access with owner Google verification. Protect it offline. Previous kits stop authorizing server recovery after this change, but copies of old kits and backups cannot be retracted.</p>
    <button type="button" className="button secondary" onClick={() => {
      const url = createPlaintextUrl(new Blob([JSON.stringify(kit, null, 2)], { type: 'text/plain' }))
      const a = document.createElement('a'); a.href = url; a.download = `haven-recovery-${kit.recoveryId}.txt`; a.click()
      setTimeout(() => revokePlaintextUrl(url), 1000); setDownloaded(true)
    }}>Download recovery kit</button>
    <p>Print the downloaded text file if you want a paper copy. Open your saved kit and enter its <code>secret</code> below to confirm possession.</p>
    <label>Saved recovery secret<input type="password" autoComplete="off" value={proof} onChange={e => setProof(e.target.value)} /></label>
    <button type="button" className="button primary" disabled={busy || !downloaded || proof !== kit.secret} onClick={onConfirm}>Confirm saved kit and commit</button>
    <button type="button" className="button secondary" disabled={busy} onClick={onCancel}>Cancel</button>
  </section>
}
export default function SecurityCenter({ config, vaultKey, check, onChanged, onEndSession, onFailure }: {
  config: VaultConfig; vaultKey: CryptoKey; check: () => void
  onChanged: (record: KeyRecord, key: CryptoKey) => void; onEndSession: () => void; onFailure: (error: unknown) => void
}) {
  const [access, setAccess] = useState<AccessList | null>(null)
  const [labels, setLabels] = useState<Record<string, string>>({})
  const [current, setCurrent] = useState(''), [next, setNext] = useState(''), [confirm, setConfirm] = useState('')
  const [kitText, setKitText] = useState('')
  const [pending, setPending] = useState<{ kit: RecoveryKit; purpose: 'recovery' | 'recover' } | null>(null)
  const [busy, setBusy] = useState(false), [message, setMessage] = useState('')
  const alive = useRef(true)
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  const valid = () => { if (!alive.current) throw new Error('Security operation cancelled.'); check() }
  const run = async (work: () => Promise<void>) => {
    if (busy) return
    setBusy(true); setMessage('')
    try { valid(); await work() }
    catch (error) { if (alive.current) { setMessage(error instanceof Error ? error.message : 'Security operation failed.'); onFailure(error) } }
    finally { if (alive.current) setBusy(false) }
  }
  const reload = async () => {
    const value = await securityCall<AccessList>('list'); valid()
    const names: Record<string, string> = {}
    for (const credential of value.passkeys) {
      if (credential.label) {
        try { names[credential.id] = await decryptJson<string>(vaultKey, credential.label, `passkey-label:${credential.id}`) }
        catch { names[credential.id] = 'Label unavailable with this generation' }
      }
    }
    valid(); setAccess(value); setLabels(names)
  }
  const latest = async () => {
    const record = await getVaultConfig(); valid()
    if (record?.version !== 2 || config.version !== 2 || record.revision !== config.revision) throw new Error('Vault keys changed. Lock and unlock the latest vault before retrying.')
    return record
  }
  const verifyCommit = async (expected: KeyRecord, key: CryptoKey) => {
    const result = await getVaultConfig(); valid()
    if (await hashJson(result) !== await hashJson(expected)) throw new Error('The committed key record could not be confirmed. Lock and unlock using the latest record before retrying.')
    valid(); onChanged(expected, key)
    setMessage('Change verified. Other sessions have been revoked; this session retains its original expiration.')
  }
  const newPass = () => { if (next !== confirm) throw new Error('The new passphrases must match.'); return next }
  return <section className="security-center">
    <h2>Keys, recovery and access</h2>
    <p>Passkeys may use a device PIN or sync through their provider. Fresh passkey verification is required for sensitive changes. Session revocation cannot erase plaintext already downloaded or held offline.</p>
    <p role="status">{message}</p>
    {config.version === 1 ? <>
      <h3>Upgrade this legacy vault</h3>
      <p>Migration pauses writes on every device. Originals and encrypted rollback safeguards remain intact. Keep this tab open; after an interruption, unlock with the original passphrase and resume here.</p>
      <label>Current passphrase<input type="password" autoComplete="current-password" value={current} onChange={e => setCurrent(e.target.value)} /></label>
      <button className="button primary" disabled={busy} onClick={() => void run(async () => {
        const secret = current; setCurrent('')
        await reauthenticate(); valid()
        const result = await migrateVault(secret, config, valid, text => { valid(); setMessage(text) }); valid()
        onChanged(result.config, result.key); setMessage('Migration verified. Original encrypted generation retained. Lock and unlock to reload the new generation.')
      })}>Migrate or resume safely</button>
    </> : <>
      <p><strong>Recovery: {config.recovery ? 'Configured — keep your kit protected' : 'INCOMPLETE — no recovery kit is registered'}</strong></p>
      <p>Without a usable passphrase or recovery kit, your content cannot be recovered. Google verification alone cannot decrypt or replace access.</p>
      <label>Current passphrase<input type="password" autoComplete="current-password" value={current} onChange={e => setCurrent(e.target.value)} /></label>
      <label>New passphrase<input type="password" autoComplete="new-password" minLength={12} maxLength={1024} value={next} onChange={e => setNext(e.target.value)} /></label>
      <label>Confirm new passphrase<input type="password" autoComplete="new-password" value={confirm} onChange={e => setConfirm(e.target.value)} /></label>
      <button className="button primary" disabled={busy || !!pending} onClick={() => void run(async () => {
        const secret = current, replacement = newPass(); setCurrent(''); setNext(''); setConfirm('')
        await reauthenticate(); valid(); const record = await latest()
        const changed = await changePassphrase(secret, replacement, record); valid()
        await securityCall('replaceKeys', { purpose: 'passphrase', record: changed }); valid()
        const key = await unlockKeyRecord(replacement, changed); valid(); await verifyCommit(changed, key)
      })}>Change passphrase</button>
      <p>Changing a passphrase rewraps the existing master key. It does not rotate the data key, invalidate stolen wrappers/backups, or remedy a compromised master key.</p>
      <button className="button secondary" disabled={busy || !!pending} onClick={() => void run(async () => {
        const secret = current; setCurrent(''); await reauthenticate(); valid()
        const kit = await prepareRecovery(secret, await latest()); valid(); setPending({ kit, purpose: 'recovery' })
      })}>{config.recovery ? 'Replace recovery kit' : 'Set up recovery kit'}</button>
      <details><summary>Forgot your passphrase? Use your recovery kit</summary>
        <label>Recovery kit file contents<textarea autoComplete="off" value={kitText} onChange={e => setKitText(e.target.value)} /></label>
        <p>Enter a new passphrase and confirmation above. A replacement kit must be saved before committing.</p>
        <button className="button secondary" disabled={busy || !!pending} onClick={() => void run(async () => {
          const oldKit = JSON.parse(kitText) as RecoveryKit, replacement = newPass(); setKitText(''); setNext(''); setConfirm('')
          await reauthenticate(); valid()
          const kit = await prepareRecoveredRecord(oldKit, replacement, await latest()); valid(); setPending({ kit, purpose: 'recover' })
        })}>Recover and set a new passphrase</button>
      </details>
      {pending && <RecoveryKitConfirmation kit={pending.kit} busy={busy} onCancel={() => setPending(null)} onConfirm={() => void run(async () => {
        const saved = pending; await reauthenticate(); valid()
        const key = await unlockRecovery(saved.kit, saved.kit.record); valid()
        await securityCall('replaceKeys', { purpose: saved.purpose, record: saved.kit.record }); valid()
        await verifyCommit(saved.kit.record, key); valid(); setPending(null)
      })} />}
    </>}
    <h3>Passkeys and active sessions</h3>
    <button className="button secondary" disabled={busy} onClick={() => void run(reload)}>Refresh access list</button>
    <button className="button secondary" disabled={busy} onClick={() => void run(async () => { await addPasskey(valid); valid(); await reload(); setMessage('Replacement passkey registered and verified.') })}>Add a passkey or hardware key</button>
    {access?.passkeys.map((credential, index) => <article className="access-row" key={credential.id}>
      <strong>{labels[credential.id] || `Passkey ${index + 1}`} {credential.current && '(current session)'}</strong>
      <span>Created {date(credential.createdAt)} · Last used {date(credential.lastUsedAt)}</span>
      {config.version === 2 && <><label>Private label<input value={labels[credential.id] || ''} maxLength={100} onChange={e => setLabels({ ...labels, [credential.id]: e.target.value })} /></label>
        <button disabled={busy} className="button secondary" onClick={() => void run(async () => {
          const name = labels[credential.id] || 'Passkey'; await reauthenticate(); valid()
          const label = await encryptJson(vaultKey, name, `passkey-label:${credential.id}`); valid()
          await securityCall('renamePasskey', { id: credential.id, label }); valid(); await reload()
        })}>Save label</button></>}
      <button className="button secondary" disabled={busy || access.passkeys.length <= 1} onClick={() => void run(async () => {
        await reauthenticate(); valid(); const result = await securityCall('removePasskey', { id: credential.id }); valid()
        if (result.currentRevoked) onEndSession(); else await reload()
      })}>Remove passkey</button>
    </article>)}
    {access?.sessions.map(session => <article className="access-row" key={session.id}>
      <strong>{session.device} {session.current && '(this session)'}</strong>
      <span>Created {date(session.createdAt)} · Last validation {date(session.lastActivityAt)} · Expires {date(session.expiresAt)}</span>
      <button className="button secondary" disabled={busy} onClick={() => void run(async () => {
        await reauthenticate(); valid(); const result = await securityCall('revokeSessions', { scope: 'one', id: session.id }); valid()
        if (result.currentRevoked) onEndSession(); else await reload()
      })}>Revoke session</button>
    </article>)}
    {(['others', 'all'] as const).map(scope => <button key={scope} className="button secondary" disabled={busy} onClick={() => void run(async () => {
      await reauthenticate(); valid(); const result = await securityCall('revokeSessions', { scope }); valid()
      if (result.currentRevoked) onEndSession(); else await reload()
    })}>Revoke {scope === 'all' ? 'all sessions' : 'other sessions'}</button>)}
  </section>
}
function date(value: number | null) { return value ? new Date(value).toLocaleString() : 'Not recorded' }
