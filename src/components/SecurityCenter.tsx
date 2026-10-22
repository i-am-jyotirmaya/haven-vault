import SecurityFeedback, { securityErrorMessage, isSessionFailure, type SecurityNotice } from './SecurityFeedback'
import { useEffect, useRef, useState } from 'react'
import { decryptJson, encryptJson, type VaultConfig } from '../lib/crypto'
import { changePassphrase, prepareRecovery, prepareRecoveredRecord, unlockRecovery, unlockKeyRecord, hashJson, validatePassphrase, type KeyRecord, type RecoveryKit } from '../lib/keys'
import { getVaultConfig } from '../lib/vault'
import { securityCall, reauthenticate, addPasskey, type AccessList } from '../lib/security'
import { migrateVault } from '../lib/migration'
import { createPlaintextUrl, revokePlaintextUrl } from '../lib/plaintext'

export function RecoveryKitConfirmation({ kit, onConfirm, onCancel, busy }: { kit: RecoveryKit; onConfirm: () => void; onCancel: () => void; busy: boolean }) {
  const [proof, setProof] = useState('')
  const [downloaded, setDownloaded] = useState(false)
  const heading = useRef<HTMLHeadingElement>(null)
  useEffect(() => { heading.current?.focus({ preventScroll: true }); heading.current?.scrollIntoView?.({ block: 'nearest' }) }, [])
  return <section className="recovery-confirm">
    <h3 ref={heading} tabIndex={-1}>Save your recovery kit</h3>
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
  const [recoveryPassphrase, setRecoveryPassphrase] = useState('')
  const [pending, setPending] = useState<{ kit: RecoveryKit; purpose: 'recovery' | 'recover' } | null>(null)
  const [busy, setBusy] = useState(false)
  type Scope = 'passphrase' | 'recovery' | 'access' | 'migration'
  const [notices, setNotices] = useState<Partial<Record<Scope, SecurityNotice>>>({})
  const operationScope = useRef<Scope>('access')
  const running = useRef(false)
  const setMessage = (message: string, kind: SecurityNotice['kind'] = 'progress') => {
    const scope = operationScope.current
    setNotices(previous => ({ ...previous, [scope]: { message, kind } }))
  }
  const alive = useRef(true)
  const cancel = useRef(new AbortController())
  useEffect(() => { alive.current = true; cancel.current = new AbortController(); return () => { alive.current = false; cancel.current.abort() } }, [])
  const valid = () => { if (!alive.current) throw new Error('Security operation cancelled.'); check() }
  const run = async (work: () => Promise<void>, scope: Scope = 'access') => {
    if (running.current) return
    running.current = true; operationScope.current = scope
    setBusy(true); setMessage('Preparing this step…')
    try { valid(); await work() }
    catch (error) {
      if (alive.current) {
        setMessage(securityErrorMessage(error), 'error')
        if (isSessionFailure(error)) onFailure(error)
      }
    }
    finally { running.current = false; if (alive.current) setBusy(false) }
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
    setMessage('Passkeys and sessions are up to date.', 'success')
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

  }
  const commitKeys = async (purpose: 'passphrase' | 'recovery' | 'recover', record: KeyRecord, key: CryptoKey) => {
    setMessage('Saving your change…')
    try {
      await securityCall('replaceKeys', { purpose, record }); valid()
      setMessage('Checking the saved vault settings…')
      await verifyCommit(record, key)
    } catch (error) {
      const code = (error as { code?: string })?.code
      if (isSessionFailure(error) || ['functions/aborted', 'functions/failed-precondition', 'functions/invalid-argument'].includes(code || '')) throw error
      throw new Error(`The save could not be confirmed and may already have succeeded. Keep any downloaded replacement kit. Lock and unlock with the new passphrase, or use your saved kit, before retrying. ${securityErrorMessage(error)}`)
    }
  }
  const requireCurrent = (value: string) => {
    if (!value) throw new Error('Enter your current passphrase before continuing. Your passkey alone cannot unlock the master key.')
    validatePassphrase(value)
    return value
  }
  const newPass = () => { validatePassphrase(next); if (next !== confirm) throw new Error('The new passphrases must match.'); return next }
  return <section className="security-center">
    <h2>Keys, recovery and access</h2>
    <p>Passkeys may use a device PIN or sync through their provider. Fresh passkey verification is required for sensitive changes. Session revocation cannot erase plaintext already downloaded or held offline.</p>
    {config.version === 1 ? <>
      <h3>Upgrade this legacy vault</h3>
      <p>Migration pauses writes on every device. Originals and encrypted rollback safeguards remain intact. Keep this tab open; after an interruption, unlock with the original passphrase and resume here.</p>
      <label>Current passphrase<input type="password" autoComplete="current-password" value={current} onChange={e => setCurrent(e.target.value)} /></label>
      <button className="button primary" disabled={busy} onClick={() => void run(async () => {
        const secret = current; setCurrent('')
        await reauthenticate(cancel.current.signal); valid()
        const result = await migrateVault(secret, config, valid, text => { valid(); setMessage(text) }); valid()
        onChanged(result.config, result.key); setMessage('Migration verified. Original encrypted generation retained. Lock and unlock to reload the new generation.', 'success')
      }, 'migration')}>Migrate or resume safely</button>
      <SecurityFeedback notice={notices.migration} />
    </> : <>
      <p><strong>Recovery: {config.recovery ? 'Configured — keep your kit protected' : 'INCOMPLETE — no recovery kit is registered'}</strong></p>
      <p>Without a usable passphrase or recovery kit, your content cannot be recovered. Google verification alone cannot decrypt or replace access.</p>
      <form className="security-panel" noValidate aria-label="Change passphrase" onSubmit={event => { event.preventDefault(); void run(async () => {
        const secret = requireCurrent(current), replacement = newPass()
        setCurrent(''); setNext(''); setConfirm('')
        setMessage('Checking your current passphrase and preparing the new encryption wrapper…')
        const record = await latest()
        const changed = await changePassphrase(secret, replacement, record); valid()
        const key = await unlockKeyRecord(replacement, changed); valid()
        setMessage('Verify your passkey to authorize the passphrase change…')
        await reauthenticate(cancel.current.signal); valid()
        await commitKeys('passphrase', changed, key); valid()
        setMessage('Passphrase changed and verified. Use your new passphrase the next time you unlock. Other sessions were signed out; this device stays signed in until its original expiration.', 'success')
      }, 'passphrase') }}>
        <h3>Change passphrase</h3>
        <label>Current passphrase<input type="password" autoComplete="current-password" required maxLength={1024} disabled={busy} value={current} onChange={e => setCurrent(e.target.value)} /></label>
        <label>New passphrase<input type="password" autoComplete="new-password" required minLength={12} maxLength={1024} disabled={busy} value={next} onChange={e => setNext(e.target.value)} /></label>
        <label>Confirm new passphrase<input type="password" autoComplete="new-password" required disabled={busy} value={confirm} onChange={e => setConfirm(e.target.value)} /></label>
        <button className="button primary" type="submit" disabled={busy || !!pending}>Change passphrase</button>
        <SecurityFeedback notice={notices.passphrase} />
        <p>This rewraps the existing master key. It does not rotate the data key, invalidate stolen wrappers/backups, or remedy a compromised master key.</p>
      </form>
      <section className="security-panel" aria-label="Recovery kit settings">
        <h3>{config.recovery ? 'Replace recovery kit' : 'Set up a recovery kit'}</h3>
        <p>Enter your current passphrase here, then verify your passkey. Haven will prepare a kit on this device for you to download and confirm.</p>
        <form noValidate aria-label="Prepare recovery kit" onSubmit={event => { event.preventDefault(); void run(async () => {
          const secret = requireCurrent(recoveryPassphrase); setRecoveryPassphrase('')
          setMessage('Checking your current passphrase…')
          const record = await latest()
          await unlockKeyRecord(secret, record); valid()
          setMessage('Verify your passkey to prepare the recovery kit…')
          await reauthenticate(cancel.current.signal); valid()
          setMessage('Generating your recovery kit on this device…')
          const kit = await prepareRecovery(secret, record); valid(); setPending({ kit, purpose: 'recovery' })
          setMessage('Recovery kit ready. Download it and confirm the saved secret below. Recovery is not enabled until you confirm and save.', 'info')
        }, 'recovery') }}>
          <label>Current passphrase for recovery setup<input type="password" autoComplete="current-password" required maxLength={1024} disabled={busy || !!pending} value={recoveryPassphrase} onChange={e => setRecoveryPassphrase(e.target.value)} /></label>
          <button type="submit" className="button secondary" disabled={busy || !!pending}>{config.recovery ? 'Replace recovery kit' : 'Set up recovery kit'}</button>
        </form>
        <SecurityFeedback notice={notices.recovery} />
        <details><summary>Forgot your passphrase? Use your recovery kit</summary>
          <label>Recovery kit file contents<textarea autoComplete="off" value={kitText} onChange={e => setKitText(e.target.value)} /></label>
          <p>Enter a new passphrase and confirmation in the passphrase form above. Save and confirm a replacement kit before committing.</p>
          <button className="button secondary" disabled={busy || !!pending} onClick={() => void run(async () => {
            const oldKit = JSON.parse(kitText) as RecoveryKit, replacement = newPass(); setKitText(''); setNext(''); setConfirm('')
            setMessage('Verify your passkey to authorize recovery…')
            await reauthenticate(cancel.current.signal); valid()
            const kit = await prepareRecoveredRecord(oldKit, replacement, await latest()); valid(); setPending({ kit, purpose: 'recover' })
            setMessage('Recovery kit ready. Download and confirm the replacement before saving your new passphrase.', 'info')
          }, 'recovery')}>Recover and set a new passphrase</button>
        </details>
        {pending && <RecoveryKitConfirmation kit={pending.kit} busy={busy} onCancel={() => {
          setPending(null); setNotices(previous => ({ ...previous, recovery: { kind: 'info', message: 'Recovery setup cancelled. Your previous recovery settings are unchanged.' } }))
        }} onConfirm={() => void run(async () => {
          const saved = pending
          setMessage('Verify your passkey to save this recovery kit…')
          await reauthenticate(cancel.current.signal); valid()
          const key = await unlockRecovery(saved.kit, saved.kit.record); valid()
          await commitKeys(saved.purpose, saved.kit.record, key); valid(); setPending(null)
          setMessage('Recovery kit saved and verified. Keep the downloaded kit protected. Other sessions were signed out; this device keeps its original expiration.', 'success')
        }, 'recovery')} />}
      </section>
    </>}
    <h3>Passkeys and active sessions</h3>
    <SecurityFeedback notice={notices.access} />
    <button className="button secondary" disabled={busy} onClick={() => void run(reload)}>Refresh access list</button>
    <button className="button secondary" disabled={busy} onClick={() => void run(async () => { await addPasskey(valid, cancel.current.signal); valid(); await reload(); setMessage('Replacement passkey registered and verified.', 'success') })}>Add a passkey or hardware key</button>
    {access?.passkeys.map((credential, index) => <article className="access-row" key={credential.id}>
      <strong>{labels[credential.id] || `Passkey ${index + 1}`} {credential.current && '(current session)'}</strong>
      <span>Created {date(credential.createdAt)} · Last used {date(credential.lastUsedAt)}</span>
      {config.version === 2 && <><label>Private label<input value={labels[credential.id] || ''} maxLength={100} onChange={e => setLabels({ ...labels, [credential.id]: e.target.value })} /></label>
        <button disabled={busy} className="button secondary" onClick={() => void run(async () => {
          const name = labels[credential.id] || 'Passkey'; await reauthenticate(cancel.current.signal); valid()
          const label = await encryptJson(vaultKey, name, `passkey-label:${credential.id}`); valid()
          await securityCall('renamePasskey', { id: credential.id, label }); valid(); await reload()
        })}>Save label</button></>}
      <button className="button secondary" disabled={busy || access.passkeys.length <= 1} onClick={() => void run(async () => {
        await reauthenticate(cancel.current.signal); valid(); const result = await securityCall('removePasskey', { id: credential.id }); valid()
        if (result.currentRevoked) onEndSession(); else await reload()
      })}>Remove passkey</button>
    </article>)}
    {access?.sessions.map(session => <article className="access-row" key={session.id}>
      <strong>{session.device} {session.current && '(this session)'}</strong>
      <span>Created {date(session.createdAt)} · Last validation {date(session.lastActivityAt)} · Expires {date(session.expiresAt)}</span>
      <button className="button secondary" disabled={busy} onClick={() => void run(async () => {
        await reauthenticate(cancel.current.signal); valid(); const result = await securityCall('revokeSessions', { scope: 'one', id: session.id }); valid()
        if (result.currentRevoked) onEndSession(); else await reload()
      })}>Revoke session</button>
    </article>)}
    {(['others', 'all'] as const).map(scope => <button key={scope} className="button secondary" disabled={busy} onClick={() => void run(async () => {
      await reauthenticate(cancel.current.signal); valid(); const result = await securityCall('revokeSessions', { scope }); valid()
      if (result.currentRevoked) onEndSession(); else await reload()
    })}>Revoke {scope === 'all' ? 'all sessions' : 'other sessions'}</button>)}
  </section>
}
function date(value: number | null) { return value ? new Date(value).toLocaleString() : 'Not recorded' }
