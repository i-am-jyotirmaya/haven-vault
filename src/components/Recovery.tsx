import { useEffect, useRef, useState } from 'react'
import { beginRecovery, finishRecovery, reauthenticate, securityCall } from '../lib/security'
import { getVaultConfig } from '../lib/vault'
import { prepareRecoveredRecord, unlockRecovery, hashJson, type RecoveryKit } from '../lib/keys'
import { RecoveryKitConfirmation } from './SecurityCenter'

export default function Recovery({ authenticated, check, onActive, onComplete, onFailure }: { authenticated: boolean; check: () => void; onActive: (active: boolean) => void; onComplete: () => void; onFailure: (error: unknown) => void }) {
  const [kitText, setKitText] = useState(''), [passphrase, setPassphrase] = useState(''), [confirm, setConfirm] = useState('')
  const [pending, setPending] = useState<{ old: RecoveryKit; next: RecoveryKit; ceremony: Awaited<ReturnType<typeof beginRecovery>> | null } | null>(null)
  const [busy, setBusy] = useState(false), [message, setMessage] = useState('')
  const alive = useRef(true)
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  const valid = () => { if (!alive.current) throw new Error('Recovery cancelled.'); check() }
  const run = async (work: () => Promise<void>) => {
    if (busy) return; setBusy(true); setMessage('')
    try { valid(); await work() } catch (error) { if (alive.current) { setMessage(error instanceof Error ? error.message : 'Recovery failed.'); onFailure(error) } }
    finally { if (alive.current) setBusy(false) }
  }
  return <details className="security-center" onToggle={event => { if (event.currentTarget.open) onActive(true) }}><summary>Recover vault access or a forgotten passphrase</summary>
    <p>A recovery kit decrypts locally. If all passkeys are lost, fresh verification of the registered owner Google account is also required to enroll a replacement. Google alone cannot recover your vault. Without any usable unlock method or recovery material, recovery is impossible.</p>
    <p>Protect your kit: it grants powerful decryption and account recovery capability. Recovery replaces the kit and revokes other sessions. Lost-passkey recovery also retires every old passkey.</p>
    <label>Recovery kit file contents<textarea autoComplete="off" value={kitText} onChange={e => setKitText(e.target.value)} /></label>
    <label>New recovery passphrase<input type="password" autoComplete="new-password" value={passphrase} maxLength={1024} onChange={e => setPassphrase(e.target.value)} /></label>
    <label>Confirm recovery passphrase<input type="password" autoComplete="new-password" value={confirm} onChange={e => setConfirm(e.target.value)} /></label>
    <button className="button secondary" disabled={busy || !!pending} onClick={() => void run(async () => {
      if (passphrase !== confirm) throw new Error('The passphrases must match.')
      const old = JSON.parse(kitText) as RecoveryKit, nextPassphrase = passphrase
      setKitText(''); setPassphrase(''); setConfirm('')
      if (authenticated) await reauthenticate()
      const ceremony = authenticated ? null : await beginRecovery(); valid()
      const record = ceremony?.record || await getVaultConfig(); valid()
      if (record?.version !== 2) throw new Error('This vault has no compatible recovery method.')
      const next = await prepareRecoveredRecord(old, nextPassphrase, record); valid()
      setPending({ old, next, ceremony })
    })}>{authenticated ? 'Recover with kit and existing passkey' : 'Verify owner and prepare recovery'}</button>
    {pending && <RecoveryKitConfirmation kit={pending.next} busy={busy} onCancel={() => setPending(null)} onConfirm={() => void run(async () => {
      const saved = pending
      if (saved.ceremony) await finishRecovery(saved.ceremony, saved.old, saved.next, valid)
      else { await reauthenticate(); valid(); await securityCall('replaceKeys', { purpose: 'recover', record: saved.next.record }) }
      valid()
      const result = await getVaultConfig(); valid()
      if (await hashJson(result) !== await hashJson(saved.next.record)) throw new Error('Recovery may have committed. Sign in with the replacement passkey and use the new passphrase or saved replacement kit.')
      await unlockRecovery(saved.next, saved.next.record); valid()
      setPending(null); setMessage('Recovery verified. Unlock with your new passphrase.'); onComplete()
    })} />}
    <p role="status">{message}</p>
  </details>
}
