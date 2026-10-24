import { useEffect, useRef } from 'react'
export type SecurityNotice = { kind: 'progress' | 'success' | 'error' | 'info'; message: string }
export default function SecurityFeedback({ notice }: { notice?: SecurityNotice }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (notice && notice.kind !== 'progress') {
      ref.current?.focus({ preventScroll: true })
      ref.current?.scrollIntoView?.({ block: 'nearest' })
    }
  }, [notice])
  if (!notice) return null
  return <div ref={ref} tabIndex={-1} className={`security-feedback ${notice.kind}`}
    role={notice.kind === 'error' ? 'alert' : 'status'} aria-live={notice.kind === 'error' ? 'assertive' : 'polite'}>
    <strong>{{ progress: 'Working…', success: 'Saved', info: 'Next step', error: 'Action needed' }[notice.kind]}</strong>
    <p>{notice.message}</p>
  </div>
}
export function securityErrorMessage(error: unknown) {
  const value = error as { name?: string; message?: string; code?: string }
  if (value?.name === 'OperationError') return 'The current passphrase is incorrect, or the encrypted key record is damaged. Re-enter the current passphrase and try again.'
  if (value?.name === 'NotAllowedError' || value?.name === 'AbortError' || value?.code === 'ERROR_CEREMONY_ABORTED') return 'Passkey verification was cancelled or timed out. No change was confirmed. Try again when you are ready.'
  return value?.message || 'The operation could not be completed. Please try again.'
}
export function isSessionFailure(error: unknown) {
  const code = (error as { code?: string })?.code
  return ['functions/unauthenticated', 'functions/permission-denied', 'permission-denied', 'storage/unauthorized'].includes(code || '')
}
