/** Shared pure validation for security mutations; all authorization remains server-side. */
export const RECENT_MS = 5 * 60_000;
export const MAX_PASSKEYS = 5;
export function freshPasskey(session: { authenticatedAt?: { toMillis(): number } }, now = Date.now()) {
  const at = session.authenticatedAt?.toMillis();
  return typeof at === 'number' && at <= now && now - at <= RECENT_MS;
}
export function validBox(b: any) {
  return b && Object.keys(b).sort().join(',') === 'ciphertext,iv,version' && b.version === 2 && /^[A-Za-z0-9+/]{16}$/.test(b.iv) && typeof b.ciphertext === 'string' && b.ciphertext.length >= 24 && b.ciphertext.length <= 8192 && /^[A-Za-z0-9+/]+={0,2}$/.test(b.ciphertext);
}
export function validKeyRecord(r: any): boolean {
  const uuid = (s: unknown) => typeof s === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(s);
  return !!r && Object.keys(r).sort().join(',') === 'generation,passphrase,recovery,revision,vaultId,version' && r.version === 2 && uuid(r.vaultId) && uuid(r.generation) && Number.isSafeInteger(r.revision) && r.revision > 0 &&
    r.passphrase && Object.keys(r.passphrase).sort().join(',') === 'box,iterations,kdf,salt,version' && r.passphrase.version === 2 && r.passphrase.kdf === 'PBKDF2-SHA256' && /^[A-Za-z0-9+/]{43}=$/.test(r.passphrase.salt) && Number.isInteger(r.passphrase.iterations) && r.passphrase.iterations >= 600000 && r.passphrase.iterations <= 2000000 && validBox(r.passphrase.box) &&
    (r.recovery === null || (Object.keys(r.recovery).sort().join(',') === 'id,master,privateKey,publicKey,version' && r.recovery.version === 2 && uuid(r.recovery.id) && validBox(r.recovery.master) && validBox(r.recovery.privateKey) && typeof r.recovery.publicKey === 'string' && r.recovery.publicKey.length <= 512 && /^[A-Za-z0-9+/]+={0,2}$/.test(r.recovery.publicKey)));
}
export function keyTransition(current: any, next: any, purpose: 'passphrase' | 'recovery' | 'recover'): boolean {
  if (!validKeyRecord(current) || !validKeyRecord(next) || current.vaultId !== next.vaultId || current.generation !== next.generation || next.revision !== current.revision + 1) return false;
  if (purpose === 'passphrase') return canonical(current.recovery) === canonical(next.recovery);
  if (!next.recovery || next.recovery.id === current.recovery?.id || next.recovery.publicKey === current.recovery?.publicKey) return false;
  return purpose === 'recover' || canonical(current.passphrase) === canonical(next.passphrase);
}

export function canonical(value: any): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
}
