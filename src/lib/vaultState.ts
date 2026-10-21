import type { VaultConfig } from './crypto'

/** Authentication never carries a key unless the vault is explicitly unlocked. */
export type VaultState =
  | { status: 'signed-out' }
  | { status: 'demo' }
  | { status: 'locked'; expiresAt: number; config: VaultConfig | null | undefined }
  | { status: 'unlocked'; expiresAt: number; config: VaultConfig; key: CryptoKey }

export function lockVaultState(state: VaultState): VaultState {
  if (state.status === 'demo') return { status: 'signed-out' }
  if (state.status !== 'unlocked') return state
  return { status: 'locked', expiresAt: state.expiresAt, config: state.config }
}

export function sessionDeadline(state: VaultState): number {
  return state.status === 'locked' || state.status === 'unlocked' ? state.expiresAt : 0
}
