// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import Preview from './Preview';
import { demoItems } from '../demo';

vi.mock('../lib/firebase', () => ({ isAuthenticationFailure: vi.fn(() => false) }));
vi.mock('../lib/vault', () => ({ downloadVaultFile: vi.fn() }));
// Keep component tests independent of .env.local: Firebase's Node Auth build
// cannot initialize the browser popup resolver used by the application.
vi.mock('../lib/firebase', () => ({
  getVaultUserId: vi.fn(),
  isAuthenticationFailure: vi.fn(),
}));

let host: HTMLDivElement;
let root: Root;
beforeEach(async () => {
  Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
  HTMLDialogElement.prototype.showModal = vi.fn();
  HTMLDialogElement.prototype.close = vi.fn();
  HTMLElement.prototype.setPointerCapture = vi.fn();
  host = document.createElement('div');
  document.body.append(host);
  root = createRoot(host);
  await act(async () => root.render(<Preview item={demoItems[0]} vaultKey={null} onClose={vi.fn()} onStep={vi.fn()} onDownload={vi.fn()} onAuthenticationFailure={vi.fn()} />));
});
afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
});

function pointer(type: string, id: number, x: number) {
  const event = new MouseEvent(type, { bubbles: true, clientX: x, clientY: 100 });
  Object.defineProperty(event, 'pointerId', { value: id });
  host.querySelector('.photo-stage')!.dispatchEvent(event);
}
const zoom = () => host.querySelector('.zoom-controls span')!.textContent;

it('spreads to zoom in and pinches to zoom out with batched pointer moves', async () => {
  await act(async () => {
    pointer('pointerdown', 1, 100);
    pointer('pointerdown', 2, 200);
    pointer('pointermove', 1, 50);
    pointer('pointermove', 2, 250);
  });
  expect(zoom()).toBe('200%');
  await act(async () => {
    pointer('pointermove', 1, 100);
    pointer('pointermove', 2, 200);
  });
  expect(zoom()).toBe('100%');
});

it('starts a fresh pinch after cancellation or lost capture and clamps zoom', async () => {
  await act(async () => {
    pointer('pointerdown', 1, 100);
    pointer('pointerdown', 2, 200);
    pointer('pointercancel', 2, 200);
    pointer('lostpointercapture', 1, 100);
    pointer('pointerdown', 3, 100);
    pointer('pointerdown', 4, 200);
    pointer('pointermove', 4, 1200);
  });
  expect(zoom()).toBe('500%');
  await act(async () => pointer('pointermove', 4, 101));
  expect(zoom()).toBe('50%');
});
