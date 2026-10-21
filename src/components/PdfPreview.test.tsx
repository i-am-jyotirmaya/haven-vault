// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import PdfPreview from './PdfPreview';

const mocks = vi.hoisted(() => ({ getDocument: vi.fn() }));
vi.mock('pdfjs-dist', () => ({ getDocument: mocks.getDocument, GlobalWorkerOptions: {} }));

let host: HTMLDivElement;
let root: Root;
let destroy: ReturnType<typeof vi.fn>;
let getPage: ReturnType<typeof vi.fn>;
beforeEach(() => {
  Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, arrayBuffer: async () => new ArrayBuffer(8) }));
  destroy = vi.fn();
  getPage = vi.fn().mockResolvedValue({
    getViewport: ({ scale }: { scale: number }) => ({ width: 600 * scale, height: 800 * scale }),
    render: () => ({ promise: Promise.resolve(), cancel: vi.fn() }),
    getTextContent: async () => ({ items: [{ str: 'Fictional document' }] }),
  });
  mocks.getDocument.mockReset().mockReturnValue({ promise: Promise.resolve({ numPages: 2, getPage }), destroy });
  host = document.createElement('div'); document.body.append(host); root = createRoot(host);
});
afterEach(async () => {
  await act(async () => root.unmount());
  host.remove(); vi.unstubAllGlobals();
});
const show = async (url: string) => act(async () => root.render(<PdfPreview url={url} name="Fictional.pdf" />));

it('renders blob PDF bytes as canvas, supports paging and zoom, and destroys the loading task', async () => {
  await show('blob:https://vault.example/fictional');
  expect(mocks.getDocument).toHaveBeenCalledWith(expect.objectContaining({ data: expect.any(Uint8Array), enableXfa: false, useWasm: false }));
  expect(host.querySelector('canvas')!.width).toBeGreaterThan(0);
  expect(host.textContent).toContain('Fictional document');
  expect(host.querySelector('.pdf-loading')).toBeNull();
  await act(async () => (host.querySelector('[aria-label="Next PDF page"]') as HTMLButtonElement).click());
  expect(getPage).toHaveBeenLastCalledWith(2);
  await act(async () => (host.querySelector('[aria-label="Zoom PDF in"]') as HTMLButtonElement).click());
  expect(host.textContent).toContain('125%');
  await act(async () => root.render(null));
  expect(destroy).toHaveBeenCalledOnce();
});

it('recovers from a failed load when another PDF is selected', async () => {
  vi.mocked(fetch).mockRejectedValueOnce(new Error('Blocked'));
  await show('blob:https://vault.example/failed');
  expect(host.querySelector('[role="alert"]')).not.toBeNull();
  await show('blob:https://vault.example/valid');
  expect(host.querySelector('[role="alert"]')).toBeNull();
  expect(host.querySelector('canvas')!.width).toBeGreaterThan(0);
});

it('does not parse an HTTP error page as a PDF', async () => {
  vi.mocked(fetch).mockResolvedValueOnce({ ok: false } as Response);
  await show('/missing.pdf');
  expect(mocks.getDocument).not.toHaveBeenCalled();
  expect(host.querySelector('[role="alert"]')).not.toBeNull();
});
