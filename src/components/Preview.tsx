import { lazy, Suspense, useEffect, useRef, useState, type PointerEvent } from 'react';
import { Download, FileText, LockKeyhole, Minus, Plus, RotateCcw, X, ChevronLeft, ChevronRight, LoaderCircle } from 'lucide-react';
import type { DisplayItem } from '../demo';
import { formatBytes } from '../demo';
import { downloadVaultFile } from '../lib/vault';
import { isAuthenticationFailure, getVaultUserId } from '../lib/firebase';
import { createPlaintextUrl, revokePlaintextUrl, plaintextGeneration, plaintextIsCurrent } from '../lib/plaintext';
const PdfPreview = lazy(() => import('./PdfPreview'));

export default function Preview({ item, vaultKey, onClose, onStep, onDownload, onAuthenticationFailure, canReveal }: { item: DisplayItem; vaultKey: CryptoKey | null; onClose: () => void; onStep: (offset: number) => void; onDownload: (item: DisplayItem) => void; onAuthenticationFailure: (error: unknown) => void; canReveal?: () => boolean }) {
  const [url, setUrl] = useState(item.demoUrl || '');
  const [text, setText] = useState(item.text || '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [scale, setScale] = useState(1);
  const [position, setPosition] = useState({ x: 0, y: 0 });
  const pointers = useRef(new Map<number, { x: number; y: number }>());
  const lastDistance = useRef(0);
  const dialog = useRef<HTMLDialogElement>(null);
  const isPhoto = item.kind === 'photo' && /^image\/(jpeg|png|webp|gif|avif|bmp)$/.test(item.mimeType);
  const isPdf = item.mimeType === 'application/pdf';
  const isText = item.kind === 'note' || item.mimeType.startsWith('text/');
  const sampleDocument = item.id.startsWith('demo-') && item.kind === 'document';

  useEffect(() => {
    dialog.current!.showModal();
    return () => dialog.current?.close();
  }, []);
  useEffect(() => {
    let cancelled = false;
    let objectUrl = '';
    const generation = plaintextGeneration();
    const active = () => !cancelled && plaintextIsCurrent(generation) &&
      document.visibilityState === 'visible' && !document.documentElement.dataset.havenConcealed && (canReveal?.() ?? true);
    setUrl(item.demoUrl || ''); setText(item.text || ''); setError(''); setScale(1); setPosition({ x: 0, y: 0 }); pointers.current.clear(); lastDistance.current = 0;
    if (!item.demoUrl && item.kind !== 'note' && !sampleDocument && vaultKey && (isPhoto || isPdf || isText)) {
      setBusy(true);
      downloadVaultFile(vaultKey, item).then(async blob => {
        if (!active()) return;
        getVaultUserId();
        if (isText) {
          if (blob.size > 2 * 1024 * 1024) throw new Error('This text file is too large to preview. Download it to read the full file.');
          const value = await blob.text();
          if (active()) { getVaultUserId(); setText(value); }
        } else {
          objectUrl = createPlaintextUrl(blob);
          setUrl(objectUrl);
        }
      }).catch(err => { if (active()) { if (isAuthenticationFailure(err)) onAuthenticationFailure(err); else setError(err instanceof Error ? err.message : 'Unable to decrypt preview.'); } }).finally(() => { if (active()) setBusy(false); });
    } else setBusy(false);
    return () => { cancelled = true; if (objectUrl) revokePlaintextUrl(objectUrl); };
  }, [item, vaultKey, isPhoto, isPdf, isText, sampleDocument, onAuthenticationFailure, canReveal]);

  const zoom = (next: number) => { setScale(Math.max(0.5, Math.min(5, next))); };
  const pointerDown = (event: PointerEvent<HTMLDivElement>) => {
    event.currentTarget.setPointerCapture(event.pointerId);
    pointers.current.set(event.pointerId, { x: event.clientX, y: event.clientY });
    if (pointers.current.size === 2) {
      const [a, b] = [...pointers.current.values()];
      lastDistance.current = Math.hypot(a.x - b.x, a.y - b.y);
    }
  };
  const pointerMove = (event: PointerEvent<HTMLDivElement>) => {
    const previous = pointers.current.get(event.pointerId);
    if (!previous) return;
    pointers.current.set(event.pointerId, { x: event.clientX, y: event.clientY });
    if (pointers.current.size === 2) {
      const [a, b] = [...pointers.current.values()];
      const distance = Math.hypot(a.x - b.x, a.y - b.y);
      // Capture the ratio before advancing the ref: React may run the updater later.
      const ratio = lastDistance.current ? distance / lastDistance.current : 1;
      setScale(value => Math.min(5, Math.max(0.5, value * ratio)));
      lastDistance.current = distance;
    } else setPosition(value => ({ x: value.x + event.clientX - previous.x, y: value.y + event.clientY - previous.y }));
  };
  const pointerEnd = (event: PointerEvent<HTMLDivElement>) => {
    pointers.current.delete(event.pointerId);
    lastDistance.current = 0;
  };

  return <dialog ref={dialog} className="preview-dialog" onCancel={event => { event.preventDefault(); onClose(); }} aria-label={`Preview ${item.name}`} onKeyDown={event => {
    if (event.key === 'ArrowLeft') onStep(-1);
    if (event.key === 'ArrowRight') onStep(1);
  }}>
    <header className="preview-header"><div className="preview-file-icon"><FileText size={21} /></div><div><h2>{item.name}</h2><span>{formatBytes(item.size)} <i>·</i> {item.id.startsWith('demo-') ? 'Sample file' : 'Decrypted on your device'}</span></div><div className="preview-actions"><button className="icon-button" title="Download file" aria-label="Download file" onClick={() => onDownload(item)}><Download size={20} /></button><button className="icon-button" onClick={onClose} aria-label="Close preview"><X size={23} /></button></div></header>
    <div className={`preview-stage ${isPhoto ? 'photo-stage' : ''}`} onWheel={isPhoto ? event => zoom(scale + (event.deltaY < 0 ? 0.15 : -0.15)) : undefined}
      onPointerDown={isPhoto ? pointerDown : undefined} onPointerMove={isPhoto ? pointerMove : undefined} onPointerUp={pointerEnd} onPointerCancel={pointerEnd} onLostPointerCapture={pointerEnd} onDoubleClick={isPhoto ? () => { setScale(scale === 1 ? 2 : 1); setPosition({ x: 0, y: 0 }); } : undefined}>
      {busy ? <div className="preview-placeholder"><LoaderCircle className="spin" size={30} /><p>Decrypting your preview…</p></div> :
        error ? <div className="preview-placeholder"><LockKeyhole size={36} /><p>{error}</p></div> :
        isPhoto && url ? <img className="preview-photo" alt={item.name} draggable={false} src={url} style={{ transform: `translate(${position.x}px, ${position.y}px) scale(${scale})` }} /> :
        isPdf && url ? <Suspense fallback={<div className="preview-placeholder"><LoaderCircle className="spin" size={25} /><p>Opening your document…</p></div>}><PdfPreview key={url} url={url} name={item.name} /></Suspense> :
        sampleDocument ? <article className="sample-document"><div className="document-wordmark">haven<span> / personal archive</span></div><div className="document-tag">SAMPLE DOCUMENT</div><h1>{item.name.replace('.pdf', '')}</h1><p>A place for the details that matter.</p><hr /><h3>Your personal collection</h3><p>Keep important documents together and find them whenever you need them. In your connected vault, this preview is decrypted on your device.</p><div className="document-placeholder-lines"><i /><i /><i /><i /></div><div className="document-stamp"><LockKeyhole size={24} /><div>Only yours.<small>This is a fictional sample, with no personal data.</small></div></div></article> :
        isText ? <article className="text-preview"><div className="note-eyebrow">PRIVATE NOTE</div><h1>{item.name}</h1><pre>{text}</pre></article> :
        <div className="preview-placeholder"><FileText size={48} /><h3>This file is safely stored.</h3><p>Preview is available for photos, PDFs, and text files.<br />Download this file to open it in its usual app.</p><button className="button primary" onClick={() => onDownload(item)}><Download size={17} />Download file</button></div>}
    </div>
    <footer className="preview-footer"><span><LockKeyhole size={14} /> {item.id.startsWith('demo-') ? 'Sample preview' : 'Private, in-memory preview'}</span>{isPhoto ? <div className="zoom-controls"><button onClick={() => zoom(scale - 0.25)} aria-label="Zoom out"><Minus size={17} /></button><span>{Math.round(scale * 100)}%</span><button onClick={() => zoom(scale + 0.25)} aria-label="Zoom in"><Plus size={17} /></button><i /><button onClick={() => { setScale(1); setPosition({ x: 0, y: 0 }); }} aria-label="Reset zoom"><RotateCcw size={16} /></button></div> : <span className="preview-hint">Your private little corner of the internet</span>}<div className="preview-arrows"><button className="icon-button" onClick={() => onStep(-1)} aria-label="Previous file"><ChevronLeft size={20} /></button><button className="icon-button" onClick={() => onStep(1)} aria-label="Next file"><ChevronRight size={20} /></button></div></footer>
  </dialog>;
}
