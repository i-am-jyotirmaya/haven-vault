import { useEffect, useRef, useState } from 'react';
import { ChevronLeft, ChevronRight, LoaderCircle, Minus, Plus } from 'lucide-react';
import { getDocument, GlobalWorkerOptions, type PDFDocumentProxy } from 'pdfjs-dist';
import workerUrl from 'pdfjs-dist/build/pdf.worker.min.mjs?url';

GlobalWorkerOptions.workerSrc = workerUrl;

/** Renders only canvas pixels. PDF scripts, links, forms, and attachments are not executed. */
export default function PdfPreview({ url, name }: { url: string; name: string }) {
  const [pdf, setPdf] = useState<PDFDocumentProxy | null>(null);
  const [page, setPage] = useState(1);
  const [zoom, setZoom] = useState(1);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState('');
  const [pageText, setPageText] = useState('');
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    let task: ReturnType<typeof getDocument> | undefined;
    setPdf(null); setBusy(true); setError(''); setPage(1); setZoom(1); setPageText('');
    void (async () => {
      // url is a private, short-lived object URL or an app-owned demo asset.
      const response = await fetch(url, { signal: controller.signal });
      if (!response.ok) throw new Error('Unable to load PDF');
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (cancelled) return;
      task = getDocument({ data: bytes, enableXfa: false, useSystemFonts: true, useWasm: false, maxImageSize: 16_000_000 });
      const document = await task.promise;
      if (!cancelled) setPdf(document);
    })().catch(reason => { if (!cancelled) { setError(reason?.name === 'PasswordException' ? 'This PDF has its own password. Download it and open it with your PDF reader.' : 'This document could not be previewed. Download it to open it in your PDF reader.'); setBusy(false); } });
    return () => { cancelled = true; controller.abort(); void task?.destroy(); };
  }, [url]);
  useEffect(() => {
    if (!pdf || !canvasRef.current) return;
    let cancelled = false;
    let render: ReturnType<Awaited<ReturnType<PDFDocumentProxy['getPage']>>['render']> | undefined;
    const canvas = canvasRef.current;
    setBusy(true);
    void (async () => {
      const documentPage = await pdf.getPage(page);
      if (cancelled) return;
      const base = documentPage.getViewport({ scale: 1 });
      const width = Math.max(260, Math.min(850, (containerRef.current?.clientWidth || 850) - 32));
      const scale = width / base.width * zoom;
      const viewport = documentPage.getViewport({ scale });
      const density = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.floor(viewport.width * density);
      canvas.height = Math.floor(viewport.height * density);
      canvas.style.width = `${viewport.width}px`;
      canvas.style.height = `${viewport.height}px`;
      render = documentPage.render({ canvas, viewport, transform: [density, 0, 0, density, 0, 0] });
      await render.promise;
      if (!cancelled) {
        setBusy(false);
        const content = await documentPage.getTextContent();
        if (!cancelled) setPageText(content.items.map(item => 'str' in item ? item.str : '').join(' '));
      }
    })().catch(reason => { if (!cancelled && reason?.name !== 'RenderingCancelledException') { setError('Unable to render this page. You can still download the document.'); setBusy(false); } });
    return () => { cancelled = true; render?.cancel(); canvas.width = 0; canvas.height = 0; };
  }, [pdf, page, zoom]);

  return <div className="pdf-reader" ref={containerRef}>
    <div className="pdf-toolbar">
      <button aria-label="Previous PDF page" disabled={page <= 1} onClick={() => setPage(value => value - 1)}><ChevronLeft size={17} /></button>
      <span>Page {page} of {pdf?.numPages ?? '…'}</span>
      <button aria-label="Next PDF page" disabled={!pdf || page >= pdf.numPages} onClick={() => setPage(value => value + 1)}><ChevronRight size={17} /></button>
      <i /><button aria-label="Zoom PDF out" disabled={zoom <= .5} onClick={() => setZoom(value => Math.max(.5, value - .25))}><Minus size={16} /></button><span>{Math.round(zoom * 100)}%</span><button aria-label="Zoom PDF in" disabled={zoom >= 2} onClick={() => setZoom(value => Math.min(2, value + .25))}><Plus size={16} /></button>
    </div>
    {error ? <p className="pdf-error" role="alert">{error}</p> : <div className="pdf-canvas-wrap">{busy && <div className="pdf-loading"><LoaderCircle className="spin" size={23} /><span>Rendering your document…</span></div>}<canvas key={`${page}-${zoom}`} ref={canvasRef} role="img" aria-label={`${name}, page ${page}`} /><p className="sr-only">{pageText}</p></div>}
  </div>;
}
