import { useLayoutEffect, useRef, type ReactNode } from 'react';
import { X } from 'lucide-react';

export default function Modal({ title, children, onClose, wide = false, concealed = false }: { title: string; children: ReactNode; onClose: () => void; wide?: boolean; concealed?: boolean }) {
  const ref = useRef<HTMLDialogElement>(null);
  useLayoutEffect(() => {
    const dialog = ref.current!;
    // A hidden modal still makes the rest of the document inert. Suspend its
    // top-layer membership so privacy-screen actions remain reachable.
    if (concealed) dialog.close();
    else dialog.showModal();
    return () => dialog.close();
  }, [concealed]);
  return <dialog ref={ref} className={`modal ${wide ? 'modal-wide' : ''}`} onCancel={event => { event.preventDefault(); onClose(); }} onClick={event => { if (event.target === ref.current) onClose(); }} aria-label={title}>
    <div className="modal-heading"><h2>{title}</h2><button className="icon-button" onClick={onClose} aria-label="Close dialog"><X size={20} /></button></div>
    {children}
  </dialog>;
}
