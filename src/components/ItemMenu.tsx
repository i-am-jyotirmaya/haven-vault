import { useLayoutEffect, useRef, type ReactNode } from 'react'

const EDGE = 8

/** Open upward when the downward menu would leave the viewport and the same
 * height fits above the anchor. */
export function menuShouldOpenUpward(top: number, bottom: number, height: number, viewportHeight: number) {
  return bottom > viewportHeight - EDGE && top >= height + EDGE
}

export default function ItemMenu({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null)
  useLayoutEffect(() => {
    const menu = ref.current
    if (!menu) return
    const rect = menu.getBoundingClientRect()
    // Add only. Dev strict mode measures again after the class is applied, and
    // a second pass must not clear a decision that already fits.
    if (rect.height > 0 && menuShouldOpenUpward(rect.top, rect.bottom, rect.height, window.innerHeight)) {
      menu.classList.add('item-menu-up')
    }
  }, [])
  return <div ref={ref} className="item-menu" onClick={event => event.stopPropagation()}>{children}</div>
}
