import { useState, useRef, useEffect } from 'react'
import { createPortal } from 'react-dom'

export function Tooltip({ text, children }: { text: string; children?: React.ReactNode }) {
  const [show, setShow] = useState(false)
  const btnRef = useRef<HTMLButtonElement>(null)
  const [pos, setPos] = useState({ top: 0, left: 0 })

  useEffect(() => {
    if (show && btnRef.current) {
      const rect = btnRef.current.getBoundingClientRect()
      setPos({
        top: rect.bottom + 6,
        left: Math.max(132, Math.min(rect.left + rect.width / 2, window.innerWidth - 132)),
      })
    }
  }, [show])

  return (
    <span className="inline-flex items-center">
      {children}
      <button
        ref={btnRef}
        type="button"
        onMouseEnter={() => setShow(true)}
        onMouseLeave={() => setShow(false)}
        onClick={() => setShow(prev => !prev)}
        className="ml-1 w-4 h-4 rounded-full bg-slate-600 text-slate-400 text-[10px] font-bold inline-flex items-center justify-center hover:bg-slate-500 hover:text-white transition-colors cursor-help"
        aria-label="More info"
      >
        ?
      </button>
      {show && createPortal(
        <span
          className="fixed px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-xs text-slate-300 leading-relaxed w-64 text-center shadow-lg z-[9999] pointer-events-none -translate-x-1/2"
          style={{ top: pos.top, left: pos.left }}
        >
          {text}
        </span>,
        document.body
      )}
    </span>
  )
}
