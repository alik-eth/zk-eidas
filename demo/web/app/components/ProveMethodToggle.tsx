import { useState, useRef, useEffect, type ReactNode } from 'react'
import { createPortal } from 'react-dom'

export type ProveMethod = 'server' | 'device'

interface ProveMethodToggleProps {
  value: ProveMethod
  onChange: (method: ProveMethod) => void
  disabled?: boolean
  /** Override labels — defaults to Server / On Device */
  labels?: { server?: string; device?: string }
}

/* Segmented pill toggle — dark glass aesthetic, animated slider */
export function ProveMethodToggle({ value, onChange, disabled, labels }: ProveMethodToggleProps) {
  const serverLabel = labels?.server ?? 'Server'
  const deviceLabel = labels?.device ?? 'On Device'

  const [tooltipVisible, setTooltipVisible] = useState(false)
  const infoRef = useRef<HTMLButtonElement>(null)
  const [tooltipPos, setTooltipPos] = useState({ top: 0, left: 0 })

  useEffect(() => {
    if (tooltipVisible && infoRef.current) {
      const rect = infoRef.current.getBoundingClientRect()
      setTooltipPos({
        top: rect.bottom + 8,
        left: Math.max(140, Math.min(rect.left + rect.width / 2, window.innerWidth - 140)),
      })
    }
  }, [tooltipVisible])

  return (
    <div className="flex items-center gap-2.5">
      {/* Segmented control */}
      <div
        className={`
          relative flex rounded-lg p-0.5
          bg-slate-800/80 border border-slate-700/60
          ${disabled ? 'opacity-40 pointer-events-none' : ''}
        `}
      >
        {/* Animated slider background */}
        <div
          className="absolute top-0.5 bottom-0.5 rounded-md bg-gradient-to-b from-slate-600/90 to-slate-700/90 shadow-sm transition-all duration-200 ease-out"
          style={{
            width: 'calc(50% - 2px)',
            left: value === 'server' ? '2px' : 'calc(50%)',
          }}
        />

        <SegmentButton
          active={value === 'server'}
          onClick={() => onChange('server')}
          icon={
            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="2" y="2" width="20" height="8" rx="2" ry="2" /><rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
              <line x1="6" y1="6" x2="6.01" y2="6" /><line x1="6" y1="18" x2="6.01" y2="18" />
            </svg>
          }
          label={serverLabel}
        />
        <SegmentButton
          active={value === 'device'}
          onClick={() => onChange('device')}
          icon={
            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="5" y="2" width="14" height="20" rx="2" ry="2" />
              <line x1="12" y1="18" x2="12.01" y2="18" />
            </svg>
          }
          label={deviceLabel}
        />
      </div>

      {/* Info button with tooltip */}
      <button
        ref={infoRef}
        type="button"
        onMouseEnter={() => setTooltipVisible(true)}
        onMouseLeave={() => setTooltipVisible(false)}
        onClick={() => setTooltipVisible(prev => !prev)}
        className="w-4 h-4 rounded-full bg-slate-700/60 text-slate-500 text-[10px] font-bold inline-flex items-center justify-center hover:bg-slate-600 hover:text-slate-300 transition-colors cursor-help shrink-0"
        aria-label="Proving method info"
      >
        ?
      </button>
      {tooltipVisible && createPortal(
        <span
          className="fixed px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-xs text-slate-300 leading-relaxed w-64 text-center shadow-lg z-[9999] pointer-events-none -translate-x-1/2"
          style={{ top: tooltipPos.top, left: tooltipPos.left }}
        >
          <strong className="text-slate-200">Server</strong> — fast (~2s), credential sent to backend.{' '}
          <strong className="text-slate-200">On Device</strong> — private, proof generated in your browser (~3 min per claim).
        </span>,
        document.body,
      )}
    </div>
  )
}

function SegmentButton({ active, onClick, icon, label }: {
  active: boolean
  onClick: () => void
  icon: ReactNode
  label: string
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`
        relative z-10 flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium
        transition-colors duration-200 cursor-pointer select-none whitespace-nowrap
        ${active
          ? 'text-slate-100'
          : 'text-slate-500 hover:text-slate-400'
        }
      `}
    >
      {icon}
      {label}
    </button>
  )
}
