import { useRef, useEffect, useState, useCallback } from 'react'

export interface WizardStep {
  label: string
  description?: string
  icon: React.ReactNode
  content: React.ReactNode
}

interface StepWizardProps {
  steps: WizardStep[]
  currentStep: number          // 1-based
  onStepBack?: (step: number) => void  // called when user clicks a completed step (1-based)
}

const checkSm = (
  <svg className="w-2.5 h-2.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
)

function StepNav({ steps, currentStep, onStepClick, className }: {
  steps: WizardStep[]
  currentStep: number
  onStepClick: (index: number) => void
  className?: string
}) {
  return (
    <div className={`flex items-center justify-center gap-1 sm:gap-1.5 px-2 sm:px-4 py-2.5 bg-slate-950/90 backdrop-blur-sm border-b border-slate-800 ${className ?? ''}`}>
      {steps.map((step, i) => {
        const num = i + 1
        const isCompleted = currentStep > num
        const isActive = currentStep === num
        const isLocked = currentStep < num

        return (
          <div key={i} className="flex items-center gap-1 sm:gap-1.5">
            {/* Connector line */}
            {i > 0 && (
              <div className="w-4 sm:w-6 h-px relative">
                <div className="absolute inset-0 bg-slate-800" />
                <div
                  className="absolute inset-y-0 left-0 bg-emerald-500/60 transition-all duration-700 ease-out"
                  style={{ width: isCompleted || isActive ? '100%' : '0%' }}
                />
              </div>
            )}
            <button
              disabled={isLocked || undefined}
              onClick={() => onStepClick(i)}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-full text-xs font-medium transition-all ${
                isActive
                  ? 'bg-blue-500/20 text-blue-400 ring-1 ring-blue-400/40'
                  : isCompleted
                    ? 'bg-emerald-500/10 text-emerald-400/80 hover:bg-emerald-500/20'
                    : 'text-slate-600 opacity-50'
              }`}
            >
              <div className={`w-5 h-5 rounded-full flex items-center justify-center shrink-0 ${
                isCompleted
                  ? 'bg-emerald-500/20 text-emerald-400'
                  : isActive
                    ? 'bg-blue-500/20 text-blue-400'
                    : 'bg-slate-800 text-slate-600'
              }`}>
                {isCompleted ? checkSm : <span className="text-[10px]">{num}</span>}
              </div>
              {/* Always show label on desktop, conditionally on mobile */}
              <span className="hidden sm:inline">{step.label}</span>
            </button>
          </div>
        )
      })}
    </div>
  )
}

export function StepWizard({ steps, currentStep, onStepBack }: StepWizardProps) {
  const stepRefs = useRef<Map<number, HTMLElement>>(new Map())
  const scrollRef = useRef<HTMLDivElement | null>(null)
  const [scrollPct, setScrollPct] = useState(0)

  // Track horizontal scroll position for progress bar
  const handleScroll = useCallback(() => {
    const el = scrollRef.current
    if (!el) return
    const max = el.scrollWidth - el.clientWidth
    setScrollPct(max > 0 ? el.scrollLeft / max : 0)
  }, [])

  useEffect(() => {
    const el = scrollRef.current
    if (!el) return
    el.addEventListener('scroll', handleScroll, { passive: true })
    handleScroll()
    return () => el.removeEventListener('scroll', handleScroll)
  }, [handleScroll])

  // Auto-scroll container to far right when step changes
  useEffect(() => {
    const container = scrollRef.current
    if (container) {
      const scrollRight = () => container.scrollTo({ left: container.scrollWidth, behavior: 'smooth' })
      requestAnimationFrame(() => {
        scrollRight()
        setTimeout(scrollRight, 520)
      })
    }
  }, [currentStep])

  const handleStepClick = (index: number) => {
    const stepNum = index + 1
    if (stepNum < currentStep && onStepBack) {
      onStepBack(stepNum)
    }
    stepRefs.current.get(index)?.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'start' })
  }

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <StepNav steps={steps} currentStep={currentStep} onStepClick={handleStepClick} />
      {/* Scroll progress bar */}
      <div className="h-0.5 bg-slate-800 w-full shrink-0">
        <div
          className="h-full bg-blue-500/60 transition-[width] duration-150 ease-out"
          style={{ width: `${scrollPct * 100}%` }}
        />
      </div>
      <div ref={scrollRef} className="flex-1 flex overflow-x-auto scroll-smooth no-scrollbar snap-x snap-mandatory sm:snap-none">
        {steps.map((step, i) => {
          const num = i + 1
          const isLocked = currentStep < num

          return (
            <section
              key={i}
              ref={el => {
                if (el) stepRefs.current.set(i, el)
              }}
              className={`shrink-0 flex flex-col transition-all duration-500 border-r border-slate-800 last:border-r-0 ${
                isLocked
                  ? 'w-0 min-w-0 overflow-hidden opacity-0'
                  : 'min-w-[min(460px,100vw)] flex-1 snap-start'
              }`}
            >
              {/* Step title bar */}
              <div className="flex items-center gap-2 px-2 py-2.5 sm:px-6 sm:justify-center sm:gap-2.5 bg-slate-900/80 border-b border-slate-800 shrink-0">
                {/* Left arrow — mobile only */}
                <button
                  className="sm:hidden w-7 h-7 flex items-center justify-center rounded-full text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors shrink-0 disabled:opacity-20 disabled:pointer-events-none"
                  disabled={i === 0 || undefined}
                  onClick={() => stepRefs.current.get(i - 1)?.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'start' })}
                >
                  <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
                </button>
                <div className="flex items-center justify-center gap-2.5 flex-1 min-w-0">
                  <div className={`w-6 h-6 rounded-full flex items-center justify-center shrink-0 ${
                    currentStep > num ? 'bg-emerald-500/20 text-emerald-400' : 'bg-blue-500/20 text-blue-400'
                  }`}>
                    {currentStep > num ? checkSm : step.icon}
                  </div>
                  <div className="min-w-0 text-center">
                    <p className="text-sm font-medium text-slate-200 truncate">{step.label}</p>
                    {step.description && <p className="text-xs text-slate-500 truncate">{step.description}</p>}
                  </div>
                </div>
                {/* Right arrow — mobile only */}
                <button
                  className="sm:hidden w-7 h-7 flex items-center justify-center rounded-full text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors shrink-0 disabled:opacity-20 disabled:pointer-events-none"
                  disabled={currentStep <= num || undefined}
                  onClick={() => stepRefs.current.get(i + 1)?.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'start' })}
                >
                  <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
                </button>
              </div>
              <div className="flex-1 overflow-y-auto">
                <div className="px-4 py-4 sm:px-6 sm:py-6 max-w-3xl mx-auto w-full">
                  {step.content}
                </div>
              </div>
            </section>
          )
        })}
      </div>
    </div>
  )
}
