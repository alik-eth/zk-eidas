import { type ReactNode } from 'react'

interface StepCardProps {
  step: number
  title: string
  description: string
  status: 'pending' | 'active' | 'complete' | 'error'
  children?: ReactNode
}

export function StepCard({ step, title, description, status, children }: StepCardProps) {
  const borderColor = {
    pending: 'border-slate-700',
    active: 'border-indigo-500',
    complete: 'border-emerald-500',
    error: 'border-red-500',
  }[status]

  const badge = {
    pending: 'bg-slate-700 text-slate-400',
    active: 'bg-indigo-600 text-white',
    complete: 'bg-emerald-600 text-white',
    error: 'bg-red-600 text-white',
  }[status]

  return (
    <div className={`border ${borderColor} rounded-lg p-5`}>
      <div className="flex items-center gap-3 mb-2">
        <span className={`${badge} text-xs font-semibold px-2 py-0.5 rounded`}>Step {step}</span>
        <h3 className="font-semibold">{title}</h3>
      </div>
      <p className="text-slate-400 text-sm mb-4">{description}</p>
      {children}
    </div>
  )
}
