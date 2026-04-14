import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/')({
  component: Landing,
})

const steps = [
  {
    number: '1',
    title: 'Escrow',
    route: '/escrow',
    color: 'from-blue-500/20 to-blue-600/10',
    border: 'border-blue-500/30',
    accent: 'text-blue-400',
    icon: (
      <svg className="w-8 h-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
      </svg>
    ),
    description:
      'Holder encrypts their identity credential under a Lit Protocol access-control condition tied to a Kleros ruling. The ciphertext and a ZK proof of credential validity are stored on-chain.',
  },
  {
    number: '2',
    title: 'Dispute',
    route: '/dispute',
    color: 'from-amber-500/20 to-amber-600/10',
    border: 'border-amber-500/30',
    accent: 'text-amber-400',
    icon: (
      <svg className="w-8 h-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 9v4" />
        <path d="M12 17h.01" />
        <path d="M3.262 16.06a1 1 0 0 0 .878 1.44h15.72a1 1 0 0 0 .878-1.44L12.878 3.94a1 1 0 0 0-1.756 0L3.262 16.06z" />
      </svg>
    ),
    description:
      'Any party can raise a dispute on Kleros. Jurors evaluate the evidence and the ZK proof. If the ruling requires identity disclosure, the Lit decryption condition is satisfied.',
  },
  {
    number: '3',
    title: 'Resolve',
    route: '/resolve',
    color: 'from-emerald-500/20 to-emerald-600/10',
    border: 'border-emerald-500/30',
    accent: 'text-emerald-400',
    icon: (
      <svg className="w-8 h-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
        <polyline points="22 4 12 14.01 9 11.01" />
      </svg>
    ),
    description:
      'After a Kleros ruling, the encrypted identity is either revealed to the counterparty (if the ruling requires it) or the escrow is released back. Privacy preserved unless arbitration demands disclosure.',
  },
]

function Landing() {
  return (
    <div className="min-h-screen">
      {/* Hero */}
      <section className="max-w-5xl mx-auto px-4 sm:px-8 py-16 sm:py-24 text-center">
        <h2 className="text-3xl sm:text-5xl font-extrabold tracking-tight mb-6">
          <span className="text-blue-400">ZK Identity</span>
          <span className="text-slate-500 mx-2">meets</span>
          <span className="text-purple-400">Kleros Arbitration</span>
        </h2>
        <p className="text-lg sm:text-xl text-slate-400 max-w-2xl mx-auto mb-4 leading-relaxed">
          Escrow your eIDAS credential behind Lit Protocol encryption.
          Only a Kleros ruling can unlock it — trustless, private, decentralized.
        </p>
        <p className="text-sm text-slate-600 font-mono">
          Sumcheck+Ligero proof &middot; ML-KEM-768 &middot; Kleros Court v2
        </p>
      </section>

      {/* Three-step flow */}
      <section className="max-w-5xl mx-auto px-4 sm:px-8 pb-20">
        <div className="grid md:grid-cols-3 gap-6">
          {steps.map((step) => (
            <div
              key={step.number}
              className={`relative bg-gradient-to-br ${step.color} rounded-2xl border ${step.border} p-6 sm:p-8 flex flex-col`}
            >
              {/* Step number badge */}
              <div className={`text-[10px] font-bold uppercase tracking-widest ${step.accent} mb-4`}>
                Step {step.number}
              </div>

              {/* Icon */}
              <div className={`${step.accent} mb-4`}>
                {step.icon}
              </div>

              {/* Title */}
              <h3 className="text-xl font-bold mb-3">{step.title}</h3>

              {/* Description */}
              <p className="text-sm text-slate-400 leading-relaxed flex-1">
                {step.description}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* Tech stack bar */}
      <section className="border-t border-slate-800 py-10">
        <div className="max-w-5xl mx-auto px-4 sm:px-8">
          <div className="flex flex-wrap justify-center gap-x-8 gap-y-3 text-xs text-slate-600 font-mono">
            <span>zk-eidas (Longfellow)</span>
            <span>Lit Protocol v7</span>
            <span>Kleros Court v2</span>
            <span>Foundry</span>
            <span>wagmi + viem</span>
            <span>TanStack Start</span>
          </div>
        </div>
      </section>
    </div>
  )
}
