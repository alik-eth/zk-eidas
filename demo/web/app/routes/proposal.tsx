import { createFileRoute, Link } from '@tanstack/react-router'
import { useT, useLocale } from '../i18n'

export const Route = createFileRoute('/proposal')({
  component: ProposalPage,
})

function ProposalPage() {
  const t = useT()
  const { locale, setLocale } = useLocale()

  const complianceItems = t("proposal.complianceItems").split('|')
  const cryptoItems = t("proposal.cryptoItems").split('|')

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      {/* Header */}
      <header className="border-b border-slate-800/60 bg-slate-950/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-4xl mx-auto px-6 py-4 flex items-center justify-between">
          <Link to="/" className="text-sm font-semibold text-white hover:text-emerald-400 transition-colors">
            zk-eidas
          </Link>
          <div className="flex items-center gap-4">
            <Link to="/learn" className="text-sm text-slate-400 hover:text-white transition-colors">
              {t("nav.learn")}
            </Link>
            <button
              onClick={() => setLocale(locale === 'en' ? 'uk' : 'en')}
              className="text-xs text-slate-500 hover:text-slate-300 transition-colors font-mono"
            >
              {locale === 'en' ? 'UK' : 'EN'}
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-16 space-y-16">
        {/* Title */}
        <div className="text-center space-y-4">
          <h1 className="text-4xl font-bold text-white tracking-tight">{t("proposal.title")}</h1>
          <p className="text-lg text-slate-400">{t("proposal.subtitle")}</p>
        </div>

        {/* Problem */}
        <section className="space-y-4">
          <h2 className="text-2xl font-bold text-white">{t("proposal.problemTitle")}</h2>
          <p className="text-slate-300 leading-relaxed text-lg">{t("proposal.problemDesc")}</p>
        </section>

        {/* Solution */}
        <section className="space-y-4">
          <h2 className="text-2xl font-bold text-white">{t("proposal.solutionTitle")}</h2>
          <p className="text-slate-300 leading-relaxed text-lg">{t("proposal.solutionDesc")}</p>
        </section>

        {/* Proving System */}
        <section className="space-y-4">
          <h2 className="text-2xl font-bold text-white">{t("proposal.provingTitle")}</h2>
          <p className="text-slate-300 leading-relaxed text-lg">{t("proposal.provingDesc")}</p>
        </section>

        {/* TSP Model */}
        <section className="space-y-8">
          <div className="space-y-2">
            <h2 className="text-2xl font-bold text-white">{t("proposal.tspTitle")}</h2>
            <p className="text-slate-300 leading-relaxed text-lg">{t("proposal.tspDesc")}</p>
          </div>

          {/* Service 1 */}
          <div className="bg-slate-800/50 rounded-xl border border-emerald-500/20 p-8 space-y-4">
            <h3 className="text-xl font-semibold text-emerald-400">{t("proposal.service1Title")}</h3>
            <p className="text-slate-300 leading-relaxed">{t("proposal.service1Desc")}</p>
            <code className="block bg-slate-900/80 rounded-lg px-4 py-3 text-sm font-mono text-emerald-400">
              {t("proposal.service1Endpoint")}
            </code>
          </div>

          {/* Service 2 */}
          <div className="bg-slate-800/50 rounded-xl border border-blue-500/20 p-8 space-y-4">
            <h3 className="text-xl font-semibold text-blue-400">{t("proposal.service2Title")}</h3>
            <p className="text-slate-300 leading-relaxed">{t("proposal.service2Desc")}</p>
            <code className="block bg-slate-900/80 rounded-lg px-4 py-3 text-sm font-mono text-blue-400">
              {t("proposal.service2Endpoint")}
            </code>
          </div>
        </section>

        {/* Compliance */}
        <section className="space-y-4">
          <h2 className="text-2xl font-bold text-white">{t("proposal.complianceTitle")}</h2>
          <ul className="space-y-3">
            {complianceItems.map((item: string, i: number) => (
              <li key={i} className="flex items-start gap-3">
                <svg className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
                <span className="text-slate-300">{item}</span>
              </li>
            ))}
          </ul>
        </section>

        {/* Cryptographic Primitives */}
        <section className="space-y-4">
          <h2 className="text-2xl font-bold text-white">{t("proposal.cryptoTitle")}</h2>
          <div className="grid gap-3">
            {cryptoItems.map((item: string, i: number) => (
              <div key={i} className="bg-slate-800/50 rounded-lg border border-slate-700/40 px-5 py-3">
                <span className="text-slate-300 text-sm">{item}</span>
              </div>
            ))}
          </div>
        </section>

        {/* Integration */}
        <section className="space-y-4">
          <h2 className="text-2xl font-bold text-white">{t("proposal.integrationTitle")}</h2>
          <p className="text-slate-300 leading-relaxed text-lg">{t("proposal.integrationDesc")}</p>
        </section>

        {/* CTA */}
        <div className="text-center pt-8 border-t border-slate-800/60">
          <Link
            to="/sandbox"
            className="inline-flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold px-8 py-3 rounded-xl transition-colors"
          >
            {t("proposal.tryDemo")}
          </Link>
        </div>
      </main>
    </div>
  )
}
