import { createFileRoute, Link } from '@tanstack/react-router'
import { useState, useEffect, useRef } from 'react'
import { useT, useLocale } from '../i18n'

export const Route = createFileRoute('/proposal')({
  component: ProposalPage,
})

function ProposalPage() {
  const t = useT()
  const { locale, setLocale } = useLocale()
  const [headerVisible, setHeaderVisible] = useState(true)
  const lastScrollY = useRef(0)

  useEffect(() => {
    const onScroll = () => {
      const y = window.scrollY
      setHeaderVisible(y < 50 || y < lastScrollY.current)
      lastScrollY.current = y
    }
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  const complianceItems = t("proposal.complianceItems").split('|')
  const cryptoItems = t("proposal.cryptoItems").split('|')

  return (
    <div className="min-h-screen bg-slate-900 text-white">
      {/* Navigation — matches root */}
      <header
        className="border-b border-slate-800 px-4 sm:px-8 py-4 pt-[max(1rem,env(safe-area-inset-top))] bg-slate-950/80 backdrop-blur-md fixed top-0 left-0 right-0 z-10 overflow-x-hidden transition-transform duration-300"
        style={{ transform: headerVisible ? 'translateY(0)' : 'translateY(-100%)' }}
      >
        <div className="max-w-5xl mx-auto flex items-center justify-between gap-2">
          <Link to="/" className="flex items-center gap-3 shrink-0">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-600 to-blue-700 flex items-center justify-center">
              <span className="text-xs font-bold text-white tracking-tighter">zk</span>
            </div>
            <div>
              <span className="text-sm font-semibold tracking-tight leading-none">
                <span style={{ color: '#005BBB' }}>zk</span>
                <span className="text-slate-600 mx-0.5">-</span>
                <span style={{ color: '#FFD500' }}>eidas</span>
              </span>
            </div>
          </Link>
          <nav className="flex items-center gap-2 sm:gap-4 flex-wrap justify-end">
            <Link to="/learn" className="text-xs text-slate-400 hover:text-slate-200 transition-colors font-medium">
              {t("nav.learn")}
            </Link>
            <Link to="/sandbox" className="text-xs text-slate-400 hover:text-slate-200 transition-colors font-medium">
              {t("nav.demo")}
            </Link>
            <button
              onClick={() => setLocale(locale === 'en' ? 'uk' : 'en')}
              className="text-xs text-slate-500 hover:text-slate-300 transition-colors font-medium px-2 py-1 rounded border border-slate-800 hover:border-slate-700"
            >
              {locale === 'en' ? 'UA' : 'EN'}
            </button>
          </nav>
        </div>
      </header>
      <div className="h-14" />

      {/* Title */}
      <section className="max-w-5xl mx-auto px-4 sm:px-8 py-10 sm:py-16">
        <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight mb-4">{t("proposal.title")}</h2>
        <p className="text-lg text-slate-400 max-w-3xl leading-relaxed">{t("proposal.subtitle")}</p>
      </section>

      {/* Problem */}
      <section className="max-w-5xl mx-auto px-4 sm:px-8 py-12 border-t border-slate-800">
        <h2 className="text-2xl sm:text-3xl font-bold mb-4">{t("proposal.problemTitle")}</h2>
        <p className="text-sm text-slate-400 leading-relaxed max-w-3xl">{t("proposal.problemDesc")}</p>
      </section>

      {/* Solution */}
      <section className="max-w-5xl mx-auto px-4 sm:px-8 py-12 border-t border-slate-800">
        <h2 className="text-2xl sm:text-3xl font-bold mb-4">{t("proposal.solutionTitle")}</h2>
        <p className="text-sm text-slate-400 leading-relaxed max-w-3xl">{t("proposal.solutionDesc")}</p>
      </section>

      {/* Proving System */}
      <section className="max-w-5xl mx-auto px-4 sm:px-8 py-12 border-t border-slate-800">
        <h2 className="text-2xl sm:text-3xl font-bold mb-4">{t("proposal.provingTitle")}</h2>
        <p className="text-sm text-slate-400 leading-relaxed max-w-3xl">{t("proposal.provingDesc")}</p>
      </section>

      {/* TSP Model */}
      <section className="max-w-5xl mx-auto px-4 sm:px-8 py-12 border-t border-slate-800">
        <h2 className="text-2xl sm:text-3xl font-bold mb-4">{t("proposal.tspTitle")}</h2>
        <p className="text-sm text-slate-400 leading-relaxed mb-8">{t("proposal.tspDesc")}</p>

        <div className="grid md:grid-cols-2 gap-6">
          {/* Service 1 */}
          <div className="bg-slate-800/50 rounded-xl border border-emerald-500/20 p-6 space-y-4">
            <h3 className="text-lg font-semibold text-emerald-400">{t("proposal.service1Title")}</h3>
            <p className="text-sm text-slate-400 leading-relaxed">{t("proposal.service1Desc")}</p>
            <code className="block bg-slate-900/80 rounded-lg px-4 py-3 text-xs font-mono text-emerald-400">
              {t("proposal.service1Endpoint")}
            </code>
          </div>

          {/* Service 2 */}
          <div className="bg-slate-800/50 rounded-xl border border-blue-500/20 p-6 space-y-4">
            <h3 className="text-lg font-semibold text-blue-400">{t("proposal.service2Title")}</h3>
            <p className="text-sm text-slate-400 leading-relaxed">{t("proposal.service2Desc")}</p>
            <code className="block bg-slate-900/80 rounded-lg px-4 py-3 text-xs font-mono text-blue-400">
              {t("proposal.service2Endpoint")}
            </code>
          </div>
        </div>
      </section>

      {/* Compliance */}
      <section className="max-w-5xl mx-auto px-4 sm:px-8 py-12 border-t border-slate-800">
        <h2 className="text-2xl sm:text-3xl font-bold mb-6">{t("proposal.complianceTitle")}</h2>
        <div className="grid sm:grid-cols-2 gap-3">
          {complianceItems.map((item: string, i: number) => (
            <div key={i} className="flex items-start gap-3 bg-slate-800/50 rounded-xl border border-slate-700/40 p-4">
              <span className="text-emerald-400 shrink-0 mt-0.5">&#10003;</span>
              <span className="text-sm text-slate-400">{item}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Cryptographic Primitives */}
      <section className="max-w-5xl mx-auto px-4 sm:px-8 py-12 border-t border-slate-800">
        <h2 className="text-2xl sm:text-3xl font-bold mb-6">{t("proposal.cryptoTitle")}</h2>
        <div className="grid gap-3">
          {cryptoItems.map((item: string, i: number) => (
            <div key={i} className="bg-slate-800/50 rounded-xl border border-slate-700/40 px-5 py-3">
              <span className="text-sm text-slate-400">{item}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Integration */}
      <section className="max-w-5xl mx-auto px-4 sm:px-8 py-12 border-t border-slate-800">
        <h2 className="text-2xl sm:text-3xl font-bold mb-4">{t("proposal.integrationTitle")}</h2>
        <p className="text-sm text-slate-400 leading-relaxed max-w-3xl">{t("proposal.integrationDesc")}</p>
      </section>

      {/* CTA */}
      <section className="max-w-5xl mx-auto px-4 sm:px-8 py-12 border-t border-slate-800 text-center">
        <Link
          to="/sandbox"
          className="inline-flex items-center gap-2 px-6 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors text-sm"
        >
          {t("proposal.tryDemo")}
        </Link>
      </section>

      {/* Footer — matches root */}
      <footer className="border-t border-slate-800 px-4 sm:px-8 py-8">
        <div className="max-w-5xl mx-auto flex items-center justify-between text-sm text-slate-500">
          <span>{t("footer.license")}</span>
          <div className="flex items-center gap-6">
            <Link to="/learn" className="hover:text-slate-300 transition-colors">{t("nav.learn")}</Link>
            <a href="https://github.com/alik-eth/zk-eidas" target="_blank" rel="noopener noreferrer" className="hover:text-slate-300 transition-colors">GitHub</a>
            <span className="font-medium tracking-wide">Alik.eth</span>
          </div>
        </div>
      </footer>
    </div>
  )
}
