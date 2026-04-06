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

  const COMPLIANCE_LINKS: Record<number, string> = {
    0: "https://eur-lex.europa.eu/eli/reg/2024/1183/oj",        // Art 5a(16)
    1: "https://eur-lex.europa.eu/eli/reg/2024/1183/oj",        // Art 45a
    2: "https://eur-lex.europa.eu/eli/reg/2024/1183/oj",        // Art 45d
    3: "https://www.iso.org/standard/69084.html",                // ISO 18013-5
    4: "https://digital-strategy.ec.europa.eu/en/library/european-digital-identity-wallet-architecture-and-reference-framework", // ARF
    5: "https://www.sogis.eu/uk/supporting_doc_en.html",         // SOG-IS
    6: "https://eur-lex.europa.eu/eli/reg/2016/679/oj",          // GDPR
  }

  const REFERENCES = [
    { label: "Regulation (EU) 2024/1183", desc: { en: "eIDAS 2.0 — amending Regulation (EU) No 910/2014", uk: "eIDAS 2.0 — зміни до Регламенту (ЄС) № 910/2014" }, url: "https://eur-lex.europa.eu/eli/reg/2024/1183/oj" },
    { label: "ARF v1.4", desc: { en: "European Digital Identity Wallet Architecture and Reference Framework", uk: "Архітектура та еталонна структура Європейського гаманця цифрової ідентичності" }, url: "https://digital-strategy.ec.europa.eu/en/library/european-digital-identity-wallet-architecture-and-reference-framework" },
    { label: "ISO 18013-5", desc: { en: "Personal identification — ISO-compliant driving licence — Part 5: Mobile driving licence (mDL)", uk: "Ідентифікація особи — Посвідчення водія за ISO — Частина 5: Мобільне посвідчення водія (mDL)" }, url: "https://www.iso.org/standard/69084.html" },
    { label: "SOG-IS", desc: { en: "Crypto Evaluation Scheme — Agreed Cryptographic Mechanisms", uk: "Схема криптографічної оцінки — Узгоджені криптографічні механізми" }, url: "https://www.sogis.eu/uk/supporting_doc_en.html" },
    { label: "NIST FIPS 203", desc: { en: "Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)", uk: "Механізм інкапсуляції ключів на базі модульних ґраток (ML-KEM)" }, url: "https://csrc.nist.gov/pubs/fips/203/final" },
    { label: "W3C VC Data Model", desc: { en: "Verifiable Credentials Data Model v2.0", uk: "Модель даних перевіряємих посвідчень v2.0" }, url: "https://www.w3.org/TR/vc-data-model-2.0/" },
    { label: "GDPR", desc: { en: "Regulation (EU) 2016/679 — General Data Protection Regulation", uk: "Регламент (ЄС) 2016/679 — Загальний регламент захисту даних" }, url: "https://eur-lex.europa.eu/eli/reg/2016/679/oj" },
    { label: "Longfellow", desc: { en: "Google's zero-knowledge proving system (Sumcheck + Ligero)", uk: "Система доведення з нульовим знанням від Google (Sumcheck + Ligero)" }, url: "https://github.com/AliKVovk/zk-eidas" },
  ]

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
            <Link to="/demo" className="text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 px-3.5 py-1.5 rounded-lg transition-colors">
              {t("nav.contracts")}
            </Link>
            <button
              onClick={() => setLocale(locale === 'en' ? 'uk' : 'en')}
              className="text-xs text-slate-500 hover:text-slate-300 transition-colors font-medium px-2 py-1 rounded border border-slate-800 hover:border-slate-700"
            >
              {locale === 'en' ? 'UA' : 'EN'}
            </button>
            <Link to="/learn" className="text-xs text-slate-400 hover:text-slate-200 transition-colors font-medium">
              {t("nav.learn")}
            </Link>
            <Link to="/verify" className="hidden sm:inline text-xs text-slate-400 hover:text-slate-200 transition-colors font-medium">
              {t("nav.verify")}
            </Link>
            <Link to="/sandbox" className="text-xs text-slate-400 hover:text-slate-200 transition-colors font-medium">
              {t("nav.demo")}
            </Link>
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
            <div className="bg-slate-900/80 rounded-lg px-4 py-3 text-xs text-emerald-400/80">
              {t("proposal.service1Endpoint")}
            </div>
          </div>

          {/* Service 2 */}
          <div className="bg-slate-800/50 rounded-xl border border-blue-500/20 p-6 space-y-4">
            <h3 className="text-lg font-semibold text-blue-400">{t("proposal.service2Title")}</h3>
            <p className="text-sm text-slate-400 leading-relaxed">{t("proposal.service2Desc")}</p>
            <div className="bg-slate-900/80 rounded-lg px-4 py-3 text-xs text-blue-400/80">
              {t("proposal.service2Endpoint")}
            </div>
          </div>
        </div>
      </section>

      {/* Compliance */}
      <section className="max-w-5xl mx-auto px-4 sm:px-8 py-12 border-t border-slate-800">
        <h2 className="text-2xl sm:text-3xl font-bold mb-6">{t("proposal.complianceTitle")}</h2>
        <div className="grid sm:grid-cols-2 gap-3">
          {complianceItems.map((item: string, i: number) => {
            const url = COMPLIANCE_LINKS[i]
            return (
              <div key={i} className="flex items-start gap-3 bg-slate-800/50 rounded-xl border border-slate-700/40 p-4">
                <span className="text-emerald-400 shrink-0 mt-0.5">&#10003;</span>
                {url ? (
                  <a href={url} target="_blank" rel="noopener noreferrer" className="text-sm text-slate-400 hover:text-slate-200 transition-colors underline decoration-slate-700 hover:decoration-slate-400">{item}</a>
                ) : (
                  <span className="text-sm text-slate-400">{item}</span>
                )}
              </div>
            )
          })}
        </div>
      </section>

      {/* Comparison Table */}
      <section className="max-w-5xl mx-auto px-4 sm:px-8 py-12 border-t border-slate-800">
        <h2 className="text-2xl sm:text-3xl font-bold mb-4">{t("proposal.comparisonTitle")}</h2>
        <p className="text-sm text-slate-400 leading-relaxed max-w-3xl mb-8">{t("proposal.comparisonSubtitle")}</p>

        <div className="overflow-x-auto -mx-4 sm:mx-0">
          <table className="w-full text-xs sm:text-sm border-collapse min-w-[540px]">
            <thead>
              <tr className="border-b border-slate-700">
                <th className="text-left py-3 px-3 text-slate-500 font-medium w-[200px]"></th>
                <th className="text-left py-3 px-3 text-slate-400 font-semibold">{t("proposal.col.batch")}</th>
                <th className="text-left py-3 px-3 text-slate-400 font-semibold">{t("proposal.col.bbs")}</th>
                <th className="text-left py-3 px-3 text-emerald-400 font-semibold">{t("proposal.col.zkeidas")}</th>
              </tr>
            </thead>
            <tbody>
              {([
                ["eidasStatus", "eidas"],
                ["selectiveDisclosure", "sd"],
                ["predicates", "predicates"],
                ["unlinkability", "unlinkability"],
                ["holderBinding", "binding"],
                ["identityEscrow", "escrow"],
                ["trustedSetup", "setup"],
                ["quantumSafe", "quantum"],
                ["issuerLoad", "issuerLoad"],
                ["holderStorage", "storage"],
                ["revocation", "revocation"],
                ["proofSize", "size"],
                ["crossBorder", "crossBorder"],
                ["auditTrail", "auditTrail"],
              ] as const).map(([rowKey, cellKey]) => (
                <tr key={rowKey} className="border-b border-slate-800/60 hover:bg-slate-800/30">
                  <td className="py-2.5 px-3 text-slate-400 font-medium">{t(`proposal.row.${rowKey}`)}</td>
                  <td className="py-2.5 px-3 text-slate-500">{t(`proposal.cell.batch.${cellKey}`)}</td>
                  <td className="py-2.5 px-3 text-slate-500">{t(`proposal.cell.bbs.${cellKey}`)}</td>
                  <td className="py-2.5 px-3 text-emerald-400/90">{t(`proposal.cell.zk.${cellKey}`)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Integration */}
      <section className="max-w-5xl mx-auto px-4 sm:px-8 py-12 border-t border-slate-800">
        <h2 className="text-2xl sm:text-3xl font-bold mb-4">{t("proposal.integrationTitle")}</h2>
        <p className="text-sm text-slate-400 leading-relaxed max-w-3xl">{t("proposal.integrationDesc")}</p>
      </section>

      {/* References */}
      <section className="max-w-5xl mx-auto px-4 sm:px-8 py-12 border-t border-slate-800">
        <h2 className="text-2xl sm:text-3xl font-bold mb-6">{locale === 'en' ? 'References' : 'Посилання'}</h2>
        <div className="grid gap-2">
          {REFERENCES.map((ref, i) => (
            <a
              key={i}
              href={ref.url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-baseline gap-3 bg-slate-800/50 rounded-lg border border-slate-700/40 px-5 py-3 hover:border-slate-600 transition-colors group"
            >
              <span className="text-sm font-semibold text-blue-400 group-hover:text-blue-300 shrink-0">{ref.label}</span>
              <span className="text-sm text-slate-500 group-hover:text-slate-400">— {ref.desc[locale]}</span>
              <span className="text-slate-600 group-hover:text-slate-400 ml-auto shrink-0 text-xs">&#x2197;</span>
            </a>
          ))}
        </div>
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
