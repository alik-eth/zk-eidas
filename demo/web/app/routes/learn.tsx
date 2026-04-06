import { createFileRoute, Link } from "@tanstack/react-router";
import { useState, useEffect, useRef } from "react";
import { useT, useLocale } from "../i18n";

export const Route = createFileRoute("/learn")({
  component: Learn,
});

/* ── Small reusable components ─────────────────────────────────────────── */

function StatusIcon({ status }: { status: "yes" | "no" | "partial" }) {
  if (status === "yes")
    return <span className="text-green-400 font-bold">&#10003;</span>;
  if (status === "no")
    return <span className="text-red-400 font-bold">&#10007;</span>;
  return <span className="text-yellow-400 font-bold">&#9888;</span>;
}

/* Stage color accents for visual variety */
const STAGE_COLORS = [
  "border-blue-500/20",      // 1. Credential
  "border-amber-500/20",     // 2. Parse
  "border-emerald-500/20",   // 3. Prove
  "border-purple-500/20",    // 4. Store
  "border-yellow-500/20",    // 5. Attest
  "border-cyan-500/20",      // 6. Verify
  "border-red-500/20",       // 7. Escrow Opening
] as const;

const STAGE_TITLE_COLORS = [
  "text-blue-400",
  "text-amber-400",
  "text-emerald-400",
  "text-purple-400",
  "text-yellow-400",
  "text-cyan-400",
  "text-red-400",
] as const;

/* ── Main component ────────────────────────────────────────────────────── */

function Learn() {
  const t = useT();
  const { locale, setLocale } = useLocale();
  const [headerVisible, setHeaderVisible] = useState(true);
  const lastScrollY = useRef(0);

  useEffect(() => {
    const onScroll = () => {
      const y = window.scrollY;
      setHeaderVisible(y < 50 || y < lastScrollY.current);
      lastScrollY.current = y;
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const stages = [
    { id: "credential", title: t("learn.stage1Title"), desc: t("learn.stage1Desc") },
    { id: "parse", title: t("learn.stage2Title"), desc: t("learn.stage2Desc") },
    { id: "prove", title: t("learn.stage3Title"), desc: t("learn.stage3Desc"), extra: [t("learn.stage3Nullifier"), t("learn.stage3Predicates")] },
    { id: "store", title: t("learn.stage4Title"), desc: t("learn.stage4Desc") },
    { id: "attest", title: t("learn.stage5Title"), desc: t("learn.stage5Desc") },
    { id: "verify", title: t("learn.stage6Title"), desc: t("learn.stage6Desc") },
    { id: "escrow-opening", title: t("learn.stage7Title"), desc: t("learn.stage7Desc") },
  ];

  const tocItems = [
    ...stages.map((s) => ({ href: `#${s.id}`, label: s.title.replace(/^\d+\.\s*/, "") })),
    { href: "#standards", label: t("learn.tocStandards") },
    { href: "#comparison", label: t("learn.tocComparison") },
  ];

  return (
    <div className="min-h-screen bg-slate-900 text-white">
      {/* Navigation — matches root */}
      <header
        className="border-b border-slate-800 px-4 sm:px-8 py-4 pt-[max(1rem,env(safe-area-inset-top))] bg-slate-950/80 backdrop-blur-md fixed top-0 left-0 right-0 z-10 overflow-x-hidden transition-transform duration-300"
        style={{ transform: headerVisible ? "translateY(0)" : "translateY(-100%)" }}
      >
        <div className="max-w-5xl mx-auto flex items-center justify-between gap-2">
          <Link to="/" className="flex items-center gap-3 shrink-0">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-600 to-blue-700 flex items-center justify-center">
              <span className="text-xs font-bold text-white tracking-tighter">zk</span>
            </div>
            <div>
              <span className="text-sm font-semibold tracking-tight leading-none">
                <span style={{ color: "#005BBB" }}>zk</span>
                <span className="text-slate-600 mx-0.5">-</span>
                <span style={{ color: "#FFD500" }}>eidas</span>
              </span>
            </div>
          </Link>
          <nav className="flex items-center gap-2 sm:gap-4 flex-wrap justify-end">
            <Link to="/proposal" className="text-xs text-slate-400 hover:text-slate-200 transition-colors font-medium">
              {t("nav.proposal")}
            </Link>
            <Link to="/sandbox" className="text-xs text-slate-400 hover:text-slate-200 transition-colors font-medium">
              {t("nav.demo")}
            </Link>
            <button
              onClick={() => setLocale(locale === "uk" ? "en" : "uk")}
              className="text-xs text-slate-500 hover:text-slate-300 transition-colors font-medium px-2 py-1 rounded border border-slate-800 hover:border-slate-700"
            >
              {locale === "uk" ? "EN" : "UA"}
            </button>
          </nav>
        </div>
      </header>
      <div className="h-14" />

      {/* Title + TOC */}
      <section className="max-w-5xl mx-auto px-4 sm:px-8 py-10 sm:py-16">
        <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight mb-4">
          {t("learn.pipelineTitle")}
        </h2>
        <p className="text-lg text-slate-400 max-w-3xl leading-relaxed mb-10">
          {t("learn.pipelineSubtitle")}
        </p>
        <nav className="flex flex-wrap gap-2 text-sm">
          {tocItems.map((item) => (
            <a
              key={item.href}
              href={item.href}
              className="px-3 py-1.5 rounded-full bg-slate-800/60 border border-slate-700/50 text-slate-400 hover:text-white hover:border-slate-600 transition-colors"
            >
              {item.label}
            </a>
          ))}
        </nav>
      </section>

      {/* 7 Stages */}
      <div className="max-w-5xl mx-auto px-4 sm:px-8 pb-24">
        {stages.map((stage, i) => (
          <section
            key={stage.id}
            id={stage.id}
            className="py-12 border-t border-slate-800 scroll-mt-24"
          >
            <h2 className={`text-2xl sm:text-3xl font-bold mb-6 ${STAGE_TITLE_COLORS[i]}`}>
              {stage.title}
            </h2>
            <div className={`bg-slate-800/50 rounded-xl border ${STAGE_COLORS[i]} p-6 space-y-4`}>
              <p className="text-sm text-slate-400 leading-relaxed">{stage.desc}</p>
              {stage.extra?.map((text, j) => (
                <div key={j} className="border-t border-slate-700/40 pt-4">
                  <p className={`${j === (stage.extra!.length - 1) ? 'text-slate-500 text-xs' : 'text-sm text-slate-400'} leading-relaxed`}>
                    {text}
                  </p>
                </div>
              ))}
            </div>
          </section>
        ))}

        {/* ── Standards & Compliance ────────────────────────────────────── */}
        <section id="standards" className="py-12 border-t border-slate-800 scroll-mt-24">
          <h2 className="text-2xl sm:text-3xl font-bold mb-4">
            {t("learn.standardsTitle")}
          </h2>
          <p className="text-sm text-slate-400 leading-relaxed mb-8 max-w-3xl">
            {t("learn.standardsSubtitle")}
          </p>

          <div className="space-y-3">
            {[
              { standard: "eIDAS 2.0", full: t("learn.stdEidas"), href: "https://eur-lex.europa.eu/eli/reg/2024/1183/oj/eng" },
              { standard: "SD-JWT (RFC 9901) / SD-JWT VC", full: t("learn.stdSdjwt"), href: "https://datatracker.ietf.org/doc/rfc9901/" },
              { standard: "mdoc / mDL (ISO 18013-5)", full: t("learn.stdMdoc"), href: "https://www.iso.org/standard/69084.html" },
              { standard: "ECDSA P-256 (secp256r1)", full: t("learn.stdEcdsa") },
              { standard: "OpenID4VP", full: t("learn.stdOpenid"), href: "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html" },
              { standard: "EUDI Wallet ARF v1.4", full: t("learn.stdArf"), href: "https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework" },
              { standard: "SOG-IS Compliance", full: t("learn.stdSogis"), href: "https://www.sogis.eu/uk/supporting_doc_en.html" },
              { standard: "POTENTIAL LSP", full: t("learn.stdPotential"), href: "https://www.digital-identity-wallet.eu/" },
            ].map((s) => (
              <div
                key={s.standard}
                className="flex gap-4 items-start bg-slate-800/50 rounded-xl border border-slate-700/40 p-4"
              >
                <span className="text-emerald-400 shrink-0 mt-0.5">&#10003;</span>
                <div>
                  {s.href ? (
                    <a
                      href={s.href}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sm font-semibold text-white hover:text-blue-400 transition-colors underline underline-offset-2 decoration-slate-600 hover:decoration-blue-400"
                    >
                      {s.standard}
                    </a>
                  ) : (
                    <span className="text-sm font-semibold text-white">{s.standard}</span>
                  )}
                  <p className="text-sm text-slate-400 mt-1 leading-relaxed">{s.full}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* ── Comparison Table ──────────────────────────────────────────── */}
        <section id="comparison" className="py-12 border-t border-slate-800 scroll-mt-24">
          <h2 className="text-2xl sm:text-3xl font-bold mb-4">
            {t("learn.comparisonTitle")}
          </h2>
          <p className="text-sm text-slate-400 leading-relaxed mb-8 max-w-3xl">
            {t("learn.comparisonSubtitle")}
          </p>

          <div className="overflow-x-auto mb-6">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700">
                  <th className="text-left py-3 px-3 text-slate-400 font-semibold">{t("learn.compCriterion")}</th>
                  <th className="text-left py-3 px-3 text-slate-400 font-semibold">{t("learn.compSdjwt")}</th>
                  <th className="text-left py-3 px-3 text-slate-400 font-semibold">{t("learn.compBbs")}</th>
                  <th className="text-left py-3 px-3 text-slate-400 font-semibold">{t("learn.compBatch")}</th>
                  <th className="text-left py-3 px-3 font-semibold border-x border-blue-500/20" style={{ color: "#FFD500" }}>{t("learn.compZk")}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                <tr className="hover:bg-slate-800/50">
                  <td className="py-3 px-3 text-slate-300 font-medium">{t("learn.compUnlinkability")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="no" /> {t("learn.compUnlinkSdjwt")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="yes" /> {t("learn.compUnlinkBbs")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="partial" /> {t("learn.compUnlinkBatch")}</td>
                  <td className="py-3 px-3 text-slate-300 border-x border-blue-500/20"><StatusIcon status="yes" /> {t("learn.compUnlinkZk")}</td>
                </tr>
                <tr className="hover:bg-slate-800/50">
                  <td className="py-3 px-3 text-slate-300 font-medium">{t("learn.compSelective")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="yes" /> {t("learn.compSelectSdjwt")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="yes" /> {t("learn.compSelectBbs")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="no" /> {t("learn.compSelectBatch")}</td>
                  <td className="py-3 px-3 text-slate-300 border-x border-blue-500/20"><StatusIcon status="yes" /> {t("learn.compSelectZk")}</td>
                </tr>
                <tr className="hover:bg-slate-800/50">
                  <td className="py-3 px-3 text-slate-300 font-medium">{t("learn.compPredicates")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="no" /> {t("learn.compPredReveals")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="no" /> {t("learn.compPredReveals")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="no" /> {t("learn.compPredReveals")}</td>
                  <td className="py-3 px-3 text-slate-300 border-x border-blue-500/20"><StatusIcon status="yes" /> {t("learn.compPredZk")}</td>
                </tr>
                <tr className="hover:bg-slate-800/50">
                  <td className="py-3 px-3 text-slate-300 font-medium">{t("learn.compSogis")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="yes" /> {t("learn.compSogisSdjwt")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="no" /> {t("learn.compSogisBbs")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="yes" /> {t("learn.compSogisBatch")}</td>
                  <td className="py-3 px-3 text-slate-300 border-x border-blue-500/20"><StatusIcon status="yes" /> {t("learn.compSogisZk")}</td>
                </tr>
                <tr className="hover:bg-slate-800/50">
                  <td className="py-3 px-3 text-slate-300 font-medium">{t("learn.compOffline")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="yes" /></td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="yes" /></td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="yes" /></td>
                  <td className="py-3 px-3 text-slate-300 border-x border-blue-500/20"><StatusIcon status="yes" /></td>
                </tr>
                <tr className="hover:bg-slate-800/50">
                  <td className="py-3 px-3 text-slate-300 font-medium">{t("learn.compFormat")}</td>
                  <td className="py-3 px-3 text-slate-400">{t("learn.compFormatSdjwt")}</td>
                  <td className="py-3 px-3 text-slate-400">{t("learn.compFormatBbs")}</td>
                  <td className="py-3 px-3 text-slate-400">{t("learn.compFormatBatch")}</td>
                  <td className="py-3 px-3 text-slate-300 border-x border-blue-500/20">{t("learn.compFormatZk")}</td>
                </tr>
                <tr className="hover:bg-slate-800/50">
                  <td className="py-3 px-3 text-slate-300 font-medium">{t("learn.compSize")}</td>
                  <td className="py-3 px-3 text-slate-400">{t("learn.compSizeFull")}</td>
                  <td className="py-3 px-3 text-slate-400">{t("learn.compSizeBbs")}</td>
                  <td className="py-3 px-3 text-slate-400">{t("learn.compSizeFull")}</td>
                  <td className="py-3 px-3 text-slate-300 border-x border-blue-500/20">{t("learn.compSizeZk")}</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div className="space-y-2 text-xs text-slate-500">
            <p>{t("learn.compFootSdjwt")}</p>
            <p>{t("learn.compFootBbs")}</p>
            <p>{t("learn.compFootBatch")}</p>
          </div>
        </section>

        {/* ── GDPR: Privacy by Design ───────────────────────────────────── */}
        <section id="privacy" className="py-12 border-t border-slate-800 scroll-mt-24">
          <h2 className="text-2xl sm:text-3xl font-bold mb-6">{t("learn.privacyTitle")}</h2>

          <div className="bg-slate-800/50 rounded-xl border border-slate-700/40 p-6 sm:p-8">
            <p className="text-sm text-slate-400 leading-relaxed mb-6">
              {t("learn.privacyDesc")}
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {[
                { principle: t("learn.privacyMinimization"), desc: t("learn.privacyMinimizationDesc") },
                { principle: t("learn.privacyLimitation"), desc: t("learn.privacyLimitationDesc") },
                { principle: t("learn.privacyStorage"), desc: t("learn.privacyStorageDesc") },
              ].map((p) => (
                <div key={p.principle} className="text-center">
                  <h4 className="text-sm font-semibold mb-1" style={{ color: "#FFD500" }}>
                    {p.principle}
                  </h4>
                  <p className="text-xs text-slate-500">{p.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── CTA ─────────────────────────────────────────────────────── */}
        <section className="py-12 border-t border-slate-800 text-center">
          <Link
            to="/sandbox"
            className="inline-flex items-center gap-2 px-6 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors text-sm"
          >
            {t("learn.cta")}
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="9 18 15 12 9 6" />
            </svg>
          </Link>
        </section>
      </div>

      {/* Footer — matches root */}
      <footer className="border-t border-slate-800 px-4 sm:px-8 py-8">
        <div className="max-w-5xl mx-auto flex items-center justify-between text-sm text-slate-500">
          <span>{t("footer.license")}</span>
          <div className="flex items-center gap-6">
            <Link to="/proposal" className="hover:text-slate-300 transition-colors">{t("nav.proposal")}</Link>
            <a href="https://github.com/alik-eth/zk-eidas" target="_blank" rel="noopener noreferrer" className="hover:text-slate-300 transition-colors">GitHub</a>
            <span className="font-medium tracking-wide">Alik.eth</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
