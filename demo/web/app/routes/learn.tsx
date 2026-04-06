import { createFileRoute, Link } from "@tanstack/react-router";
import { useT } from "../i18n";

export const Route = createFileRoute("/learn")({
  component: Learn,
});

/* ── Small reusable components ─────────────────────────────────────────── */

function SectionHeading({
  id,
  title,
  subtitle,
}: {
  id: string;
  title: string;
  subtitle?: string;
}) {
  return (
    <div className="mb-10" id={id}>
      <h2 className="text-2xl sm:text-3xl font-bold mb-3">{title}</h2>
      {subtitle && (
        <p className="text-slate-400 leading-relaxed max-w-3xl">{subtitle}</p>
      )}
    </div>
  );
}

function StatusIcon({ status }: { status: "yes" | "no" | "partial" }) {
  if (status === "yes")
    return <span className="text-green-400 font-bold">✓</span>;
  if (status === "no")
    return <span className="text-red-400 font-bold">✗</span>;
  return <span className="text-yellow-400 font-bold">⚠</span>;
}

/* ── Main component ────────────────────────────────────────────────────── */

function Learn() {
  const t = useT();

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      {/* Header */}
      <header className="max-w-4xl mx-auto px-4 sm:px-8 pt-8 pb-4">
        <Link
          to="/"
          className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-white transition-colors"
        >
          <svg
            className="w-4 h-4"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <polyline points="15 18 9 12 15 6" />
          </svg>
          {t("learn.back")}
        </Link>
      </header>

      {/* Title + TOC */}
      <section className="max-w-4xl mx-auto px-4 sm:px-8 pt-8 pb-16">
        <h1 className="text-3xl sm:text-5xl font-bold mb-4">
          {t("learn.pipelineTitle")}
        </h1>
        <p className="text-lg text-slate-400 max-w-3xl leading-relaxed mb-10">
          {t("learn.pipelineSubtitle")}
        </p>
        <nav className="flex flex-wrap gap-3 text-sm">
          {[
            { href: "#credential", label: t("learn.tocStage1") },
            { href: "#parse", label: t("learn.tocStage2") },
            { href: "#prove", label: t("learn.tocStage3") },
            { href: "#store", label: t("learn.tocStage4") },
            { href: "#attest", label: t("learn.tocStage5") },
            { href: "#verify", label: t("learn.tocStage6") },
            { href: "#escrow-opening", label: t("learn.tocStage7") },
            { href: "#standards", label: t("learn.tocStandards") },
            { href: "#comparison", label: t("learn.tocComparison") },
          ].map((item) => (
            <a
              key={item.href}
              href={item.href}
              className="px-3 py-1.5 rounded-full bg-slate-800 border border-slate-700/50 text-slate-400 hover:text-white hover:border-slate-600 transition-colors"
            >
              {item.label}
            </a>
          ))}
        </nav>
      </section>

      <div className="max-w-4xl mx-auto px-4 sm:px-8 space-y-24 pb-24">
        {/* Stage 1: Credential */}
        <section id="credential" className="scroll-mt-24">
          <SectionHeading id="credential-heading" title={t("learn.stage1Title")} />
          <div className="bg-slate-800/50 rounded-xl border border-slate-700/40 p-6">
            <p className="text-slate-300 leading-relaxed">{t("learn.stage1Desc")}</p>
          </div>
        </section>

        {/* Stage 2: Parse */}
        <section id="parse" className="scroll-mt-24">
          <SectionHeading id="parse-heading" title={t("learn.stage2Title")} />
          <div className="bg-slate-800/50 rounded-xl border border-slate-700/40 p-6">
            <p className="text-slate-300 leading-relaxed">{t("learn.stage2Desc")}</p>
          </div>
        </section>

        {/* Stage 3: Prove */}
        <section id="prove" className="scroll-mt-24">
          <SectionHeading id="prove-heading" title={t("learn.stage3Title")} />
          <div className="bg-slate-800/50 rounded-xl border border-slate-700/40 p-6 space-y-4">
            <p className="text-slate-300 leading-relaxed">{t("learn.stage3Desc")}</p>
            <div className="border-t border-slate-700/40 pt-4">
              <p className="text-slate-300 leading-relaxed">{t("learn.stage3Nullifier")}</p>
            </div>
            <div className="border-t border-slate-700/40 pt-4">
              <p className="text-slate-400 text-sm leading-relaxed">{t("learn.stage3Predicates")}</p>
            </div>
          </div>
        </section>

        {/* Stage 4: Store */}
        <section id="store" className="scroll-mt-24">
          <SectionHeading id="store-heading" title={t("learn.stage4Title")} />
          <div className="bg-slate-800/50 rounded-xl border border-slate-700/40 p-6">
            <p className="text-slate-300 leading-relaxed">{t("learn.stage4Desc")}</p>
          </div>
        </section>

        {/* Stage 5: Attest */}
        <section id="attest" className="scroll-mt-24">
          <SectionHeading id="attest-heading" title={t("learn.stage5Title")} />
          <div className="bg-slate-800/50 rounded-xl border border-slate-700/40 p-6">
            <p className="text-slate-300 leading-relaxed">{t("learn.stage5Desc")}</p>
          </div>
        </section>

        {/* Stage 6: Verify */}
        <section id="verify" className="scroll-mt-24">
          <SectionHeading id="verify-heading" title={t("learn.stage6Title")} />
          <div className="bg-slate-800/50 rounded-xl border border-slate-700/40 p-6">
            <p className="text-slate-300 leading-relaxed">{t("learn.stage6Desc")}</p>
          </div>
        </section>

        {/* Stage 7: Escrow Opening */}
        <section id="escrow-opening" className="scroll-mt-24">
          <SectionHeading id="escrow-opening-heading" title={t("learn.stage7Title")} />
          <div className="bg-slate-800/50 rounded-xl border border-slate-700/40 p-6">
            <p className="text-slate-300 leading-relaxed">{t("learn.stage7Desc")}</p>
          </div>
        </section>

        {/* ── Standards & Compliance ────────────────────────────────────── */}
        <section>
          <SectionHeading
            id="standards"
            title={t("learn.standardsTitle")}
            subtitle={t("learn.standardsSubtitle")}
          />

          <div className="space-y-4">
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
                className="flex gap-4 items-start bg-slate-800/50 rounded-xl border border-slate-700/50 p-4"
              >
                <span className="text-green-400 shrink-0 mt-0.5">&#10003;</span>
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
                    <span className="text-sm font-semibold text-white">
                      {s.standard}
                    </span>
                  )}
                  <p className="text-sm text-slate-400 mt-1 leading-relaxed">
                    {s.full}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* ── Comparison Table ──────────────────────────────────────────── */}
        <section>
          <SectionHeading
            id="comparison"
            title={t("learn.comparisonTitle")}
            subtitle={t("learn.comparisonSubtitle")}
          />

          <div className="overflow-x-auto mb-6">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700">
                  <th className="text-left py-3 px-3 text-slate-400 font-semibold">
                    {t("learn.compCriterion")}
                  </th>
                  <th className="text-left py-3 px-3 text-slate-400 font-semibold">
                    {t("learn.compSdjwt")}
                  </th>
                  <th className="text-left py-3 px-3 text-slate-400 font-semibold">
                    {t("learn.compBbs")}
                  </th>
                  <th className="text-left py-3 px-3 text-slate-400 font-semibold">
                    {t("learn.compBatch")}
                  </th>
                  <th
                    className="text-left py-3 px-3 font-semibold border-x border-blue-500/20"
                    style={{ color: "#FFD500" }}
                  >
                    {t("learn.compZk")}
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {/* Unlinkability */}
                <tr className="hover:bg-slate-800/50">
                  <td className="py-3 px-3 text-slate-300 font-medium">{t("learn.compUnlinkability")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="no" /> {t("learn.compUnlinkSdjwt")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="yes" /> {t("learn.compUnlinkBbs")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="partial" /> {t("learn.compUnlinkBatch")}</td>
                  <td className="py-3 px-3 text-slate-300 border-x border-blue-500/20"><StatusIcon status="yes" /> {t("learn.compUnlinkZk")}</td>
                </tr>
                {/* Selective Disclosure */}
                <tr className="hover:bg-slate-800/50">
                  <td className="py-3 px-3 text-slate-300 font-medium">{t("learn.compSelective")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="yes" /> {t("learn.compSelectSdjwt")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="yes" /> {t("learn.compSelectBbs")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="no" /> {t("learn.compSelectBatch")}</td>
                  <td className="py-3 px-3 text-slate-300 border-x border-blue-500/20"><StatusIcon status="yes" /> {t("learn.compSelectZk")}</td>
                </tr>
                {/* Predicates */}
                <tr className="hover:bg-slate-800/50">
                  <td className="py-3 px-3 text-slate-300 font-medium">{t("learn.compPredicates")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="no" /> {t("learn.compPredReveals")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="no" /> {t("learn.compPredReveals")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="no" /> {t("learn.compPredReveals")}</td>
                  <td className="py-3 px-3 text-slate-300 border-x border-blue-500/20"><StatusIcon status="yes" /> {t("learn.compPredZk")}</td>
                </tr>
                {/* SOG-IS */}
                <tr className="hover:bg-slate-800/50">
                  <td className="py-3 px-3 text-slate-300 font-medium">{t("learn.compSogis")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="yes" /> {t("learn.compSogisSdjwt")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="no" /> {t("learn.compSogisBbs")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="yes" /> {t("learn.compSogisBatch")}</td>
                  <td className="py-3 px-3 text-slate-300 border-x border-blue-500/20"><StatusIcon status="yes" /> {t("learn.compSogisZk")}</td>
                </tr>
                {/* Offline */}
                <tr className="hover:bg-slate-800/50">
                  <td className="py-3 px-3 text-slate-300 font-medium">{t("learn.compOffline")}</td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="yes" /></td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="yes" /></td>
                  <td className="py-3 px-3 text-slate-400"><StatusIcon status="yes" /></td>
                  <td className="py-3 px-3 text-slate-300 border-x border-blue-500/20"><StatusIcon status="yes" /></td>
                </tr>
                {/* Format */}
                <tr className="hover:bg-slate-800/50">
                  <td className="py-3 px-3 text-slate-300 font-medium">{t("learn.compFormat")}</td>
                  <td className="py-3 px-3 text-slate-400">{t("learn.compFormatSdjwt")}</td>
                  <td className="py-3 px-3 text-slate-400">{t("learn.compFormatBbs")}</td>
                  <td className="py-3 px-3 text-slate-400">{t("learn.compFormatBatch")}</td>
                  <td className="py-3 px-3 text-slate-300 border-x border-blue-500/20">{t("learn.compFormatZk")}</td>
                </tr>
                {/* Proof Size */}
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
        <section>
          <SectionHeading id="privacy" title={t("learn.privacyTitle")} />

          <div className="bg-slate-800 rounded-xl border border-slate-700 p-6 sm:p-8">
            <p className="text-slate-300 leading-relaxed mb-6">
              {t("learn.privacyDesc")}
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {[
                { principle: t("learn.privacyMinimization"), desc: t("learn.privacyMinimizationDesc") },
                { principle: t("learn.privacyLimitation"), desc: t("learn.privacyLimitationDesc") },
                { principle: t("learn.privacyStorage"), desc: t("learn.privacyStorageDesc") },
              ].map((p) => (
                <div key={p.principle} className="text-center">
                  <h4
                    className="text-sm font-semibold mb-1"
                    style={{ color: "#FFD500" }}
                  >
                    {p.principle}
                  </h4>
                  <p className="text-sm text-slate-400">{p.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── CTA ─────────────────────────────────────────────────────── */}
        <section className="text-center py-8">
          <Link
            to="/sandbox"
            className="inline-flex items-center gap-2 px-6 py-3 rounded-lg font-semibold transition-colors"
            style={{ backgroundColor: "#FFD500", color: "#0f172a" }}
          >
            {t("learn.cta")}
            <svg
              className="w-4 h-4"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <polyline points="9 18 15 12 9 6" />
            </svg>
          </Link>
        </section>
      </div>
    </div>
  );
}
