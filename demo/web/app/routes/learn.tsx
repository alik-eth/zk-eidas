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

function PipelineStep({
  num,
  title,
  description,
}: {
  num: number;
  title: string;
  description: string;
}) {
  return (
    <div className="relative pl-12">
      <div
        className="absolute left-0 top-0 w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold border border-blue-500/40 text-blue-400"
        style={{ backgroundColor: "rgba(59, 130, 246, 0.08)" }}
      >
        {num}
      </div>
      {title && <h4 className="text-lg font-semibold mb-1">{title}</h4>}
      <p className="text-slate-400 leading-relaxed">{description}</p>
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
          {t("learn.title")}
        </h1>
        <p className="text-lg text-slate-400 max-w-3xl leading-relaxed mb-10">
          {t("learn.subtitle")}
        </p>
        <nav className="flex flex-wrap gap-3 text-sm">
          {[
            { href: "#problem", label: t("learn.tocProblem") },
            { href: "#why-zk", label: t("learn.tocWhyZk") },
            { href: "#comparison", label: t("learn.tocComparison") },
            { href: "#trust-gap", label: t("learn.tocTrustGap") },
            { href: "#how-it-works", label: t("learn.tocHowItWorks") },
            { href: "#capabilities", label: t("learn.tocCapabilities") },
            { href: "#escrow", label: t("learn.tocEscrow") },
            { href: "#attestation", label: t("learn.tocAttestation") },
            { href: "#standards", label: t("learn.tocStandards") },
            { href: "#privacy", label: t("learn.tocPrivacy") },
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
        {/* ── 1. The eIDAS 2.0 Unlinkability Problem ───────────────────── */}
        <section>
          <div className="mb-10" id="problem">
            <h2 className="text-2xl sm:text-3xl font-bold mb-3">{t("learn.problemTitle")}</h2>
            <p className="text-slate-400 leading-relaxed max-w-3xl">
              <a
                href="https://eur-lex.europa.eu/eli/reg/2024/1183/oj/eng"
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-400 hover:text-blue-300 underline underline-offset-2"
              >
                Article 5a(16)
              </a>{" "}
              {t("learn.problemSubtitleAfterLink")}
            </p>
          </div>

          {/* Two-card comparison */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            {/* SD-JWT VC */}
            <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
              <h4 className="text-sm font-semibold mb-4 text-slate-400 uppercase tracking-wider">
                {t("learn.problemSdjwtLabel")}
              </h4>
              <div className="bg-slate-900 rounded-lg p-3 font-mono text-xs space-y-1">
                <div className="text-slate-500">{t("learn.problemSdjwtSees")}</div>
                <div className="text-red-400">
                  signature: eyJhbGci...{" "}
                  <span className="text-slate-600">← {t("learn.problemSdjwtSig")}</span>
                </div>
                <div className="text-red-400">
                  cnf: {"{"}jwk: ...{"}"}{" "}
                  <span className="text-slate-600">← {t("learn.problemSdjwtCnf")}</span>
                </div>
                <div className="text-green-400">
                  age_over_18: true{" "}
                  <span className="text-slate-600">← {t("learn.problemSdjwtClaim")}</span>
                </div>
                <div className="text-slate-600">
                  name: [redacted]{" "}
                  <span className="text-slate-600">← {t("learn.problemSdjwtHidden")}</span>
                </div>
              </div>
            </div>

            {/* zk-eidas */}
            <div
              className="bg-slate-800 rounded-xl border border-blue-700/40 p-6"
              style={{ boxShadow: "0 0 20px rgba(59,130,246,0.06)" }}
            >
              <h4
                className="text-sm font-semibold mb-4 uppercase tracking-wider"
                style={{ color: "#FFD500" }}
              >
                {t("learn.problemZkLabel")}
              </h4>
              <div className="bg-slate-900 rounded-lg p-3 font-mono text-xs space-y-1">
                <div className="text-slate-500">{t("learn.problemZkSees")}</div>
                <div className="text-green-400">
                  age &gt;= 18: true{" "}
                  <span className="text-slate-600">← {t("learn.problemZkResult")}</span>
                </div>
                <div className="text-green-400">
                  signature_valid: true{" "}
                  <span className="text-slate-600">← {t("learn.problemZkSigValid")}</span>
                </div>
                <div className="text-green-400">
                  nullifier: 0xa7f3…{" "}
                  <span className="text-slate-600">← {t("learn.problemZkNullifier")}</span>
                </div>
                <div className="text-slate-600">
                  name: ████████{" "}
                  <span className="text-slate-500">← {t("learn.problemZkHidden")}</span>
                </div>
                <div className="text-slate-600">
                  signature: ████████{" "}
                  <span className="text-slate-500">← {t("learn.problemZkSigHidden")}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Three failure modes */}
          <div className="space-y-4 mb-8">
            {[
              { title: t("learn.problemSdjwtTitle"), desc: t("learn.problemSdjwtDesc"), href: "https://datatracker.ietf.org/doc/rfc9901/" },
              { title: t("learn.problemBbsTitle"), desc: t("learn.problemBbsDesc"), href: "https://www.sogis.eu/uk/supporting_doc_en.html" },
              { title: t("learn.problemBatchTitle"), desc: t("learn.problemBatchDesc") },
            ].map((item) => (
              <div
                key={item.title}
                className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-4"
              >
                <h4 className="text-sm font-semibold mb-1 text-slate-200">
                  {item.title}
                  {item.href && (
                    <a
                      href={item.href}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="ml-2 text-xs text-slate-500 hover:text-blue-400 transition-colors"
                    >
                      ↗
                    </a>
                  )}
                </h4>
                <p className="text-sm text-slate-400 leading-relaxed">
                  {item.desc}
                </p>
              </div>
            ))}
          </div>

          <p className="text-slate-300 font-medium text-center italic">
            {t("learn.problemClosing")}
          </p>
        </section>

        {/* ── 2. Why Only ZK Works ─────────────────────────────────────── */}
        <section>
          <SectionHeading
            id="why-zk"
            title={t("learn.whyZkTitle")}
          />

          <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-6 sm:p-8 mb-8">
            <p className="text-slate-300 leading-relaxed text-lg">
              {t("learn.whyZkDesc")}
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
            {[
              { property: t("learn.whyZkCompleteness"), desc: t("learn.whyZkCompletenessDesc") },
              { property: t("learn.whyZkSoundness"), desc: t("learn.whyZkSoundnessDesc") },
              { property: t("learn.whyZkZeroKnowledge"), desc: t("learn.whyZkZeroKnowledgeDesc") },
            ].map((p) => (
              <div
                key={p.property}
                className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-4"
              >
                <h4
                  className="text-sm font-semibold mb-2"
                  style={{ color: "#FFD500" }}
                >
                  {p.property}
                </h4>
                <p className="text-sm text-slate-400 leading-relaxed">
                  {p.desc}
                </p>
              </div>
            ))}
          </div>

          <p className="text-slate-300 font-medium text-center italic">
            {t("learn.whyZkClosing")}
          </p>
        </section>

        {/* ── 3. Comparison Table ──────────────────────────────────────── */}
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

        {/* ── 4. The Trust Gap ─────────────────────────────────────────── */}
        <section>
          <SectionHeading
            id="trust-gap"
            title={t("learn.trustGapTitle")}
            subtitle={t("learn.trustGapSubtitle")}
          />

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            {/* Typical ZK */}
            <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
              <h4 className="text-sm font-semibold mb-4 text-slate-400 uppercase tracking-wider">
                {t("learn.trustGapTypical")}
              </h4>
              <ul className="space-y-3 text-sm text-slate-400">
                <li className="flex gap-2">
                  <span className="text-red-400 shrink-0">1.</span>
                  {t("learn.trustGapTyp1")}
                </li>
                <li className="flex gap-2">
                  <span className="text-red-400 shrink-0">2.</span>
                  {t("learn.trustGapTyp2")}
                </li>
                <li className="flex gap-2">
                  <span className="text-red-400 shrink-0">3.</span>
                  {t("learn.trustGapTyp3")}
                </li>
                <li className="flex gap-2">
                  <span className="text-red-400 shrink-0">4.</span>
                  {t("learn.trustGapTyp4")}
                </li>
                <li className="text-red-300 italic mt-2">
                  {t("learn.trustGapTyp5")}
                </li>
              </ul>
            </div>

            {/* zk-eidas */}
            <div
              className="bg-slate-800 rounded-xl border border-blue-700/40 p-6"
              style={{ boxShadow: "0 0 20px rgba(59,130,246,0.06)" }}
            >
              <h4
                className="text-sm font-semibold mb-4 uppercase tracking-wider"
                style={{ color: "#FFD500" }}
              >
                {t("learn.trustGapZkTitle")}
              </h4>
              <ul className="space-y-3 text-sm text-slate-300">
                <li className="flex gap-2">
                  <span className="text-green-400 shrink-0">✓</span>
                  {t("learn.trustGapZk1")}
                </li>
                <li className="flex gap-2">
                  <span className="text-green-400 shrink-0">✓</span>
                  {t("learn.trustGapZk2")}
                </li>
                <li className="flex gap-2">
                  <span className="text-green-400 shrink-0">✓</span>
                  {t("learn.trustGapZk3")}
                </li>
              </ul>

              {/* Chain diagram — vertical to fit in half-width card */}
              <div className="mt-4 bg-slate-900 rounded-lg p-3 border border-blue-500/20">
                <div className="flex flex-col items-center gap-1 text-xs font-mono text-blue-400">
                  {t("learn.trustGapChain").split("→").map((part, i, arr) => (
                    <div key={i} className="flex flex-col items-center">
                      <span className="bg-slate-800 border border-blue-500/30 rounded px-3 py-1 text-center w-full max-w-48">
                        {part.trim()}
                      </span>
                      {i < arr.length - 1 && (
                        <svg className="w-3 h-3 text-blue-500 shrink-0 my-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <polyline points="6 9 12 15 18 9" />
                        </svg>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <p className="text-slate-300 font-medium text-center italic">
            {t("learn.trustGapClosing")}
          </p>
        </section>

        {/* ── 5. How It Works ──────────────────────────────────────────── */}
        <section>
          <SectionHeading
            id="how-it-works"
            title={t("learn.howTitle")}
            subtitle={t("learn.howSubtitle")}
          />

          {/* Pipeline visual */}
          <div className="bg-slate-800/30 rounded-xl border border-slate-700/50 p-6 sm:p-8 mb-10">
            <div className="flex flex-wrap items-center justify-center gap-2 sm:gap-3 text-sm font-mono">
              {[
                { label: t("learn.howInputLabel"), sub: t("learn.howCredential") },
                { label: t("learn.howParser"), sub: t("learn.howParserSub") },
                { label: t("learn.howWitness"), sub: t("learn.howWitnessSub") },
                { label: t("learn.howCircuit"), sub: t("learn.howCircuitSub") },
                { label: t("learn.howProof"), sub: t("learn.howProofSub") },
                { label: t("learn.howVerifier"), sub: t("learn.howVerifierSub") },
              ].map((stage, i) => (
                <div key={stage.label} className="flex items-center gap-2 sm:gap-3">
                  <div className="bg-slate-800 border border-slate-700/50 rounded-lg px-3 py-2 text-center">
                    <span className="text-slate-200 whitespace-nowrap block text-xs sm:text-sm">
                      {stage.label}
                    </span>
                    <span className="text-slate-500 whitespace-nowrap block text-xs">
                      {stage.sub}
                    </span>
                  </div>
                  {i < 5 && (
                    <svg
                      className="w-3 h-3 sm:w-4 sm:h-4 text-slate-600 shrink-0"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                    >
                      <polyline points="9 18 15 12 9 6" />
                    </svg>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Five steps */}
          <div className="space-y-8 mb-10">
            <PipelineStep num={1} title={t("learn.howStep1Title")} description={t("learn.howStep1Desc")} />
            <PipelineStep num={2} title={t("learn.howStep2Title")} description={t("learn.howStep2Desc")} />
            <PipelineStep num={3} title={t("learn.howStep3Title")} description={t("learn.howStep3Desc")} />
            <PipelineStep num={4} title={t("learn.howStep4Title")} description={t("learn.howStep4Desc")} />
            <PipelineStep num={5} title={t("learn.howStep5Title")} description={t("learn.howStep5Desc")} />
          </div>

          {/* Metrics box */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-4 text-center">
              <div className="text-2xl font-bold text-white mb-1">~350KB</div>
              <div className="text-xs text-slate-400">{t("learn.howMetricSize")}</div>
            </div>
            <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-4 text-center">
              <div className="text-2xl font-bold text-white mb-1">&lt;100ms</div>
              <div className="text-xs text-slate-400">{t("learn.howMetricVerify")}</div>
            </div>
            <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-4 text-center">
              <div className="text-2xl font-bold text-white mb-1">{t("learn.howMetricOffline")}</div>
              <div className="text-xs text-slate-400">{t("learn.howMetricOfflineDesc")}</div>
            </div>
            <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-4 text-center">
              <div className="text-2xl font-bold text-white mb-1">{t("learn.howMetricDevice")}</div>
              <div className="text-xs text-slate-400">{t("learn.howMetricDeviceDesc")}</div>
            </div>
          </div>
        </section>

        {/* ── 6. Capabilities ──────────────────────────────────────────── */}
        <section>
          <SectionHeading
            id="capabilities"
            title={t("learn.capabilitiesTitle")}
            subtitle={t("learn.capabilitiesSubtitle")}
          />

          {/* Predicate types table */}
          <div className="overflow-x-auto mb-8">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700">
                  <th className="text-left py-3 px-4 text-slate-400 font-semibold">
                    {t("learn.capType")}
                  </th>
                  <th className="text-left py-3 px-4 text-slate-400 font-semibold">
                    {t("learn.capDescription")}
                  </th>
                  <th className="text-left py-3 px-4 text-slate-400 font-semibold">
                    {t("learn.capExample")}
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {[
                  { type: "gte", desc: t("learn.capGteDesc"), ex: "age ≥ 18" },
                  { type: "lte", desc: t("learn.capLteDesc"), ex: "age ≤ 65" },
                  { type: "eq", desc: t("learn.capEqDesc"), ex: 'status == "active"' },
                  { type: "neq", desc: t("learn.capNeqDesc"), ex: 'status ≠ "revoked"' },
                  { type: "range", desc: t("learn.capRangeDesc"), ex: "18 ≤ age ≤ 25" },
                  { type: "set_member", desc: t("learn.capSetDesc"), ex: "nationality ∈ {DE,FR,NL}" },
                  { type: "nullifier", desc: t("learn.capNullDesc"), ex: "hash(secret, scope)" },
                ].map((p) => (
                  <tr key={p.type} className="hover:bg-slate-800/50">
                    <td className="py-3 px-4 font-mono text-blue-400">{p.type}</td>
                    <td className="py-3 px-4 text-slate-300">{p.desc}</td>
                    <td className="py-3 px-4 font-mono text-slate-500 text-xs">{p.ex}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Advanced feature cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
            {[
              { title: t("learn.capCompoundTitle"), desc: t("learn.capCompoundDesc") },
              { title: t("learn.capNullifierTitle"), desc: t("learn.capNullifierDesc") },
              { title: t("learn.capRevocationTitle"), desc: t("learn.capRevocationDesc") },
              { title: t("learn.capBindingTitle"), desc: t("learn.capBindingDesc") },
            ].map((feature) => (
              <div
                key={feature.title}
                className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-5"
              >
                <h4
                  className="text-sm font-semibold mb-2"
                  style={{ color: "#FFD500" }}
                >
                  {feature.title}
                </h4>
                <p className="text-sm text-slate-400 leading-relaxed">
                  {feature.desc}
                </p>
              </div>
            ))}
          </div>

          <p className="text-sm text-slate-500">{t("learn.capNote")}</p>
        </section>

        {/* ── 6b. Identity Escrow ─────────────────────────────────────── */}
        <section>
          <SectionHeading
            id="escrow"
            title={t("learn.escrowTitle")}
            subtitle={t("learn.escrowSubtitle")}
          />

          {/* How it works — numbered steps */}
          <div className="mb-8">
            <h4 className="text-sm font-semibold mb-4" style={{ color: "#FFD500" }}>
              {t("learn.escrowHowTitle")}
            </h4>
            <p className="text-sm text-slate-400 mb-4">{t("learn.escrowHowIntro")}</p>
            <div className="space-y-4">
              {[
                t("learn.escrowStep1"),
                t("learn.escrowStep2"),
                t("learn.escrowStep3"),
                t("learn.escrowStep4"),
                t("learn.escrowStep5"),
              ].map((step, i) => (
                <PipelineStep key={i} num={i + 1} title="" description={step} />
              ))}
            </div>
          </div>

          {/* Honest encryption */}
          <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-5 mb-8">
            <h4 className="text-sm font-semibold mb-2" style={{ color: "#FFD500" }}>
              {t("learn.escrowHonestTitle")}
            </h4>
            <p className="text-sm text-slate-400 leading-relaxed">
              {t("learn.escrowHonestDesc")}
            </p>
          </div>

          {/* Pluggable escrow authority */}
          <div className="mb-8">
            <h4 className="text-sm font-semibold mb-2" style={{ color: "#FFD500" }}>
              {t("learn.escrowPluggableTitle")}
            </h4>
            <p className="text-sm text-slate-400 leading-relaxed mb-4">
              {t("learn.escrowPluggableDesc")}
            </p>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-700">
                    <th className="text-left py-3 px-4 text-slate-400 font-semibold">{t("learn.escrowAuthorityCol")}</th>
                    <th className="text-left py-3 px-4 text-slate-400 font-semibold">{t("learn.escrowTriggerCol")}</th>
                    <th className="text-left py-3 px-4 text-slate-400 font-semibold">{t("learn.escrowTrustCol")}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {[
                    { auth: t("learn.escrowNotary"), trigger: t("learn.escrowNotaryTrigger"), trust: t("learn.escrowNotaryTrust") },
                    { auth: t("learn.escrowArbitration"), trigger: t("learn.escrowArbitrationTrigger"), trust: t("learn.escrowArbitrationTrust") },
                    { auth: t("learn.escrowRegistry"), trigger: t("learn.escrowRegistryTrigger"), trust: t("learn.escrowRegistryTrust") },
                    { auth: t("learn.escrowSmartContract"), trigger: t("learn.escrowSmartContractTrigger"), trust: t("learn.escrowSmartContractTrust") },
                  ].map((row) => (
                    <tr key={row.auth} className="hover:bg-slate-800/50">
                      <td className="py-3 px-4 text-slate-300 font-medium">{row.auth}</td>
                      <td className="py-3 px-4 text-slate-400">{row.trigger}</td>
                      <td className="py-3 px-4 text-slate-400">{row.trust}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Architecture diagram */}
          <div className="mb-8">
            <h4 className="text-sm font-semibold mb-4" style={{ color: "#FFD500" }}>
              {t("learn.escrowArchTitle")}
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Inside circuit */}
              <div className="bg-slate-900 rounded-xl border border-blue-500/20 p-4">
                <p className="text-xs text-blue-400 font-semibold mb-3 uppercase tracking-wider">{t("learn.escrowArchCircuit")}</p>
                <div className="space-y-2">
                  {t("learn.escrowArchCircuitItems").split("|").map((item, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <div className="w-1.5 h-1.5 rounded-full bg-blue-500 shrink-0" />
                      <span className="text-xs text-slate-300">{item}</span>
                    </div>
                  ))}
                </div>
                <div className="mt-3 pt-3 border-t border-blue-500/10">
                  <p className="text-[10px] text-slate-500 mb-1.5">Public outputs:</p>
                  <div className="flex flex-wrap gap-1.5">
                    {t("learn.escrowArchOutputs").split("|").map((out, i) => (
                      <span key={i} className="text-[10px] font-mono bg-blue-500/10 text-blue-400 rounded px-1.5 py-0.5">{out}</span>
                    ))}
                  </div>
                </div>
              </div>
              {/* Outside circuit */}
              <div className="bg-slate-900 rounded-xl border border-amber-500/20 p-4">
                <p className="text-xs text-amber-400 font-semibold mb-3 uppercase tracking-wider">{t("learn.escrowArchOutside")}</p>
                <div className="flex items-center gap-2 mb-3">
                  <div className="w-1.5 h-1.5 rounded-full bg-amber-500 shrink-0" />
                  <span className="text-xs text-slate-300">{t("learn.escrowArchMlkem")}</span>
                </div>
                <div className="text-[10px] text-slate-500 space-y-1.5">
                  <p>K → ML-KEM-768 encapsulate → encrypted_key (1120 bytes)</p>
                  <p>Post-quantum safe: NIST FIPS 203</p>
                </div>
              </div>
            </div>
          </div>

          {/* Offline vs On-Chain */}
          <div className="mb-8">
            <h4 className="text-sm font-semibold mb-4" style={{ color: "#FFD500" }}>
              {t("learn.escrowModesTitle")}
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Offline */}
              <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-5">
                <h5 className="text-sm font-semibold text-slate-200 mb-3">{t("learn.escrowOfflineTitle")}</h5>
                <div className="space-y-2">
                  {[t("learn.escrowOffline1"), t("learn.escrowOffline2"), t("learn.escrowOffline3"), t("learn.escrowOffline4")].map((item, i) => (
                    <div key={i} className="flex items-start gap-2">
                      <span className="text-blue-400 text-xs mt-0.5 shrink-0">{i + 1}.</span>
                      <p className="text-xs text-slate-400 leading-relaxed">{item}</p>
                    </div>
                  ))}
                </div>
              </div>
              {/* On-Chain */}
              <div className="bg-slate-800/50 rounded-xl border border-amber-500/20 p-5">
                <h5 className="text-sm font-semibold text-amber-400 mb-3">{t("learn.escrowOnchainTitle")}</h5>
                <div className="space-y-2">
                  {[t("learn.escrowOnchain1"), t("learn.escrowOnchain2"), t("learn.escrowOnchain3"), t("learn.escrowOnchain4")].map((item, i) => (
                    <div key={i} className="flex items-start gap-2">
                      <span className="text-amber-400 text-xs mt-0.5 shrink-0">{i + 1}.</span>
                      <p className="text-xs text-slate-400 leading-relaxed">{item}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Quantum Safety */}
          <div className="bg-emerald-950/20 border border-emerald-500/20 rounded-xl p-5 mb-8">
            <h4 className="text-sm font-semibold text-emerald-400 mb-2">{t("learn.escrowQuantumTitle")}</h4>
            <p className="text-sm text-slate-400 leading-relaxed">
              {t("learn.escrowQuantumDesc")}
            </p>
          </div>

          {/* Overhead note */}
          <p className="text-sm text-slate-500">{t("learn.escrowOverhead")}</p>
        </section>

        {/* ── 7b. Proof Attestation ─────────────────────────────────────── */}
        <section id="attestation" className="scroll-mt-24">
          <h2 className="text-2xl font-bold text-white mb-2">{t("learn.attestTitle")}</h2>
          <p className="text-slate-400 mb-6">{t("learn.attestSubtitle")}</p>
          <div className="bg-slate-800/50 rounded-xl border border-slate-700/40 p-6 space-y-4">
            <p className="text-slate-300 leading-relaxed">{t("learn.attestWhy")}</p>
            <div className="bg-slate-900/60 rounded-lg p-4 font-mono text-sm text-emerald-400">
              {t("learn.attestFlow")}
            </div>
            <p className="text-slate-300 leading-relaxed">{t("learn.attestOffline")}</p>
            <p className="text-slate-300 leading-relaxed">{t("learn.attestAdvantage")}</p>
          </div>
        </section>

        {/* ── 7. Standards & Compliance ─────────────────────────────────── */}
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

        {/* ── 8. GDPR: Privacy by Design ───────────────────────────────── */}
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
