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

function CodeBlock({ code }: { code: string }) {
  return (
    <pre className="bg-slate-900 border border-slate-700/50 rounded-lg p-4 overflow-x-auto text-sm font-mono text-slate-300 leading-relaxed">
      {code}
    </pre>
  );
}

function PipelineStep({
  num,
  title,
  description,
  detail,
}: {
  num: number;
  title: string;
  description: string;
  detail?: string;
}) {
  return (
    <div className="relative pl-12">
      <div
        className="absolute left-0 top-0 w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold border border-blue-500/40 text-blue-400"
        style={{ backgroundColor: "rgba(59, 130, 246, 0.08)" }}
      >
        {num}
      </div>
      <h4 className="text-lg font-semibold mb-1">{title}</h4>
      <p className="text-slate-400 leading-relaxed">{description}</p>
      {detail && (
        <p className="text-sm text-slate-500 mt-2 leading-relaxed">{detail}</p>
      )}
    </div>
  );
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
            { href: "#zkp-basics", label: t("learn.tocZkp") },
            { href: "#pipeline", label: t("learn.tocPipeline") },
            { href: "#predicates", label: t("learn.tocPredicates") },
            { href: "#advanced", label: t("learn.tocAdvanced") },
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
        {/* ── 1. The Privacy Problem ──────────────────────────────────────── */}
        <section>
          <SectionHeading
            id="problem"
            title={t("learn.problemTitle")}
            subtitle={t("learn.problemSubtitle")}
          />

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            {/* Traditional */}
            <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
              <h4 className="text-sm font-semibold mb-4 text-slate-400 uppercase tracking-wider">
                {t("learn.problemTraditional")}
              </h4>
              <div className="space-y-3 text-sm">
                <div className="bg-slate-900 rounded-lg p-3 font-mono text-xs">
                  <div className="text-slate-500 mb-1">
                    {t("learn.problemVerifierSees")}
                  </div>
                  <div className="text-red-400">name: Hans Mueller</div>
                  <div className="text-red-400">birth_date: 1985-11-30</div>
                  <div className="text-red-400">
                    document_number: DE-PID-2025-001
                  </div>
                  <div className="text-red-400">
                    address: Alexanderplatz 1, Berlin
                  </div>
                  <div className="text-red-400">nationality: DE</div>
                </div>
                <p className="text-slate-400">
                  {t("learn.problemTraditionalDesc")}
                </p>
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
                {t("learn.problemZkTitle")}
              </h4>
              <div className="space-y-3 text-sm">
                <div className="bg-slate-900 rounded-lg p-3 font-mono text-xs">
                  <div className="text-slate-500 mb-1">
                    {t("learn.problemVerifierSees")}
                  </div>
                  <div className="text-green-400">
                    age &gt;= 18: <span className="text-white">true</span>
                  </div>
                  <div className="text-green-400">
                    signature_valid: <span className="text-white">true</span>
                  </div>
                  <div className="text-slate-600">name: ████████████</div>
                  <div className="text-slate-600">birth_date: ██████████</div>
                  <div className="text-slate-600">
                    document_number: ████████████
                  </div>
                </div>
                <p className="text-slate-300">{t("learn.problemZkDesc")}</p>
              </div>
            </div>
          </div>
        </section>

        {/* ── 2. Zero-Knowledge Proofs in 30 Seconds ─────────────────────── */}
        <section>
          <SectionHeading
            id="zkp-basics"
            title={t("learn.zkpTitle")}
            subtitle={t("learn.zkpSubtitle")}
          />

          <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-6 sm:p-8 mb-8">
            <div className="space-y-6 text-slate-300 leading-relaxed">
              <p>{t("learn.zkpAnalogy1")}</p>
              <div className="bg-slate-900 rounded-lg p-4 border border-slate-700/50">
                <p className="text-sm font-mono text-blue-400 mb-2">
                  {t("learn.zkpAnalogyLabel")}
                </p>
                <p className="text-sm text-slate-400">
                  {t("learn.zkpAnalogy2")}
                </p>
              </div>
              <p>{t("learn.zkpAnalogy3")}</p>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {[
              {
                property: t("learn.zkpCompleteness"),
                desc: t("learn.zkpCompletenessDesc"),
              },
              {
                property: t("learn.zkpSoundness"),
                desc: t("learn.zkpSoundnessDesc"),
              },
              {
                property: t("learn.zkpZeroKnowledge"),
                desc: t("learn.zkpZeroKnowledgeDesc"),
              },
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
        </section>

        {/* ── 3. How zk-eidas Works: The Pipeline ────────────────────────── */}
        <section>
          <SectionHeading
            id="pipeline"
            title={t("learn.pipelineTitle")}
            subtitle={t("learn.pipelineSubtitle")}
          />

          {/* Visual pipeline */}
          <div className="bg-slate-800/30 rounded-xl border border-slate-700/50 p-6 sm:p-8 mb-10">
            <div className="flex flex-wrap items-center justify-center gap-2 sm:gap-3 text-sm font-mono">
              {[
                {
                  label: "SD-JWT / mdoc",
                  sub: t("learn.pipelineCredential"),
                },
                {
                  label: t("learn.pipelineParser"),
                  sub: t("learn.pipelineParserSub"),
                },
                {
                  label: t("learn.pipelineWitness"),
                  sub: t("learn.pipelineWitnessSub"),
                },
                {
                  label: t("learn.pipelineCircuit"),
                  sub: t("learn.pipelineCircuitSub"),
                },
                { label: "Groth16", sub: "ark-circom / snarkjs" },
                {
                  label: t("learn.pipelineProof"),
                  sub: t("learn.pipelineProofSub"),
                },
                {
                  label: t("learn.pipelineVerifier"),
                  sub: t("learn.pipelineVerifierSub"),
                },
              ].map((stage, i) => (
                <div
                  key={stage.label}
                  className="flex items-center gap-2 sm:gap-3"
                >
                  <div className="bg-slate-800 border border-slate-700/50 rounded-lg px-3 py-2 text-center">
                    <span className="text-slate-200 whitespace-nowrap block text-xs sm:text-sm">
                      {stage.label}
                    </span>
                    <span className="text-slate-500 whitespace-nowrap block text-xs">
                      {stage.sub}
                    </span>
                  </div>
                  {i < 6 && (
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

          {/* Step-by-step */}
          <div className="space-y-8">
            <PipelineStep
              num={1}
              title={t("learn.step1Title")}
              description={t("learn.step1Desc")}
              detail={t("learn.step1Detail")}
            />
            <PipelineStep
              num={2}
              title={t("learn.step2Title")}
              description={t("learn.step2Desc")}
              detail={t("learn.step2Detail")}
            />
            <PipelineStep
              num={3}
              title={t("learn.step3Title")}
              description={t("learn.step3Desc")}
            />
            <PipelineStep
              num={4}
              title={t("learn.step4Title")}
              description={t("learn.step4Desc")}
              detail={t("learn.step4Detail")}
            />
            <PipelineStep
              num={5}
              title={t("learn.step5Title")}
              description={t("learn.step5Desc")}
              detail={t("learn.step5Detail")}
            />
          </div>

          <div className="mt-8">
            <CodeBlock
              code={`// Holder: prove age >= 18 with ECDSA verified in-circuit
let proof = ZkCredential::from_sdjwt(&credential, "circuits/predicates")?
    .predicate("birth_date", Predicate::gte(18))
    .prove()?;

// Verifier: learns nothing except that the predicate holds
let valid = ZkVerifier::new("circuits/predicates").verify(&proof)?;
// valid == true — the holder is 18+, signature is authentic
// The verifier never sees the birth date, name, or any other claim`}
            />
          </div>
        </section>

        {/* ── 4. Predicates ───────────────────────────────────────────────── */}
        <section>
          <SectionHeading
            id="predicates"
            title={t("learn.predicatesTitle")}
            subtitle={t("learn.predicatesSubtitle")}
          />

          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700">
                  <th className="text-left py-3 px-4 text-slate-400 font-semibold">
                    {t("learn.predType")}
                  </th>
                  <th className="text-left py-3 px-4 text-slate-400 font-semibold">
                    {t("learn.predDescription")}
                  </th>
                  <th className="text-left py-3 px-4 text-slate-400 font-semibold">
                    {t("learn.predExample")}
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {[
                  {
                    type: "gte",
                    desc: t("learn.predGteDesc"),
                    ex: "age >= 18",
                  },
                  {
                    type: "lte",
                    desc: t("learn.predLteDesc"),
                    ex: "age <= 65",
                  },
                  {
                    type: "eq",
                    desc: t("learn.predEqDesc"),
                    ex: 'status == "active"',
                  },
                  {
                    type: "neq",
                    desc: t("learn.predNeqDesc"),
                    ex: 'status != "revoked"',
                  },
                  {
                    type: "range",
                    desc: t("learn.predRangeDesc"),
                    ex: "18 <= age <= 25",
                  },
                  {
                    type: "set_member",
                    desc: t("learn.predSetDesc"),
                    ex: 'nationality \u2208 {"DE","FR","NL"}',
                  },
                  {
                    type: "nullifier",
                    desc: t("learn.predNullDesc"),
                    ex: "hash(secret, scope)",
                  },
                ].map((p) => (
                  <tr key={p.type} className="hover:bg-slate-800/50">
                    <td className="py-3 px-4 font-mono text-blue-400">
                      {p.type}
                    </td>
                    <td className="py-3 px-4 text-slate-300">{p.desc}</td>
                    <td className="py-3 px-4 font-mono text-slate-500 text-xs">
                      {p.ex}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <p className="text-sm text-slate-500 mt-4">
            {t("learn.predicatesNote")}
          </p>
        </section>

        {/* ── 6. Advanced Features ────────────────────────────────────────── */}
        <section>
          <SectionHeading
            id="advanced"
            title={t("learn.advancedTitle")}
            subtitle={t("learn.advancedSubtitle")}
          />

          <div className="space-y-6">
            {[
              {
                title: t("learn.advCompoundTitle"),
                desc: t("learn.advCompoundDesc"),
                code: `.predicate("birth_date", Predicate::gte(18))
.predicate("nationality", Predicate::set_member(vec!["DE","FR","NL"]))
.prove_all()?  // AND: both must hold`,
              },
              {
                title: t("learn.advNullifierTitle"),
                desc: t("learn.advNullifierDesc"),
                code: `// Same credential, different scope = different nullifier
// bar.example.com can't link to shop.example.com
nullifier = hash(holder_secret, "bar.example.com")`,
              },
              {
                title: t("learn.advRevocationTitle"),
                desc: t("learn.advRevocationDesc"),
                code: `// Sparse Merkle Tree: prove credential NOT in revocation set
// Issuer publishes tree root, holder proves non-membership
SMT::prove_non_membership(credential_id, tree_root)`,
              },
              {
                title: t("learn.advBindingTitle"),
                desc: t("learn.advBindingDesc"),
                code: `// Prove PID and driver's license belong to same person
// Without revealing the shared identifier
hash(pid.personal_id) == hash(license.personal_id)`,
              },
            ].map((feature) => (
              <div
                key={feature.title}
                className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-6"
              >
                <h4
                  className="text-lg font-semibold mb-2"
                  style={{ color: "#FFD500" }}
                >
                  {feature.title}
                </h4>
                <p className="text-slate-400 leading-relaxed mb-4">
                  {feature.desc}
                </p>
                <CodeBlock code={feature.code} />
              </div>
            ))}
          </div>
        </section>

        {/* ── 7. Standards ────────────────────────────────────────────────── */}
        <section>
          <SectionHeading
            id="standards"
            title={t("learn.standardsTitle")}
            subtitle={t("learn.standardsSubtitle")}
          />

          <div className="space-y-4">
            {[
              { standard: "eIDAS 2.0", full: t("learn.stdEidas") },
              { standard: "SD-JWT VC (RFC 9901)", full: t("learn.stdSdjwt") },
              {
                standard: "mdoc / mDL (ISO 18013-5)",
                full: t("learn.stdMdoc"),
              },
              {
                standard: "ECDSA P-256 (secp256r1)",
                full: t("learn.stdEcdsa"),
              },
              { standard: "OpenID4VP", full: t("learn.stdOpenid") },
              { standard: "EUDI Wallet ARF", full: t("learn.stdEudi") },
            ].map((s) => (
              <div
                key={s.standard}
                className="flex gap-4 items-start bg-slate-800/50 rounded-xl border border-slate-700/50 p-4"
              >
                <span className="text-green-400 shrink-0 mt-0.5">
                  &#10003;
                </span>
                <div>
                  <span className="text-sm font-semibold text-white">
                    {s.standard}
                  </span>
                  <p className="text-sm text-slate-400 mt-1 leading-relaxed">
                    {s.full}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* ── 8. GDPR & Privacy ───────────────────────────────────────────── */}
        <section>
          <SectionHeading id="privacy" title={t("learn.privacyTitle")} />

          <div className="bg-slate-800 rounded-xl border border-slate-700 p-6 sm:p-8">
            <p className="text-slate-300 leading-relaxed mb-6">
              {t("learn.privacyDesc")}
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {[
                {
                  principle: t("learn.privacyMinimization"),
                  desc: t("learn.privacyMinimizationDesc"),
                },
                {
                  principle: t("learn.privacyLimitation"),
                  desc: t("learn.privacyLimitationDesc"),
                },
                {
                  principle: t("learn.privacyStorage"),
                  desc: t("learn.privacyStorageDesc"),
                },
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

        {/* ── CTA ─────────────────────────────────────────────────────────── */}
        <section className="text-center py-8">
          <Link
            to="/demo"
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
