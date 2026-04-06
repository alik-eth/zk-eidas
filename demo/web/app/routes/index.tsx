import { createFileRoute, Link } from "@tanstack/react-router";
import { useState, useEffect, useRef } from "react";
import { useT, useLocale } from "../i18n";

export const Route = createFileRoute("/")({
  component: Landing,
});

/* === Credential Showcase — state-machine animation === */
/*
  Phases:
  0  idle         — fields visible, checkboxes empty              1.8 s
  1  check+stamp  — checkboxes tick + stamp appears tilted        0.8 s
  2  hold-tilted  — stamp stays tilted, checkboxes set            1.0 s
  3  settle       — stamp untilts, fields blur, predicates+sig    0.7 s
  4  hold         — everything settled                            1.5 s
  5  revoke-show  — revoke button appears below stamp             0.5 s
  6  revoke-press — button press animation                        0.4 s
  7  post-revoke  — still after revoke                            1.0 s
  8  teardown     — everything unravels back to idle              0.8 s
  9  fade-out     — card fades out for profile swap               0.4 s
  10 fade-in      — new profile card fades in                     0.4 s
  → back to 0
*/
const PHASE_DURATIONS = [
  1800, 800, 1000, 700, 1500, 500, 400, 1000, 800, 400, 400,
];

type Profile = {
  country: string;
  docTypeKey: string;
  format: string;
  flag: string[];
  flagDir: "row" | "col";
  fields: {
    labelKey: string;
    value: string;
    predicate: string | null;
    idx: number;
  }[];
};

const PROFILES: Profile[] = [
  {
    country: "Ukraine",
    docTypeKey: "cred.pid",
    format: "mdoc",
    flag: ["#005BBB", "#FFD500"],
    flagDir: "col",
    fields: [
      { labelKey: "cred.name", value: "Oleksandr Petrenko", predicate: null, idx: 0 },
      { labelKey: "cred.birthdate", value: "1998-05-14", predicate: "\u2265 18", idx: 1 },
      { labelKey: "cred.nationality", value: "UA", predicate: "\u2208 eIDAS", idx: 2 },
      { labelKey: "cred.document", value: "UA-1234567890", predicate: "\u2208 active", idx: 3 },
      { labelKey: "cred.authority", value: "Min. Digital", predicate: "government", idx: 4 },
    ],
  },
  {
    country: "Germany",
    docTypeKey: "cred.driverLicense",
    format: "mdoc / mDL",
    flag: ["#000000", "#DD0000", "#FFCC00"],
    flagDir: "col",
    fields: [
      { labelKey: "cred.name", value: "Maximilian Schneider", predicate: null, idx: 0 },
      { labelKey: "cred.category", value: "A, B, C1", predicate: "\u2208 {B}", idx: 1 },
      { labelKey: "cred.issueDate", value: "2019-03-22", predicate: "\u2265 2y ago", idx: 2 },
      { labelKey: "cred.expiryDate", value: "2034-03-22", predicate: "\u2265 today", idx: 3 },
      { labelKey: "cred.restrictions", value: "None", predicate: "== none", idx: 4 },
    ],
  },
  {
    country: "France",
    docTypeKey: "cred.diploma",
    format: "mdoc",
    flag: ["#002395", "#FFFFFF", "#ED2939"],
    flagDir: "row",
    fields: [
      { labelKey: "cred.university", value: "Sorbonne Universit\u00e9", predicate: null, idx: 0 },
      { labelKey: "cred.degree", value: "Master (M2)", predicate: "\u2208 {M1,M2}", idx: 1 },
      { labelKey: "cred.field", value: "Computer Science", predicate: "\u2208 STEM", idx: 2 },
      { labelKey: "cred.gradYear", value: "2023", predicate: "\u2265 2020", idx: 3 },
      { labelKey: "cred.honors", value: "Magna Cum Laude", predicate: null, idx: 4 },
    ],
  },
  {
    country: "Estonia",
    docTypeKey: "cred.vehicleReg",
    format: "mdoc / mDL",
    flag: ["#0072CE", "#000000", "#FFFFFF"],
    flagDir: "col",
    fields: [
      { labelKey: "cred.owner", value: "Kadri Tamm", predicate: null, idx: 0 },
      { labelKey: "cred.plate", value: "123 ABC", predicate: null, idx: 1 },
      { labelKey: "cred.make", value: "Toyota Corolla", predicate: "\u2208 EU-type", idx: 2 },
      { labelKey: "cred.insurance", value: "2027-01-15", predicate: "\u2265 today", idx: 3 },
      { labelKey: "cred.vin", value: "JTDKN3DU5A0...", predicate: "\u2208 active", idx: 4 },
    ],
  },
];
function CredentialShowcase() {
  const t = useT();
  const [phase, setPhase] = useState(0);
  const [profileIdx, setProfileIdx] = useState(0);
  const [checkedSet, setCheckedSet] = useState<Set<number>>(new Set());

  const profile = PROFILES[profileIdx];
  const checkable = new Set(profile.fields.filter(f => f.predicate).map(f => f.idx));

  // Phase timer
  useEffect(() => {
    const timer = setTimeout(() => {
      if (phase === 10) {
        setPhase(0); // fade-in done → idle
      } else if (phase === 9) {
        // Swap profile during fade-out
        setProfileIdx((i) => (i + 1) % PROFILES.length);
        setPhase(10);
      } else {
        setPhase((p) => p + 1);
      }
    }, PHASE_DURATIONS[phase]);
    return () => clearTimeout(timer);
  }, [phase]);

  // Staggered checkbox checking in phase 0 (idle)
  useEffect(() => {
    if (phase !== 0) return;
    const toCheck = [...checkable];
    const timers = toCheck.map((fieldIdx, order) =>
      setTimeout(
        () => setCheckedSet((prev) => new Set([...prev, fieldIdx])),
        order * 350,
      ),
    );
    return () => timers.forEach(clearTimeout);
  }, [phase, profileIdx]);

  // Clear checkboxes on post-revoke
  useEffect(() => {
    if (phase !== 7) return;
    setCheckedSet(new Set([]));
  }, [phase]);

  const showCheckboxes = true;
  const isBlurred = phase >= 2 && phase <= 6;
  const showPredicates = phase >= 2 && phase <= 6;
  const showStamp = phase >= 2 && phase <= 6;
  const showFooterSig = phase >= 2 && phase <= 6;
  const stampScale = showStamp ? 1 : 0.7;
  const stampRotate = phase <= 2 ? "12deg" : "0deg";
  const stampTransform = `translate(-50%, -50%) scale(${stampScale}) rotate(${stampRotate})`;

  // Phase 9 = slide out, phase 10 = slide in with new profile
  const isSwapping = phase === 9 || phase === 10;
  const swapStyle: React.CSSProperties = isSwapping
    ? {
        transition: "transform 0.4s ease-in-out, opacity 0.4s ease-in-out",
        transform: phase === 9 ? "translateY(-20px)" : "translateY(0)",
        opacity: phase === 9 ? 0 : 1,
      }
    : { transition: "none" };

  return (
    <div className="relative cred-glow rounded-2xl">
      <div
        className="relative cred-noise bg-gradient-to-br from-slate-800/90 via-slate-800/80 to-slate-900/90 rounded-2xl border border-slate-700/60 overflow-hidden"
        style={swapStyle}
      >
        {/* Scanline */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="cred-scanline absolute left-0 right-0 h-px bg-gradient-to-r from-transparent via-blue-400/20 to-transparent" />
        </div>

        {/* Header */}
        <div className="relative px-5 py-3 border-b border-slate-700/40">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div
                className={`w-7 h-5 rounded-sm overflow-hidden flex ${profile.flagDir === "col" ? "flex-col" : "flex-row"}`}
              >
                {profile.flag.map((color, i) => (
                  <div
                    key={i}
                    className="flex-1"
                    style={{ background: color }}
                  />
                ))}
              </div>
              <div>
                <p className="text-[10px] font-semibold tracking-[0.2em] text-slate-400 uppercase">
                  {profile.country}
                </p>
                <p className="text-[9px] text-slate-500 tracking-wide">
                  {t(profile.docTypeKey)}
                </p>
              </div>
            </div>
            <div className="text-right">
              <p className="text-[9px] font-mono text-slate-600">{profile.format}</p>
              <p className="text-[9px] font-mono text-slate-600">
                {profile.format.startsWith("mdoc") ? "COSE_Sign1" : "ECDSA P-256"}
              </p>
            </div>
          </div>
        </div>

        {/* Fields */}
        <div className="px-5 py-4 space-y-2.5">
          {profile.fields.map((f) => {
            const hasPred = !!f.predicate;
            const isChecked = checkedSet.has(f.idx);

            return (
              <div key={f.labelKey} className="flex items-center gap-3">
                {/* Checkbox column */}
                <div className="w-4 shrink-0 flex items-center justify-center">
                  {showCheckboxes ? (
                    <div
                      className="w-3.5 h-3.5 rounded-sm border flex items-center justify-center transition-all duration-300"
                      style={{
                        borderColor: isChecked ? "#34d399" : "#475569",
                        backgroundColor: isChecked ? "#34d399" : "transparent",
                        transitionDelay: `${f.idx * 80}ms`,
                      }}
                    >
                      {isChecked && (
                        <svg
                          className="w-2.5 h-2.5 text-slate-900"
                          viewBox="0 0 24 24"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="4"
                          strokeLinecap="round"
                        >
                          <polyline points="20 6 9 17 4 12" />
                        </svg>
                      )}
                    </div>
                  ) : (
                    <div className="w-3.5 h-3.5" />
                  )}
                </div>

                <span className="text-[10px] font-medium text-slate-500 uppercase w-18 shrink-0 leading-tight">
                  {t(f.labelKey)}
                </span>
                <div className="flex-1 relative min-w-0">
                  <span
                    className="text-xs font-mono text-slate-300 truncate transition-all duration-500 block"
                    style={{
                      filter: isBlurred ? "blur(6px)" : "blur(0)",
                      opacity: isBlurred ? 0.5 : 1,
                    }}
                  >
                    {f.value}
                  </span>
                  {/* "hidden" overlay — appears on top of blurred value for non-predicate fields */}
                  {!hasPred && (
                    <span
                      className="absolute inset-0 flex items-center gap-1 text-[10px] font-medium text-slate-500 transition-opacity duration-400"
                      style={{ opacity: isBlurred ? 1 : 0 }}
                    >
                      <svg
                        className="w-3 h-3"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        strokeLinecap="round"
                      >
                        <path d="M17 10h-2V7c0-2.76-2.24-5-5-5S5 4.24 5 7v3H3c-.55 0-1 .45-1 1v10c0 .55.45 1 1 1h14c.55 0 1-.45 1-1V11c0-.55-.45-1-1-1z" />
                      </svg>
                      {t("cred.hidden")}
                    </span>
                  )}
                </div>
                <div className="shrink-0 text-right">
                  {hasPred && (
                    <span
                      className="inline-flex items-center gap-1 text-[10px] font-semibold text-emerald-400 transition-all duration-400"
                      style={{
                        opacity: showPredicates ? 1 : 0,
                        transform: showPredicates
                          ? "translateX(0)"
                          : "translateX(-4px)",
                      }}
                    >
                      <svg
                        className="w-3 h-3"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="3"
                        strokeLinecap="round"
                      >
                        <polyline points="20 6 9 17 4 12" />
                      </svg>
                      {f.predicate}
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {/* Footer — sig line, only visible after stamp settles */}
        <div
          className="px-5 py-3 border-t border-slate-700/40 transition-all duration-500"
          style={{
            opacity: showFooterSig ? 1 : 0,
            maxHeight: showFooterSig ? "40px" : "0px",
            padding: showFooterSig ? undefined : "0 1.25rem",
            overflow: "hidden",
          }}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              <span className="text-[10px] font-mono text-slate-500">
                {t("cred.sigLine")}
              </span>
            </div>
            <span className="text-[10px] font-mono text-slate-600">
              {t("cred.proofSize")}
            </span>
          </div>
        </div>

        {/* "ZK VERIFIED" stamp — center overlay, rotates then flattens */}
        <div
          className="absolute top-3/7 left-1/2 pointer-events-none transition-all duration-600 ease-out"
          style={{
            opacity: showStamp ? 1 : 0,
            transform: stampTransform,
          }}
        >
          <div className="border-2 border-emerald-500/60 rounded-lg px-4 py-2.5">
            <p className="text-emerald-500/80 text-xs font-bold tracking-widest uppercase whitespace-nowrap">
              {t("cred.zkVerified")}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

/* === Section: Dilemma === */

function DilemmaSection() {
  const t = useT();
  const cards = [
    { title: t("dilemma.gapTitle"), desc: t("dilemma.gapDesc"), color: "text-amber-400", border: "border-amber-500/20" },
    { title: t("dilemma.promiseTitle"), desc: t("dilemma.promiseDesc"), color: "text-blue-400", border: "border-blue-500/20" },
    { title: t("dilemma.centralTitle"), desc: t("dilemma.centralDesc"), color: "text-red-400", border: "border-red-500/20" },
    { title: t("dilemma.web3Title"), desc: t("dilemma.web3Desc"), color: "text-purple-400", border: "border-purple-500/20" },
  ];

  return (
    <section className="max-w-5xl mx-auto px-4 sm:px-8 py-16 sm:py-20 border-t border-slate-800">
      <h2 className="text-2xl sm:text-3xl font-bold mb-8">{t("dilemma.title")}</h2>
      <div className="grid md:grid-cols-2 gap-6">
        {cards.map((card, i) => (
          <div key={i} className={`bg-slate-800/50 rounded-xl border ${card.border} p-6 space-y-3`}>
            <h3 className={`text-lg font-semibold ${card.color}`}>{card.title}</h3>
            <p className="text-sm text-slate-400 leading-relaxed">{card.desc}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

/* === Section: Proposal Brief === */

function ProposalBrief() {
  const t = useT();
  return (
    <section className="max-w-5xl mx-auto px-4 sm:px-8 py-16 sm:py-20 border-t border-slate-800">
      <h2 className="text-2xl sm:text-3xl font-bold mb-8">{t("rootProposal.title")}</h2>
      <div className="grid md:grid-cols-2 gap-6">
        <div className="bg-slate-800/50 rounded-xl border border-emerald-500/20 p-6 space-y-3">
          <h3 className="text-lg font-semibold text-emerald-400">{t("proposal.service1Title")}</h3>
          <p className="text-sm text-slate-400 leading-relaxed">{t("rootProposal.attestDesc")}</p>
        </div>
        <div className="bg-slate-800/50 rounded-xl border border-blue-500/20 p-6 space-y-3">
          <h3 className="text-lg font-semibold text-blue-400">{t("proposal.service2Title")}</h3>
          <p className="text-sm text-slate-400 leading-relaxed">{t("rootProposal.escrowDesc")}</p>
        </div>
      </div>
      <div className="mt-8 flex flex-col sm:flex-row items-start sm:items-center gap-4">
        <Link
          to="/proposal"
          className="px-6 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-lg transition-colors text-sm"
        >
          {t("rootProposal.cta")}
        </Link>
        <Link
          to="/learn"
          className="text-sm text-slate-400 hover:text-white transition-colors underline underline-offset-4"
        >
          {t("rootProposal.learnMore")}
        </Link>
      </div>
    </section>
  );
}

function Landing() {
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

  return (
    <div className="min-h-screen bg-slate-900 text-white">
      {/* Navigation */}
      <header
        className="border-b border-slate-800 px-4 sm:px-8 py-4 pt-[max(1rem,env(safe-area-inset-top))] bg-slate-950/80 backdrop-blur-md fixed top-0 left-0 right-0 z-10 overflow-x-hidden transition-transform duration-300"
        style={{
          transform: headerVisible ? "translateY(0)" : "translateY(-100%)",
        }}
      >
        <div className="max-w-5xl mx-auto flex items-center justify-between gap-2">
          {/* Left: logo + byline */}
          <div className="flex items-center gap-3 shrink-0">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-600 to-blue-700 flex items-center justify-center">
              <span className="text-xs font-bold text-white tracking-tighter">
                zk
              </span>
            </div>
            <div>
              <h1 className="text-sm font-semibold tracking-tight leading-none">
                <span style={{ color: "#005BBB" }}>zk</span>
                <span className="text-slate-600 mx-0.5">-</span>
                <span style={{ color: "#FFD500" }}>eidas</span>
              </h1>
              <span className="text-[10px] text-slate-600 tracking-wide">by Alik.eth</span>
            </div>
          </div>
          {/* Right: Demo (button) | language | Verify | Sandbox */}
          <nav className="flex items-center gap-2 sm:gap-4 flex-wrap justify-end">
            <Link
              to="/demo"
              className="text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 px-3.5 py-1.5 rounded-lg transition-colors"
            >
              {t("nav.contracts")}
            </Link>
            <button
              onClick={() => setLocale(locale === "uk" ? "en" : "uk")}
              className="text-xs text-slate-500 hover:text-slate-300 transition-colors font-medium px-2 py-1 rounded border border-slate-800 hover:border-slate-700"
            >
              {locale === "uk" ? "EN" : "UA"}
            </button>
            <Link
              to="/proposal"
              className="text-xs text-slate-400 hover:text-slate-200 transition-colors font-medium"
            >
              {t("nav.proposal")}
            </Link>
            <Link
              to="/verify"
              className="hidden sm:inline text-xs text-slate-400 hover:text-slate-200 transition-colors font-medium"
            >
              {t("nav.verify")}
            </Link>
            <Link
              to="/sandbox"
              className="text-xs text-slate-400 hover:text-slate-200 transition-colors font-medium"
            >
              {t("nav.demo")}
            </Link>
          </nav>
        </div>
      </header>
      {/* Header spacer for fixed positioning */}
      <div className="h-14" />

      {/* Hero */}
      <section className="hero-mesh">
        <div className="max-w-5xl mx-auto px-4 sm:px-8 py-10 sm:py-16 grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
          {/* Left: text */}
          <div>
            <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight mb-5">
              <span style={{ color: "#005BBB" }}>zk</span>
              <span className="text-slate-500 mx-1">-</span>
              <span style={{ color: "#FFD500" }}>eidas</span>
            </h2>
            <p className="text-lg sm:text-xl text-slate-200 mb-3 leading-relaxed font-semibold">
              {t("hero.subtitle")}
            </p>
            <p className="text-base text-slate-400 mb-8">{t("hero.tagline")}</p>
            <div className="flex items-center gap-3">
              <Link
                to="/demo"
                className="px-6 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors text-sm"
              >
                {t("hero.tryDemo")}
              </Link>
              <a
                href="https://github.com/alik-eth/zk-eidas"
                target="_blank"
                rel="noopener noreferrer"
                className="px-6 py-2.5 border border-slate-700 text-slate-300 hover:text-white hover:border-slate-500 font-semibold rounded-lg transition-colors text-sm"
              >
                {t("hero.viewGithub")}
              </a>
            </div>
          </div>

          {/* Right: credential showcase */}
          <div className="flex justify-center lg:justify-end">
            <div className="w-full max-w-sm h-[340px] overflow-hidden">
              <CredentialShowcase />
              <p className="text-[10px] text-slate-600 text-center mt-3 italic">
                {t("cred.tagline")}
              </p>
            </div>
          </div>
        </div>
      </section>

      <DilemmaSection />

      <ProposalBrief />

      {/* Footer */}
      <footer className="border-t border-slate-800 px-4 sm:px-8 py-8">
        <div className="max-w-5xl mx-auto flex items-center justify-between text-sm text-slate-500">
          <span>{t("footer.license")}</span>
          <div className="flex items-center gap-6">
            <Link to="/learn" className="hover:text-slate-300 transition-colors">
              {t("nav.learn")}
            </Link>
            <Link to="/proposal" className="hover:text-slate-300 transition-colors">
              {t("nav.proposal")}
            </Link>
            <a
              href="https://github.com/alik-eth/zk-eidas"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-slate-300 transition-colors"
            >
              GitHub
            </a>
            <span className="font-medium tracking-wide">Alik.eth</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
