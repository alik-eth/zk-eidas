import { createFileRoute, Link } from "@tanstack/react-router";
import { useState, useEffect, useRef, useCallback } from "react";
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

/* === Section: The Unlinkability Gap === */

type CellVal = boolean | "partial";
const COMPARISON_DATA: { rowKey: string; sdjwt: CellVal; bbs: CellVal; batch: CellVal; zk: CellVal }[] = [
  { rowKey: "problem.row1", sdjwt: true, bbs: false, batch: true, zk: true },
  { rowKey: "problem.row2", sdjwt: true, bbs: false, batch: true, zk: "partial" },
  { rowKey: "problem.row3", sdjwt: false, bbs: true, batch: false, zk: true },
  { rowKey: "problem.row4", sdjwt: true, bbs: true, batch: "partial", zk: true },
  { rowKey: "problem.row5", sdjwt: false, bbs: false, batch: false, zk: true },
  { rowKey: "problem.row6", sdjwt: true, bbs: false, batch: false, zk: "partial" },
];

function CheckIcon() {
  return (
    <svg className="w-4 h-4 text-emerald-400 mx-auto" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

function CrossIcon() {
  return (
    <svg className="w-4 h-4 text-red-400/70 mx-auto" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  );
}

function CellValue({ value }: { value: boolean | "partial" }) {
  if (value === "partial") return <span className="text-[10px] text-yellow-500/70 font-medium">partial</span>;
  return value ? <CheckIcon /> : <CrossIcon />;
}

function ProblemSection() {
  const t = useT();
  const headers = ["problem.sdjwt", "problem.bbs", "problem.batch", "problem.zk"] as const;

  return (
    <section className="max-w-5xl mx-auto px-4 sm:px-8 py-16 sm:py-20 border-t border-slate-800">
      <h3 className="text-2xl sm:text-3xl font-bold text-center mb-3">
        {t("problem.title")}
      </h3>
      <p className="text-sm text-slate-400 text-center mb-12 max-w-3xl mx-auto leading-relaxed">
        {t("problem.subtitle")}
      </p>

      <div className="max-w-4xl mx-auto overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-700/40">
              <th className="text-left py-3 px-3 text-xs text-slate-500 font-medium uppercase tracking-wider">
                {t("problem.criterion")}
              </th>
              {headers.map((h) => (
                <th
                  key={h}
                  className={`py-3 px-3 text-xs font-medium uppercase tracking-wider text-center ${
                    h === "problem.zk"
                      ? "text-emerald-400 bg-emerald-950/20 border-x border-emerald-500/30"
                      : "text-slate-500"
                  }`}
                >
                  {t(h)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {COMPARISON_DATA.map((row, i) => (
              <tr key={row.rowKey} className={i < COMPARISON_DATA.length - 1 ? "border-b border-slate-800/60" : ""}>
                <td className="py-3 px-3 text-slate-300 text-xs sm:text-sm">{t(row.rowKey)}</td>
                <td className="py-3 px-3 text-center"><CellValue value={row.sdjwt} /></td>
                <td className="py-3 px-3 text-center"><CellValue value={row.bbs} /></td>
                <td className="py-3 px-3 text-center"><CellValue value={row.batch} /></td>
                <td className="py-3 px-3 text-center bg-emerald-950/20 border-x border-emerald-500/30">
                  <CellValue value={row.zk} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

/* === Section: Solution Pipeline === */

function SolutionSteps() {
  const t = useT();

  return (
    <section className="max-w-5xl mx-auto px-4 sm:px-8 py-16 sm:py-20 border-t border-slate-800">
      <h3 className="text-2xl sm:text-3xl font-bold text-center mb-3">
        {t("solution.title")}
      </h3>
      <p className="text-sm text-slate-400 text-center mb-14 max-w-2xl mx-auto">
        {t("solution.subtitle")}
      </p>

      {/* Pipeline: three nodes connected by dashed lines */}
      <div className="max-w-4xl mx-auto">
        {/* Desktop: horizontal pipeline */}
        <div className="hidden md:grid grid-cols-[1fr_auto_1fr_auto_1fr] items-center gap-0">
          {/* Node 1: Issuer */}
          <div className="relative group">
            <div className="absolute -inset-px rounded-xl bg-gradient-to-b from-blue-500/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
            <div className="relative bg-slate-900/80 rounded-xl border border-slate-700/40 p-5">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center justify-center shrink-0">
                  <span className="text-[10px] font-bold text-blue-400 tracking-wider">ES256</span>
                </div>
                <div>
                  <p className="text-sm font-semibold text-white leading-tight">{t("solution.step1Title")}</p>
                  <p className="text-[10px] text-slate-500 uppercase tracking-widest">{t("solution.step1Label")}</p>
                </div>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">{t("solution.step1Desc")}</p>
            </div>
          </div>

          {/* Connector 1→2 */}
          <div className="flex items-center px-1">
            <div className="w-8 border-t border-dashed border-slate-600" />
            <svg className="w-3 h-3 text-slate-600 -ml-0.5 shrink-0" viewBox="0 0 12 12" fill="currentColor">
              <path d="M2 1l8 5-8 5z" />
            </svg>
          </div>

          {/* Node 2: Prover */}
          <div className="relative group">
            <div className="absolute -inset-px rounded-xl bg-gradient-to-b from-yellow-500/15 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
            <div className="relative bg-slate-900/80 rounded-xl border border-slate-700/40 p-5">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-8 h-8 rounded-lg bg-yellow-500/10 border border-yellow-500/30 flex items-center justify-center shrink-0">
                  <svg className="w-4 h-4 text-yellow-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                    <rect x="3" y="11" width="18" height="11" rx="2" />
                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                  </svg>
                </div>
                <p className="text-sm font-semibold text-white leading-tight">{t("solution.step2Title")}</p>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">{t("solution.step2Desc")}</p>
              <div className="mt-3 flex items-center gap-1.5">
                <div className="w-1.5 h-1.5 rounded-full bg-yellow-500/50" />
                <span className="text-[10px] font-mono text-slate-500">ECDSA P-256 in-circuit</span>
              </div>
            </div>
          </div>

          {/* Connector 2→3 */}
          <div className="flex items-center px-1">
            <div className="w-8 border-t border-dashed border-slate-600" />
            <svg className="w-3 h-3 text-slate-600 -ml-0.5 shrink-0" viewBox="0 0 12 12" fill="currentColor">
              <path d="M2 1l8 5-8 5z" />
            </svg>
          </div>

          {/* Node 3: Verifier */}
          <div className="relative group">
            <div className="absolute -inset-px rounded-xl bg-gradient-to-b from-emerald-500/15 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
            <div className="relative bg-slate-900/80 rounded-xl border border-emerald-500/20 p-5">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center shrink-0">
                  <svg className="w-4 h-4 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                </div>
                <p className="text-sm font-semibold text-white leading-tight">{t("solution.step3Title")}</p>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">{t("solution.step3Desc")}</p>
              <div className="mt-3 flex items-center gap-1.5">
                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500/50" />
                <span className="text-[10px] font-mono text-emerald-400/60">Longfellow · Quantum-safe · No trusted setup</span>
              </div>
            </div>
          </div>
        </div>

        {/* Mobile: vertical pipeline */}
        <div className="md:hidden space-y-0">
          {/* Node 1 */}
          <div className="bg-slate-900/80 rounded-t-xl border border-slate-700/40 p-5">
            <div className="flex items-center gap-3 mb-2">
              <div className="w-7 h-7 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center justify-center shrink-0">
                <span className="text-[8px] font-bold text-blue-400">ES256</span>
              </div>
              <div>
                <p className="text-sm font-semibold text-white">{t("solution.step1Title")}</p>
                <p className="text-[10px] text-slate-500 uppercase tracking-widest">{t("solution.step1Label")}</p>
              </div>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">{t("solution.step1Desc")}</p>
          </div>
          {/* Vertical connector */}
          <div className="flex justify-center">
            <div className="h-5 border-l border-dashed border-slate-600" />
          </div>
          {/* Node 2 */}
          <div className="bg-slate-900/80 border border-slate-700/40 p-5">
            <div className="flex items-center gap-3 mb-2">
              <div className="w-7 h-7 rounded-lg bg-yellow-500/10 border border-yellow-500/30 flex items-center justify-center shrink-0">
                <svg className="w-3.5 h-3.5 text-yellow-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                  <rect x="3" y="11" width="18" height="11" rx="2" />
                  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
              </div>
              <p className="text-sm font-semibold text-white">{t("solution.step2Title")}</p>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">{t("solution.step2Desc")}</p>
          </div>
          {/* Vertical connector */}
          <div className="flex justify-center">
            <div className="h-5 border-l border-dashed border-slate-600" />
          </div>
          {/* Node 3 */}
          <div className="bg-slate-900/80 rounded-b-xl border border-emerald-500/20 p-5">
            <div className="flex items-center gap-3 mb-2">
              <div className="w-7 h-7 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center shrink-0">
                <svg className="w-3.5 h-3.5 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              </div>
              <p className="text-sm font-semibold text-white">{t("solution.step3Title")}</p>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">{t("solution.step3Desc")}</p>
          </div>
        </div>
      </div>
    </section>
  );
}

/* === Section 3: Live Proof === */

const API_URL =
  typeof window !== "undefined" && window.location.hostname === "localhost"
    ? "http://localhost:3001"
    : "";

type LiveProofPhase = "idle" | "proving" | "proved" | "verifying" | "verified" | "error";

function ProofQrComparison({
  compressedCborRef,
  compressedSizeBytes,
  qrDataUrl,
  setQrDataUrl,
  t,
}: {
  compressedCborRef: React.RefObject<string | null>;
  compressedSizeBytes: number;
  qrDataUrl: string | null;
  setQrDataUrl: (url: string | null) => void;
  t: (key: string) => string;
}) {
  useEffect(() => {
    if (!compressedCborRef.current) return;
    (async () => {
      try {
        const { encodeProofChunks, LogicalOpFlag } = await import("../lib/qr-chunking");
        const QRCode = (await import("qrcode")).default;
        const compressed = Uint8Array.from(
          atob(compressedCborRef.current!),
          (c) => c.charCodeAt(0),
        );
        const chunks = encodeProofChunks(compressed, 1, 0, 1, LogicalOpFlag.Single);
        const url = await QRCode.toDataURL(
          [{ data: chunks[0], mode: "byte" as const }],
          { errorCorrectionLevel: "L", margin: 1, width: 120 },
        );
        setQrDataUrl(url);
      } catch {
        // silently fail
      }
    })();
  }, [compressedCborRef, setQrDataUrl]);

  const sms = 160;
  const tweet = 280;

  return (
    <div className="bg-slate-900/50 rounded-lg p-4 space-y-3">
      <div className="flex items-start gap-4">
        {/* QR code */}
        <div className="flex-shrink-0">
          {qrDataUrl ? (
            <img src={qrDataUrl} alt="Proof QR" className="w-[80px] h-[80px] rounded" />
          ) : (
            <div className="w-[80px] h-[80px] bg-slate-800 rounded animate-pulse" />
          )}
        </div>
        {/* Size comparisons */}
        <div className="flex-1 space-y-2">
          <p className="text-xs text-slate-400 font-medium">{t("liveProof.sizeComparison")}</p>
          {/* SMS bar */}
          <div className="space-y-1">
            <div className="flex items-center justify-between text-[10px]">
              <span className="text-slate-500">SMS</span>
              <span className="text-slate-500 font-mono">{sms} B</span>
            </div>
            <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
              <div className="h-full bg-slate-600 rounded-full" style={{ width: `${Math.min(100, (sms / compressedSizeBytes) * 100)}%` }} />
            </div>
          </div>
          {/* Tweet bar */}
          <div className="space-y-1">
            <div className="flex items-center justify-between text-[10px]">
              <span className="text-slate-500">Tweet</span>
              <span className="text-slate-500 font-mono">{tweet} B</span>
            </div>
            <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
              <div className="h-full bg-slate-600 rounded-full" style={{ width: `${Math.min(100, (tweet / compressedSizeBytes) * 100)}%` }} />
            </div>
          </div>
          {/* Proof bar */}
          <div className="space-y-1">
            <div className="flex items-center justify-between text-[10px]">
              <span className="text-emerald-400 font-medium">{t("liveProof.yourProof")}</span>
              <span className="text-emerald-400 font-mono font-bold">
                {compressedSizeBytes > 1024
                  ? `${(compressedSizeBytes / 1024).toFixed(1)} KB`
                  : `${compressedSizeBytes} B`}
              </span>
            </div>
            <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
              <div className="h-full bg-emerald-500 rounded-full" style={{ width: "100%" }} />
            </div>
          </div>
        </div>
      </div>
      <p className="text-[10px] text-slate-600 text-center">
        {t("liveProof.sizeNote")}
      </p>
    </div>
  );
}

function LiveProofSection() {
  const t = useT();
  const [phase, setPhase] = useState<LiveProofPhase>("idle");
  const [verifyTimeMs, setVerifyTimeMs] = useState(0);
  const [proofSizeBytes, setProofSizeBytes] = useState(0);
  const [compressedSizeBytes, setCompressedSizeBytes] = useState(0);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const proofRef = useRef<{
    compound_proof_json: string;
    op: string;
    credential: string;
    format: string;
  } | null>(null);
  const compressedCborRef = useRef<string | null>(null);
  const handleGenerate = useCallback(async () => {
    setPhase("proving");
    setError(null);
    try {
      // 1. Issue a PID credential
      const issueRes = await fetch(`${API_URL}/issuer/issue`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          credential_type: "pid",
          claims: {
            given_name: "Олександр",
            family_name: "Петренко",
            birth_date: "1998-05-14",
            age_over_18: "true",
            nationality: "UA",
            issuing_country: "UA",
            resident_country: "UA",
            resident_city: "Київ",
            gender: "M",
            document_number: "UA-1234567890",
            expiry_date: "2035-05-14",
            issuing_authority: "Міністерство цифрової трансформації",
          },
          issuer: "https://diia.gov.ua",
        }),
      });
      if (!issueRes.ok) throw new Error(await issueRes.text());
      const { credential, format } = await issueRes.json();

      // 2. Generate proof: age >= 18
      const proveRes = await fetch(`${API_URL}/holder/prove-compound`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          credential,
          format,
          predicates: [{ claim: "birth_date", op: "gte", value: 18 }],
          op: "single",
        }),
      });
      if (!proveRes.ok) throw new Error(await proveRes.text());
      const proveData = await proveRes.json();
      // Measure raw proof size
      const jsonStr = proveData.compound_proof_json;
      const parsed = JSON.parse(jsonStr);
      const subProofs = parsed.sub_proofs || parsed.proofs || [parsed];
      const rawBytes = subProofs.reduce(
        (sum: number, sp: { proof_bytes?: number[] }) =>
          sum + (sp.proof_bytes?.length ?? 0),
        0,
      );
      setProofSizeBytes(rawBytes);

      // Measure compressed transport size
      const exportRes = await fetch(`${API_URL}/holder/proof-export-compound?compress=true`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ compound_proof_json: jsonStr }),
      });
      if (exportRes.ok) {
        const exportData = await exportRes.json();
        compressedCborRef.current = exportData.compressed_cbor_base64 || exportData.cbor_base64;
        setCompressedSizeBytes(atob(compressedCborRef.current!).length);
      }

      proofRef.current = {
        compound_proof_json: jsonStr,
        op: proveData.op,
        credential,
        format,
      };
      setPhase("proved");
    } catch (e: any) {
      setError(e.message);
      setPhase("error");
    }
  }, []);

  const handleVerify = useCallback(async () => {
    if (!proofRef.current) return;
    setPhase("verifying");
    setError(null);
    try {
      const t0 = performance.now();
      const res = await fetch(`${API_URL}/verifier/verify-compound`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          compound_proof_json: proofRef.current.compound_proof_json,
          hidden_fields: [],
        }),
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setVerifyTimeMs(Math.round(performance.now() - t0));
      if (!data.valid) throw new Error("Proof invalid");
      setPhase("verified");
    } catch (e: any) {
      setError(e.message);
      setPhase("error");
    }
  }, []);

  const reset = useCallback(() => {
    setPhase("idle");
    setError(null);
    setVerifyTimeMs(0);
    setProofSizeBytes(0);
    setCompressedSizeBytes(0);
    compressedCborRef.current = null;
    setQrDataUrl(null);
    proofRef.current = null;
  }, []);

  return (
    <section className="max-w-5xl mx-auto px-4 sm:px-8 py-16 sm:py-20">
      <h3 className="text-2xl sm:text-3xl font-bold text-center mb-3">
        {t("liveProof.title")}
      </h3>
      <p className="text-sm text-slate-400 text-center mb-10 max-w-2xl mx-auto">
        {t("liveProof.subtitle")}
      </p>

      <div className="max-w-lg mx-auto">
        {/* Scenario label */}
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-3 font-medium">
            {t("liveProof.scenario.label")}
          </p>
          <p className="text-sm text-slate-300 mb-6 font-medium">
            {t("liveProof.scenario")}
          </p>

          {/* Phase 1: Generate */}
          <div className="space-y-4">
            {phase === "idle" && (
              <button
                onClick={handleGenerate}
                className="w-full px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors text-sm"
              >
                {t("liveProof.generate")}
              </button>
            )}

            {phase === "proving" && (
              <div className="flex items-center justify-center gap-3 py-3">
                <div className="w-4 h-4 border-2 border-blue-400 border-t-transparent rounded-full animate-spin" />
                <span className="text-sm text-slate-300">
                  {t("liveProof.generating")}
                </span>
              </div>
            )}

            {/* Phase 2: Proof generated — show stats + verify button */}
            {(phase === "proved" || phase === "verifying" || phase === "verified") && (
              <div className="space-y-4">
                <div className="flex items-center gap-2 text-emerald-400 text-sm font-medium">
                  <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  {t("liveProof.proofGenerated")}
                </div>

                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="bg-slate-900/50 rounded-lg p-3">
                    <span className="text-slate-500">{t("liveProof.proofSize")}</span>
                    <p className="text-white font-mono font-bold mt-1">
                      {proofSizeBytes > 1024
                        ? `${(proofSizeBytes / 1024).toFixed(1)} KB`
                        : `${proofSizeBytes} B`}
                    </p>
                    <span className="text-[10px] text-slate-600">raw</span>
                  </div>
                  <div className="bg-slate-900/50 rounded-lg p-3">
                    <span className="text-slate-500">{t("liveProof.transportSize")}</span>
                    <p className="text-white font-mono font-bold mt-1">
                      {compressedSizeBytes > 1024
                        ? `${(compressedSizeBytes / 1024).toFixed(1)} KB`
                        : `${compressedSizeBytes} B`}
                    </p>
                    <span className="text-[10px] text-slate-600">CBOR + zstd</span>
                  </div>
                </div>

                {phase === "proved" && (
                  <button
                    onClick={handleVerify}
                    className="w-full px-6 py-3 bg-emerald-600 hover:bg-emerald-700 text-white font-semibold rounded-lg transition-colors text-sm"
                  >
                    {t("liveProof.verify")}
                  </button>
                )}

                {phase === "verifying" && (
                  <div className="flex items-center justify-center gap-3 py-3">
                    <div className="w-4 h-4 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin" />
                    <span className="text-sm text-slate-300">
                      {t("liveProof.verifying")}
                    </span>
                  </div>
                )}

                {phase === "verified" && (
                  <>
                    <div className="bg-emerald-900/30 border border-emerald-700/50 rounded-lg p-4">
                      <div className="flex items-center gap-2 text-emerald-400 font-medium text-sm mb-2">
                        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                          <polyline points="22 4 12 14.01 9 11.01" />
                        </svg>
                        {t("liveProof.verified")}
                      </div>
                      <div className="text-xs text-slate-400">
                        <span className="text-slate-500">{t("liveProof.verifyTime")}:</span>{" "}
                        <span className="text-white font-mono font-bold">
                          {verifyTimeMs < 1000
                            ? `${verifyTimeMs} ms`
                            : `${(verifyTimeMs / 1000).toFixed(1)} s`}
                        </span>{" "}
                        <span className="text-emerald-500/70 text-[10px]">
                          {t("liveProof.clientSide")}
                        </span>
                      </div>
                    </div>
                    {/* Proof QR + size comparison */}
                    <ProofQrComparison
                      compressedCborRef={compressedCborRef}
                      compressedSizeBytes={compressedSizeBytes}
                      qrDataUrl={qrDataUrl}
                      setQrDataUrl={setQrDataUrl}
                      t={t}
                    />
                    {/* Print + Reset */}
                    <div className="grid grid-cols-2 gap-2">
                      <button
                        onClick={() => {
                          if (!compressedCborRef.current) return;
                          const printState = {
                            proofs: [{ predicate: "age \u2265 18", op: "and", compressedCbor: compressedCborRef.current }],
                            predicates: [{ claim: "birth_date", op: "\u2265", publicValue: "18", disclosed: false }],
                            logicalOp: "single",
                            credentialLabel: "Personal Identification Data (PID)",
                          };
                          sessionStorage.setItem("zk-eidas-print-data", JSON.stringify(printState));
                          window.location.href = "/print";
                        }}
                        className="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-600 text-slate-300 hover:text-white rounded-lg transition-colors text-xs flex items-center justify-center gap-1.5"
                      >
                        <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="6 9 6 2 18 2 18 9" /><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2" /><rect x="6" y="14" width="12" height="8" />
                        </svg>
                        {t("liveProof.printQr")}
                      </button>
                      <button
                        onClick={reset}
                        className="px-4 py-2 border border-slate-700 text-slate-400 hover:text-white hover:border-slate-500 rounded-lg transition-colors text-xs"
                      >
                        {t("liveProof.reset")}
                      </button>
                    </div>
                  </>
                )}
              </div>
            )}

            {phase === "error" && (
              <div className="space-y-3">
                <div className="bg-red-900/30 border border-red-700/50 rounded-lg p-4 text-sm text-red-400">
                  {t("liveProof.failed")}: {error}
                </div>
                <button
                  onClick={reset}
                  className="w-full px-4 py-2 border border-slate-700 text-slate-400 hover:text-white hover:border-slate-500 rounded-lg transition-colors text-xs"
                >
                  Reset
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

/* === Section 4: Paper Contracts === */

function PaperContractsSection() {
  const t = useT();
  const todayItems = (t("paperContracts.todayItems") ?? "").split("|");

  return (
    <section
      className="max-w-5xl mx-auto px-4 sm:px-8 py-16 sm:py-20 border-t border-slate-800"
    >
      <h3 className="text-2xl sm:text-3xl font-bold text-center mb-3">
        {t("paperContracts.title")}
      </h3>
      <p className="text-sm text-slate-400 text-center mb-12 max-w-2xl mx-auto leading-relaxed">
        {t("paperContracts.subtitle")}
      </p>

      {/* Before / After comparison */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-3xl mx-auto mb-10">
        {/* Today */}
        <div className="bg-red-950/20 border border-red-900/30 rounded-xl p-5">
          <p className="text-xs text-red-400/80 uppercase tracking-wider font-medium mb-4">
            {t("paperContracts.todayLabel")}
          </p>
          <div className="space-y-2.5">
            {todayItems.map((item, i) => (
              <div key={i} className="flex items-start gap-2.5">
                <span className="text-red-500/60 mt-0.5 shrink-0 text-xs">✕</span>
                <p className="text-xs text-slate-400 leading-relaxed">{item}</p>
              </div>
            ))}
          </div>
        </div>

        {/* With ZK */}
        <div className="bg-emerald-950/20 border border-emerald-900/30 rounded-xl p-5">
          <p className="text-xs text-emerald-400/80 uppercase tracking-wider font-medium mb-4">
            {t("paperContracts.zkLabel")}
          </p>
          <div className="space-y-2.5">
            {(
              [
                { key: "paperContracts.sellerProved", icon: "user" },
                { key: "paperContracts.vehicleProved", icon: "car" },
                { key: "paperContracts.buyerProved", icon: "user" },
              ] as const
            ).map(({ key, icon }) => (
              <div key={key} className="flex items-start gap-2.5">
                <div className="w-4 h-4 rounded-full bg-emerald-500/20 flex items-center justify-center shrink-0 mt-0.5">
                  {icon === "car" ? (
                    <svg className="w-2.5 h-2.5 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M14 16H9m10 0h3v-3.15a1 1 0 0 0-.84-.99L16 11l-2.7-3.6a1 1 0 0 0-.8-.4H5.24a2 2 0 0 0-1.8 1.1l-.8 1.63A6 6 0 0 0 2 12.42V16h2" />
                      <circle cx="6.5" cy="16.5" r="2.5" />
                      <circle cx="16.5" cy="16.5" r="2.5" />
                    </svg>
                  ) : (
                    <svg className="w-2.5 h-2.5 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                      <circle cx="12" cy="7" r="4" />
                    </svg>
                  )}
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">{t(key)}</p>
              </div>
            ))}
            <div className="flex items-start gap-2.5">
              <div className="w-4 h-4 rounded-full bg-emerald-500/20 flex items-center justify-center shrink-0 mt-0.5">
                <svg className="w-2.5 h-2.5 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
                  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">{t("paperContracts.escrowLine")}</p>
            </div>
            <div className="pt-1">
              <p className="text-[11px] text-emerald-500/60 italic">
                {t("paperContracts.noNames")}
              </p>
            </div>
            <div className="pt-2 border-t border-emerald-900/30 mt-2">
              {t("paperContracts.courtResolution").split("\n").map((line, i) => (
                <p key={i} className="text-[10px] text-slate-400 leading-relaxed">
                  {line}
                </p>
              ))}
            </div>
            <div className="pt-2 mt-2 border-t border-emerald-900/30">
              <p className="text-[10px] text-emerald-400/70 leading-relaxed">
                {t("paperContracts.quantumSafe")}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Registry isolation callout */}
      <div className="max-w-3xl mx-auto mb-10 bg-slate-800/30 border border-slate-700/40 rounded-xl p-5 sm:p-6">
        <h4 className="text-sm font-semibold mb-3" style={{ color: "#FFD500" }}>
          {t("paperContracts.isolationTitle")}
        </h4>
        <p className="text-xs sm:text-sm text-slate-400 leading-relaxed mb-3">
          {t("paperContracts.isolationDesc1")}
        </p>
        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed mb-4 font-medium">
          {t("paperContracts.isolationDesc2")}
        </p>
        <div className="grid grid-cols-3 gap-3 text-center">
          {[
            { icon: "registry", label: t("paperContracts.isolationRegistry1") },
            { icon: "citizen", label: t("paperContracts.isolationCitizen") },
            { icon: "registry", label: t("paperContracts.isolationRegistry2") },
          ].map((item, i) => (
            <div key={item.label} className="flex flex-col items-center gap-1.5">
              {item.icon === "citizen" ? (
                <div className="relative flex items-center">
                  <svg className="w-3 h-3 text-slate-600 -mr-1" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="15 18 9 12 15 6" /></svg>
                  <div className="w-8 h-8 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center">
                    <svg className="w-4 h-4 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                      <circle cx="12" cy="7" r="4" />
                    </svg>
                  </div>
                  <svg className="w-3 h-3 text-slate-600 -ml-1" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="9 18 15 12 9 6" /></svg>
                </div>
              ) : (
                <div className="w-8 h-8 rounded-lg bg-slate-700/50 border border-slate-600/50 flex items-center justify-center">
                  <svg className="w-4 h-4 text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="2" y="3" width="20" height="14" rx="2" />
                    <path d="M8 21h8" /><path d="M12 17v4" />
                  </svg>
                </div>
              )}
              <span className="text-[10px] sm:text-xs text-slate-500">{item.label}</span>
              {i === 1 && (
                <span className="text-[9px] text-emerald-500/60 font-mono">{t("paperContracts.isolationProofOnly")}</span>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* CTA */}
      <div className="text-center mt-8">
        <Link
          to="/demo"
          className="inline-flex px-6 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors text-sm"
        >
          {t("paperContracts.cta")}
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
              to="/ukraine"
              className="hidden sm:inline text-xs text-slate-400 hover:text-slate-200 transition-colors font-medium"
            >
              {t("nav.ukraine")}
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

      <ProblemSection />

      <SolutionSteps />

      <LiveProofSection />

      <PaperContractsSection />

      {/* Footer */}
      <footer className="border-t border-slate-800 px-4 sm:px-8 py-8">
        <div className="max-w-5xl mx-auto flex items-center justify-between text-sm text-slate-500">
          <span>{t("footer.license")}</span>
          <div className="flex items-center gap-6">
            <Link to="/learn" className="hover:text-slate-300 transition-colors">
              {t("nav.learn")}
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
