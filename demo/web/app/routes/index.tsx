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
    format: "SD-JWT VC",
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
    format: "SD-JWT VC",
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
  const showRevoke = phase >= 4 && phase <= 6;
  const revokePressed = phase >= 6 && phase <= 6;
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
          <div className="border-2 border-emerald-500/60 rounded-lg px-3 py-2 space-y-0.5">
            <p className="text-emerald-500/80 text-[10px] font-bold tracking-wide whitespace-nowrap">
              {t("cred.conditions")}
            </p>
            <p className="text-slate-400 text-[9px] font-mono whitespace-nowrap">
              {t("cred.nullifier")}
            </p>
            <p className="text-emerald-500/60 text-[9px] font-medium whitespace-nowrap">
              {t("cred.noPersonalData")}
            </p>
          </div>
          {/* Revoke button — appears below stamp */}
          <div className="flex justify-center mt-3">
            <button
              className="text-[10px] font-medium px-3 py-1 rounded border transition-all duration-200"
              style={{
                opacity: showRevoke ? 1 : 0,
                transform: `translateY(${showRevoke ? "0" : "4px"}) scale(${revokePressed ? 0.95 : 1})`,
                borderColor: revokePressed ? "#ef4444" : "#64748b",
                color: revokePressed ? "#ef4444" : "#94a3b8",
                backgroundColor: revokePressed
                  ? "rgba(239,68,68,0.1)"
                  : "rgba(15,23,42,0.8)",
              }}
            >
              {t("cred.revoke")}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/* === Capabilities Triptych — 3 animated cards === */

/* ── Capabilities Triptych — animated cards ──────────────────────────── */
// Durations: build-up phases, then hold, fade-out, relax
const WASM_DURATIONS = [800, 600, 2000, 800, 600];
const PAPER_DURATIONS = [1400, 1200, 1000, 2000, 800, 600];
const CONTRACTS_DURATIONS = [1200, 1000, 800, 2000, 800, 600];

// Phase model: 0..N-3 = build-up phases (accumulative), N-2 = hold, N-1 = fade-out, then reset after relax
function useCardPhase(durations: number[], startDelay: number, visible: boolean) {
  const [phase, setPhase] = useState(-1);
  const fadePhase = durations.length - 2; // fade-out phase index
  const relaxDuration = durations[durations.length - 1]; // relax pause after fade

  useEffect(() => {
    if (!visible) return;
    const timer = setTimeout(() => setPhase(0), startDelay);
    return () => clearTimeout(timer);
  }, [visible, startDelay]);

  useEffect(() => {
    if (phase < 0) return;
    if (phase < durations.length - 1) {
      // Advance to next phase after current duration
      const timer = setTimeout(() => setPhase((p) => p + 1), durations[phase]);
      return () => clearTimeout(timer);
    }
    // Last phase (relax): wait, then reset to 0
    const timer = setTimeout(() => setPhase(0), relaxDuration);
    return () => clearTimeout(timer);
  }, [phase, durations, relaxDuration]);

  return { phase, fadePhase };
}

/* Card 1 — Client-Side Verification
   Story: proof bytes stream into the browser → device processes locally → instant verified
   Phases: 0=proof stream, 1=device processing, 2=flash, 3=verified+timing, 4=hold */
function WasmCard({ startDelay, visible }: { startDelay: number; visible: boolean }) {
  const t = useT();
  const { phase, fadePhase } = useCardPhase(WASM_DURATIONS, startDelay, visible);
  const isFading = phase >= fadePhase;

  return (
    <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-5 flex flex-col group hover:border-slate-600/80 transition-colors">
      <div className="bg-slate-900/60 rounded-lg h-40 flex items-center justify-center mb-4 overflow-hidden relative">
        {/* Subtle grid background */}
        <div className="absolute inset-0 opacity-[0.03]" style={{
          backgroundImage: 'linear-gradient(rgba(255,255,255,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px)',
          backgroundSize: '12px 12px',
        }} />

        <div className="flex flex-col items-center gap-2 transition-opacity duration-700" style={{ opacity: isFading ? 0 : 1 }}>
          {/* Phase 0: Phone appears */}
          {phase >= 0 && (
            <div className="flex items-center gap-3" style={{ animation: 'fadeIn 0.4s ease-out' }}>
              {/* Phone outline */}
              <div className="w-12 h-20 rounded-lg border-2 border-slate-500 bg-slate-800 flex flex-col items-center justify-center relative overflow-hidden">
                {/* Notch */}
                <div className="absolute top-1 w-5 h-1 rounded-full bg-slate-600" />
                {/* Screen content */}
                <div className="flex flex-col items-center gap-1 mt-1">
                  {/* Phase 1: Checkmark + time appear */}
                  {phase >= 1 ? (
                    <>
                      <div className="w-7 h-7 rounded-full border-2 border-emerald-400/60 flex items-center justify-center bg-emerald-400/5" style={{ animation: 'fadeIn 0.3s ease-out' }}>
                        <svg className="w-4 h-4 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12" /></svg>
                      </div>
                      <span className="text-[7px] font-mono text-emerald-400 tracking-tight" style={{ animation: 'fadeIn 0.3s ease-out 200ms both' }}>47ms</span>
                    </>
                  ) : (
                    <div className="w-5 h-5 rounded-full border-2 border-blue-400/60 relative">
                      <div className="absolute inset-1 rounded-full bg-blue-400/30 animate-ping" />
                      <div className="absolute inset-1.5 rounded-full bg-blue-400/60" />
                    </div>
                  )}
                </div>
                {/* Home bar */}
                <div className="absolute bottom-1 w-4 h-0.5 rounded-full bg-slate-600" />
              </div>
              {/* Label next to phone */}
              <div className="flex flex-col gap-0.5">
                {phase >= 1 ? (
                  <span className="text-[8px] text-emerald-400 tracking-widest uppercase font-semibold" style={{ animation: 'fadeIn 0.3s ease-out' }}>verified</span>
                ) : (
                  <span className="text-[8px] text-blue-400/60 font-mono tracking-wider">VERIFYING</span>
                )}
                <span className="text-[7px] text-slate-500 tracking-wider">on your device</span>
              </div>
            </div>
          )}
        </div>
      </div>
      <h4 className="text-sm font-semibold mb-2 text-white">{t("caps.wasmTitle")}</h4>
      <p className="text-sm text-slate-400 leading-relaxed mb-3 flex-1">{t("caps.wasmDesc")}</p>
      <Link to="/demo" className="text-sm text-blue-400 hover:text-blue-300 font-semibold transition-colors">
        {t("caps.wasmCta")} <span className="inline-block transition-transform group-hover:translate-x-0.5">→</span>
      </Link>
    </div>
  );
}

/* Card 2 — Backward Compatibility with Paper
   Story: digital credential → printed A4 with QR → scanned back → verified offline
   Phases: 0=digital badge, 1=transforms to paper+QR, 2=camera scan, 3=offline verified, 4=hold */
function PaperCard({ startDelay, visible }: { startDelay: number; visible: boolean }) {
  const t = useT();
  const { phase, fadePhase } = useCardPhase(PAPER_DURATIONS, startDelay, visible);
  const isFading = phase >= fadePhase;

  return (
    <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-5 flex flex-col group hover:border-slate-600/80 transition-colors">
      <div className="bg-slate-900/60 rounded-lg h-40 flex items-center justify-center mb-4 overflow-hidden relative">
        <div className="absolute inset-0 opacity-[0.03]" style={{
          backgroundImage: 'linear-gradient(rgba(255,255,255,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px)',
          backgroundSize: '12px 12px',
        }} />

        <div className="transition-opacity duration-700" style={{ opacity: isFading ? 0 : 1 }}>
          {phase >= 0 && (
            <div className="flex flex-col items-center gap-2">
              <div className="flex items-center gap-2">
                {/* eID badge */}
                <div className="w-10 h-7 rounded border border-blue-500/40 bg-blue-500/10 flex items-center justify-center" style={{ animation: 'slideInLeft 0.5s ease-out' }}>
                  <span className="text-[7px] font-mono text-blue-300 tracking-tight">eID</span>
                </div>
                <svg className="w-3 h-3 text-slate-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="9 18 15 12 9 6" /></svg>

                {/* Phase 1: A4 paper with QR codes appears */}
                {phase >= 1 && (
                  <div className="w-12 h-16 bg-slate-200/90 rounded-[2px] shadow-md shadow-black/20 flex flex-col items-center justify-between p-1.5 relative" style={{ animation: 'fadeIn 0.4s ease-out' }}>
                    <div className="w-full space-y-0.5">
                      <div className="h-[2px] bg-slate-400/40 rounded w-full" />
                      <div className="h-[2px] bg-slate-400/30 rounded w-3/4" />
                    </div>
                    <div className="flex gap-1">
                      {[0, 1].map((i) => (
                        <div key={i} className="w-3 h-3 bg-slate-700/80 rounded-[1px]" style={{
                          animation: `fadeIn 0.3s ease-out ${300 + i * 200}ms both`,
                        }}>
                          <div className="w-full h-full grid grid-cols-2 grid-rows-2 gap-[1px] p-[1px]">
                            {[0,1,2,3].map(j => <div key={j} className="bg-slate-200/60 rounded-[0.5px]" />)}
                          </div>
                        </div>
                      ))}
                    </div>
                    <div className="h-[2px] bg-slate-400/20 rounded w-full" />
                    {/* Phase 2: Scan line overlay */}
                    {phase >= 2 && (
                      <div className="absolute left-0 right-0 h-[2px] bg-emerald-400/60 rounded" style={{
                        animation: 'scanDown 1s ease-in-out infinite',
                      }} />
                    )}
                  </div>
                )}

                {/* Phase 2: Camera icon */}
                {phase >= 2 && (
                  <div style={{ animation: 'fadeIn 0.3s ease-out' }}>
                    <svg className="w-6 h-6 text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                      <rect x="2" y="4" width="20" height="16" rx="2" />
                      <circle cx="12" cy="12" r="4" />
                      <circle cx="12" cy="12" r="1.5" fill="currentColor" opacity="0.3" />
                    </svg>
                  </div>
                )}
              </div>

              {/* Phase 3: Verified + offline result */}
              {phase >= 3 && (
                <div className="flex items-center gap-2" style={{ animation: 'fadeIn 0.3s ease-out' }}>
                  <div className="w-6 h-6 rounded-full border-2 border-emerald-400/60 flex items-center justify-center bg-emerald-400/5">
                    <svg className="w-3 h-3 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12" /></svg>
                  </div>
                  <div className="relative">
                    <svg className="w-4 h-4 text-slate-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                      <path d="M5 12.55a11 11 0 0 1 14.08 0" />
                      <path d="M1.42 9a16 16 0 0 1 21.16 0" />
                      <path d="M8.53 16.11a6 6 0 0 1 6.95 0" />
                      <circle cx="12" cy="20" r="1" fill="currentColor" />
                    </svg>
                    <div className="absolute inset-0 flex items-center justify-center">
                      <div className="w-[140%] h-[1.5px] bg-red-400/80 rotate-45 rounded" />
                    </div>
                  </div>
                  <span className="text-[8px] text-slate-500 tracking-widest uppercase">no internet needed</span>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
      <h4 className="text-sm font-semibold mb-2 text-white">{t("caps.paperTitle")}</h4>
      <p className="text-sm text-slate-400 leading-relaxed mb-3 flex-1">{t("caps.paperDesc")}</p>
      <Link to="/verify" className="text-sm text-blue-400 hover:text-blue-300 font-semibold transition-colors">
        {t("caps.paperCta")} <span className="inline-block transition-transform group-hover:translate-x-0.5">→</span>
      </Link>
    </div>
  );
}

/* Card 3 — ZK-Enhanced Contracts
   Story: contract with personal data → ZK replaces credentials → clean document with proof
   Phases: 0=contract with exposed data, 1=data redacted by ZK, 2=stamp appears, 3=clean doc, 4=hold */
function ContractsCard({ startDelay, visible }: { startDelay: number; visible: boolean }) {
  const t = useT();
  const { phase, fadePhase } = useCardPhase(CONTRACTS_DURATIONS, startDelay, visible);
  const isFading = phase >= fadePhase;

  return (
    <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-5 flex flex-col group hover:border-slate-600/80 transition-colors">
      <div className="bg-slate-900/60 rounded-lg h-40 flex items-center justify-center mb-4 overflow-hidden relative">
        <div className="absolute inset-0 opacity-[0.03]" style={{
          backgroundImage: 'linear-gradient(rgba(255,255,255,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px)',
          backgroundSize: '12px 12px',
        }} />

        <div className="transition-opacity duration-700" style={{ opacity: isFading ? 0 : 1 }}>
          {phase >= 0 && (
            <div className="flex flex-col items-center gap-2">
              {/* Contract document — evolves through phases */}
              <div className="w-16 h-24 bg-slate-200/90 rounded-[2px] shadow-md shadow-black/20 p-1.5 flex flex-col gap-1 relative" style={{ animation: 'slideInLeft 0.4s ease-out' }}>
                <div className="h-[2px] bg-slate-400/40 rounded w-full" />

                {/* Row 1: PII → ZK badge */}
                <div className="flex items-center gap-0.5">
                  {phase >= 1 ? (
                    <div className="h-2.5 bg-emerald-500/20 border border-emerald-500/30 rounded flex-1 flex items-center justify-center" style={{ animation: 'fadeIn 0.3s ease-out' }}>
                      <span className="text-[4px] font-bold text-emerald-600 tracking-wider">ZK</span>
                    </div>
                  ) : (
                    <>
                      <div className="h-[2px] bg-red-400/60 rounded flex-1" />
                      <span className="text-[4px] text-red-400/80">PII</span>
                    </>
                  )}
                </div>

                <div className="h-[2px] bg-slate-400/30 rounded w-3/4" />

                {/* Row 2: PII → ZK badge */}
                <div className="flex items-center gap-0.5">
                  {phase >= 1 ? (
                    <div className="h-2.5 bg-emerald-500/20 border border-emerald-500/30 rounded flex-1 flex items-center justify-center" style={{ animation: 'fadeIn 0.3s ease-out 200ms both' }}>
                      <span className="text-[4px] font-bold text-emerald-600 tracking-wider">ZK</span>
                    </div>
                  ) : (
                    <>
                      <div className="h-[2px] bg-red-400/60 rounded flex-1" />
                      <span className="text-[4px] text-red-400/80">PII</span>
                    </>
                  )}
                </div>

                <div className="h-[2px] bg-slate-400/20 rounded w-1/2" />

                {/* Phase 2: VERIFIED stamp on the document */}
                {phase >= 2 && (
                  <div className="absolute bottom-1 left-1/2 -translate-x-1/2 text-[5px] font-bold text-emerald-600 border border-emerald-500/40 rounded px-1.5 py-0.5 bg-emerald-500/10" style={{
                    animation: 'fadeIn 0.3s ease-out 300ms both',
                    transform: 'translateX(-50%) rotate(-3deg)',
                  }}>
                    VERIFIED
                  </div>
                )}
              </div>

              {/* Phase 3: Compliant result below the document */}
              {phase >= 3 && (
                <div className="flex items-center gap-2" style={{ animation: 'fadeIn 0.3s ease-out' }}>
                  <div className="w-5 h-5 rounded-full border-2 border-emerald-400/60 flex items-center justify-center bg-emerald-400/5">
                    <svg className="w-3 h-3 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12" /></svg>
                  </div>
                  <div className="text-left">
                    <div className="text-[8px] text-emerald-400 font-semibold tracking-wider">COMPLIANT</div>
                    <div className="text-[7px] text-slate-500">no PII exposed</div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
      <h4 className="text-sm font-semibold mb-2 text-white">{t("caps.contractsTitle")}</h4>
      <p className="text-sm text-slate-400 leading-relaxed mb-3 flex-1">{t("caps.contractsDesc")}</p>
      <Link to="/contracts" className="text-sm text-blue-400 hover:text-blue-300 font-semibold transition-colors">
        {t("caps.contractsCta")} <span className="inline-block transition-transform group-hover:translate-x-0.5">→</span>
      </Link>
    </div>
  );
}

function CapabilitiesTriptych() {
  const t = useT();
  const sectionRef = useRef<HTMLElement>(null);
  const [visible, setVisible] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(false);

  useEffect(() => {
    const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (prefersReduced) {
      setReducedMotion(true);
      setVisible(true);
      return;
    }

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setVisible(true);
          observer.disconnect();
        }
      },
      { threshold: 0.2 },
    );

    if (sectionRef.current) {
      observer.observe(sectionRef.current);
    }

    return () => observer.disconnect();
  }, []);

  return (
    <section ref={sectionRef} className="max-w-5xl mx-auto px-4 sm:px-8 py-16 border-t border-slate-800">
      <style>{`
        @keyframes slideInLeft {
          from { transform: translateX(-20px); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        @keyframes scanDown {
          0% { top: 0; }
          50% { top: 100%; }
          100% { top: 0; }
        }
      `}</style>
      <h3 className="text-2xl font-bold text-center mb-4">{t("caps.title")}</h3>
      <p className="text-sm text-slate-400 text-center mb-12 max-w-2xl mx-auto">{t("caps.subtitle")}</p>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <WasmCard startDelay={reducedMotion ? 0 : 0} visible={visible} />
        <PaperCard startDelay={reducedMotion ? 0 : 500} visible={visible} />
        <ContractsCard startDelay={reducedMotion ? 0 : 1000} visible={visible} />
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
  const wasmReadyRef = useRef(false);
  const sdkRef = useRef<Awaited<typeof import("@zk-eidas/verifier-sdk")> | null>(null);
  const vksRef = useRef<any>(null);

  // Pre-load WASM when section mounts
  useEffect(() => {
    (async () => {
      try {
        const sdk = await import("@zk-eidas/verifier-sdk");
        const vks = await sdk.loadTrustedVks("/trusted-vks.json");
        await sdk.initVerifier();
        sdkRef.current = sdk;
        vksRef.current = vks;
        wasmReadyRef.current = true;
      } catch {
        // Will fall through to lazy init in handleVerify
      }
    })();
  }, []);

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
        compressedCborRef.current = exportData.compressed_cbor_base64;
        setCompressedSizeBytes(atob(exportData.compressed_cbor_base64).length);
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
      // Use pre-loaded SDK if available, otherwise lazy-load
      let sdk = sdkRef.current;
      let trustedVks = vksRef.current;
      if (!sdk || !trustedVks) {
        sdk = await import("@zk-eidas/verifier-sdk");
        trustedVks = await sdk.loadTrustedVks("/trusted-vks.json");
        await sdk.initVerifier();
        sdkRef.current = sdk;
        vksRef.current = trustedVks;
        wasmReadyRef.current = true;
      }

      const envelope = JSON.parse(proofRef.current.compound_proof_json);
      const chainResult = await sdk.verifyCompoundProof(envelope, trustedVks);
      setVerifyTimeMs(Math.round(performance.now() - t0));
      if (!chainResult.valid) throw new Error("Proof invalid");
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
          to="/contracts"
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
              to="/contracts"
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
              to="/verify"
              className="hidden sm:inline text-xs text-slate-400 hover:text-slate-200 transition-colors font-medium"
            >
              {t("nav.verify")}
            </Link>
            <Link
              to="/demo"
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
            <p className="text-lg text-slate-300 mb-3 leading-relaxed">
              {t("hero.subtitle")}
            </p>
            <p className="text-base text-slate-400 mb-3">{t("hero.tagline")}</p>
            <p className="text-sm text-slate-500 mb-4 leading-relaxed">
              {t("hero.description")}
            </p>
            <p className="text-sm text-slate-300 font-semibold mb-8">
              {t("hero.closing")}
            </p>
            <div className="flex items-center gap-3">
              <Link
                to="/contracts"
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
            <div className="w-full max-w-sm">
              <CredentialShowcase />
              <p className="text-[10px] text-slate-600 text-center mt-3 italic">
                {t("cred.tagline")}
              </p>
            </div>
          </div>
        </div>
      </section>

      <CapabilitiesTriptych />

      <LiveProofSection />

      <PaperContractsSection />

      {/* Research note */}
      <div className="max-w-5xl mx-auto px-4 sm:px-8 py-10 border-t border-slate-800 mt-8">
        <div className="max-w-2xl mx-auto text-center">
          {t("footer.research").split("\n").map((line, i) => (
            <p key={i} className={`text-xs leading-relaxed ${line === "" ? "h-3" : i >= 3 ? "text-slate-500 italic" : "text-slate-400"}`}>
              {line}
            </p>
          ))}
        </div>
      </div>

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
