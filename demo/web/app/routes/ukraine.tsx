import { createFileRoute, Link } from "@tanstack/react-router";
import { useT, useLocale } from "../i18n";

export const Route = createFileRoute("/ukraine")({
  component: UkrainePage,
});

function UkrainePage() {
  const t = useT();
  const { locale, setLocale } = useLocale();

  const facts = [
    "ua.fact1", "ua.fact2", "ua.fact3",
    "ua.fact4", "ua.fact5", "ua.fact6",
  ];

  const problems = ["ua.problem1", "ua.problem2", "ua.problem3", "ua.problem4"];
  const solutions = ["ua.solution1", "ua.solution2", "ua.solution3", "ua.solution4"];
  const wartime = ["ua.wartime1", "ua.wartime2", "ua.wartime3"];

  return (
    <div className="min-h-screen bg-slate-900 text-white">
      {/* Header */}
      <header className="border-b border-slate-800 px-4 sm:px-8 py-4 pt-[max(1rem,env(safe-area-inset-top))] bg-slate-950/80 backdrop-blur-md">
        <div className="max-w-4xl mx-auto flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-600 to-blue-700 flex items-center justify-center">
              <span className="text-xs font-bold text-white tracking-tighter">zk</span>
            </div>
            <h1 className="text-sm font-semibold tracking-tight leading-none">
              <span style={{ color: "#005BBB" }}>zk</span>
              <span className="text-slate-600 mx-0.5">-</span>
              <span style={{ color: "#FFD500" }}>eidas</span>
            </h1>
          </Link>
          <div className="flex items-center gap-4">
            <button
              onClick={() => setLocale(locale === "uk" ? "en" : "uk")}
              className="text-xs text-slate-500 hover:text-slate-300 transition-colors font-medium px-2 py-1 rounded border border-slate-800 hover:border-slate-700"
            >
              {locale === "uk" ? "EN" : "UA"}
            </button>
            <Link to="/" className="text-xs text-slate-400 hover:text-slate-200 transition-colors">
              {t("ua.back")}
            </Link>
          </div>
        </div>
      </header>

      {/* Hero with flag gradient */}
      <section
        className="border-t-[3px] border-t-transparent"
        style={{ borderImage: "linear-gradient(to right, #005BBB, #FFD500) 1" }}
      >
        <div className="max-w-4xl mx-auto px-4 sm:px-8 py-12 sm:py-16">
          {/* Flag */}
          <div className="flex items-center gap-4 mb-6">
            <div className="w-12 h-8 rounded-sm overflow-hidden flex flex-col shadow-md">
              <div className="flex-1" style={{ background: "#005BBB" }} />
              <div className="flex-1" style={{ background: "#FFD500" }} />
            </div>
            <h2 className="text-2xl sm:text-3xl font-bold">{t("ua.title")}</h2>
          </div>
          <p className="text-base sm:text-lg text-slate-300 max-w-2xl leading-relaxed">
            {t("ua.heroSubtitle")}
          </p>
        </div>
      </section>

      {/* Facts */}
      <section className="max-w-4xl mx-auto px-4 sm:px-8 py-12 border-t border-slate-800">
        <h3 className="text-lg font-semibold mb-6 flex items-center gap-2">
          <div className="w-1.5 h-1.5 rounded-full" style={{ background: "#005BBB" }} />
          {t("ua.factsTitle")}
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {facts.map((key) => (
            <div key={key} className="bg-slate-800/40 border border-slate-700/30 rounded-lg px-4 py-3 flex items-start gap-3">
              <svg className="w-4 h-4 text-blue-400 mt-0.5 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                <polyline points="20 6 9 17 4 12" />
              </svg>
              <span className="text-sm text-slate-300 leading-relaxed">{t(key)}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Problem / Solution split */}
      <section className="max-w-4xl mx-auto px-4 sm:px-8 py-12 border-t border-slate-800">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Problem */}
          <div className="bg-red-950/20 border border-red-900/30 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-red-400/80 uppercase tracking-wider mb-4 flex items-center gap-2">
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                <circle cx="12" cy="12" r="10" />
                <line x1="15" y1="9" x2="9" y2="15" />
                <line x1="9" y1="9" x2="15" y2="15" />
              </svg>
              {t("ua.problemTitle")}
            </h3>
            <div className="space-y-2.5">
              {problems.map((key) => (
                <div key={key} className="flex items-start gap-2.5">
                  <span className="text-red-500/60 mt-0.5 shrink-0 text-xs">&times;</span>
                  <p className="text-xs text-slate-400 leading-relaxed">{t(key)}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Solution */}
          <div className="bg-emerald-950/20 border border-emerald-900/30 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-emerald-400/80 uppercase tracking-wider mb-4 flex items-center gap-2">
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                <polyline points="20 6 9 17 4 12" />
              </svg>
              {t("ua.solutionTitle")}
            </h3>
            <div className="space-y-2.5">
              {solutions.map((key, i) => (
                <div key={key} className="flex items-start gap-2.5">
                  <span className="text-emerald-500/60 mt-0.5 shrink-0 text-[10px] font-mono font-bold">{i + 1}.</span>
                  <p className="text-xs text-slate-300 leading-relaxed">{t(key)}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Wartime context */}
      <section className="max-w-4xl mx-auto px-4 sm:px-8 py-12 border-t border-slate-800">
        <h3 className="text-lg font-semibold mb-6 flex items-center gap-2">
          <div className="w-1.5 h-1.5 rounded-full" style={{ background: "#FFD500" }} />
          {t("ua.wartimeTitle")}
        </h3>
        <div className="space-y-3">
          {wartime.map((key) => (
            <div key={key} className="bg-slate-800/30 border border-slate-700/30 rounded-lg px-4 py-3 flex items-start gap-3">
              <svg className="w-4 h-4 text-yellow-500/60 mt-0.5 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              <span className="text-sm text-slate-300 leading-relaxed">{t(key)}</span>
            </div>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="max-w-4xl mx-auto px-4 sm:px-8 py-12 border-t border-slate-800 text-center">
        <div className="flex items-center justify-center gap-3">
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
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-800 px-4 sm:px-8 py-8">
        <div className="max-w-4xl mx-auto flex items-center justify-between text-sm text-slate-500">
          <span>{t("footer.license")}</span>
          <span className="font-medium tracking-wide">Alik.eth</span>
        </div>
      </footer>
    </div>
  );
}
