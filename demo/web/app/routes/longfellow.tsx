import { createFileRoute, Link } from '@tanstack/react-router'
import { useState } from 'react'

export const Route = createFileRoute('/longfellow')({
  component: Longfellow,
})

const API_URL = typeof window !== 'undefined' && window.location.hostname === 'localhost' ? 'http://localhost:3001' : ''

interface BenchmarkResult {
  status: string
  backend: string
  proving_system: string
  quantum_safe: boolean
  trusted_setup: boolean
  circuit_bytes: number
  proof_bytes: number
  timing: {
    circuit_gen_ms: number
    circuit_cached: boolean
    prove_verify_ms: number
    total_ms: number
  }
}

function Longfellow() {
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<BenchmarkResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [history, setHistory] = useState<BenchmarkResult[]>([])

  const runBenchmark = async () => {
    setRunning(true)
    setError(null)
    try {
      const res = await fetch(`${API_URL}/longfellow/demo`)
      if (!res.ok) throw new Error(await res.text())
      const data: BenchmarkResult = await res.json()
      setResult(data)
      setHistory(prev => [data, ...prev].slice(0, 10))
    } catch (e: any) {
      setError(e.message)
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2">
            <span className="text-xl font-bold text-blue-400">zk-eidas</span>
            <span className="text-sm text-amber-400 font-mono">/longfellow</span>
          </Link>
          <nav className="flex gap-6 text-sm text-slate-400">
            <Link to="/demo" className="hover:text-slate-300 transition-colors">Demo</Link>
            <Link to="/learn" className="hover:text-slate-300 transition-colors">Learn</Link>
          </nav>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-12 space-y-12">
        {/* Hero */}
        <div className="text-center space-y-4">
          <h1 className="text-4xl font-bold">
            <span className="text-blue-400">Groth16</span>
            {' vs '}
            <span className="text-amber-400">Longfellow</span>
          </h1>
          <p className="text-slate-400 text-lg max-w-2xl mx-auto">
            Comparing our current BN254/Groth16 proving backend with Google's
            Longfellow ZK (Sumcheck + Ligero). Same credential, same predicate, different proof system.
          </p>
        </div>

        {/* Comparison Table */}
        <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700">
                <th className="text-left px-6 py-3 text-slate-400 font-medium">Property</th>
                <th className="text-center px-6 py-3 text-blue-400 font-medium">Groth16 (current)</th>
                <th className="text-center px-6 py-3 text-amber-400 font-medium">Longfellow (new)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/50">
              <Row label="Proving system" groth16="BN254 pairings" longfellow="Sumcheck + Ligero" />
              <Row label="Quantum safe" groth16={<No />} longfellow={<Yes />} />
              <Row label="Trusted setup" groth16={<Bad text="Required" />} longfellow={<Good text="None" />} />
              <Row label="Proof size" groth16="192 bytes" longfellow="~360 KB" />
              <Row label="Prove + verify (server)" groth16="~2.5s" longfellow={result ? `${(result.timing.prove_verify_ms / 1000).toFixed(1)}s` : '~1.8s'} />
              <Row label="Security assumption" groth16="Pairing (broken by Shor)" longfellow="SHA-256 only" />
              <Row label="Browser proving" groth16="Yes (slow)" longfellow="No (native only)" />
              <Row label="ECDSA P-256" groth16="~1.8M constraints" longfellow="~21K wires, depth 7" />
              <Row label="Credential format" groth16="SD-JWT + mdoc" longfellow="mdoc (ISO 18013-5)" />
            </tbody>
          </table>
        </div>

        {/* Live Benchmark */}
        <div className="bg-slate-800 rounded-xl border border-slate-700 p-8 space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-bold text-amber-400">Live Benchmark</h2>
              <p className="text-sm text-slate-400 mt-1">
                Proves age_over_18 on a real mdoc credential via Longfellow
              </p>
            </div>
            <button
              onClick={runBenchmark}
              disabled={running}
              className="px-6 py-3 bg-amber-600 hover:bg-amber-700 disabled:bg-slate-600 text-white font-semibold rounded-lg transition-colors flex items-center gap-2"
            >
              {running ? (
                <>
                  <svg className="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Proving...
                </>
              ) : 'Run Benchmark'}
            </button>
          </div>

          {error && (
            <div className="bg-red-950/30 border border-red-700/40 rounded-lg p-4 text-red-300 text-sm">
              {error}
            </div>
          )}

          {result && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <Stat
                label="Prove + Verify"
                value={`${(result.timing.prove_verify_ms / 1000).toFixed(2)}s`}
                color="amber"
              />
              <Stat
                label="Circuit Gen"
                value={result.timing.circuit_cached ? 'Cached' : `${(result.timing.circuit_gen_ms / 1000).toFixed(1)}s`}
                color={result.timing.circuit_cached ? 'green' : 'slate'}
              />
              <Stat
                label="Proof Size"
                value={`${(result.proof_bytes / 1024).toFixed(0)} KB`}
                color="blue"
              />
              <Stat
                label="Circuit Size"
                value={`${(result.circuit_bytes / 1024).toFixed(0)} KB`}
                color="slate"
              />
            </div>
          )}

          {result && (
            <div className="flex flex-wrap gap-3">
              <Badge color="amber" text={`Backend: ${result.backend}`} />
              <Badge color="green" text="Quantum Safe" />
              <Badge color="blue" text="No Trusted Setup" />
              <Badge color="slate" text={`Proving: ${result.proving_system}`} />
            </div>
          )}

          {/* History */}
          {history.length > 1 && (
            <div className="border-t border-slate-700 pt-4">
              <h3 className="text-sm font-semibold text-slate-400 mb-2">Run History</h3>
              <div className="space-y-1">
                {history.map((h, i) => (
                  <div key={i} className="flex items-center justify-between text-xs text-slate-500 font-mono">
                    <span>Run #{history.length - i}</span>
                    <span>{h.timing.circuit_cached ? 'cached' : 'cold'}</span>
                    <span>{h.timing.prove_verify_ms}ms prove+verify</span>
                    <span>{h.timing.total_ms}ms total</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Architecture */}
        <div className="bg-slate-800 rounded-xl border border-slate-700 p-8 space-y-4">
          <h2 className="text-xl font-bold">Architecture</h2>
          <div className="grid md:grid-cols-2 gap-8">
            <div className="space-y-3">
              <h3 className="text-blue-400 font-semibold">Current: Groth16</h3>
              <div className="font-mono text-xs text-slate-400 bg-slate-900 rounded-lg p-4 space-y-1">
                <p>SD-JWT/mdoc</p>
                <p className="text-slate-600">  |</p>
                <p>  Rust Parser</p>
                <p className="text-slate-600">  |</p>
                <p>  Circom Circuits (BN254)</p>
                <p className="text-slate-600">  |</p>
                <p>  Groth16 Prover (rapidsnark)</p>
                <p className="text-slate-600">  |</p>
                <p className="text-blue-400">  192-byte proof</p>
              </div>
            </div>
            <div className="space-y-3">
              <h3 className="text-amber-400 font-semibold">New: Longfellow</h3>
              <div className="font-mono text-xs text-slate-400 bg-slate-900 rounded-lg p-4 space-y-1">
                <p>mdoc (ISO 18013-5)</p>
                <p className="text-slate-600">  |</p>
                <p>  Longfellow C++ Circuits</p>
                <p className="text-slate-600">  |</p>
                <p>  Sumcheck + Ligero Prover</p>
                <p className="text-slate-600">  |</p>
                <p className="text-amber-400">  ~360 KB proof (post-quantum)</p>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}

function Row({ label, groth16, longfellow }: { label: string; groth16: React.ReactNode; longfellow: React.ReactNode }) {
  return (
    <tr>
      <td className="px-6 py-3 text-slate-300 font-medium">{label}</td>
      <td className="px-6 py-3 text-center text-slate-400">{groth16}</td>
      <td className="px-6 py-3 text-center text-slate-300">{longfellow}</td>
    </tr>
  )
}

function Yes() { return <span className="text-green-400 font-semibold">Yes</span> }
function No() { return <span className="text-red-400 font-semibold">No</span> }
function Good({ text }: { text: string }) { return <span className="text-green-400">{text}</span> }
function Bad({ text }: { text: string }) { return <span className="text-red-400">{text}</span> }

function Stat({ label, value, color }: { label: string; value: string; color: string }) {
  const colors: Record<string, string> = {
    amber: 'text-amber-400',
    green: 'text-green-400',
    blue: 'text-blue-400',
    slate: 'text-slate-300',
  }
  return (
    <div className="bg-slate-900 rounded-lg p-4">
      <p className="text-xs text-slate-500 mb-1">{label}</p>
      <p className={`text-2xl font-bold font-mono ${colors[color] || 'text-slate-300'}`}>{value}</p>
    </div>
  )
}

function Badge({ color, text }: { color: string; text: string }) {
  const colors: Record<string, string> = {
    amber: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    green: 'bg-green-500/10 text-green-400 border-green-500/30',
    blue: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
    slate: 'bg-slate-700/50 text-slate-400 border-slate-600/50',
  }
  return (
    <span className={`px-3 py-1 rounded-full text-xs font-medium border ${colors[color] || colors.slate}`}>
      {text}
    </span>
  )
}
