import { createFileRoute, Link } from '@tanstack/react-router'
import { useState, useCallback, useEffect, useRef } from 'react'
import { useT, useLocale } from '../i18n'
import { ChunkCollector, decompressDeflate } from '../lib/qr-chunking'
import { useQrScanner } from '../lib/use-qr-scanner'

export const Route = createFileRoute('/verify')({
  component: VerifyPage,
})

interface DecodedProof {
  predicate: string
  proofBytes: Uint8Array
  publicInputs: Uint8Array[]
  op: string
  valid: boolean | null
}

function VerifyPage() {
  const t = useT()
  const { locale, setLocale } = useLocale()
  const [proofs, setProofs] = useState<DecodedProof[]>([])
  const [error, setError] = useState<string | null>(null)
  const [verifying, setVerifying] = useState(false)
  const [verified, setVerified] = useState(false)
  const [fileName, setFileName] = useState<string | null>(null)
  const [dragging, setDragging] = useState(false)
  const [wasmReady, setWasmReady] = useState(false)
  const [scanMode, setScanMode] = useState(false)
  const [scanProgress, setScanProgress] = useState<Map<number, [number, number]>>(new Map())
  const collectorRef = useRef(new ChunkCollector())

  // Pre-initialize snarkjs verification backend
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const [, { initVerifier, loadTrustedVks }] = await Promise.all([
          import('cbor-x'),  // eagerly cache for offline use
          import('@zk-eidas/verifier-sdk'),
        ])
        await loadTrustedVks('/trusted-vks.json')
        await initVerifier()
        if (!cancelled) setWasmReady(true)
      } catch (e) {
        console.warn('WASM init failed:', e)
      }
    })()
    return () => { cancelled = true }
  }, [])

  const handleFile = useCallback(async (file: File) => {
    setError(null)
    setVerified(false)
    setFileName(file.name)

    try {
      const buffer = await file.arrayBuffer()
      const bytes = new Uint8Array(buffer)

      const { decode } = await import('cbor-x')
      const envelope = decode(bytes)

      if (!envelope || !Array.isArray(envelope.proofs)) {
        throw new Error('Invalid proof envelope: missing proofs array')
      }

      const decoded: DecodedProof[] = envelope.proofs.map((p: any) => ({
        predicate: p.predicate || 'unknown',
        proofBytes: p.proof_bytes instanceof Uint8Array
          ? p.proof_bytes
          : new Uint8Array(p.proof_bytes),
        publicInputs: (p.public_inputs || []).map((pi: any) =>
          pi instanceof Uint8Array ? pi : new Uint8Array(pi)
        ),
        op: p.op || 'unknown',
        valid: null,
      }))

      setProofs(decoded)
    } catch (e: any) {
      setError(`Failed to decode CBOR: ${e.message}`)
      setProofs([])
    }
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragging(false)
    const file = e.dataTransfer.files[0]
    if (file) handleFile(file)
  }, [handleFile])

  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) handleFile(file)
  }, [handleFile])

  const stopScanRef = useRef<() => void>(() => {})

  const handleScanData = useCallback(async (data: Uint8Array) => {
    const collector = collectorRef.current
    const isNew = collector.add(data)
    if (!isNew) return

    // Update progress
    const progress = new Map<number, [number, number]>()
    for (const id of collector.proofIds()) {
      progress.set(id, collector.progress(id))
    }
    setScanProgress(new Map(progress))

    // Check if all complete
    if (collector.isAllComplete()) {
      try {
        const allProofs: DecodedProof[] = []
        for (const proofId of collector.proofIds()) {
          const compressed = collector.reassemble(proofId)!
          const cbor = await decompressDeflate(compressed)
          const { decode } = await import('cbor-x')
          const envelope = decode(cbor)

          if (envelope && Array.isArray(envelope.proofs)) {
            for (const p of envelope.proofs) {
              allProofs.push({
                predicate: p.predicate || 'unknown',
                proofBytes: p.proof_bytes instanceof Uint8Array
                  ? p.proof_bytes
                  : new Uint8Array(p.proof_bytes),
                publicInputs: (p.public_inputs || []).map((pi: unknown) =>
                  pi instanceof Uint8Array ? pi : new Uint8Array(pi as ArrayLike<number>)
                ),
                op: p.op || 'unknown',
                valid: null,
              })
            }
          }
        }

        setScanMode(false)
        stopScanRef.current()
        setProofs(allProofs)
        setFileName('paper-proof (scanned)')
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : 'Proof data corrupted, try re-scanning.')
      } finally {
        collectorRef.current.clear()
        setScanProgress(new Map())
      }
    }
  }, [])

  const scanner = useQrScanner(handleScanData)
  stopScanRef.current = scanner.stop

  const handleVerify = async () => {
    setVerifying(true)
    setError(null)
    try {
      const { verifyCompoundProof, loadTrustedVks } = await import('@zk-eidas/verifier-sdk')
      const vks = await loadTrustedVks('/trusted-vks.json')

      // Build a CompoundEnvelope from the decoded proofs
      const envelope = {
        proofs: proofs.map(p => ({
          proof_bytes: Array.from(p.proofBytes),
          public_inputs: p.publicInputs.map(pi => Array.from(pi)),
          verification_key: [],
          predicate_op: p.op,
        })),
        op: proofs.length > 1 ? 'and' : 'single',
      }
      const chainResult = await verifyCompoundProof(envelope, vks)

      const results = proofs.map((p, i) => ({
        ...p,
        valid: chainResult.predicateResults[i]?.valid ?? false,
      }))

      setProofs(results)
      setVerified(true)
    } catch (e: any) {
      setError(`Verification failed: ${e.message}`)
    } finally {
      setVerifying(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-900 text-white">
      <header className="border-b border-slate-700/80 px-8 py-5 bg-slate-900/95 backdrop-blur-sm">
        <div className="max-w-3xl mx-auto flex items-center justify-between">
          <Link to="/" className="group">
            <h1 className="text-xl font-bold tracking-tight group-hover:opacity-80 transition-opacity">
              <span style={{ color: '#005BBB' }}>zk</span>
              <span className="text-slate-500 mx-0.5">-</span>
              <span style={{ color: '#FFD500' }}>eidas</span>
            </h1>
          </Link>
          <div className="flex items-center gap-6">
            <Link to="/demo" className="text-sm text-slate-300 hover:text-white transition-colors">
              {t('nav.demo')}
            </Link>
            <span className="text-sm text-slate-500 font-medium tracking-wide">{t('verify.offlineVerifier')}</span>
            <button onClick={() => setLocale(locale === 'uk' ? 'en' : 'uk')} className="text-sm text-slate-400 hover:text-white transition-colors font-medium">
              {locale === 'uk' ? 'EN' : 'UA'}
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-3xl mx-auto px-8 py-12">
        <h2 className="text-2xl font-bold mb-2">{t('verify.title')}</h2>
        <p className="text-sm text-slate-400 mb-4">
          {t('verify.subtitle')}
        </p>
        <div className="bg-slate-800/60 border border-slate-700/50 rounded-lg px-4 py-3 mb-8 text-xs text-slate-400">
          <span className="text-slate-300 font-medium">{t('verify.pwaTip')}</span>{' '}
          {t('verify.pwaDesc')}
        </div>

        {proofs.length === 0 && (
          <div
            onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
            className={`border-2 border-dashed rounded-lg p-16 text-center transition-colors cursor-pointer ${
              dragging
                ? 'border-blue-500 bg-blue-900/20'
                : 'border-slate-600 hover:border-slate-500 bg-slate-800/50'
            }`}
            onClick={() => document.getElementById('file-input')?.click()}
          >
            <p className="text-lg text-slate-300 mb-2">{t('verify.dropHere')}</p>
            <p className="text-sm text-slate-500">{t('verify.orBrowse')}</p>
            <input
              id="file-input"
              type="file"
              accept=".cbor"
              onChange={handleFileInput}
              className="hidden"
            />
          </div>
        )}

        {proofs.length === 0 && (
          <div className="mt-4 text-center">
            <p className="text-xs text-slate-500 mb-2">{t('verify.orScanPaper')}</p>
            {!scanMode ? (
              <button
                onClick={() => { setScanMode(true); scanner.start() }}
                className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm font-medium rounded-lg transition-colors"
              >
                {t('verify.scanPaper')}
              </button>
            ) : (
              <div className="space-y-4">
                <div className="relative rounded-lg overflow-hidden bg-black max-w-md mx-auto">
                  <video ref={scanner.videoRef} className="w-full" playsInline muted />
                  <canvas ref={scanner.canvasRef} className="hidden" />
                </div>

                <p className="text-sm text-slate-400">{t('verify.scanning')}</p>

                {scanner.error && (
                  <p className="text-red-400 text-sm">{t('verify.cameraError')}</p>
                )}

                {scanProgress.size > 0 && (
                  <div className="space-y-2">
                    {[...scanProgress.entries()].map(([proofId, [scanned, total]]) => (
                      <div key={proofId} className="flex items-center gap-2 justify-center">
                        <div className="w-32 h-2 bg-slate-700 rounded-full overflow-hidden">
                          <div className="h-full bg-green-500 transition-all" style={{ width: `${(scanned / total) * 100}%` }} />
                        </div>
                        <span className="text-xs text-slate-400">{scanned}/{total} {t('verify.scanProgress')}</span>
                      </div>
                    ))}
                  </div>
                )}

                <button
                  onClick={() => { scanner.stop(); setScanMode(false); setScanProgress(new Map()); collectorRef.current.clear() }}
                  className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white text-sm font-medium rounded-lg transition-colors"
                >
                  {t('verify.stopScanning')}
                </button>
              </div>
            )}
          </div>
        )}

        {error && (
          <div className="bg-red-900/30 border border-red-700 rounded-lg p-4 text-red-300 text-sm mt-4">
            {error}
          </div>
        )}

        {proofs.length > 0 && (
          <div className="space-y-6">
            <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
              <div className="px-6 py-3 border-b border-slate-700 flex items-center justify-between">
                <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">{t('verify.proofEnvelope')}</h3>
                <span className="text-xs text-slate-500">{fileName}</span>
              </div>
              <div className="p-4 space-y-3">
                {proofs.map((p, i) => (
                  <div
                    key={i}
                    className={`flex items-center gap-3 rounded-lg px-4 py-3 border ${
                      p.valid === null
                        ? 'bg-slate-700/30 border-slate-600'
                        : p.valid
                          ? 'bg-green-900/20 border-green-700/40'
                          : 'bg-red-900/20 border-red-700/40'
                    }`}
                  >
                    <span className="text-xl font-bold">
                      {p.valid === null ? '\u2022' : p.valid ? '\u2713' : '\u2717'}
                    </span>
                    <div className="flex-1">
                      <p className={`font-semibold text-sm ${
                        p.valid === null ? 'text-slate-300' : p.valid ? 'text-green-300' : 'text-red-300'
                      }`}>
                        {p.predicate}
                      </p>
                      <p className="text-xs text-slate-500 mt-0.5">
                        {p.op} &middot; {p.proofBytes.length.toLocaleString()} bytes
                      </p>
                    </div>
                    {p.valid !== null && (
                      <span className={`text-xs font-semibold px-2 py-0.5 rounded ${
                        p.valid ? 'bg-green-900/50 text-green-300' : 'bg-red-900/50 text-red-300'
                      }`}>
                        {p.valid ? t('verify.valid') : t('verify.invalid')}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {!verified && (
              <button
                onClick={handleVerify}
                disabled={verifying || !wasmReady}
                className="w-full bg-purple-600 hover:bg-purple-700 disabled:bg-slate-600 text-white font-semibold py-3 rounded-lg transition-colors"
              >
                {verifying ? t('verify.verifyingBrowser') : !wasmReady ? t('verify.initWasm') : t('verify.verifyAllWasm')}
              </button>
            )}

            {verified && (
              <div className="bg-slate-800 border border-green-700/30 rounded-lg px-6 py-4 text-center"
                style={{ boxShadow: '0 0 20px rgba(34,197,94,0.1)' }}>
                <p className="text-green-300 font-bold text-sm">
                  {t('verify.allVerified')}
                </p>
                <p className="text-xs text-slate-500 mt-1">
                  {t('verify.vkNote')}
                </p>
              </div>
            )}

            <button
              onClick={() => { setProofs([]); setVerified(false); setFileName(null); setError(null) }}
              className="w-full bg-slate-700 hover:bg-slate-600 text-white font-semibold py-3 rounded-lg transition-colors"
            >
              {t('verify.verifyAnother')}
            </button>
          </div>
        )}
      </main>
    </div>
  )
}
