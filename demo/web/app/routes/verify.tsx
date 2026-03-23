import { createFileRoute, Link } from '@tanstack/react-router'
import { useState, useCallback, useEffect, useRef } from 'react'
import { useT, useLocale } from '../i18n'
import { ChunkCollector, decompressDeflate, TERMS_PROOF_ID, METADATA_PROOF_ID } from '../lib/qr-chunking'
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
  const [scanProgress, setScanProgress] = useState<{ scanned: number; total: number; items: { type: 'terms' | 'metadata' | 'proof'; proofIndex: number; complete: boolean }[] }>({ scanned: 0, total: 0, items: [] })
  const [contractTerms, setContractTerms] = useState<{ terms: string; timestamp: string } | null>(null)
  const [contractMeta, setContractMeta] = useState<{ contract_hash: string; parties: { role: string; nullifier: string; salt: string }[] } | null>(null)
  const [hashCheckResult, setHashCheckResult] = useState<'match' | 'mismatch' | null>(null)
  const [computedHash, setComputedHash] = useState<string | null>(null)
  const [partyCheckOpen, setPartyCheckOpen] = useState(false)
  const [credentialIdInput, setCredentialIdInput] = useState('')
  const [partyCheckResults, setPartyCheckResults] = useState<{ role: string; matched: boolean }[] | null>(null)
  const [partyChecking, setPartyChecking] = useState(false)
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

  const runVerificationPipeline = async (
    proofsToVerify: DecodedProof[],
    terms: { terms: string; timestamp: string } | null,
    meta: { contract_hash: string; parties: { role: string; nullifier: string; salt: string }[] } | null,
  ) => {
    setVerifying(true)
    setError(null)
    try {
      // Stage 1: Proof verification
      const { verifyCompoundProof, loadTrustedVks } = await import('@zk-eidas/verifier-sdk')
      const vks = await loadTrustedVks('/trusted-vks.json')
      const envelope = {
        proofs: proofsToVerify.map(p => ({
          proof_bytes: Array.from(p.proofBytes),
          public_inputs: p.publicInputs.map(pi => Array.from(pi)),
          verification_key: [],
          predicate_op: p.op,
        })),
        op: proofsToVerify.length > 1 ? 'and' : 'single',
      }
      const chainResult = await verifyCompoundProof(envelope, vks)
      const results = proofsToVerify.map((p, i) => ({
        ...p,
        valid: chainResult.predicateResults[i]?.valid ?? false,
      }))
      setProofs(results)

      // Stage 2: Contract hash cross-check
      if (terms && meta) {
        const { computeContractHash } = await import('../lib/nullifier-check')
        const computed = await computeContractHash(terms.terms, terms.timestamp)
        setComputedHash(computed)
        setHashCheckResult(computed === meta.contract_hash ? 'match' : 'mismatch')
      }

      setVerified(true)
    } catch (e: any) {
      setError(`Verification failed: ${e.message}`)
    } finally {
      setVerifying(false)
    }
  }

  const handlePartyCheck = async () => {
    if (!credentialIdInput.trim() || !contractMeta) return
    setPartyChecking(true)
    try {
      const { checkNullifier } = await import('../lib/nullifier-check')
      const results = await checkNullifier(
        credentialIdInput.trim(),
        contractMeta.contract_hash,
        contractMeta.parties,
      )
      setPartyCheckResults(results)
    } catch (e: any) {
      setError(`Nullifier check failed: ${e.message}`)
    } finally {
      setPartyChecking(false)
    }
  }

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

    // Update overall progress
    const ids = collector.proofIds()
    const firstHeader = ids.length > 0 ? collector.getHeader(ids[0]) : null
    const total = firstHeader?.proofCount ?? 0
    const scanned = ids.filter(id => collector.isProofComplete(id)).length
    setScanProgress({ scanned, total, items: collector.scannedItems() })

    // Check if all complete
    if (collector.isAllComplete()) {
      try {
        // Separate proof data from terms/metadata
        const allProofs: DecodedProof[] = []
        for (const proofId of collector.proofIds()) {
          if (proofId === TERMS_PROOF_ID || proofId === METADATA_PROOF_ID) continue
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

        // Extract contract data if present
        const isContract = collector.isContractDocument()
        let termsData: { terms: string; timestamp: string } | null = null
        let metaData: { contract_hash: string; parties: { role: string; nullifier: string; salt: string }[] } | null = null
        if (isContract) {
          termsData = await collector.getTermsData()
          metaData = await collector.getMetadataData()
        }

        setScanMode(false)
        stopScanRef.current()
        setProofs(allProofs)
        setFileName('paper-proof (scanned)')
        setContractTerms(termsData)
        setContractMeta(metaData)

        // Auto-verify for contract documents
        if (isContract && allProofs.length > 0) {
          runVerificationPipeline(allProofs, termsData, metaData)
        }
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : 'Proof data corrupted, try re-scanning.')
      } finally {
        collectorRef.current.clear()
        setScanProgress({ scanned: 0, total: 0, items: [] })
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

                {scanProgress.total > 0 && (
                  <div className="space-y-3">
                    <div className="flex items-center gap-3 justify-center">
                      <div className="w-48 h-2 bg-slate-700 rounded-full overflow-hidden">
                        <div className="h-full bg-green-500 transition-all" style={{ width: `${(scanProgress.scanned / scanProgress.total) * 100}%` }} />
                      </div>
                      <span className="text-xs text-slate-400">
                        {t('verify.scanOverall').replace('{n}', String(scanProgress.scanned)).replace('{total}', String(scanProgress.total))}
                      </span>
                    </div>
                    <div className="space-y-1">
                      {scanProgress.items.map((item, i) => (
                        <div key={i} className="flex items-center gap-2 justify-center text-xs">
                          <span className={item.complete ? 'text-green-400' : 'text-slate-500'}>
                            {item.complete ? '\u2713' : '\u25CB'}
                          </span>
                          <span className={item.complete ? 'text-slate-300' : 'text-slate-500'}>
                            {item.type === 'terms' ? t('verify.termsQr')
                              : item.type === 'metadata' ? t('verify.metadataQr')
                              : t('verify.proofN').replace('{n}', String(item.proofIndex + 1))}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <button
                  onClick={() => { scanner.stop(); setScanMode(false); setScanProgress({ scanned: 0, total: 0, items: [] }); collectorRef.current.clear() }}
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
                        {p.op}
                        {p.publicInputs.length > 0 && (
                          <span className="ml-1">
                            — [{p.publicInputs.map(pi => {
                              const hex = Array.from(pi).map(b => b.toString(16).padStart(2, '0')).join('')
                              return hex.length > 16 ? hex.slice(0, 16) + '\u2026' : hex
                            }).join(', ')}]
                          </span>
                        )}
                        <span className="ml-2">&middot; {p.proofBytes.length.toLocaleString()} bytes</span>
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

            {/* Stage 2: Contract Integrity */}
            {hashCheckResult && (
              <div className={`rounded-lg border px-6 py-4 ${
                hashCheckResult === 'match'
                  ? 'bg-green-900/20 border-green-700/40'
                  : 'bg-red-900/20 border-red-700/40'
              }`}>
                <h3 className="text-sm font-semibold uppercase tracking-wider mb-2 text-slate-300">
                  {t('verify.contractIntegrity')}
                </h3>
                {hashCheckResult === 'match' ? (
                  <div className="space-y-1">
                    <p className="text-green-300 text-sm">{'\u2713'} {t('verify.hashMatch')}</p>
                    <p className="text-xs text-slate-500 font-mono">{computedHash}</p>
                  </div>
                ) : (
                  <p className="text-red-300 text-sm">{'\u2717'} {t('verify.hashMismatch')}</p>
                )}
              </div>
            )}

            {/* Stage 3: Party Summary */}
            {contractMeta && contractMeta.parties.length > 0 && (
              <div className="bg-slate-800 rounded-lg border border-slate-700 px-6 py-4">
                <h3 className="text-sm font-semibold uppercase tracking-wider mb-3 text-slate-300">
                  {t('verify.parties')}
                </h3>
                <div className="space-y-2">
                  {contractMeta.parties.map((party, i) => (
                    <div key={i} className="flex items-start gap-4 text-sm">
                      <span className="text-slate-400 font-semibold uppercase w-20">{party.role}</span>
                      <div className="flex-1 font-mono text-xs text-slate-400 space-y-0.5">
                        <p>nullifier: {party.nullifier}</p>
                        <p>salt: {party.salt}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {!verified && !contractMeta && (
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

            {/* Nullifier Calculator */}
            {contractMeta && contractMeta.parties.length > 0 && verified && (
              <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
                <button
                  onClick={() => setPartyCheckOpen(!partyCheckOpen)}
                  className="w-full px-6 py-3 flex items-center justify-between hover:bg-slate-700/50 transition-colors"
                >
                  <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                    {partyCheckOpen ? '\u25BE' : '\u25B8'} {t('verify.verifyParty')}
                  </h3>
                </button>
                {partyCheckOpen && (
                  <div className="px-6 pb-4 space-y-3">
                    <div className="flex gap-2">
                      <input
                        type="text"
                        placeholder={t('verify.documentNumber')}
                        value={credentialIdInput}
                        onChange={e => setCredentialIdInput(e.target.value)}
                        onKeyDown={e => e.key === 'Enter' && handlePartyCheck()}
                        className="flex-1 bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                      />
                      <button
                        onClick={handlePartyCheck}
                        disabled={partyChecking || !credentialIdInput.trim()}
                        className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 text-white text-sm font-medium rounded-lg transition-colors"
                      >
                        {partyChecking ? '...' : t('verify.check')}
                      </button>
                    </div>
                    {partyCheckResults && (
                      <div className="space-y-2">
                        {partyCheckResults.some(r => r.matched) ? (
                          partyCheckResults.filter(r => r.matched).map((r, i) => (
                            <div key={i} className="bg-green-900/20 border border-green-700/40 rounded-lg px-4 py-3">
                              <p className="text-green-300 text-sm font-semibold">
                                {'\u2713'} {t('verify.partyMatch').replace('{role}', r.role.toUpperCase())}
                              </p>
                              <p className="text-xs text-slate-500 mt-1">
                                Poseidon(credential_id, contract_hash, salt) = nullifier {'\u2713'}
                              </p>
                            </div>
                          ))
                        ) : (
                          <div className="bg-slate-700/30 border border-slate-600 rounded-lg px-4 py-3">
                            <p className="text-slate-400 text-sm">{t('verify.noMatch')}</p>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            <button
              onClick={() => { setProofs([]); setVerified(false); setFileName(null); setError(null); setContractTerms(null); setContractMeta(null); setHashCheckResult(null); setComputedHash(null); setPartyCheckOpen(false); setCredentialIdInput(''); setPartyCheckResults(null) }}
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
