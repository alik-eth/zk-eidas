import { createFileRoute } from '@tanstack/react-router'
import React, { useEffect, useRef, useState } from 'react'
import { Tooltip } from '../components/Tooltip'
import { StepWizard } from '../components/StepWizard'
import { useT, useLocale } from '../i18n'
import { CREDENTIAL_TYPES, resolveVariant, type FieldDisplay } from '../lib/credential-types'
import { EscrowPanel, type EscrowConfig } from '../components/EscrowPanel'

// Types

interface ProofResult {
  predicate: string
  proof_json: string
  proof_hex: string
  op: string
}

interface PrintProofItem {
  predicate: string
  op?: string
  compressedCbor: string // base64
}

interface PrintPredicate {
  claim: string
  claimKey?: string // i18n key for dynamic translation
  op: string
  publicValue: string
  disclosed: boolean
}

interface WizardState {
  step: 1 | 2 | 3 | 4
  credentialType: string | null
  credential: string | null
  format: string | null
  fields: FieldDisplay[]
  proofs: ProofResult[]
  hiddenFields: string[]
  nullifier: string | null
  compoundProofJson: string | null
  compoundOp: string | null
  credentialId: string | null
  selectedPredicateIds: string[]
  escrowConfig: EscrowConfig | null
  escrowPrivkey: string | null
  // Print data (populated when entering step 4)
  printProofs: PrintProofItem[]
  printPredicates: PrintPredicate[]
  printLogicalOp: 'single' | 'and' | 'or'
  printCredentialLabel: string
  printCredentialLabelKey?: string // i18n key for dynamic translation
}

const API_URL = typeof window !== 'undefined' && window.location.hostname === 'localhost' ? 'http://localhost:3001' : ''


export const Route = createFileRoute('/sandbox')({
  component: Demo,
})

function Demo() {
  const t = useT()
  const { locale, setLocale } = useLocale()
  const [state, setState] = useState<WizardState>({
    step: 1,
    credentialType: null,
    credential: null,
    format: null,
    fields: [],
    proofs: [],
    hiddenFields: [],
    nullifier: null,
    compoundProofJson: null,
    compoundOp: null,
    credentialId: null,
    selectedPredicateIds: [],
    escrowConfig: null,
    escrowPrivkey: null,
    printProofs: [],
    printPredicates: [],
    printLogicalOp: 'single',
    printCredentialLabel: '',
  })

  const steps = [
    {
      label: t('sandbox.step1Label'),
      description: t('sandbox.step1Desc'),
      icon: (<svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>),
      content: <IssuerStep state={state} setState={setState} t={t} />,
    },
    {
      label: t('sandbox.step2Label'),
      description: t('sandbox.step2Desc'),
      icon: (<svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>),
      content: <HolderStep state={state} setState={setState} t={t} />,
    },
    {
      label: t('sandbox.step3Label'),
      description: t('sandbox.step3Desc'),
      icon: (<svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>),
      content: <VerifierStep state={state} setState={setState} t={t} />,
    },
    {
      label: t('sandbox.step4Label'),
      description: t('sandbox.step4Desc'),
      icon: (<svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>),
      content: <PrintStep state={state} t={t} />,
    },
  ]

  return (
    <div className="h-screen bg-slate-900 text-white flex flex-col overflow-hidden">
      {/* Header */}
      <header className="border-b border-slate-800 px-4 sm:px-8 py-3 sm:py-4 bg-slate-950/80 backdrop-blur-md shrink-0">
        <div className="max-w-5xl mx-auto flex items-center justify-between gap-2">
          <a href="/" className="group flex items-center gap-2 sm:gap-3 min-w-0">
            <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-lg bg-gradient-to-br from-blue-600 to-blue-700 flex items-center justify-center shrink-0">
              <span className="text-[10px] sm:text-xs font-bold text-white tracking-tighter">zk</span>
            </div>
            <div className="min-w-0">
              <h1 className="text-sm font-semibold tracking-tight text-slate-200 group-hover:text-white transition-colors">
                <span style={{ color: '#005BBB' }}>zk</span>
                <span className="text-slate-600 mx-0.5">-</span>
                <span style={{ color: '#FFD500' }}>eidas</span>
              </h1>
              <p className="text-xs text-slate-500 truncate">{t('sandbox.subtitle')}</p>
            </div>
          </a>
          <div className="flex items-center gap-2 sm:gap-4 shrink-0">
            <button onClick={() => setLocale(locale === 'uk' ? 'en' : 'uk')} className="text-xs text-slate-500 hover:text-slate-300 transition-colors font-medium px-2 py-1 rounded border border-slate-800 hover:border-slate-700">
              {locale === 'uk' ? 'EN' : 'UA'}
            </button>
            <span className="hidden sm:inline text-xs text-slate-600 font-medium tracking-wider uppercase">Alik.eth</span>
          </div>
        </div>
      </header>

      <StepWizard steps={steps} currentStep={state.step} />
    </div>
  )
}

// === Step 1: Issuer ===

function IssuerStep({ setState, t }: { state: WizardState; setState: React.Dispatch<React.SetStateAction<WizardState>>; t: (key: string) => string }) {
  const { locale } = useLocale()
  const [loading, setLoading] = useState(false)
  const [activeType, setActiveType] = useState('pid')
  const config = CREDENTIAL_TYPES.find(ct => ct.id === activeType)!
  const variant = resolveVariant(config, locale === 'uk' ? 'uk' : 'en')
  const [formValues, setFormValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(variant.fields.map(f => [f.name, f.defaultValue]))
  )

  const handleIssue = async () => {
    setLoading(true)
    try {
      const res = await fetch(`${API_URL}/issuer/issue`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credential_type: config.id,
          claims: formValues,
          issuer: variant.issuer,
        }),
      })
      if (!res.ok) throw new Error(await res.text())
      const data = await res.json()
      setState(prev => ({
        ...prev,
        step: 2,
        credentialType: config.id,
        credential: data.credential,
        format: data.format,
        fields: data.credential_display.fields.map((f: FieldDisplay) => {
          const fieldConfig = variant.fields.find(cf => cf.name === f.name)
          return { ...f, label: fieldConfig ? t(fieldConfig.labelKey) : f.label }
        }),
        credentialId: formValues.document_number || formValues.license_number || formValues.vin || config.id,
      }))
    } catch (e: any) {
      alert(`Issue failed: ${e.message}`)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <select
        data-testid="credential-type-select"
        value={activeType}
        onChange={e => {
          const ct = CREDENTIAL_TYPES.find(c => c.id === e.target.value)!
          setActiveType(ct.id)
          const v = resolveVariant(ct, locale === 'uk' ? 'uk' : 'en')
          setFormValues(Object.fromEntries(v.fields.map(f => [f.name, f.defaultValue])))
        }}
        className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2.5 text-sm font-medium text-slate-200 focus:outline-none focus:border-blue-500"
      >
        {CREDENTIAL_TYPES.map(ct => (
          <option key={ct.id} value={ct.id}>{t(ct.labelKey)}</option>
        ))}
      </select>
      <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
        <div className="bg-blue-700 px-6 py-3">
          <h2 className="text-lg font-semibold">{t(variant.issuerTitleKey)}</h2>
          <p className="text-sm text-blue-200">{t(variant.issuerSubtitleKey)}</p>
        </div>
        <div className="p-6">
          <p className="text-slate-400 text-sm mb-4">{t(config.credLabelKey)}</p>
          <div className="grid grid-cols-2 gap-4">
            {variant.fields.map(field => (
              <div key={field.name} className={field.colSpan === 2 ? 'col-span-2' : ''}>
                <label className="block text-xs text-slate-400 mb-1">{t(field.labelKey)}</label>
                <input
                  type="text"
                  value={formValues[field.name] ?? ''}
                  onChange={e => setFormValues(prev => ({ ...prev, [field.name]: e.target.value }))}
                  className="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                />
              </div>
            ))}
          </div>
        </div>
      </div>

      <button
        onClick={handleIssue}
        disabled={loading}
        className="flex items-center justify-center gap-2 w-full bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 disabled:cursor-not-allowed text-white font-semibold py-3 rounded-lg transition-colors"
      >
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/></svg>
        {loading ? t('sandbox.issuing') : t('sandbox.issueBtn')}
      </button>
    </div>
  )
}

// === Step 2: Holder ===

function HolderStep({ state, setState, t }: { state: WizardState; setState: React.Dispatch<React.SetStateAction<WizardState>>; t: (key: string) => string }) {
  const config = CREDENTIAL_TYPES.find(c => c.id === state.credentialType)
  if (!config) return null
  const resolvedPredicates = config.predicates.map(p => ({
    ...p,
    predicate: {
      ...p.predicate,
      value: p.predicate.value === '__FROM_FORM__'
        ? state.fields.find(f => f.name === p.predicate.claim)?.value ?? ''
        : p.predicate.value,
    },
  }))

  const [selected, setSelected] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(resolvedPredicates.map(p => [p.id, p.defaultChecked]))
  )
  const [loading, setLoading] = useState(false)
  const [elapsed, setElapsed] = useState(0)
  const [proved, setProved] = useState(false)
  const [compoundMode, setCompoundMode] = useState<'individual' | 'and' | 'or'>('and')
  const [escrowConfig, setEscrowConfig] = useState<EscrowConfig | null>(null)
  const escrowPrivkeyRef = useRef<string | null>(null)
  const [proveTimeMs, setProveTimeMs] = useState<number | null>(null)
  // TODO v2: remove after WASM code cleanup — stubs for dead browser-proving code
  const [presReqLoading, setPresReqLoading] = useState(false)
  const [presReqResult, setPresReqResult] = useState<{ id: string; input_descriptors: { id: string; constraints: { path: string; predicate_op: string; value: string }[] }[] } | null>(null)
  // Reset proved state when user reverts back to this step
  useEffect(() => {
    if (state.step === 2 && proved) {
      setProved(false)
      setProveTimeMs(null)
    }
  }, [state.step])

  const selectedCount = Object.values(selected).filter(Boolean).length

  const handlePresentationRequest = async () => {
    const reqs = resolvedPredicates.filter(p => selected[p.id]).map(p => ({
      claim: p.predicate.claim,
      op: p.predicate.op,
      value: String(Array.isArray(p.predicate.value) ? p.predicate.value.join(',') : p.predicate.value),
    }))
    if (reqs.length === 0) return
    setPresReqLoading(true)
    try {
      const res = await fetch(`${API_URL}/verifier/presentation-request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requirements: reqs }),
      })
      if (!res.ok) throw new Error(await res.text())
      setPresReqResult(await res.json())
    } catch (e: any) {
      alert(`Presentation request failed: ${e.message}`)
    } finally {
      setPresReqLoading(false)
    }
  }


  const handleProve = async () => {
    setLoading(true)
    setElapsed(0)
    const timer = setInterval(() => setElapsed(prev => prev + 1), 1000)
    try {
      const predicates = resolvedPredicates.filter(p => selected[p.id]).map(p => p.predicate)
      const t0 = performance.now()

      if (compoundMode === 'individual') {
        const body: Record<string, unknown> = { credential: state.credential, format: state.format, predicates }
        const res = await fetch(`${API_URL}/holder/prove`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        })
        if (!res.ok) throw new Error(await res.text())
        const data = await res.json()
        const proveMs = performance.now() - t0
        setProveTimeMs(proveMs)
        clearInterval(timer)
        setLoading(false)
        setProved(true)
        setTimeout(() => {
          setState(prev => ({
            ...prev,
            step: 3,
            proofs: data.proofs,
            hiddenFields: data.hidden_fields,
            nullifier: data.nullifier ?? null,
            compoundProofJson: null,
            compoundOp: null,
            selectedPredicateIds: Object.entries(selected).filter(([, v]) => v).map(([k]) => k),
          }))
        }, 800)
      } else {
        const res = await fetch(`${API_URL}/holder/prove-compound`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            credential: state.credential,
            format: state.format,
            predicates,
            op: compoundMode,
            ...(escrowConfig ? { identity_escrow: escrowConfig } : {}),
          }),
        })
        if (!res.ok) throw new Error(await res.text())
        const data = await res.json()
        const proveMs = performance.now() - t0
        setProveTimeMs(proveMs)
        clearInterval(timer)
        setLoading(false)
        setProved(true)
        setTimeout(() => {
          setState(prev => ({
            ...prev,
            step: 3,
            proofs: [],
            hiddenFields: data.hidden_fields,
            nullifier: null,
            compoundProofJson: data.compound_proof_json,
            compoundOp: data.op,
            selectedPredicateIds: Object.entries(selected).filter(([, v]) => v).map(([k]) => k),
            escrowConfig: escrowConfig,
            escrowPrivkey: escrowPrivkeyRef.current,
          }))
        }, 800)
      }
    } catch (e: any) {
      clearInterval(timer)
      setLoading(false)
      alert(`Proof generation failed: ${e.message}`)
    }
  }

  return (
    <div className="space-y-6">
      {/* Predicate Picker */}
      <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
          <div className="bg-slate-700 px-6 py-3">
            <h2 className="text-lg font-semibold">
              <Tooltip text={t('sandbox.predicateTooltip')}>
                <span>{t('sandbox.selectClaims')}</span>
              </Tooltip>
            </h2>
            <p className="text-sm text-slate-400">{t('sandbox.selectClaimsSub')}</p>
          </div>
          <div className="p-6 space-y-4">
            {resolvedPredicates.map(opt => (
              <label key={opt.id} className={`flex items-start gap-3 p-4 rounded-lg border cursor-pointer transition-colors ${selected[opt.id] ? 'border-blue-500 bg-slate-700/50' : 'border-slate-600 bg-slate-800 hover:border-slate-500'}`}>
                <input
                  type="checkbox"
                  checked={selected[opt.id]}
                  onChange={e => setSelected(prev => ({ ...prev, [opt.id]: e.target.checked }))}
                  disabled={loading}
                  className="mt-0.5 w-4 h-4 rounded border-slate-500 text-blue-600 focus:ring-blue-500 bg-slate-700"
                />
                <div className="flex items-center gap-1">
                  <span className="text-sm font-medium text-white">{t(opt.labelKey)}</span>
                  <Tooltip text={t(opt.descKey)} />
                </div>
              </label>
            ))}

            {/* Compound Mode */}
            {selectedCount >= 2 && (
              <div className="mt-4 pt-4 border-t border-slate-600">
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  <Tooltip text={t('sandbox.proofModeTooltip')}>
                    <span>{t('sandbox.proofMode')}</span>
                  </Tooltip>
                </label>
                <div className="flex gap-2">
                  {[
                    { value: 'individual' as const, label: t('sandbox.modeIndividual'), desc: t('sandbox.modeIndividualDesc') },
                    { value: 'and' as const, label: 'AND', desc: t('sandbox.modeAndDesc') },
                    { value: 'or' as const, label: 'OR', desc: t('sandbox.modeOrDesc') },
                  ].map(mode => (
                    <button
                      key={mode.value}
                      onClick={() => setCompoundMode(mode.value)}
                      disabled={loading}
                      className={`flex-1 py-2 px-3 rounded text-sm font-medium transition-colors ${
                        compoundMode === mode.value
                          ? 'bg-blue-600 text-white'
                          : 'bg-slate-700 text-slate-400 hover:text-white'
                      }`}
                    >
                      {mode.label}
                    </button>
                  ))}
                </div>
                <p className="text-xs text-slate-500 mt-1">
                  {compoundMode === 'individual' && t('sandbox.modeExplainIndividual')}
                  {compoundMode === 'and' && t('sandbox.modeExplainAnd')}
                  {compoundMode === 'or' && t('sandbox.modeExplainOr')}
                </p>

              {/* Identity Escrow */}
              {(compoundMode === 'and' || compoundMode === 'or') && (
                <EscrowPanel
                  availableFields={resolvedPredicates.map(p => p.predicate.claim)}
                  predicateFields={resolvedPredicates.filter(p => selected[p.id]).map(p => p.predicate.claim)}
                  onConfigChange={setEscrowConfig}
                  onPrivkeyGenerated={(pk) => { escrowPrivkeyRef.current = pk }}
                  showKeypairGenerator
                />
              )}
              </div>
            )}


          </div>
        </div>

      {/* OpenID4VP Schema Generation */}
      {selectedCount > 0 && (
        <details className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
          <summary className="px-6 py-3 cursor-pointer text-sm font-semibold text-slate-400 hover:text-slate-200 transition-colors select-none">
            OpenID4VP
          </summary>
          <div className="px-6 pb-4 space-y-3">
            <p className="text-xs text-slate-500">{t('sandbox.openid4vpDesc')}</p>
            {!presReqResult ? (
              <button
                onClick={handlePresentationRequest}
                disabled={presReqLoading}
                className="px-4 py-2 bg-slate-700 hover:bg-slate-600 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
              >
                {presReqLoading ? t('sandbox.openid4vpGenerating') : t('sandbox.openid4vpBtn')}
              </button>
            ) : (
              <div className="bg-slate-900 rounded border border-slate-600 p-3 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-500">PresentationDefinition</span>
                  <span className="text-xs font-mono text-slate-500">{presReqResult.id}</span>
                </div>
                {presReqResult.input_descriptors.map((desc, i) => (
                  <div key={i} className="bg-slate-800 rounded p-2 border border-slate-700">
                    <p className="text-xs text-slate-400 font-medium mb-1">{desc.id}</p>
                    {desc.constraints.map((c, j) => (
                      <p key={j} className="text-xs font-mono text-slate-300">
                        {c.path} <span className="text-blue-400">{c.predicate_op}</span> {c.value}
                      </p>
                    ))}
                  </div>
                ))}
              </div>
            )}
          </div>
        </details>
      )}

      {/* Loading state */}
      {loading && (
        <div className="bg-slate-800 rounded-lg border border-blue-500/50 p-6 text-center space-y-3">
          <div className="flex items-center justify-center gap-3">
            <svg className="animate-spin h-5 w-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            <span className="text-blue-300 font-semibold">{t('sandbox.generating')}{elapsed}s</span>
          </div>
          <p className="text-sm text-slate-400">{t('sandbox.generatingDesc')}</p>
        </div>
      )}

      {/* Success state */}
      {proved && !loading && (
        <div className="bg-slate-800 rounded-lg border border-green-500/50 p-6 text-center flex items-center justify-center gap-3">
          <span className="text-green-400 font-semibold">{t('sandbox.proofGenerated')}</span>
          {proveTimeMs !== null && (
            <span className="text-xs text-slate-400 bg-slate-700 px-2 py-1 rounded">
              {(proveTimeMs / 1000).toFixed(1)}s
            </span>
          )}
        </div>
      )}

      {/* Actions */}
      <button
        onClick={handleProve}
        disabled={loading || selectedCount === 0}
        className="flex items-center justify-center gap-2 w-full bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 disabled:cursor-not-allowed text-white font-semibold py-3 rounded-lg transition-colors"
      >
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        {loading
          ? t('sandbox.generatingShort')
          : t('sandbox.generateBtn')}
      </button>
    </div>
  )
}

// === Step 3: Verifier ===

function VerifierStep({ state, setState, t }: { state: WizardState; setState: React.Dispatch<React.SetStateAction<WizardState>>; t: (key: string) => string }) {
  const [verifying, setVerifying] = useState(false)
  const [verified, setVerified] = useState(false)
  const [results, setResults] = useState<{ predicate: string; valid: boolean }[]>([])
  const [notDisclosed, setNotDisclosed] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [exportData, setExportData] = useState<{ cbor_base64: string; cbor_size_bytes: number } | null>(null)
  const [exportLoading, setExportLoading] = useState(false)
  const [verificationPath, setVerificationPath] = useState<'server' | null>(null)
  const [verifyTimeMs, setVerifyTimeMs] = useState<number | null>(null)
  const [revoking, setRevoking] = useState(false)
  const [revocationResult, setRevocationResult] = useState<{ status: string; revocation_root: string } | null>(null)
  const [currentRoot, setCurrentRoot] = useState<string | null>(null)

  const escrowData = (() => {
    if (!state.compoundProofJson || !state.escrowConfig) return null
    try {
      const compound = JSON.parse(state.compoundProofJson)
      return compound.identity_escrow ?? null
    } catch { return null }
  })()

  const [decryptedFields, setDecryptedFields] = useState<{ fields: Record<string, string>; integrityValid: boolean } | null>(null)
  const [decrypting, setDecrypting] = useState(false)

  const bytesToHex = (bytes: number[]) => bytes.map((b: number) => b.toString(16).padStart(2, '0')).join('')

  const handleDecrypt = async () => {
    if (!escrowData || !state.escrowPrivkey) return
    setDecrypting(true)
    try {
      const { decryptEscrow } = await import('../lib/escrow-decrypt')
      const result = await decryptEscrow(
        escrowData.encrypted_key,
        state.escrowPrivkey,
        escrowData.ciphertexts,
        escrowData.tags,
        escrowData.field_names,
      )
      setDecryptedFields(result)
    } catch (e: any) {
      alert(`Decrypt failed: ${e.message}`)
    } finally {
      setDecrypting(false)
    }
  }

  useEffect(() => {
    fetch(`${API_URL}/issuer/revocation-root`)
      .then(res => res.json())
      .then(data => setCurrentRoot(data.revocation_root))
      .catch(() => {})
  }, [])

  // Auto-export CBOR on mount so buttons are instantly available
  useEffect(() => {
    const doExport = state.compoundProofJson ? handleExportCompound : handleExport
    doExport()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-verify on mount via server
  const autoVerifyRan = useRef(false)
  useEffect(() => {
    if (autoVerifyRan.current || verified) return
    autoVerifyRan.current = true
    handleVerifyServer()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const handleExport = async () => {
    setExportLoading(true)
    try {
      const res = await fetch(`${API_URL}/holder/proof-export`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          proofs: state.proofs.map(p => ({ proof_json: p.proof_json, predicate: p.predicate })),
        }),
      })
      if (!res.ok) throw new Error(await res.text())
      setExportData(await res.json())
    } catch (e: any) {
      alert(`Export failed: ${e.message}`)
    } finally {
      setExportLoading(false)
    }
  }

  const handleExportCompound = async () => {
    setExportLoading(true)
    try {
      const res = await fetch(`${API_URL}/holder/proof-export-compound`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ compound_proof_json: state.compoundProofJson }),
      })
      if (!res.ok) throw new Error(await res.text())
      setExportData(await res.json())
    } catch (e: any) {
      alert(`Export failed: ${e.message}`)
    } finally {
      setExportLoading(false)
    }
  }

  const handleVerifyServer = async () => {
    setVerifying(true)
    setError(null)
    try {
      const t0 = performance.now()
      if (state.compoundProofJson) {
        const res = await fetch(`${API_URL}/verifier/verify-compound`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            compound_proof_json: state.compoundProofJson,
            hidden_fields: state.hiddenFields,
          }),
        })
        if (!res.ok) throw new Error(await res.text())
        const data = await res.json()
        setResults([{
          predicate: `compound[${data.op}]: ${data.sub_proofs_verified} sub-proofs verified`,
          valid: data.valid,
        }])
        setNotDisclosed(data.not_disclosed ?? state.hiddenFields)
        setVerificationPath('server')
        setVerified(true)
        setVerifyTimeMs(performance.now() - t0)
      } else {
        const res = await fetch(`${API_URL}/verifier/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            proofs: state.proofs.map(p => ({ proof_json: p.proof_json, predicate: p.predicate })),
            hidden_fields: state.hiddenFields,
          }),
        })
        if (!res.ok) throw new Error(await res.text())
        const data = await res.json()
        setResults(data.results)
        setNotDisclosed(data.not_disclosed ?? state.hiddenFields)
        setVerificationPath('server')
        setVerified(true)
        setVerifyTimeMs(performance.now() - t0)
      }

    } catch (e: any) {
      setError(`Server verification failed: ${e.message}`)
    } finally {
      setVerifying(false)
    }
  }

  const handleRevoke = async () => {
    if (!state.credentialId) return
    setRevoking(true)
    try {
      const res = await fetch(`${API_URL}/issuer/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential_id: state.credentialId }),
      })
      if (!res.ok) throw new Error(await res.text())
      const data = await res.json()
      setRevocationResult(data)
      setCurrentRoot(data.revocation_root)
    } catch (e: any) {
      alert(`Revocation failed: ${e.message}`)
    } finally {
      setRevoking(false)
    }
  }

  const handlePrintProof = async () => {
    try {
      const logicalOp = state.compoundOp === 'And' ? 'and' as const : state.compoundOp === 'Or' ? 'or' as const : 'single' as const
      let proofs: PrintProofItem[]
      const predicates: PrintPredicate[] = []
      const config = CREDENTIAL_TYPES.find(c => c.id === state.credentialType)
      const opSymbol = (op: string) => ({ gte: '\u2265', lte: '\u2264', eq: '=', neq: '\u2260', range: '\u2208', set_member: '\u2208' }[op] || op)
      const resolveValue = (pred: { claim: string; op: string; value: string | number | string[] | number[] }) => {
        if (pred.value === '__FROM_FORM__') return state.fields.find(f => f.name === pred.claim)?.value ?? ''
        if (Array.isArray(pred.value)) return pred.value.length <= 5 ? pred.value.join(', ') : `${pred.value.slice(0, 3).join(', ')} … (${pred.value.length})`
        return String(pred.value)
      }
      if (state.compoundProofJson) {
        const compound = (() => { try { return JSON.parse(state.compoundProofJson) } catch { return null } })() as { proofs?: { predicate_op?: string }[] } | null
        if (compound?.proofs && config) {
          const selectedPreds = config.predicates.filter(p => state.selectedPredicateIds.includes(p.id))
          for (let pi = 0; pi < compound.proofs.length; pi++) {
            const matched = selectedPreds[pi]
            if (matched) {
              const fieldConfig = resolveVariant(config, 'uk').fields.find(f => f.name === matched.predicate.claim)
              predicates.push({
                claim: fieldConfig ? t(fieldConfig.labelKey) : matched.predicate.claim,
                claimKey: fieldConfig?.labelKey,
                op: opSymbol(matched.predicate.op),
                publicValue: resolveValue(matched.predicate),
                disclosed: false,
              })
            }
          }
        }
        const res = await fetch(`${API_URL}/holder/proof-export-compound?compress=true`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ compound_proof_json: state.compoundProofJson }),
        })
        if (!res.ok) throw new Error(await res.text())
        const data = await res.json()
        proofs = [{ predicate: `${logicalOp.toUpperCase()} compound`, op: logicalOp, compressedCbor: data.compressed_cbor_base64 }]
      } else {
        proofs = await Promise.all(state.proofs.map(async (p) => {
          predicates.push({ claim: p.predicate, op: p.op, publicValue: '', disclosed: false })
          const res = await fetch(`${API_URL}/holder/proof-export?compress=true`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ proofs: [{ proof_json: p.proof_json, predicate: p.predicate }] }),
          })
          if (!res.ok) throw new Error(await res.text())
          const data = await res.json()
          return { predicate: p.predicate, op: p.op, compressedCbor: data.compressed_cbor_base64 }
        }))
      }
      setState(prev => ({
        ...prev,
        step: 4,
        printProofs: proofs,
        printPredicates: predicates,
        printLogicalOp: logicalOp,
        printCredentialLabel: config ? t(config.labelKey) : state.credentialType || '',
        printCredentialLabelKey: config?.labelKey,
      }))
    } catch (e: unknown) {
      alert(`Print export failed: ${e instanceof Error ? e.message : e}`)
    }
  }

  return (
    <div className="space-y-6">
      {/* Auto-verifying state */}
      {!verified && (
        <div className="flex flex-col items-center justify-center gap-4 py-12">
          {error ? (
            <div className="bg-red-900/30 border border-red-700 rounded-lg p-4 text-red-300 text-sm w-full">{error}</div>
          ) : (
            <>
              <svg className="animate-spin h-8 w-8 text-purple-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              <p className="text-sm text-slate-400">{t('sandbox.autoVerifying')}</p>
            </>
          )}
        </div>
      )}

      {/* Verification Results */}
      {verified && (
        <div className="space-y-4">

          {/* Zero-Knowledge Explainer — 3 step visual story */}
          {(() => {
            // Build list of individual predicates with human descriptions
            // For compound proofs, extract sub-proofs and match to config descriptions
            const config = CREDENTIAL_TYPES.find(c => c.id === state.credentialType)
            const predicateDescriptions: { claim: string; description: string; proofSize: number }[] = []

            if (state.compoundProofJson) {
              const compound = (() => { try { return JSON.parse(state.compoundProofJson) } catch { return null } })() as { proofs?: { proof_bytes?: number[]; predicate_op?: string }[] } | null
              if (compound?.proofs && config) {
                for (const sub of compound.proofs) {
                  const matchedConfig = config.predicates.find(p => {
                    const opMap: Record<string, string[]> = {
                      gte: ['Gte', 'GteSigned'], lte: ['Lte', 'LteSigned'], eq: ['Eq', 'EqSigned'],
                      neq: ['Neq', 'NeqSigned'], range: ['Range', 'RangeSigned'],
                      set_member: ['SetMember', 'SetMemberSigned'],
                    }
                    const ops = opMap[p.predicate.op] || []
                    return ops.includes(sub.predicate_op || '') && !predicateDescriptions.some(d => d.claim === p.predicate.claim)
                  })
                  const resolveVal = (v: unknown) => v === '__FROM_FORM__' && matchedConfig ? (state.fields.find(f => f.name === matchedConfig.predicate.claim)?.value ?? v) : v
                  const label = matchedConfig
                    ? `${matchedConfig.predicate.claim} ${matchedConfig.predicate.op === 'set_member' ? 'in allowed set' : matchedConfig.predicate.op === 'gte' ? '>= ' + resolveVal(matchedConfig.predicate.value) : matchedConfig.predicate.op === 'lte' ? '<= ' + resolveVal(matchedConfig.predicate.value) : matchedConfig.predicate.op === 'eq' ? '= ' + resolveVal(matchedConfig.predicate.value) : matchedConfig.predicate.op + ' ' + resolveVal(matchedConfig.predicate.value)}`
                    : sub.predicate_op || '?'
                  predicateDescriptions.push({ claim: matchedConfig?.predicate.claim || '', description: label, proofSize: sub.proof_bytes?.length || 0 })
                }
              }
            } else {
              for (const proof of state.proofs) {
                const parsed = (() => { try { return JSON.parse(proof.proof_json) } catch { return null } })() as { proof_bytes?: number[] } | null
                predicateDescriptions.push({ claim: '', description: proof.predicate, proofSize: parsed?.proof_bytes?.length || 0 })
              }
            }

            const fieldMatchesPredicate = (fieldName: string) => {
              const fn = fieldName.toLowerCase()
              // Check individual proof results first
              const fromResults = results.find(r => {
                const p = r.predicate.toLowerCase()
                return p.includes(fn) || ((fn === 'birthdate' || fn === 'birth_date') && p.includes('age')) || (fn === 'expiry_date' && p.includes('valid')) || (fn === 'issue_date' && p.includes('experience')) || (fn === 'graduation_year' && p.includes('grad'))
              })
              if (fromResults) return fromResults.predicate
              // For compound proofs, match against extracted descriptions
              const fromDesc = predicateDescriptions.find(d => {
                const c = d.claim.toLowerCase()
                return c === fn || ((fn === 'birthdate' || fn === 'birth_date') && (c === 'birthdate' || c === 'birth_date')) || (fn === 'nationality' && c === 'nationality') || (fn === 'expiry_date' && c === 'expiry_date') || (fn === 'field_of_study' && c === 'field_of_study') || (fn === 'category' && c === 'category') || (fn === 'issue_date' && c === 'issue_date') || (fn === 'graduation_year' && c === 'graduation_year')
              })
              return fromDesc?.description || null
            }

            return (
              <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
                <div className="px-6 py-4 border-b border-slate-700">
                  <h3 className="text-sm font-semibold text-slate-200 tracking-wide">{t('sandbox.zkTitle')}</h3>
                  <p className="text-xs text-slate-500 mt-1">{t('sandbox.zkSubtitle')}</p>
                </div>
                <div className="p-5 space-y-0">

                  {/* STEP 1 — Your data */}
                  <div className="relative">
                    <div className="flex items-center gap-3 mb-3">
                      <div className="w-7 h-7 rounded-full bg-blue-500/20 border border-blue-500/40 flex items-center justify-center shrink-0">
                        <span className="text-blue-400 text-xs font-bold">1</span>
                      </div>
                      <div>
                        <p className="text-sm font-semibold text-slate-200">{t('sandbox.zkStep1Title')}</p>
                        <p className="text-xs text-slate-500">{t('sandbox.zkStep1Desc')}</p>
                      </div>
                    </div>
                    <div className="ml-3.5 border-l-2 border-blue-500/20 pl-6 pb-6">
                      <div className="rounded-lg border border-slate-600/60 bg-slate-900/50 overflow-hidden">
                        {state.fields.map((field, i) => (
                          <div key={field.name} className={`flex items-center justify-between px-4 py-2 ${i > 0 ? 'border-t border-slate-700/40' : ''}`}>
                            <span className="text-slate-400 text-xs shrink-0">{field.label || field.name}</span>
                            <span className="text-slate-200 text-xs font-mono text-right truncate ml-4">{field.value}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* STEP 2 — The math */}
                  <div className="relative">
                    <div className="flex items-center gap-3 mb-3">
                      <div className="w-7 h-7 rounded-full bg-amber-500/20 border border-amber-500/40 flex items-center justify-center shrink-0">
                        <span className="text-amber-400 text-xs font-bold">2</span>
                      </div>
                      <div>
                        <p className="text-sm font-semibold text-slate-200">{t('sandbox.zkStep2Title')}</p>
                        <p className="text-xs text-slate-500">{t('sandbox.zkStep2Desc')}</p>
                      </div>
                    </div>
                    <div className="ml-3.5 border-l-2 border-amber-500/20 pl-6 pb-6 space-y-2">
                      {predicateDescriptions.map((pred, i) => (
                        <div key={i} className="rounded-lg border border-amber-800/30 bg-amber-950/15 px-4 py-3">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-amber-300 text-xs font-semibold">{pred.description}</span>
                            <span className="text-amber-500/60 text-xs font-mono">{(pred.proofSize / 1024).toFixed(1)} KB</span>
                          </div>
                          <div className="flex items-center gap-2 text-xs">
                            <span className="text-slate-500">{t('sandbox.zkRealValue')}</span>
                            <span className="bg-slate-700/60 text-slate-600 font-mono px-1.5 py-0.5 rounded text-xs tracking-widest select-none" aria-hidden="true">{'\u2588'.repeat(8)}</span>
                            <span className="text-amber-300 font-medium">{t('sandbox.zkOnlyAnswer')}</span>
                          </div>
                        </div>
                      ))}
                      <p className="text-xs text-slate-600 italic">{t('sandbox.zkStep2Note')}</p>
                    </div>
                  </div>

                  {/* STEP 3 — What verifier gets */}
                  <div className="relative">
                    <div className="flex items-center gap-3 mb-3">
                      <div className="w-7 h-7 rounded-full bg-green-500/20 border border-green-500/40 flex items-center justify-center shrink-0">
                        <span className="text-green-400 text-xs font-bold">3</span>
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-semibold text-slate-200">{t('sandbox.zkStep3Title')}</p>
                        <p className="text-xs text-slate-500">{t('sandbox.zkStep3Desc')}</p>
                      </div>
                      {verificationPath === 'server' && verifyTimeMs !== null && (
                        <span className="text-xs text-slate-400 bg-slate-700/30 border border-slate-600/30 px-2 py-0.5 rounded-full font-mono shrink-0">{Math.round(verifyTimeMs)}ms</span>
                      )}
                    </div>
                    <div className="ml-3.5 pl-6">
                      <div className="rounded-lg border border-green-800/30 bg-green-950/10 overflow-hidden">
                        {state.fields.map((field, i) => {
                          const matched = fieldMatchesPredicate(field.name)
                          return (
                            <div key={field.name} className={`flex items-center justify-between px-4 py-2 ${i > 0 ? 'border-t border-slate-700/30' : ''}`}>
                              <span className={`shrink-0 ${matched ? 'text-slate-300 text-xs' : 'text-slate-600 text-xs'}`}>{field.label || field.name}</span>
                              {matched ? (
                                <span className="text-green-400 text-xs font-semibold text-right truncate ml-4">&#10003; {matched}</span>
                              ) : (
                                <span className="font-mono text-xs text-slate-700 select-none tracking-widest" aria-hidden="true">{'\u2588'.repeat(6)}</span>
                              )}
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  </div>

                </div>

                {/* Bottom banner */}
                <div className="px-6 py-4 bg-green-950/20 border-t border-green-800/20">
                  <p className="text-sm text-green-300 font-medium text-center">{t('sandbox.privacyBanner')}</p>
                </div>
              </div>
            )
          })()}

          {/* Save & Print buttons */}
          {(state.proofs.length > 0 || state.compoundProofJson) && (
            <div className="space-y-3">
              <a href={exportData ? `data:application/cbor;base64,${exportData.cbor_base64}` : '#'} download="zk-eidas-proof.cbor"
                className={`flex items-center justify-center gap-2 w-full py-3 text-white font-semibold rounded-lg transition-colors ${exportData ? 'bg-blue-600 hover:bg-blue-700' : 'bg-slate-700 opacity-50 pointer-events-none'}`}>
                <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                {exportLoading ? t('sandbox.encoding') : t('sandbox.saveProof')}
              </a>
              <button
                disabled={exportLoading || (state.compoundOp === 'Or') || (!state.compoundProofJson && state.proofs.length > 1)}
                onClick={handlePrintProof}
                className="flex items-center justify-center gap-2 w-full py-3 bg-slate-700 hover:bg-slate-600 disabled:bg-slate-800 disabled:text-slate-500 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-colors"
              >
                <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
                {t('sandbox.printProof')}
              </button>
              {(state.compoundOp === 'Or' || (!state.compoundProofJson && state.proofs.length > 1)) && (
                <p className="text-xs text-amber-400/70">{t('sandbox.printRequiresAnd')}</p>
              )}
            </div>
          )}

          {/* Escrow Envelope */}
          {escrowData && (
            <div className="bg-slate-800 rounded-lg border border-amber-500/30 overflow-hidden">
              <div className="px-6 py-3 border-b border-amber-500/20 bg-amber-500/5">
                <h3 className="text-sm font-semibold text-amber-400">{t('escrow.envelopeTitle')}</h3>
              </div>
              <div className="p-5 space-y-3">
                <div className="grid grid-cols-1 gap-2 text-xs">
                  <div>
                    <span className="text-slate-500">{t('escrow.ciphertext')}:</span>
                    <span className="font-mono text-slate-300 ml-2">{escrowData.ciphertexts.length} fields</span>
                  </div>
                  <div>
                    <span className="text-slate-500">{t('escrow.authorityPubkey')}:</span>
                    <span className="font-mono text-slate-300 ml-2 break-all">{bytesToHex(escrowData.authority_pubkey).slice(0, 20)}...</span>
                  </div>
                </div>

                {state.escrowPrivkey && !decryptedFields && (
                  <button
                    onClick={handleDecrypt}
                    disabled={decrypting}
                    className="w-full bg-amber-600 hover:bg-amber-700 disabled:bg-slate-600 text-white text-sm font-semibold py-2 rounded-lg transition-colors"
                  >
                    {decrypting ? t('escrow.decrypting') : t('escrow.decryptBtn')}
                  </button>
                )}

                {decryptedFields && (
                  <div className="bg-amber-500/5 border border-amber-500/20 rounded-lg p-4">
                    <p className="text-xs text-amber-400 font-semibold mb-2">{t('escrow.decryptedTitle')}</p>
                    <div className="space-y-1">
                      {Object.entries(decryptedFields.fields).map(([name, value]) => (
                        <div key={name} className="flex justify-between text-xs">
                          <span className="text-slate-400">{name}</span>
                          <span className="font-mono text-amber-300">{String(value)}</span>
                        </div>
                      ))}
                    </div>
                    <div className={`mt-3 pt-3 border-t border-amber-500/20 flex items-center gap-2 text-xs ${
                      decryptedFields.integrityValid ? 'text-green-400' : 'text-red-400'
                    }`}>
                      {decryptedFields.integrityValid ? (
                        <svg className="w-3.5 h-3.5 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                      ) : (
                        <svg className="w-3.5 h-3.5 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                      )}
                      <span className="font-semibold">
                        {decryptedFields.integrityValid ? t('contracts.integrityValid') : t('contracts.integrityFail')}
                      </span>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// === Step 4: Print ===

function PrintStep({ state, t }: { state: WizardState; t: (key: string) => string }) {
  const [qrSections, setQrSections] = useState<{ predicate: string; dataUrls: string[]; compressedSize: number }[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (state.printProofs.length === 0) return
    generateQRCodes()
  }, [state.printProofs])

  async function generateQRCodes() {
    try {
      const QRCode = (await import('qrcode')).default

      const sections: typeof qrSections = []
      for (let i = 0; i < state.printProofs.length; i++) {
        const proof = state.printProofs[i]
        const proofBytes = Uint8Array.from(atob(proof.compressedCbor), c => c.charCodeAt(0))

        // Store proof in blob store
        const blobRes = await fetch(`${API_URL}/proofs`, { method: 'POST', body: proofBytes })
        if (!blobRes.ok) throw new Error('Failed to store proof')
        const { cid } = await blobRes.json()

        // Get QEAA attestation from TSP
        const attestRes = await fetch(`${API_URL}/tsp/attest`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            cid,
            predicate: proof.predicate,
            credentialType: 'org.iso.18013.5.1.mDL',
          }),
        })
        if (!attestRes.ok) throw new Error('Failed to get attestation')
        const attestation = await attestRes.json()
        const attestJson = JSON.stringify(attestation)

        // Single QR code for the attestation (~1-2KB fits easily)
        const url = await QRCode.toDataURL(attestJson, { errorCorrectionLevel: 'L', margin: 1, width: 280 })
        const dataUrls = [url]

        sections.push({ predicate: proof.predicate, dataUrls, compressedSize: proofBytes.length })
      }
      setQrSections(sections)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }

  if (state.printProofs.length === 0) return null

  const totalQRs = qrSections.reduce((sum, s) => sum + s.dataUrls.length, 0)
  const totalSize = qrSections.reduce((sum, s) => sum + s.compressedSize, 0)

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <p className="text-slate-500">{t('print.generating')}</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-red-900/30 border border-red-700 rounded-lg px-8 py-6 text-center">
        <p className="text-red-300 text-sm">{error}</p>
      </div>
    )
  }

  return (
    <div className="space-y-4 print-area">
      {/* Print content */}
      <div className="bg-white text-black rounded-lg overflow-hidden print:rounded-none print:shadow-none">
        <div className="max-w-[210mm] mx-auto px-6 py-4 print:px-8 print:py-3">
          {/* Header */}
          <div className="border-b border-gray-300 pb-3 mb-4">
            <div className="flex items-baseline justify-between">
              <h1 className="text-lg font-bold">{t('print.title')}</h1>
              <span className="text-xs text-gray-400 font-mono">zk-eidas.com/verify</span>
            </div>
            <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-600">
              {state.printLogicalOp !== 'single' && (
                <span className="font-semibold text-gray-800">
                  {state.printLogicalOp === 'and' ? t('print.allMustVerify') : t('print.anyMustVerify')}
                </span>
              )}
              {(state.printCredentialLabelKey || state.printCredentialLabel) && (
                <span>{state.printCredentialLabelKey ? t(state.printCredentialLabelKey) : state.printCredentialLabel}</span>
              )}
              <span>{totalQRs} {t('print.qrCount')} · {(totalSize / 1024).toFixed(1)} KB</span>
            </div>
            {state.printPredicates.length > 0 && (
              <div className="mt-2">
                <span className="text-xs font-medium text-gray-500">{t('print.predicates')}:</span>
                <table className="mt-1 text-xs text-gray-700 w-full">
                  <tbody>
                    {state.printPredicates.map((p, i) => (
                      <tr key={i} className="border-b border-gray-100 last:border-0">
                        <td className="py-0.5 pr-2 font-medium">{p.claimKey ? t(p.claimKey) : p.claim}</td>
                        <td className="py-0.5 pr-2 font-mono text-gray-500">{p.op}</td>
                        <td className="py-0.5 pr-2">{p.publicValue}</td>
                        <td className="py-0.5 text-right">
                          {p.disclosed
                            ? <span className="text-blue-600 font-semibold">{t('print.public')}</span>
                            : <span className="text-gray-400">{t('print.private')}</span>
                          }
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* QR codes */}
          {qrSections.map((section, si) => (
            <div key={si} className="mb-4">
              {qrSections.length > 1 && (
                <h2 className="text-sm font-semibold mb-2">
                  {t('print.proofSection')} {si + 1}/{qrSections.length}: {section.predicate}
                </h2>
              )}
              <div className="grid grid-cols-3 gap-1 justify-items-center print:grid-cols-3 print:gap-1">
                {section.dataUrls.map((url, qi) => (
                  <div key={qi} className="text-center">
                    <img
                      src={url}
                      alt={`QR ${qi + 1}/${section.dataUrls.length}`}
                      className="w-36 h-36 print:w-[55mm] print:h-[55mm]"
                    />
                    <p className="text-[9px] text-gray-400 -mt-0.5">{qi + 1}/{section.dataUrls.length}</p>
                  </div>
                ))}
              </div>
            </div>
          ))}

          {/* Footer */}
          <div className="text-center text-xs text-gray-400 mt-4 pt-3 border-t border-gray-200">
            {t('print.scanToVerify')} · {t('print.verifyAt')}: zk-eidas.com/verify
          </div>
        </div>
      </div>

      {/* Print button — below the preview */}
      <button
        onClick={() => window.print()}
        className="flex items-center justify-center gap-2 w-full py-3 bg-slate-700 hover:bg-slate-600 text-white font-semibold rounded-lg transition-colors print:hidden"
      >
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
        {t('print.printBtn')}
      </button>
    </div>
  )
}
