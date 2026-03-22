import { createFileRoute } from '@tanstack/react-router'
import React, { useEffect, useRef, useState } from 'react'
import { StepWizard } from '../components/StepWizard'
import { ProveMethodToggle, type ProveMethod } from '../components/ProveMethodToggle'
import { useT, useLocale, tLang } from '../i18n'
import { CREDENTIAL_TYPES, type FieldDisplay } from '../lib/credential-types'
import { CONTRACT_TEMPLATES } from '../lib/contract-templates'
import { proveContractInBrowser } from '../lib/snarkjs-prover'

// Types

interface CredentialData {
  role: string
  credentialType: string
  credential: string
  format: string
  fields: FieldDisplay[]
  credentialId: string
  compoundProofJson: string | null
  compoundOp: string | null
  hiddenFields: string[]
  predicateDescriptions: string[]
}

interface BindingResult {
  labelKey: string
  bindingHash: string
  verified: boolean
}

interface ContractWizardState {
  step: 1 | 2 | 3 | 4 | 5
  templateId: string | null
  credentialIndex: number
  credentials: CredentialData[]
  bindings: BindingResult[]
  qrDataUrls: string[]
  compressedSize: number
  compressedCborBase64: string | null
  cached: boolean
  nullifier: string | null
  contractHash: string | null
  salt: string | null
}

const API_URL = typeof window !== 'undefined' && window.location.hostname === 'localhost' ? 'http://localhost:3001' : ''

const INITIAL_STATE: ContractWizardState = {
  step: 1,
  templateId: null,
  credentialIndex: 0,
  credentials: [],
  bindings: [],
  qrDataUrls: [],
  compressedSize: 0,
  compressedCborBase64: null,
  cached: false,
  nullifier: null,
  contractHash: null,
  salt: null,
}

export const Route = createFileRoute('/contracts')({
  component: Contracts,
})

function Contracts() {
  const t = useT()
  const { locale, setLocale } = useLocale()
  const [state, setState] = useState<ContractWizardState>(INITIAL_STATE)

  const steps = [
    {
      label: t('contracts.step1Label'),
      description: t('contracts.step1Desc'),
      icon: (
        <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>
        </svg>
      ),
      content: <TemplateStep setState={setState} t={t} />,
    },
    {
      label: t('contracts.step2Label'),
      description: t('contracts.step2Desc'),
      icon: (
        <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/>
        </svg>
      ),
      content: <CredentialStep state={state} setState={setState} t={t} />,
    },
    {
      label: t('contracts.step3Label'),
      description: t('contracts.step3Desc'),
      icon: (
        <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
      ),
      content: <ProveStep state={state} setState={setState} t={t} />,
    },
    {
      label: t('contracts.step4Label'),
      description: t('contracts.step4Desc'),
      icon: (
        <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/>
        </svg>
      ),
      content: <DocumentStep state={state} setState={setState} t={t} />,
    },
    {
      label: t('contracts.step5Label'),
      description: t('contracts.step5Desc'),
      icon: (
        <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
        </svg>
      ),
      content: <VerifyStep state={state} t={t} />,
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
              <p className="text-xs text-slate-500 truncate">{t('contracts.subtitle')}</p>
            </div>
          </a>
          <div className="flex items-center gap-2 sm:gap-4 shrink-0">
            {state.step > 1 && (
              <button
                onClick={() => setState(INITIAL_STATE)}
                className="text-xs text-slate-400 hover:text-slate-200 transition-colors font-medium px-2 py-1 rounded border border-slate-700 hover:border-slate-600"
              >
                {t('contracts.startOver')}
              </button>
            )}
            <button
              onClick={() => setLocale(locale === 'uk' ? 'en' : 'uk')}
              className="text-xs text-slate-500 hover:text-slate-300 transition-colors font-medium px-2 py-1 rounded border border-slate-800 hover:border-slate-700"
            >
              {locale === 'uk' ? 'EN' : 'UA'}
            </button>
            <span className="hidden sm:inline text-xs text-slate-600 font-medium tracking-wider uppercase">Alik.eth</span>
          </div>
        </div>
      </header>

      <StepWizard steps={steps} currentStep={state.step} onStepBack={(step) => {
        if (step === 1) {
          // Back to template picker — full reset
          setState(INITIAL_STATE)
        } else if (step === 2) {
          // Back to credential issuer — keep template, reset credentials
          setState(prev => ({
            ...prev,
            step: 2 as const,
            credentialIndex: 0,
            credentials: [],
            bindings: [],
            qrDataUrls: [],
            compressedSize: 0,
            compressedCborBase64: null,
            nullifier: null,
            contractHash: null,
            salt: null,
          }))
        } else if (step < state.step) {
          setState(prev => ({ ...prev, step: step as ContractWizardState['step'] }))
        }
      }} />
    </div>
  )
}

// === Step 1: Template Picker ===

function TemplateStep({ setState, t }: { setState: React.Dispatch<React.SetStateAction<ContractWizardState>>; t: (key: string) => string }) {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-slate-100">{t('contracts.title')}</h2>
        <p className="text-sm text-slate-400 mt-1">{t('contracts.step1Desc')}</p>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {CONTRACT_TEMPLATES.map(template => (
          <button
            key={template.id}
            onClick={() =>
              setState(prev => ({
                ...prev,
                step: 2,
                templateId: template.id,
                credentialIndex: 0,
                credentials: [],
              }))
            }
            className="flex flex-col items-start gap-3 p-5 bg-slate-800 border border-slate-700 rounded-xl hover:border-blue-500/60 hover:bg-slate-800/80 transition-all text-left group"
          >
            <div className="flex items-center gap-3 w-full">
              <span className="text-3xl" role="img" aria-label={t(template.titleKey)}>{template.icon}</span>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold text-slate-200 group-hover:text-white transition-colors">{t(template.titleKey)}</p>
                <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">{t(template.descKey)}</p>
              </div>
              <svg className="w-4 h-4 text-slate-600 group-hover:text-blue-400 transition-colors shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="9 18 15 12 9 6"/>
              </svg>
            </div>
            {/* Stats row */}
            <div className="flex items-center gap-3 text-[10px] text-slate-500">
              <span className="flex items-center gap-1">
                <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                {template.credentials.length} {template.credentials.length === 1 ? t('contracts.credentialSingular') : t('contracts.credentialPlural')}
              </span>
              <span className="flex items-center gap-1">
                <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                {template.credentials.reduce((sum, r) => sum + r.predicateIds.length, 0)} {t('contracts.proofs')}
              </span>
              {template.bindings && template.bindings.length > 0 && (
                <span className="flex items-center gap-1">
                  <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
                  {template.bindings.length} {t('contracts.binding.count')}
                </span>
              )}
            </div>
            {/* Credential breakdown */}
            <div className="flex flex-wrap gap-1">
              {template.credentials.map(req => {
                const credConfig = CREDENTIAL_TYPES.find(c => c.id === req.credentialType)
                return (
                  <React.Fragment key={req.role}>
                    <span className="text-[10px] bg-blue-900/40 text-blue-300 px-1.5 py-0.5 rounded font-medium">
                      {t(req.roleLabelKey)}
                    </span>
                    {req.predicateIds.map(pid => {
                      const pred = credConfig?.predicates.find(p => p.id === pid)
                      return (
                        <span key={`${req.role}-${pid}`} className="text-[10px] bg-slate-700 text-slate-400 px-1.5 py-0.5 rounded">
                          {pred ? t(pred.labelKey) : pid}
                        </span>
                      )
                    })}
                  </React.Fragment>
                )
              })}
            </div>
          </button>
        ))}
      </div>
    </div>
  )
}

// === Step 2: Credential Issuer (multi-credential, one at a time) ===

function CredentialStep({ state, setState, t }: { state: ContractWizardState; setState: React.Dispatch<React.SetStateAction<ContractWizardState>>; t: (key: string) => string }) {
  const template = CONTRACT_TEMPLATES.find(tpl => tpl.id === state.templateId)
  const currentReq = template?.credentials[state.credentialIndex]
  const config = currentReq ? CREDENTIAL_TYPES.find(ct => ct.id === currentReq.credentialType) : null

  const [formValues, setFormValues] = useState<Record<string, string>>(() =>
    config ? Object.fromEntries(config.fields.map(f => [f.name, f.defaultValue])) : {}
  )
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Reset form values when credential index or template changes
  useEffect(() => {
    if (config) {
      setFormValues(Object.fromEntries(config.fields.map(f => [f.name, f.defaultValue])))
    }
    setError(null)
  }, [state.credentialIndex, state.templateId]) // eslint-disable-line react-hooks/exhaustive-deps

  if (!template) return null

  const totalCredentials = template.credentials.length

  // All credentials issued — show read-only summary of each credential
  if (!currentReq || !config) {
    return (
      <div className="space-y-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-2xl">{template.icon}</span>
            <h2 className="text-lg font-semibold text-slate-100">{t(template.titleKey)}</h2>
          </div>
          <p className="text-sm text-slate-400">{t('contracts.step2Desc')}</p>
        </div>
        {state.credentials.map((cred, i) => {
          const req = template.credentials[i]
          const credConfig = req ? CREDENTIAL_TYPES.find(ct => ct.id === req.credentialType) : null
          return (
            <div key={cred.role} className="bg-slate-800 rounded-lg border border-green-700/30 overflow-hidden">
              <div className="bg-green-900/30 px-6 py-3 flex items-center gap-2">
                <svg className="w-4 h-4 text-green-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="20 6 9 17 4 12"/>
                </svg>
                <h3 className="text-sm font-semibold text-green-300">{req ? t(req.roleLabelKey) : cred.role}</h3>
                {credConfig && <span className="text-xs text-slate-500 ml-auto">{t(credConfig.credLabelKey)}</span>}
              </div>
              <div className="p-6">
                <div className="grid grid-cols-2 gap-3">
                  {cred.fields.map(f => (
                    <div key={f.name}>
                      <span className="block text-xs text-slate-500 mb-0.5">{f.label}</span>
                      <span className="text-sm text-slate-300 font-mono">{f.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )
        })}
      </div>
    )
  }

  const handleIssue = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(`${API_URL}/issuer/issue`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credential_type: config.id,
          claims: formValues,
          issuer: config.issuer,
        }),
      })
      if (!res.ok) throw new Error(await res.text())
      const data = await res.json()
      const credentialId = formValues[currentReq.disclosedField] || config.id

      const newCredData: CredentialData = {
        role: currentReq.role,
        credentialType: currentReq.credentialType,
        credential: data.credential,
        format: data.format,
        fields: data.credential_display.fields.map((f: FieldDisplay) => {
          const fieldConfig = config.fields.find(cf => cf.name === f.name)
          return { ...f, label: fieldConfig ? t(fieldConfig.labelKey) : f.label }
        }),
        credentialId,
        compoundProofJson: null,
        compoundOp: null,
        hiddenFields: [],
        predicateDescriptions: [],
      }

      const nextIndex = state.credentialIndex + 1
      const isLast = nextIndex >= totalCredentials

      setState(prev => ({
        ...prev,
        credentials: [...prev.credentials, newCredData],
        credentialIndex: nextIndex,
        step: isLast ? 3 : prev.step,
      }))
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="text-2xl">{template.icon}</span>
          <h2 className="text-lg font-semibold text-slate-100">{t(template.titleKey)}</h2>
        </div>
        <p className="text-sm text-slate-400">{t('contracts.step2Desc')}</p>
      </div>

      {/* Progress indicator */}
      {totalCredentials > 1 && (
        <div className="flex items-center gap-3">
          {template.credentials.map((req, i) => {
            const isDone = i < state.credentialIndex
            const isCurrent = i === state.credentialIndex
            return (
              <div key={req.role} className="flex items-center gap-2">
                {i > 0 && <div className={`w-6 h-px ${isDone ? 'bg-green-500' : 'bg-slate-700'}`} />}
                <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${
                  isDone
                    ? 'bg-green-900/30 border-green-700/50 text-green-400'
                    : isCurrent
                      ? 'bg-blue-900/30 border-blue-500/50 text-blue-300'
                      : 'bg-slate-800 border-slate-700 text-slate-500'
                }`}>
                  {isDone ? (
                    <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                  ) : (
                    <span className="w-3 text-center">{i + 1}</span>
                  )}
                  <span>{t(req.roleLabelKey)}</span>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Current credential header */}
      <div className="bg-slate-800/50 rounded-lg border border-blue-500/30 px-4 py-3">
        <p className="text-sm font-semibold text-blue-300">
          {t('contracts.credentialOf')} {state.credentialIndex + 1} / {totalCredentials} — {t(currentReq.roleLabelKey)}
        </p>
      </div>

      {/* Issuer form */}
      <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
        <div className="bg-blue-700 px-6 py-3">
          <h3 className="text-base font-semibold">{t(config.issuerTitleKey)}</h3>
          <p className="text-sm text-blue-200">{t(config.issuerSubtitleKey)}</p>
        </div>
        <div className="p-6">
          <p className="text-slate-400 text-sm mb-4">{t(config.credLabelKey)}</p>
          <div className="grid grid-cols-2 gap-4">
            {config.fields.map(field => (
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

      {/* Already completed credentials */}
      {state.credentials.length > 0 && (
        <div className="space-y-2">
          {state.credentials.map((cred, i) => {
            const req = template.credentials[i]
            return (
              <div key={cred.role} className="flex items-center gap-3 px-4 py-3 bg-green-950/20 rounded-lg border border-green-700/30">
                <svg className="w-4 h-4 text-green-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="20 6 9 17 4 12"/>
                </svg>
                <span className="text-sm text-green-300 font-medium">{t(req.roleLabelKey)}</span>
                <span className="text-xs text-slate-500 font-mono">{cred.credentialId}</span>
              </div>
            )
          })}
        </div>
      )}

      {error && (
        <div className="bg-red-900/30 border border-red-700 rounded-lg p-4 flex items-center justify-between gap-3">
          <span className="text-sm text-red-300">{error}</span>
          <button onClick={() => setError(null)} className="text-xs text-red-400 hover:text-red-200 font-medium shrink-0">{t('contracts.dismiss') || 'Dismiss'}</button>
        </div>
      )}

      <button
        onClick={handleIssue}
        disabled={loading}
        className="flex items-center justify-center gap-2 w-full bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 disabled:cursor-not-allowed text-white font-semibold py-3 rounded-lg transition-colors"
      >
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/>
        </svg>
        {loading ? t('demo.issuing') : t('demo.issueBtn')}
      </button>
    </div>
  )
}

// === Step 3: Prove (all credentials at once) ===

function ProveStep({ state, setState, t }: { state: ContractWizardState; setState: React.Dispatch<React.SetStateAction<ContractWizardState>>; t: (key: string) => string }) {
  const template = CONTRACT_TEMPLATES.find(tpl => tpl.id === state.templateId)

  const [loading, setLoading] = useState(false)
  const [elapsed, setElapsed] = useState(0)
  const [proved, setProved] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [currentProvingIndex, setCurrentProvingIndex] = useState(-1)
  const [skipCache, setSkipCache] = useState(false)
  const [proveMethod, setProveMethod] = useState<ProveMethod>('server')

  // Reset local state when credentials change
  useEffect(() => {
    setProved(false)
    setError(null)
    setLoading(false)
    setElapsed(0)
    setCurrentProvingIndex(-1)
    setSkipCache(false)
  }, [state.credentials.length])

  if (!template || state.credentials.length === 0) return null

  const handleProve = async (forceSkipCache = false) => {
    setLoading(true)
    setElapsed(0)
    setError(null)
    const timer = setInterval(() => setElapsed(prev => prev + 1), 1000)
    try {
      const updatedCredentials = [...state.credentials]
      const allQrDataUrls: string[] = []
      let totalCompressedSize = 0
      let anyCached = false
      let nullifierData: { nullifier: string; contractHash: string; salt: string } | null = null

      const { encodeProofChunks, LogicalOpFlag } = await import('../lib/qr-chunking')
      const QRCode = (await import('qrcode')).default
      const proofCount = template.credentials.length

      // On-device proving path
      if (proveMethod === 'device') {
        // Build credentials array for proveContractInBrowser
        const credParams = template.credentials.map((req, ci) => {
          const cred = state.credentials[ci]
          const config = CREDENTIAL_TYPES.find(ct => ct.id === req.credentialType)
          if (!config) throw new Error(`Unknown credential type: ${req.credentialType}`)
          const templatePredicates = req.predicateIds
            .map(pid => config.predicates.find(p => p.id === pid))
            .filter((p): p is NonNullable<typeof p> => p !== undefined)
          const predicates = templatePredicates.map(p => ({
            claim: p.predicate.claim,
            op: p.predicate.op,
            value: p.predicate.value === '__FROM_FORM__'
              ? (cred.fields.find(f => f.name === p.predicate.claim)?.value ?? '')
              : p.predicate.value,
          }))
          return { credential: cred.credential, format: cred.format as 'sdjwt' | 'mdoc', predicates }
        })

        // Build bindings array
        const bindingParams = template.bindings?.map(b => {
          const credIndexA = template.credentials.findIndex(c => c.role === b.roleA)
          const credIndexB = template.credentials.findIndex(c => c.role === b.roleB)
          return { credIndexA, claimA: b.claimA, credIndexB, claimB: b.claimB }
        })

        const selectedTemplate = CONTRACT_TEMPLATES.find(tpl => tpl.id === state.templateId)!
        const result = await proveContractInBrowser(
          {
            credentials: credParams,
            contractTerms: JSON.stringify(selectedTemplate),
            timestamp: new Date().toISOString(),
            bindings: bindingParams,
            onProgress: (msg) => { /* future: display progress message */ },
            onCredentialIndex: (idx) => setCurrentProvingIndex(idx),
          },
          API_URL,
        )

        // Process results — same as server path
        const updatedDeviceCredentials = [...state.credentials]
        for (let ci = 0; ci < template.credentials.length; ci++) {
          const req = template.credentials[ci]
          const config = CREDENTIAL_TYPES.find(ct => ct.id === req.credentialType)!
          const templatePredicates = req.predicateIds
            .map(pid => config.predicates.find(p => p.id === pid))
            .filter((p): p is NonNullable<typeof p> => p !== undefined)
          const predicateDescriptions = templatePredicates.map(p => t(p.labelKey))

          // Generate QR codes from envelope bytes
          const compressed = result.envelopeBytes[ci]
          totalCompressedSize += compressed.length
          const proofId = ci + 1
          const logicalOp = proofCount > 1 ? LogicalOpFlag.And : LogicalOpFlag.Single
          const chunks = encodeProofChunks(compressed, proofId, ci, proofCount, logicalOp)
          for (const chunk of chunks) {
            const url = await QRCode.toDataURL([{ data: chunk, mode: 'byte' as const }], {
              errorCorrectionLevel: 'L', margin: 1, width: 280,
            })
            allQrDataUrls.push(url)
          }

          updatedDeviceCredentials[ci] = {
            ...state.credentials[ci],
            compoundProofJson: result.compoundProofs[ci],
            compoundOp: 'And',
            hiddenFields: [],
            predicateDescriptions,
          }
        }

        // Process bindings
        const bindingResultsData: BindingResult[] = (template.bindings ?? []).map((b, i) => ({
          labelKey: b.labelKey,
          bindingHash: result.bindingResults[i]?.bindingHash ?? '',
          verified: result.bindingResults[i]?.verified ?? false,
        }))

        nullifierData = result.nullifier ? {
          nullifier: result.nullifier,
          contractHash: result.contractHash,
          salt: result.salt,
        } : null

        clearInterval(timer)
        setLoading(false)
        setProved(true)
        setTimeout(() => {
          setState(prev => ({
            ...prev,
            step: 4,
            credentials: updatedDeviceCredentials,
            bindings: bindingResultsData,
            qrDataUrls: allQrDataUrls,
            compressedSize: totalCompressedSize,
            cached: false,
            nullifier: nullifierData?.nullifier ?? null,
            contractHash: nullifierData?.contractHash ?? null,
            salt: nullifierData?.salt ?? null,
          }))
        }, 600)
        return
      }

      for (let ci = 0; ci < template.credentials.length; ci++) {
        setCurrentProvingIndex(ci)
        const req = template.credentials[ci]
        const cred = updatedCredentials[ci]
        const config = CREDENTIAL_TYPES.find(ct => ct.id === req.credentialType)
        if (!config) throw new Error(`Unknown credential type: ${req.credentialType}`)

        const templatePredicates = req.predicateIds
          .map(pid => config.predicates.find(p => p.id === pid))
          .filter((p): p is NonNullable<typeof p> => p !== undefined)

        // Build predicates, resolving __FROM_FORM__ values
        const predicates = templatePredicates.map(p => ({
          claim: p.predicate.claim,
          op: p.predicate.op,
          value: p.predicate.value === '__FROM_FORM__'
            ? (cred.fields.find(f => f.name === p.predicate.claim)?.value ?? '')
            : p.predicate.value,
        }))

        // Prove via /holder/contract-prove (includes nullifier generation)
        const selectedTemplate = CONTRACT_TEMPLATES.find(tpl => tpl.id === state.templateId)
        const proveRes = await fetch(`${API_URL}/holder/contract-prove`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            credential: cred.credential,
            format: cred.format,
            predicates,
            contract_terms: JSON.stringify(selectedTemplate),
            timestamp: new Date().toISOString(),
            ...(forceSkipCache ? { skip_cache: true } : {}),
          }),
        })
        if (!proveRes.ok) throw new Error(await proveRes.text())
        const proveData = await proveRes.json()
        if (proveData.cached) anyCached = true

        // Export compound with compression
        const exportRes = await fetch(`${API_URL}/holder/proof-export-compound?compress=true`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ compound_proof_json: proveData.compound_proof_json }),
        })
        if (!exportRes.ok) throw new Error(await exportRes.text())
        const exportData = await exportRes.json()

        // Generate QR codes for this credential's proof
        const compressed = Uint8Array.from(atob(exportData.compressed_cbor_base64), c => c.charCodeAt(0))
        totalCompressedSize += compressed.length
        const proofId = ci + 1
        const logicalOp = proofCount > 1 ? LogicalOpFlag.And : LogicalOpFlag.Single
        const chunks = encodeProofChunks(compressed, proofId, ci, proofCount, logicalOp)
        for (const chunk of chunks) {
          const url = await QRCode.toDataURL([{ data: chunk, mode: 'byte' as const }], {
            errorCorrectionLevel: 'L',
            margin: 1,
            width: 280,
          })
          allQrDataUrls.push(url)
        }

        // Build predicate descriptions
        const predicateDescriptions = templatePredicates.map(p => t(p.labelKey))

        // Update credential data with proof info
        updatedCredentials[ci] = {
          ...cred,
          compoundProofJson: proveData.compound_proof_json,
          compoundOp: proveData.op,
          hiddenFields: proveData.hidden_fields,
          predicateDescriptions,
        }

        // Store nullifier data from the first credential's response
        if (ci === 0 && proveData.nullifier) {
          nullifierData = {
            nullifier: proveData.nullifier,
            contractHash: proveData.contract_hash,
            salt: proveData.salt,
          }
        }
      }

      // Prove holder bindings if any
      const bindingResults: BindingResult[] = []
      if (template.bindings) {
        for (const binding of template.bindings) {
          setCurrentProvingIndex(-2) // signal binding phase
          const credA = updatedCredentials.find(c => c.role === binding.roleA)
          const credB = updatedCredentials.find(c => c.role === binding.roleB)
          if (credA && credB) {
            const bindingRes = await fetch(`${API_URL}/holder/prove-binding`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                sdjwt_a: credA.credential,
                sdjwt_b: credB.credential,
                binding_claim: binding.claimA,
                binding_claim_b: binding.claimA !== binding.claimB ? binding.claimB : undefined,
                predicates_a: [],
                predicates_b: [],
              }),
            })
            if (bindingRes.ok) {
              const bindingData = await bindingRes.json()
              bindingResults.push({
                labelKey: binding.labelKey,
                bindingHash: bindingData.binding_hash,
                verified: bindingData.binding_verified,
              })
            } else {
              console.warn('Holder binding failed:', await bindingRes.text())
            }
          }
        }
      }

      clearInterval(timer)
      setLoading(false)
      setProved(true)
      setTimeout(() => {
        setState(prev => ({
          ...prev,
          step: 4,
          credentials: updatedCredentials,
          bindings: bindingResults,
          qrDataUrls: allQrDataUrls,
          compressedSize: totalCompressedSize,
          cached: anyCached,
          nullifier: nullifierData?.nullifier ?? null,
          contractHash: nullifierData?.contractHash ?? null,
          salt: nullifierData?.salt ?? null,
        }))
      }, 600)
    } catch (e: unknown) {
      clearInterval(timer)
      setLoading(false)
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="text-2xl">{template.icon}</span>
          <h2 className="text-lg font-semibold text-slate-100">{t(template.titleKey)}</h2>
        </div>
        <p className="text-sm text-slate-400">{t('contracts.step3Desc')}</p>
      </div>

      {/* Predicates list grouped by credential */}
      <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
        <div className="bg-slate-700 px-6 py-3">
          <h3 className="text-sm font-semibold text-slate-200">{t('contracts.predicatesProved')}</h3>
        </div>
        <div className="p-5 space-y-4">
          {template.credentials.map((req, ci) => {
            const config = CREDENTIAL_TYPES.find(ct => ct.id === req.credentialType)
            const cred = state.credentials[ci]
            const templatePredicates = req.predicateIds
              .map(pid => config?.predicates.find(p => p.id === pid))
              .filter((p): p is NonNullable<typeof p> => p !== undefined)

            return (
              <div key={req.role}>
                {/* Role header */}
                <p className="text-xs font-semibold text-slate-400 mb-2">{t(req.roleLabelKey)}</p>
                <div className="space-y-2">
                  {templatePredicates.map(p => (
                    <div key={`${req.role}-${p.id}`} className="flex items-center gap-3 px-4 py-3 bg-slate-900/50 rounded-lg border border-slate-700">
                      <svg className="w-4 h-4 text-blue-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                      </svg>
                      <span className="text-sm text-slate-200">{t(p.labelKey)}</span>
                      {loading && currentProvingIndex === ci && (
                        <svg className="animate-spin h-3 w-3 text-blue-400 ml-auto" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                        </svg>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )
          })}

          {/* Holder bindings */}
          {template.bindings && template.bindings.length > 0 && (
            <div className="mt-4 pt-4 border-t border-slate-700">
              <p className="text-xs font-semibold text-slate-400 mb-2">{t('contracts.binding.hashMatch')}</p>
              {template.bindings.map((binding, bi) => (
                <div key={bi} className="flex items-center gap-3 px-4 py-3 bg-purple-950/20 rounded-lg border border-purple-700/30">
                  <svg className="w-4 h-4 text-purple-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
                    <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
                  </svg>
                  <span className="text-sm text-purple-300">{t(binding.labelKey)}</span>
                  {loading && currentProvingIndex === -2 && (
                    <svg className="animate-spin h-3 w-3 text-purple-400 ml-auto" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Loading state */}
      {loading && (
        <div className="bg-slate-800 rounded-lg border border-blue-500/50 p-6 text-center space-y-3">
          <div className="flex items-center justify-center gap-3">
            <svg className="animate-spin h-5 w-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            <span className="text-blue-300 font-semibold">
              {t('contracts.generating')}{elapsed > 0 ? ` ${elapsed}s` : ''}
              {currentProvingIndex >= 0 && ` (${currentProvingIndex + 1}/${template.credentials.length})`}
            </span>
          </div>
        </div>
      )}

      {/* Success state */}
      {proved && !loading && (
        <div className="bg-slate-800 rounded-lg border border-green-500/50 p-6 text-center flex items-center justify-center gap-3">
          <svg className="w-5 h-5 text-green-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
          </svg>
          <span className="text-green-400 font-semibold">{t('demo.proofGenerated')}</span>
        </div>
      )}

      {/* Error state */}
      {error && !loading && (
        <div className="bg-red-900/30 border border-red-700 rounded-lg p-4 flex items-center justify-between gap-3">
          <span className="text-sm text-red-300">{error}</span>
          <button onClick={() => setError(null)} className="text-xs text-red-400 hover:text-red-200 font-medium shrink-0">{t('contracts.dismiss') || 'Dismiss'}</button>
        </div>
      )}

      {/* Prove method toggle */}
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-slate-500 font-medium uppercase tracking-wider">Proving</span>
        <ProveMethodToggle
          value={proveMethod}
          onChange={setProveMethod}
          disabled={loading || proved}
        />
      </div>

      <button
        onClick={() => handleProve()}
        disabled={loading || proved}
        className="flex items-center justify-center gap-2 w-full bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 disabled:cursor-not-allowed text-white font-semibold py-3 rounded-lg transition-colors"
      >
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        {loading ? t('contracts.generating') : t('contracts.generateProof')}
      </button>

      {proved && state.cached && !loading && (
        <button
          onClick={() => { setProved(false); handleProve(true) }}
          className="text-xs text-slate-500 hover:text-slate-300 transition-colors cursor-pointer"
        >
          {t('contracts.cachedNotice')} →
        </button>
      )}

    </div>
  )
}

// === Step 4: Document Preview ===

function DocumentStep({ state, setState, t }: { state: ContractWizardState; setState: React.Dispatch<React.SetStateAction<ContractWizardState>>; t: (key: string) => string }) {
  const template = CONTRACT_TEMPLATES.find(tpl => tpl.id === state.templateId)
  if (!template) return null

  const today = new Date().toLocaleDateString('en-GB', { year: 'numeric', month: 'long', day: 'numeric' })

  return (
    <div className="space-y-4">
      {/* A4 Document */}
      <div className="print-area">
        <div className="bg-white text-black rounded-lg overflow-hidden print:rounded-none print:shadow-none">
          <div className="max-w-[210mm] mx-auto px-6 py-6 print:px-8 print:py-6">
            {/* Header */}
            <div className="flex items-baseline justify-between border-b border-gray-300 pb-3 mb-5">
              <span className="text-base font-bold tracking-tight">zk-eidas</span>
              <span className="text-xs text-gray-500">{today}</span>
            </div>

            {/* Title — always bilingual */}
            <h1 className="text-xl font-bold text-center mb-1">{tLang(template.titleKey, 'en')}</h1>
            <p className="text-base text-gray-500 italic text-center mb-6">{tLang(template.titleKey, 'uk')}</p>

            {/* Parties — one per credential */}
            {template.credentials.map((req, ci) => {
              const cred = state.credentials[ci]
              if (!cred) return null
              const config = CREDENTIAL_TYPES.find(ct => ct.id === req.credentialType)
              const templatePredicates = req.predicateIds
                .map(pid => config?.predicates.find(p => p.id === pid))
                .filter((p): p is NonNullable<typeof p> => p !== undefined)

              return (
                <div key={req.role} className="mb-5">
                  <p className="text-xs font-semibold text-gray-500 mb-2">{t(req.roleLabelKey)}:</p>

                  {/* Proved predicates */}
                  <div className="space-y-2">
                    {templatePredicates.map((p, i) => (
                      <div key={p.id} className="flex items-center gap-2">
                        <span className="text-green-600 font-bold text-sm">&#10003;</span>
                        <span className="text-sm text-gray-800">{t(p.labelKey)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )
            })}

            {/* Bilingual body — always both languages */}
            <div className="space-y-3 mb-6">
              <p className="text-sm text-gray-800 leading-relaxed">{t(template.bodyKey_en)}</p>
              <p className="text-sm text-gray-500 italic leading-relaxed">{t(template.bodyKey_uk)}</p>
            </div>

            {/* QR codes */}
            {state.qrDataUrls.length > 0 && (
              <div className="mb-5">
                <div className="grid grid-cols-3 gap-2 justify-items-center">
                  {state.qrDataUrls.map((url, qi) => (
                    <div key={qi} className="text-center">
                      <img
                        src={url}
                        alt={`QR ${qi + 1}/${state.qrDataUrls.length}`}
                        className="w-28 h-28 print:w-[50mm] print:h-[50mm]"
                      />
                      <p className="text-[9px] text-gray-400 -mt-0.5">{qi + 1}/{state.qrDataUrls.length}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Holder bindings */}
            {state.bindings.length > 0 && (
              <div className="mb-5 border border-gray-300 rounded-lg p-4 print:border-black/30">
                <p className="text-xs font-semibold text-gray-500 mb-2 uppercase tracking-wider">{t('contracts.binding.hashMatch')}</p>
                {state.bindings.map((binding, bi) => (
                  <div key={bi} className="flex items-center gap-2 mb-1">
                    <span className="text-green-600 font-bold text-sm print:text-black">
                      {binding.verified ? '🔗 ✓' : '✗'}
                    </span>
                    <span className="text-sm text-gray-800">{t(binding.labelKey)}</span>
                  </div>
                ))}
                {state.bindings.filter(b => b.verified).map((binding, bi) => (
                  <p key={bi} className="text-[10px] text-gray-400 font-mono mt-1 print:text-gray-600">
                    SHA-256 binding: {binding.bindingHash}
                  </p>
                ))}
              </div>
            )}

            {/* Nullifier / Contract Hash / Salt */}
            {state.nullifier && (
              <div className="mb-5 border border-gray-300 rounded-lg p-4 print:border-black/30">
                <p className="text-xs font-semibold text-gray-500 mb-2 uppercase tracking-wider">{t('contracts.nullifier')}</p>
                <div className="space-y-1.5">
                  <div>
                    <span className="text-[10px] text-gray-400 font-medium">{t('contracts.nullifier')}</span>
                    <p className="text-xs text-gray-700 font-mono break-all">{state.nullifier}</p>
                  </div>
                  {state.contractHash && (
                    <div>
                      <span className="text-[10px] text-gray-400 font-medium">{t('contracts.contractHash')}</span>
                      <p className="text-xs text-gray-700 font-mono break-all">{state.contractHash}</p>
                    </div>
                  )}
                  {state.salt && (
                    <div>
                      <span className="text-[10px] text-gray-400 font-medium">{t('contracts.salt')}</span>
                      <p className="text-xs text-gray-700 font-mono break-all">{state.salt}</p>
                    </div>
                  )}
                </div>
                <p className="text-[9px] text-gray-400 mt-2 leading-relaxed italic">{t('contracts.nullifierTooltip')}</p>
              </div>
            )}

            {/* Signature line */}
            <div className="border-t border-gray-200 pt-4 mt-4">
              <div className="flex justify-between text-xs text-gray-400">
                <span>{t('contracts.signatureLine')}: ____________________________</span>
                <span>{today}</span>
              </div>
            </div>

            {/* Footer */}
            <div className="text-center text-[9px] text-gray-400 mt-4">
              <span>zk-eidas.com/verify</span>
              <span className="mx-2">·</span>
              <span>{state.qrDataUrls.length} QR · {(state.compressedSize / 1024).toFixed(1)} KB</span>
            </div>
          </div>
        </div>
      </div>

      {/* Screen-only buttons */}
      <div className="flex gap-3 print:hidden">
        <button
          onClick={() => window.print()}
          className="flex items-center justify-center gap-2 flex-1 py-3 bg-slate-700 hover:bg-slate-600 text-white font-semibold rounded-lg transition-colors"
        >
          <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/>
          </svg>
          {t('contracts.print')}
        </button>
        <button
          onClick={() => setState(prev => ({ ...prev, step: 5 }))}
          className="flex items-center justify-center gap-2 flex-1 py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors"
        >
          <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
          </svg>
          {t('contracts.verifyDocument')}
        </button>
      </div>

    </div>
  )
}

// === Step 5: Verify ===

function VerifyStep({ state, t }: { state: ContractWizardState; t: (key: string) => string }) {
  const template = CONTRACT_TEMPLATES.find(tpl => tpl.id === state.templateId)
  const [verifying, setVerifying] = useState(false)
  const [verified, setVerified] = useState(false)
  const [allValid, setAllValid] = useState(false)
  const [results, setResults] = useState<{ role: string; predicate: string; valid: boolean }[]>([])
  const [error, setError] = useState<string | null>(null)
  const [verificationMethod, setVerificationMethod] = useState<'wasm' | 'server' | null>(null)
  const [verifyTimeMs, setVerifyTimeMs] = useState<number | null>(null)
  const autoVerifyRan = useRef(false)

  const allProofs = state.credentials.map(c => c.compoundProofJson).filter(Boolean)

  useEffect(() => {
    if (autoVerifyRan.current || allProofs.length === 0) return
    autoVerifyRan.current = true
    ;(async () => {
      setVerifying(true)
      setError(null)
      const t0 = performance.now()
      const subResults: { role: string; predicate: string; valid: boolean }[] = []

      // Try WASM first
      try {
        const sdk = await import('@zk-eidas/verifier-sdk')
        const trustedVks = await sdk.loadTrustedVks('/trusted-vks.json')
        await sdk.initVerifier()

        for (let ci = 0; ci < state.credentials.length; ci++) {
          const cred = state.credentials[ci]
          const req = template?.credentials[ci]
          if (!cred.compoundProofJson || !req) continue

          const envelope = JSON.parse(cred.compoundProofJson)
          const chainResult = await sdk.verifyCompoundProof(envelope, trustedVks)

          for (let i = 0; i < chainResult.predicateResults.length; i++) {
            const pr = chainResult.predicateResults[i]
            const desc = cred.predicateDescriptions[i] || pr.op || 'unknown'
            subResults.push({ role: req.role, predicate: desc, valid: pr.valid })
          }
        }

        const valid = subResults.every(r => r.valid)
        setResults(subResults)
        setAllValid(valid)
        setVerificationMethod('wasm')
        setVerifyTimeMs(performance.now() - t0)
        setVerified(true)
      } catch (wasmErr) {
        console.warn('WASM verification failed, falling back to server:', wasmErr)
        // Fall back to server — verify each credential's proof
        try {
          subResults.length = 0
          for (let ci = 0; ci < state.credentials.length; ci++) {
            const cred = state.credentials[ci]
            const req = template?.credentials[ci]
            if (!cred.compoundProofJson || !req) continue

            const res = await fetch(`${API_URL}/verifier/verify-compound`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                compound_proof_json: cred.compoundProofJson,
                hidden_fields: cred.hiddenFields,
              }),
            })
            if (!res.ok) throw new Error(await res.text())
            const data = await res.json()

            if (data.sub_proofs_verified != null) {
              cred.predicateDescriptions.forEach((desc, i) => {
                subResults.push({
                  role: req.role,
                  predicate: desc,
                  valid: i < data.sub_proofs_verified,
                })
              })
            } else {
              subResults.push({
                role: req.role,
                predicate: `compound[${data.op}]`,
                valid: data.valid,
              })
            }
          }

          const valid = subResults.every(r => r.valid)
          setResults(subResults)
          setAllValid(valid)
          setVerificationMethod('server')
          setVerifyTimeMs(performance.now() - t0)
          setVerified(true)
        } catch (serverErr) {
          setError(`Verification failed: ${serverErr instanceof Error ? serverErr.message : String(serverErr)}`)
        }
      } finally {
        setVerifying(false)
      }
    })()
  }, [allProofs.length]) // eslint-disable-line react-hooks/exhaustive-deps

  // Group results by role for display
  const resultsByRole = results.reduce<Record<string, { role: string; predicate: string; valid: boolean }[]>>((acc, r) => {
    if (!acc[r.role]) acc[r.role] = []
    acc[r.role].push(r)
    return acc
  }, {})

  return (
    <div className="space-y-6">
      {/* Spinner */}
      {verifying && (
        <div className="flex flex-col items-center justify-center gap-4 py-12">
          <svg className="animate-spin h-8 w-8 text-purple-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          <p className="text-sm text-slate-400">{t('contracts.verifying')}</p>
        </div>
      )}

      {/* Error */}
      {error && !verifying && (
        <div className="bg-red-900/30 border border-red-700 rounded-lg p-4 text-red-300 text-sm">{error}</div>
      )}

      {/* Results */}
      {verified && !verifying && (
        <div className="space-y-4">
          {/* Overall result banner */}
          <div className={`flex items-center gap-3 rounded-lg px-5 py-4 border ${
            allValid
              ? 'bg-green-950/30 border-green-700/40 text-green-300'
              : 'bg-red-950/30 border-red-700/40 text-red-300'
          }`}>
            {allValid ? (
              <svg className="w-6 h-6 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
              </svg>
            ) : (
              <svg className="w-6 h-6 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>
              </svg>
            )}
            <div className="flex-1">
              <p className="font-semibold text-sm">{allValid ? t('contracts.verified') : t('contracts.verifyFailed')}</p>
              {verifyTimeMs !== null && (
                <p className="text-xs opacity-70 mt-0.5">
                  {verificationMethod === 'wasm' ? 'WASM' : 'Server'} · {Math.round(verifyTimeMs)}ms · {state.credentials.length} credential{state.credentials.length > 1 ? 's' : ''}
                </p>
              )}
            </div>
          </div>

          {/* Per-predicate results grouped by role */}
          <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
            <div className="bg-slate-700 px-6 py-3">
              <h3 className="text-sm font-semibold text-slate-200">{t('contracts.predicatesProved')}</h3>
            </div>
            <div className="divide-y divide-slate-700">
              {template?.credentials.map(req => {
                const roleResults = resultsByRole[req.role] || []
                return (
                  <div key={req.role}>
                    <div className="px-5 py-2 bg-slate-800/80">
                      <span className="text-xs font-semibold text-slate-400">{t(req.roleLabelKey)}</span>
                    </div>
                    {roleResults.map((r, i) => (
                      <div key={i} className="flex items-center justify-between px-5 py-3">
                        <span className="text-sm text-slate-300">{r.predicate}</span>
                        {r.valid ? (
                          <span className="text-green-400 text-xs font-semibold flex items-center gap-1">
                            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                            OK
                          </span>
                        ) : (
                          <span className="text-red-400 text-xs font-semibold flex items-center gap-1">
                            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                            FAIL
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                )
              })}
            </div>
          </div>

          {/* Holder bindings */}
          {state.bindings.length > 0 && (
            <div className="bg-slate-800 rounded-lg border border-purple-700/30 overflow-hidden">
              <div className="bg-purple-900/30 px-6 py-3">
                <h3 className="text-sm font-semibold text-purple-300">{t('contracts.binding.hashMatch')}</h3>
              </div>
              <div className="divide-y divide-slate-700">
                {state.bindings.map((binding, bi) => (
                  <div key={bi} className="flex items-center justify-between px-5 py-3">
                    <div className="flex items-center gap-2">
                      <svg className="w-4 h-4 text-purple-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
                        <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
                      </svg>
                      <span className="text-sm text-slate-300">{t(binding.labelKey)}</span>
                    </div>
                    {binding.verified ? (
                      <span className="text-purple-400 text-xs font-semibold flex items-center gap-1">
                        <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                        {binding.bindingHash.slice(0, 10)}…
                      </span>
                    ) : (
                      <span className="text-red-400 text-xs font-semibold">MISMATCH</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
