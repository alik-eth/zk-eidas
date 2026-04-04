import { createFileRoute } from '@tanstack/react-router'
import React, { useEffect, useRef, useState } from 'react'
import { StepWizard } from '../components/StepWizard'
import { ProveMethodToggle, type ProveMethod } from '../components/ProveMethodToggle'
import { proveCompoundInBrowser, proveInBrowser } from '../lib/snarkjs-prover'
import { useT, useLocale, tLang } from '../i18n'
import { CREDENTIAL_TYPES, resolveVariant, type FieldDisplay } from '../lib/credential-types'
import { CONTRACT_TEMPLATES } from '../lib/contract-templates'
import { EscrowPanel, type EscrowConfig, DEMO_AUTHORITY_PUBKEY, DEMO_AUTHORITY_PRIVKEY, deriveEncapsulationKey, DEMO_AUTHORITY_NAME } from '../components/EscrowPanel'
import type { EscrowEnvelopeQr } from '../lib/qr-chunking'

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
  qrDataUrls: string[]
  escrowData: any | null
}

interface BindingResult {
  labelKey: string
  bindingHash: string
  verified: boolean
}

interface PartyProof {
  role: string
  roleLabelKey: string
  nullifier: string
  salt: string
  issuer: string
  qrDataUrls: string[]
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
  partyProofs: PartyProof[]
  contractHash: string | null
  termsQrUrl: string | null
  metadataQrUrl: string | null
  bundleCborUrl: string | null
  escrowEnabled: boolean
  escrowQrUrls: { role: string; roleLabelKey: string; urls: string[]; escrowIndex: number; escrowCount: number }[]
}

const API_URL = typeof window !== 'undefined' && window.location.hostname === 'localhost' ? 'http://localhost:3001' : ''

function formatFieldHash(bytes: number[]): string {
  const s = String.fromCharCode(...bytes)
  return s.length > 20 ? s.slice(0, 10) + '...' + s.slice(-10) : s
}

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
  partyProofs: [],
  contractHash: null,
  termsQrUrl: null,
  metadataQrUrl: null,
  bundleCborUrl: null,
  escrowEnabled: true,
  escrowQrUrls: [],
}

export const Route = createFileRoute('/demo')({
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
            partyProofs: [],
            contractHash: null,
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
  const { locale } = useLocale()
  const template = CONTRACT_TEMPLATES.find(tpl => tpl.id === state.templateId)
  const currentReq = template?.credentials[state.credentialIndex]
  const config = currentReq ? CREDENTIAL_TYPES.find(ct => ct.id === currentReq.credentialType) : null
  const isSecondary = template && currentReq
    ? template.credentials.slice(0, state.credentialIndex).some(r => r.credentialType === currentReq.credentialType)
    : false
  const variant = config ? resolveVariant(config, locale === 'uk' ? 'uk' : 'en', isSecondary) : null

  const [formValues, setFormValues] = useState<Record<string, string>>(() =>
    variant ? Object.fromEntries(variant.fields.map(f => [f.name, f.defaultValue])) : {}
  )
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Reset form values when credential index or template changes
  useEffect(() => {
    if (variant) {
      setFormValues(Object.fromEntries(variant.fields.map(f => [f.name, f.defaultValue])))
    }
    setError(null)
  }, [state.credentialIndex, state.templateId, locale]) // eslint-disable-line react-hooks/exhaustive-deps

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
          issuer: variant?.issuer,
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
          const fieldConfig = variant?.fields.find(cf => cf.name === f.name)
          return { ...f, label: fieldConfig ? t(fieldConfig.labelKey) : f.label }
        }),
        credentialId,
        compoundProofJson: null,
        compoundOp: null,
        hiddenFields: [],
        predicateDescriptions: [],
        qrDataUrls: [],
        escrowData: null,
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
          <h3 className="text-base font-semibold">{t(variant!.issuerTitleKey)}</h3>
          <p className="text-sm text-blue-200">{t(variant!.issuerSubtitleKey)}</p>
        </div>
        <div className="p-6">
          <p className="text-slate-400 text-sm mb-4">{t(config.credLabelKey)}</p>
          <div className="grid grid-cols-2 gap-4">
            {variant!.fields.map(field => (
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
        {loading ? t('sandbox.issuing') : t('sandbox.issueBtn')}
      </button>
    </div>
  )
}

// === Step 3: Prove (all credentials at once) ===

function ProveStep({ state, setState, t }: { state: ContractWizardState; setState: React.Dispatch<React.SetStateAction<ContractWizardState>>; t: (key: string) => string }) {
  const { locale } = useLocale()
  const template = CONTRACT_TEMPLATES.find(tpl => tpl.id === state.templateId)

  const [loading, setLoading] = useState(false)
  const [elapsed, setElapsed] = useState(0)
  const [proved, setProved] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [currentProvingIndex, setCurrentProvingIndex] = useState(-1)
  const [skipCache, setSkipCache] = useState(false)
  const [proveMethod, setProveMethod] = useState<ProveMethod>('server')
  const [browserProgress, setBrowserProgress] = useState('')
  const proveOnDevice = proveMethod === 'device'
  const [escrowEnabled, setEscrowEnabled] = useState(true)

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
      const partyProofs: PartyProof[] = []
      let sharedContractHash: string | null = null
      const timestamp = new Date().toISOString()

      const { encodeProofChunks, LogicalOpFlag, encodeTermsQr, encodeMetadataQr, encodeEscrowChunks } = await import('../lib/qr-chunking')
      const QRCode = (await import('qrcode')).default
      const proofCount = template.credentials.length + 2 // proofs + terms + metadata

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
            timestamp,
            nullifier_field: req.nullifierField,
            role: req.role,
            ...(forceSkipCache ? { skip_cache: true } : {}),
            ...(escrowEnabled && req.credentialType === 'pid' ? {
              identity_escrow: {
                field_names: ['given_name', 'family_name', 'document_number', 'birth_date', 'resident_city'],
                ecdsa_claim: templatePredicates[0]?.predicate.claim ?? 'given_name',
                authority_pubkey: DEMO_AUTHORITY_PUBKEY,
              }
            } : {}),
          }),
        })
        if (!proveRes.ok) throw new Error(await proveRes.text())
        const proveData = await proveRes.json()
        if (proveData.cached) anyCached = true

        let credEscrowData = null
        if (escrowEnabled && proveData.compound_proof_json) {
          try {
            const compound = JSON.parse(proveData.compound_proof_json)
            credEscrowData = compound.identity_escrow ?? null
          } catch {}
        }

        // Strip escrow data from proof before QR generation (separate storage domain)
        let proofJsonForQr = proveData.compound_proof_json
        if (credEscrowData) {
          try {
            const compound = JSON.parse(proveData.compound_proof_json)
            delete compound.identity_escrow
            proofJsonForQr = JSON.stringify(compound)
          } catch {}
        }

        // Export compound with compression
        const exportRes = await fetch(`${API_URL}/holder/proof-export-compound?compress=true`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ compound_proof_json: proofJsonForQr }),
        })
        if (!exportRes.ok) throw new Error(await exportRes.text())
        const exportData = await exportRes.json()

        // Generate QR codes for this credential's proof
        const compressed = Uint8Array.from(atob(exportData.compressed_cbor_base64), c => c.charCodeAt(0))
        totalCompressedSize += compressed.length
        const proofId = ci + 1
        const logicalOp = proofCount > 1 ? LogicalOpFlag.And : LogicalOpFlag.Single
        const chunks = encodeProofChunks(compressed, proofId, ci, proofCount, logicalOp)
        const qrStartIndex = allQrDataUrls.length
        for (const chunk of chunks) {
          const url = await QRCode.toDataURL([{ data: chunk, mode: 'byte' as const }], {
            errorCorrectionLevel: 'L',
            margin: 1,
            width: 280,
          })
          allQrDataUrls.push(url)
        }
        const qrUrlsForThisCredential = allQrDataUrls.slice(qrStartIndex)

        // Build predicate descriptions
        const predicateDescriptions = templatePredicates.map(p => t(p.labelKey))

        // Update credential data with proof info
        updatedCredentials[ci] = {
          ...cred,
          compoundProofJson: proveData.compound_proof_json,
          compoundOp: proveData.op,
          hiddenFields: proveData.hidden_fields,
          predicateDescriptions,
          qrDataUrls: qrUrlsForThisCredential,
          escrowData: credEscrowData,
        }

        // Store per-party nullifier data
        if (req.nullifierField && proveData.nullifier) {
          if (!sharedContractHash) {
            sharedContractHash = proveData.contract_hash
          }
          partyProofs.push({
            role: req.role,
            roleLabelKey: req.roleLabelKey,
            nullifier: proveData.nullifier,
            salt: proveData.salt,
            issuer: config ? resolveVariant(config, locale === 'uk' ? 'uk' : 'en').issuer : '',
            qrDataUrls: qrUrlsForThisCredential,
          })
        }
      }

      // Generate terms QR (page 1)
      const selectedTemplateForTerms = CONTRACT_TEMPLATES.find(tpl => tpl.id === state.templateId)
      const termsString = JSON.stringify(selectedTemplateForTerms)
      const termsQrChunk = await encodeTermsQr(termsString, timestamp, proofCount)
      const termsQrUrl = await QRCode.toDataURL([{ data: termsQrChunk, mode: 'byte' as const }], {
        errorCorrectionLevel: 'L',
        margin: 1,
        width: 280,
      })

      // Generate metadata QR (page 2 shared section)
      if (!sharedContractHash) throw new Error('No contract hash — template must have at least one nullifierField credential')
      const metadataQrChunk = await encodeMetadataQr(
        sharedContractHash,
        partyProofs.map(p => ({ role: p.role, nullifier: p.nullifier, salt: p.salt })),
        proofCount,
      )
      const metadataQrUrl = await QRCode.toDataURL([{ data: metadataQrChunk, mode: 'byte' as const }], {
        errorCorrectionLevel: 'L',
        margin: 1,
        width: 280,
      })

      // Generate escrow QRs per party — binary-chunked protocol (0xFFF0+ range)
      const escrowQrUrls: { role: string; roleLabelKey: string; urls: string[]; escrowIndex: number; escrowCount: number }[] = []

      // Count credentials with escrow
      const escrowCredentialIndices: number[] = []
      for (let ci = 0; ci < updatedCredentials.length; ci++) {
        if (updatedCredentials[ci].escrowData) escrowCredentialIndices.push(ci)
      }
      const escrowCount = escrowCredentialIndices.length

      if (escrowCount > 0) {
        const ek = await deriveEncapsulationKey(DEMO_AUTHORITY_PUBKEY)

        for (let ei = 0; ei < escrowCredentialIndices.length; ei++) {
          const ci = escrowCredentialIndices[ei]
          const cred = updatedCredentials[ci]
          const req = template.credentials[ci]
          if (!cred.escrowData || !req) continue

          try {
            const envelope: EscrowEnvelopeQr = {
              encrypted_key: cred.escrowData.encrypted_key,
              credential_hash: cred.escrowData.credential_hash,
              key_commitment: cred.escrowData.key_commitment,
              ciphertext: cred.escrowData.ciphertext,
              field_names: cred.escrowData.field_names,
              authority_pubkey: Array.from(ek),
              authority_name: DEMO_AUTHORITY_NAME,
            }

            const chunks = await encodeEscrowChunks(envelope, ci, escrowCount)
            const urls: string[] = []
            for (const chunk of chunks) {
              const url = await QRCode.toDataURL([{ data: chunk, mode: 'byte' as const }], {
                errorCorrectionLevel: 'L',
                margin: 1,
                width: 280,
              })
              urls.push(url)
            }
            escrowQrUrls.push({ role: req.role, roleLabelKey: req.roleLabelKey, urls, escrowIndex: ei, escrowCount })
          } catch (e) {
            console.error('Escrow QR generation failed:', e)
          }
        }
      }

      // Build CBOR bundle for download
      const { decode, encode } = await import('cbor-x')
      const proofEnvelopes = []
      for (const cred of updatedCredentials) {
        if (!cred.compoundProofJson) continue
        const expRes = await fetch(`${API_URL}/holder/proof-export-compound?compress=true`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ compound_proof_json: cred.compoundProofJson }),
        })
        if (!expRes.ok) continue
        const expData = await expRes.json()
        const comp = Uint8Array.from(atob(expData.compressed_cbor_base64), c => c.charCodeAt(0))
        const { decompressDeflate } = await import('../lib/qr-chunking')
        const cbor = await decompressDeflate(comp)
        proofEnvelopes.push(decode(cbor))
      }
      const bundle = encode({
        version: 2,
        proof_envelopes: proofEnvelopes,
        terms: { terms: termsString, timestamp },
        metadata: {
          contract_hash: sharedContractHash,
          parties: partyProofs.map(p => ({ role: p.role, nullifier: p.nullifier, salt: p.salt })),
        },
      })
      const bundleCborUrl = `data:application/cbor;base64,${btoa(String.fromCharCode(...new Uint8Array(bundle)))}`

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
          partyProofs,
          contractHash: sharedContractHash,
          termsQrUrl,
          metadataQrUrl,
          bundleCborUrl,
          escrowQrUrls,
        }))
      }, 600)
    } catch (e: unknown) {
      clearInterval(timer)
      setLoading(false)
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const handleProveBrowser = async () => {
    setLoading(true)
    setElapsed(0)
    setError(null)
    setBrowserProgress('Preparing...')
    const timer = setInterval(() => setElapsed(prev => prev + 1), 1000)
    try {
      // Load WASM for credential parsing
      const { default: init, prepare_inputs } = await import('zk-eidas-wasm')
      await init()

      const updatedCredentials = [...state.credentials]
      const allQrDataUrls: string[] = []
      let totalCompressedSize = 0
      const partyProofs: PartyProof[] = []
      let sharedContractHash: string | null = null
      const timestamp = new Date().toISOString()

      const { encodeProofChunks, LogicalOpFlag, encodeTermsQr, encodeMetadataQr } = await import('../lib/qr-chunking')
      const QRCode = (await import('qrcode')).default
      const proofCount = template!.credentials.length + 2

      // Compute contract_hash client-side: SHA256(terms + timestamp) → first 8 bytes as u64
      const selectedTemplate = CONTRACT_TEMPLATES.find(tpl => tpl.id === state.templateId)
      const termsString = JSON.stringify(selectedTemplate)
      const termsHashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(termsString + timestamp))
      const termsHashView = new DataView(termsHashBuf)
      const contractHashU64 = termsHashView.getBigUint64(0)
      const contractHashHex = `0x${contractHashU64.toString(16).padStart(16, '0')}`
      sharedContractHash = contractHashHex

      for (let ci = 0; ci < template!.credentials.length; ci++) {
        setCurrentProvingIndex(ci)
        const req = template!.credentials[ci]
        const cred = updatedCredentials[ci]
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

        // 1. Browser-side ECDSA + predicate proving
        setBrowserProgress(`[${ci + 1}/${template!.credentials.length}] Proving ${t(req.roleLabelKey)} on device...`)
        const result = await proveCompoundInBrowser(
          cred.credential,
          cred.format,
          predicates,
          API_URL,
          t,
          (_stage: string, detail: string) => setBrowserProgress(`[${ci + 1}/${template!.credentials.length}] ${detail}`),
        )

        // 2. Browser-side nullifier proving (if this credential has a nullifier field)
        let nullifierHex: string | null = null
        const salt = crypto.getRandomValues(new BigUint64Array(1))[0]
        const saltHex = `0x${salt.toString(16).padStart(16, '0')}`

        if (req.nullifierField) {
          setBrowserProgress(`[${ci + 1}/${template!.credentials.length}] ${t("prove.generatingProof")} (nullifier)...`)

          // The nullifier circuit needs an ECDSA commitment for the nullifier field,
          // which may differ from the predicate claim. Generate a separate ECDSA proof.
          const nullifierFieldName = req.nullifierField
          const credIdRaw = prepare_inputs(cred.credential, nullifierFieldName)
          const credIdData = JSON.parse(credIdRaw)
          const credentialId = credIdData.claim_value

          // Check if we already have an ECDSA proof for this claim
          let nullifierEcdsa = result.ecdsaProofs.get(nullifierFieldName)
          if (!nullifierEcdsa) {
            // Need a separate ECDSA proof for the nullifier field
            setBrowserProgress(`[${ci + 1}/${template!.credentials.length}] ECDSA (${nullifierFieldName})...`)
            nullifierEcdsa = await proveInBrowser(
              'ecdsa_verify',
              credIdData.ecdsa_inputs,
              API_URL,
              t,
              (_stage: string, detail: string) => setBrowserProgress(`[${ci + 1}/${template!.credentials.length}] Nullifier ECDSA: ${detail}`),
            )
          }

          const commitment = nullifierEcdsa.publicSignals[0]
          const sdArrayHash = nullifierEcdsa.publicSignals[1]
          const msgHashField = nullifierEcdsa.publicSignals[2]

          const nullifierInputs: Record<string, string> = {
            credential_id: credentialId,
            sd_array_hash: sdArrayHash,
            message_hash: msgHashField,
            commitment,
            contract_hash: contractHashU64.toString(),
            salt: salt.toString(),
          }

          const nullifierResult = await proveInBrowser(
            'nullifier',
            nullifierInputs,
            API_URL,
            t,
            (_stage: string, detail: string) => setBrowserProgress(`[${ci + 1}/${template!.credentials.length}] Nullifier: ${detail}`),
          )

          // Nullifier output is publicSignals[0]
          nullifierHex = `0x${BigInt(nullifierResult.publicSignals[0]).toString(16).padStart(64, '0')}`
        }

        // 3. Build compound proof JSON matching server format
        const compoundProof = {
          proofs: result.predicateProofs.map((p, i) => ({
            proof_bytes: Array.from(new TextEncoder().encode(JSON.stringify(p.proof))),
            public_inputs: p.publicSignals.map(s => Array.from(new TextEncoder().encode(s))),
            verification_key: [],
            predicate_op: predicates[i]?.op === 'gte' ? 'Gte' :
              predicates[i]?.op === 'lte' ? 'Lte' :
              predicates[i]?.op === 'eq' ? 'Eq' :
              predicates[i]?.op === 'neq' ? 'Neq' :
              predicates[i]?.op === 'set_member' ? 'SetMember' :
              predicates[i]?.op === 'range' ? 'Range' : 'Gte',
            nullifier: null,
            claim_name: predicates[i]?.claim ?? null,
          })),
          op: 'And',
          ecdsa_proofs: Object.fromEntries(
            [...new Set(predicates.map(p => p.claim))].map(claim => {
              const ecdsaForClaim = result.ecdsaProofs.get(claim) ?? result.ecdsaProof
              return [claim, {
                proof_bytes: Array.from(new TextEncoder().encode(JSON.stringify(ecdsaForClaim.proof))),
                public_inputs: ecdsaForClaim.publicSignals.map(s => Array.from(new TextEncoder().encode(s))),
                verification_key: [],
                predicate_op: 'Ecdsa',
                nullifier: null,
              }]
            })
          ),
        }
        const compoundProofJson = JSON.stringify(compoundProof)

        // 4. Export compound proof for QR codes (sends proof bytes only, NOT credential)
        const exportRes = await fetch(`${API_URL}/holder/proof-export-compound?compress=true`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ compound_proof_json: compoundProofJson }),
        })
        if (!exportRes.ok) throw new Error(await exportRes.text())
        const exportData = await exportRes.json()

        // Generate QR codes
        const compressed = Uint8Array.from(atob(exportData.compressed_cbor_base64), c => c.charCodeAt(0))
        totalCompressedSize += compressed.length
        const proofId = ci + 1
        const logicalOp = proofCount > 1 ? LogicalOpFlag.And : LogicalOpFlag.Single
        const chunks = encodeProofChunks(compressed, proofId, ci, proofCount, logicalOp)
        const qrStartIndex = allQrDataUrls.length
        for (const chunk of chunks) {
          const url = await QRCode.toDataURL([{ data: chunk, mode: 'byte' as const }], {
            errorCorrectionLevel: 'L', margin: 1, width: 280,
          })
          allQrDataUrls.push(url)
        }
        const qrUrlsForThisCredential = allQrDataUrls.slice(qrStartIndex)

        const predicateDescriptions = templatePredicates.map(p => t(p.labelKey))

        updatedCredentials[ci] = {
          ...cred,
          compoundProofJson,
          compoundOp: 'And',
          hiddenFields: predicates.map(p => p.claim),
          predicateDescriptions,
          qrDataUrls: qrUrlsForThisCredential,
        }

        if (req.nullifierField && nullifierHex) {
          partyProofs.push({
            role: req.role,
            roleLabelKey: req.roleLabelKey,
            nullifier: nullifierHex,
            salt: saltHex,
            issuer: config ? resolveVariant(config, locale === 'uk' ? 'uk' : 'en').issuer : '',
            qrDataUrls: qrUrlsForThisCredential,
          })
        }
      }

      // Terms QR
      setBrowserProgress('Generating QR codes...')
      const termsQrChunk = await encodeTermsQr(termsString, timestamp, proofCount)
      const termsQrUrl = await QRCode.toDataURL([{ data: termsQrChunk, mode: 'byte' as const }], {
        errorCorrectionLevel: 'L', margin: 1, width: 280,
      })

      // Metadata QR
      const metadataQrChunk = await encodeMetadataQr(
        sharedContractHash!,
        partyProofs.map(p => ({ role: p.role, nullifier: p.nullifier, salt: p.salt })),
        proofCount,
      )
      const metadataQrUrl = await QRCode.toDataURL([{ data: metadataQrChunk, mode: 'byte' as const }], {
        errorCorrectionLevel: 'L', margin: 1, width: 280,
      })

      // CBOR bundle
      const { decode, encode } = await import('cbor-x')
      const proofEnvelopes = []
      for (const cred of updatedCredentials) {
        if (!cred.compoundProofJson) continue
        const expRes = await fetch(`${API_URL}/holder/proof-export-compound?compress=true`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ compound_proof_json: cred.compoundProofJson }),
        })
        if (!expRes.ok) continue
        const expData = await expRes.json()
        const comp = Uint8Array.from(atob(expData.compressed_cbor_base64), c => c.charCodeAt(0))
        const { decompressDeflate } = await import('../lib/qr-chunking')
        const cbor = await decompressDeflate(comp)
        proofEnvelopes.push(decode(cbor))
      }
      const bundle = encode({
        version: 2,
        proof_envelopes: proofEnvelopes,
        terms: { terms: termsString, timestamp },
        metadata: {
          contract_hash: sharedContractHash,
          parties: partyProofs.map(p => ({ role: p.role, nullifier: p.nullifier, salt: p.salt })),
        },
      })
      const bundleCborUrl = `data:application/cbor;base64,${btoa(String.fromCharCode(...new Uint8Array(bundle)))}`

      // Holder bindings (still server-side — only sends claim hashes, not credentials)
      const bindingResults: BindingResult[] = []
      if (template!.bindings) {
        for (const binding of template!.bindings) {
          setCurrentProvingIndex(-2)
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
      setBrowserProgress('')
      setTimeout(() => {
        setState(prev => ({
          ...prev,
          step: 4,
          credentials: updatedCredentials,
          bindings: bindingResults,
          qrDataUrls: allQrDataUrls,
          compressedSize: totalCompressedSize,
          cached: false,
          partyProofs,
          contractHash: sharedContractHash,
          termsQrUrl,
          metadataQrUrl,
          bundleCborUrl,
        }))
      }, 600)
    } catch (e: unknown) {
      clearInterval(timer)
      setLoading(false)
      setBrowserProgress('')
      setError(`On-device proof failed: ${e instanceof Error ? e.message : String(e)}`)
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

          {/* Identity Escrow — inside proofs section */}
          <EscrowPanel
            availableFields={[]}
            lockedFields={['given_name', 'family_name', 'document_number', 'birth_date', 'resident_city']}
            predicateFields={(() => {
              const pidReq = template.credentials.find(c => c.credentialType === 'pid')
              if (!pidReq) return []
              const config = CREDENTIAL_TYPES.find(ct => ct.id === 'pid')
              return pidReq.predicateIds
                .map(pid => config?.predicates.find(p => p.id === pid)?.predicate.claim)
                .filter((c): c is string => !!c)
            })()}
            onConfigChange={(cfg) => setEscrowEnabled(cfg !== null)}
            defaultEnabled
            hardcodedPubkey={DEMO_AUTHORITY_PUBKEY}
          />
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
              {currentProvingIndex >= 0 && ` (${currentProvingIndex + 1}/${template.credentials.length + (template.bindings?.length || 0)})`}
              {currentProvingIndex === -2 && ` (${template.credentials.length + 1}/${template.credentials.length + (template.bindings?.length || 0)})`}
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
          <span className="text-green-400 font-semibold">{t('sandbox.proofGenerated')}</span>
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

      {/* Browser proving progress */}
      {loading && proveOnDevice && browserProgress && (
        <p className="text-xs text-blue-400 mb-2 animate-pulse">{browserProgress}</p>
      )}

      <button
        onClick={proveOnDevice ? handleProveBrowser : () => handleProve()}
        disabled={loading || proved}
        className="flex items-center justify-center gap-2 w-full bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 disabled:cursor-not-allowed text-white font-semibold py-3 rounded-lg transition-colors"
      >
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        {loading
          ? proveOnDevice
            ? `${t('contracts.generating')} (${elapsed}s)`
            : t('contracts.generating')
          : proveOnDevice
            ? t('sandbox.generateBrowserBtn')
            : t('contracts.generateProof')}
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

            {/* Bilingual body — always both languages */}
            <div className="space-y-3 mb-6">
              <p className="text-sm text-gray-800 leading-relaxed">{t(template.bodyKey_en)}</p>
              <p className="text-sm text-gray-500 italic leading-relaxed">{t(template.bodyKey_uk)}</p>
            </div>

            {/* Terms QR — page 1 (for verifier cross-check) */}
            {state.termsQrUrl && (
              <div className="flex justify-end mb-4">
                <div className="text-center">
                  <img src={state.termsQrUrl} alt="Terms QR" className="w-20 h-20 print:w-[30mm] print:h-[30mm]" />
                  <p className="text-[8px] text-gray-400">{t('verify.termsQr')}</p>
                </div>
              </div>
            )}

            {/* Unified credential blocks — one per role */}
            {(() => {
              let globalQrIndex = 0
              const totalQrs = state.qrDataUrls.length

              return template.credentials.map((req, ci) => {
                const cred = state.credentials[ci]
                if (!cred) return null
                const config = CREDENTIAL_TYPES.find(ct => ct.id === req.credentialType)
                const party = state.partyProofs.find(p => p.role === req.role)
                const isParty = !!req.nullifierField
                const templatePredicates = req.predicateIds
                  .map(pid => config?.predicates.find(p => p.id === pid))
                  .filter((p): p is NonNullable<typeof p> => p !== undefined)

                // Find bindings where this role is roleB (the "bound" credential)
                const roleBindings = template.bindings
                  ?.map((b, bi) => ({ binding: b, result: state.bindings[bi] }))
                  .filter(({ binding }) => binding.roleB === req.role) ?? []

                // QR global numbering
                const credQrs = cred.qrDataUrls
                const qrGlobalStart = globalQrIndex
                globalQrIndex += credQrs.length

                return (
                  <div key={req.role} className="mb-5 border border-gray-300 rounded-lg p-4 print:border-black/30">
                    <p className="text-xs font-semibold text-gray-500 mb-3 uppercase tracking-wider">
                      {t(req.roleLabelKey)}
                    </p>

                    {/* Proved predicates */}
                    <div className="space-y-1 mb-3">
                      {templatePredicates.map(p => (
                        <div key={p.id} className="flex items-center gap-2">
                          <span className="text-green-600 font-bold text-sm print:text-black">&#10003;</span>
                          <span className="text-sm text-gray-800">{t(p.labelKey)}</span>
                        </div>
                      ))}
                    </div>

                    {/* Holder binding (if this role is the bound credential) */}
                    {roleBindings.map(({ binding, result }) => (
                      <div key={binding.labelKey} className="flex items-center gap-2 mb-3">
                        <span className="text-green-600 font-bold text-sm print:text-black">
                          {result?.verified ? '🔗 ✓' : '✗'}
                        </span>
                        <span className="text-sm text-gray-800">{t(binding.labelKey)}</span>
                      </div>
                    ))}

                    {/* Nullifier + salt + issuer (party credentials only) */}
                    {isParty && party && (
                      <div className="space-y-1.5 mb-3 border-t border-gray-200 pt-3">
                        <div>
                          <span className="text-[10px] text-gray-400 font-medium">{t('contracts.nullifier')}</span>
                          <p className="text-xs text-gray-700 font-mono break-all">{party.nullifier}</p>
                        </div>
                        <div>
                          <span className="text-[10px] text-gray-400 font-medium">{t('contracts.salt')}</span>
                          <p className="text-xs text-gray-700 font-mono break-all">{party.salt}</p>
                        </div>
                        <div>
                          <span className="text-[10px] text-gray-400 font-medium">{t('contracts.issuer')}</span>
                          <p className="text-xs text-gray-700 font-mono break-all">{party.issuer}</p>
                        </div>
                      </div>
                    )}

                    {/* QR codes with global numbering */}
                    {credQrs.length > 0 && (
                      <div className="mt-2">
                        <div className="grid grid-cols-3 gap-2 justify-items-center">
                          {credQrs.map((url, qi) => (
                            <div key={qi} className="text-center">
                              <img
                                src={url}
                                alt={`QR ${qrGlobalStart + qi + 1}/${totalQrs}`}
                                className="w-28 h-28 print:w-[50mm] print:h-[50mm]"
                              />
                              <p className="text-[9px] text-gray-400 -mt-0.5">{t('doc.proofLabel')}{qrGlobalStart + qi + 1}/{totalQrs}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Escrow envelope inline with this credential */}
                    {(() => {
                      const escrowParty = state.escrowQrUrls.find(p => p.role === req.role)
                      const ed = state.credentials[ci]?.escrowData
                      if (!escrowParty || !ed) return null
                      return (
                        <div className="mt-3 pt-3 border-t border-gray-200 print:border-black/10">
                          <div className="flex items-center gap-1.5 mb-2">
                            <svg className="w-3.5 h-3.5 text-gray-400 print:text-black/50" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                              <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
                              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                            </svg>
                            <span className="text-[10px] font-semibold text-gray-500 print:text-black/60 uppercase tracking-wider">{t('escrow.qrLabel')}</span>
                          </div>
                          <div className="mb-2 text-[9px] font-mono text-gray-500 print:text-black/60 space-y-0.5">
                            <div><span className="text-gray-400 print:text-black/40">{t('escrow.credentialHash')}:</span> {formatFieldHash(ed.credential_hash)}</div>
                            <div><span className="text-gray-400 print:text-black/40">{t('escrow.keyCommitment')}:</span> {formatFieldHash(ed.key_commitment)}</div>
                          </div>
                          {/* Authority info */}
                          <div className="mb-2 text-[9px] text-gray-500 print:text-black/60">
                            <span className="text-gray-400 print:text-black/40">{t('escrow.authorityLabel')}:</span>{' '}
                            <span className="font-medium">{DEMO_AUTHORITY_NAME}</span>
                          </div>
                          {/* Bordered escrow QRs with E counter */}
                          <div className="flex flex-wrap gap-2">
                            {escrowParty.urls.map((url: string, ei: number) => (
                              <div key={ei} className="text-center">
                                <div className="border-[3px] border-amber-900 p-0.5 rounded print:border-black/60">
                                  <div className="border border-amber-700 rounded print:border-black/30">
                                    <img src={url} alt={`${req.role} Escrow E${ei + 1}`} className="w-24 h-24 print:w-[35mm] print:h-[35mm]" />
                                  </div>
                                </div>
                                <p className="text-[9px] text-gray-400 mt-0.5">
                                  {t('doc.escrowLabel')}{escrowParty.escrowIndex + 1}/{escrowParty.escrowCount} 🔒
                                </p>
                              </div>
                            ))}
                          </div>
                        </div>
                      )
                    })()}
                  </div>
                )
              })
            })()}

            {/* Shared section */}
            {state.contractHash && (
              <div className="mb-5 border border-gray-300 rounded-lg p-4 print:border-black/30">
                <p className="text-xs font-semibold text-gray-500 mb-2 uppercase tracking-wider">{t('contracts.shared')}</p>
                <div className="space-y-1.5">
                  <div>
                    <span className="text-[10px] text-gray-400 font-medium">{t('contracts.contractHash')}</span>
                    <p className="text-xs text-gray-700 font-mono break-all">{state.contractHash}</p>
                  </div>
                  <div>
                    <span className="text-[10px] text-gray-400 font-medium">{t('contracts.date')}</span>
                    <p className="text-xs text-gray-700">{today}</p>
                  </div>
                </div>
                <p className="text-[9px] text-gray-400 mt-2 leading-relaxed italic">{t('contracts.nullifierTooltip')}</p>
                {state.metadataQrUrl && (
                  <div className="flex justify-end mt-2">
                    <div className="text-center">
                      <img src={state.metadataQrUrl} alt="Metadata QR" className="w-20 h-20 print:w-[30mm] print:h-[30mm]" />
                      <p className="text-[8px] text-gray-400">{t('verify.metadataQr')}</p>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Signature lines — one per party */}
            <div className="border-t border-gray-200 pt-4 mt-4 space-y-3">
              {state.partyProofs.length > 0 ? (
                state.partyProofs.map((party) => (
                  <div key={party.role} className="flex justify-between text-xs text-gray-400">
                    <span>{t(party.roleLabelKey)} {t('contracts.signatureLine')}: ____________________________</span>
                    <span>{today}</span>
                  </div>
                ))
              ) : (
                <div className="flex justify-between text-xs text-gray-400">
                  <span>{t('contracts.signatureLine')}: ____________________________</span>
                  <span>{today}</span>
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="text-center text-[9px] text-gray-400 mt-4">
              <span>zk-eidas.com/verify</span>
              <span className="mx-2">·</span>
              <span>
                {state.qrDataUrls.length} {t('doc.proofLabel')} QR
                {state.escrowQrUrls.length > 0 && ` · ${state.escrowQrUrls.reduce((s: number, e: any) => s + e.urls.length, 0)} ${t('doc.escrowLabel')} QR`}
                {' · '}{(state.compressedSize / 1024).toFixed(1)} KB
              </span>
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
        {state.bundleCborUrl && (
          <a
            href={state.bundleCborUrl}
            download={`zk-eidas-contract-${state.templateId}.cbor`}
            className="flex items-center justify-center gap-2 flex-1 py-3 bg-slate-700 hover:bg-slate-600 text-white font-semibold rounded-lg transition-colors"
          >
            <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
            </svg>
            .cbor
          </a>
        )}
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
  const [chainDetails, setChainDetails] = useState<{
    ecdsaResults: Record<string, { valid: boolean; commitment: string }>
    chainValid: boolean | null
    escrowValid: boolean | null
  } | null>(null)
  const autoVerifyRan = useRef(false)
  // Per-party escrow decrypt state: role → { fields, integrityValid }
  const [decryptedByRole, setDecryptedByRole] = useState<Record<string, { fields: Record<string, string>; integrityValid: boolean }>>({})
  const [decryptingRole, setDecryptingRole] = useState<string | null>(null)

  const escrowCredentials = state.credentials
    .map((c, i) => ({ cred: c, req: template?.credentials[i] }))
    .filter(({ cred }) => cred.escrowData)

  const handleDecrypt = async (role: string, escrowData: any) => {
    setDecryptingRole(role)
    try {
      const { decryptEscrow } = await import('../lib/escrow-decrypt')
      const result = await decryptEscrow(
        escrowData.encrypted_key,
        DEMO_AUTHORITY_PRIVKEY,
        escrowData.ciphertext,
        escrowData.field_names,
        escrowData.credential_hash,
      )
      setDecryptedByRole(prev => ({ ...prev, [role]: result }))
    } catch (e: any) {
      alert(`Decrypt failed: ${e.message}`)
    } finally {
      setDecryptingRole(null)
    }
  }

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

        const mergedEcdsa: Record<string, { valid: boolean; commitment: string }> = {}
        let mergedChainValid: boolean | null = null
        let mergedEscrowValid: boolean | null = null

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

          // Merge ECDSA results
          for (const [claim, res] of Object.entries(chainResult.ecdsaResults)) {
            mergedEcdsa[`${req.role}:${claim}`] = res
          }
          if (chainResult.chainValid !== null) {
            mergedChainValid = mergedChainValid === null ? chainResult.chainValid : (mergedChainValid && chainResult.chainValid)
          }
          if (chainResult.escrowValid !== undefined && chainResult.escrowValid !== null) {
            mergedEscrowValid = mergedEscrowValid === null ? chainResult.escrowValid : (mergedEscrowValid && chainResult.escrowValid)
          }
        }

        const valid = subResults.every(r => r.valid)
        setResults(subResults)
        setAllValid(valid)
        setChainDetails({ ecdsaResults: mergedEcdsa, chainValid: mergedChainValid, escrowValid: mergedEscrowValid })
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

          {/* ECDSA Signature Verification */}
          {chainDetails && Object.keys(chainDetails.ecdsaResults).length > 0 && (
            <div className="bg-slate-800 rounded-lg border border-blue-700/30 overflow-hidden">
              <div className="bg-blue-900/30 px-6 py-3">
                <h3 className="text-sm font-semibold text-blue-300">{t('contracts.ecdsaVerification')}</h3>
              </div>
              <div className="divide-y divide-slate-700">
                {Object.entries(chainDetails.ecdsaResults).map(([claim, res]) => (
                  <div key={claim} className="flex items-center justify-between px-5 py-3">
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-slate-300">{claim.split(':')[1] || claim}</span>
                      <span className="text-[10px] font-mono text-slate-600">{claim.split(':')[0]}</span>
                    </div>
                    {res.valid ? (
                      <span className="text-blue-400 text-xs font-semibold flex items-center gap-1">
                        <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                        OK
                      </span>
                    ) : (
                      <span className="text-red-400 text-xs font-semibold">FAIL</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Commitment Chain */}
          {chainDetails && chainDetails.chainValid !== null && (
            <div className={`flex items-center gap-3 rounded-lg px-5 py-3 border ${
              chainDetails.chainValid
                ? 'bg-blue-950/20 border-blue-700/30 text-blue-300'
                : 'bg-red-950/30 border-red-700/40 text-red-300'
            }`}>
              <svg className="w-5 h-5 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
                <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
              </svg>
              <div className="flex-1">
                <p className="text-sm font-semibold">
                  {chainDetails.chainValid ? t('contracts.chainValid') : t('contracts.chainBroken')}
                </p>
                <p className="text-xs opacity-70">
                  {t('contracts.chainDesc')}
                </p>
              </div>
              {chainDetails.chainValid ? (
                <svg className="w-5 h-5 text-blue-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
              ) : (
                <svg className="w-5 h-5 text-red-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
              )}
            </div>
          )}

          {/* Escrow Proof Verification + Integrity */}
          {chainDetails && chainDetails.escrowValid !== null && (
            <div className={`rounded-lg border overflow-hidden ${
              chainDetails.escrowValid
                ? 'bg-amber-950/20 border-amber-700/30'
                : 'bg-red-950/30 border-red-700/40'
            }`}>
              <div className={`flex items-center gap-3 px-5 py-3 ${chainDetails.escrowValid ? 'text-amber-300' : 'text-red-300'}`}>
                <svg className="w-5 h-5 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
                  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
                <div className="flex-1">
                  <p className="text-sm font-semibold">
                    {chainDetails.escrowValid ? t('contracts.escrowProofValid') : t('contracts.escrowProofFail')}
                  </p>
                  <p className="text-xs opacity-70">{t('contracts.escrowProofDesc')}</p>
                </div>
                {chainDetails.escrowValid ? (
                  <svg className="w-5 h-5 text-amber-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                ) : (
                  <svg className="w-5 h-5 text-red-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                )}
              </div>
              {chainDetails.escrowValid && (
                <div className="flex items-center gap-2 px-5 py-2 border-t border-amber-700/20 text-xs text-green-400">
                  <svg className="w-3.5 h-3.5 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                  <span className="font-semibold">{t('contracts.integrityValid')}</span>
                </div>
              )}
            </div>
          )}

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

          {/* Escrow Decrypt — per party */}
          {escrowCredentials.map(({ cred, req }) => (
            <div key={req!.role} className="bg-slate-800 rounded-lg border border-amber-500/30 p-5 mt-4">
              <h4 className="text-sm font-semibold text-amber-400 mb-3">
                {t('escrow.envelopeTitle')} — {t(req!.roleLabelKey)}
              </h4>

              {!decryptedByRole[req!.role] ? (
                <button
                  onClick={() => handleDecrypt(req!.role, cred.escrowData)}
                  disabled={decryptingRole === req!.role}
                  className="w-full bg-amber-600 hover:bg-amber-700 disabled:bg-slate-600 text-white text-sm font-semibold py-2 rounded-lg transition-colors"
                >
                  {decryptingRole === req!.role ? t('escrow.decrypting') : t('escrow.decryptBtn')}
                </button>
              ) : (
                <div className="bg-amber-500/5 border border-amber-500/20 rounded-lg p-4">
                  <p className="text-xs text-amber-400 font-semibold mb-2">{t('escrow.decryptedTitle')}</p>
                  <div className="space-y-1">
                    {Object.entries(decryptedByRole[req!.role].fields).map(([name, value]) => (
                      <div key={name} className="flex justify-between text-xs">
                        <span className="text-slate-400">{name}</span>
                        <span className="font-mono text-amber-300">{String(value)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
