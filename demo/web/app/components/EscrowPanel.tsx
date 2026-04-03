import { useState, useEffect, useCallback } from 'react'
import { useT } from '../i18n'

export interface EscrowConfig {
  field_names: string[]
  ecdsa_claim: string
  authority_pubkey: string
}

interface EscrowPanelProps {
  availableFields: string[]
  predicateFields?: string[]
  lockedFields?: string[]
  onConfigChange: (config: EscrowConfig | null) => void
  onPrivkeyGenerated?: (privkey: string) => void
  showKeypairGenerator?: boolean
  defaultEnabled?: boolean
  hardcodedPubkey?: string
}

// ML-KEM-768 demo authority seed (64 bytes) — deterministic, derived from SHA-512('zk-eidas-demo-escrow-authority')
// Both encrypt and decrypt use this seed. In production, only the escrow authority holds it.
export const DEMO_AUTHORITY_SEED = '4517acb4dc2fdbedddd75851b056cd05bc775731ed1e905af4ce43e31169fce06fa6a62e52a2603e9d733f62f4265d8ce919d218dd265dd2739e9d8e57c3f5f3'

// Legacy aliases — the backend uses the seed for both roles
export const DEMO_AUTHORITY_PUBKEY = DEMO_AUTHORITY_SEED
export const DEMO_AUTHORITY_PRIVKEY = DEMO_AUTHORITY_SEED

export function EscrowPanel({
  availableFields,
  predicateFields = [],
  lockedFields,
  onConfigChange,
  onPrivkeyGenerated,
  showKeypairGenerator = false,
  defaultEnabled = false,
  hardcodedPubkey,
}: EscrowPanelProps) {
  const t = useT()
  const [enabled, setEnabled] = useState(defaultEnabled)
  const [selectedFields, setSelectedFields] = useState<string[]>([])
  const [pubkey, setPubkey] = useState<string>(hardcodedPubkey ?? '')
  const [privkey, setPrivkey] = useState<string>(hardcodedPubkey ? DEMO_AUTHORITY_PRIVKEY : '')
  const [keypairGenerated, setKeypairGenerated] = useState(false)

  useEffect(() => {
    if (lockedFields) {
      setSelectedFields(lockedFields)
    } else if (enabled && selectedFields.length === 0 && predicateFields.length > 0) {
      setSelectedFields(predicateFields.filter(f => availableFields.includes(f)).slice(0, 8))
    }
  }, [enabled]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (enabled && showKeypairGenerator && !keypairGenerated && !hardcodedPubkey) {
      generateKeypair()
    }
  }, [enabled]) // eslint-disable-line react-hooks/exhaustive-deps

  const generateKeypair = useCallback(async () => {
    const secp = await import('@noble/secp256k1')
    const priv = secp.utils.randomSecretKey()
    const pub = secp.getPublicKey(priv, true)
    const privHex = Array.from(priv).map((b: number) => b.toString(16).padStart(2, '0')).join('')
    const pubHex = Array.from(pub).map((b: number) => b.toString(16).padStart(2, '0')).join('')
    setPubkey(pubHex)
    setPrivkey(privHex)
    setKeypairGenerated(true)
    onPrivkeyGenerated?.(privHex)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const ecdsaClaim = selectedFields.find(f => predicateFields.includes(f)) ?? selectedFields[0] ?? ''

  useEffect(() => {
    if (!enabled || selectedFields.length === 0 || !pubkey || !ecdsaClaim) {
      onConfigChange(null)
      return
    }
    onConfigChange({
      field_names: selectedFields,
      ecdsa_claim: ecdsaClaim,
      authority_pubkey: pubkey,
    })
  }, [enabled, selectedFields, pubkey, ecdsaClaim]) // eslint-disable-line react-hooks/exhaustive-deps

  const toggleField = (field: string) => {
    setSelectedFields(prev => {
      if (prev.includes(field)) return prev.filter(f => f !== field)
      if (prev.length >= 8) return prev
      return [...prev, field]
    })
  }

  return (
    <div className="mt-4 pt-4 border-t border-slate-700">
      <label className="flex items-center gap-3 cursor-pointer mb-3">
        <input
          type="checkbox"
          checked={enabled}
          onChange={e => setEnabled(e.target.checked)}
          className="w-4 h-4 rounded border-slate-500 text-amber-600 focus:ring-amber-500 bg-slate-700"
        />
        <div>
          <span className="text-sm font-medium text-white">{t('escrow.toggle')}</span>
          <p className="text-xs text-slate-500">{t('escrow.toggleDesc')}</p>
        </div>
      </label>

      {enabled && (
        <div className="space-y-3 pl-7">
          {lockedFields ? (
            <div>
              <p className="text-xs text-slate-400 mb-2">{t('escrow.lockedFieldsLabel')}</p>
              <div className="flex flex-wrap gap-1.5">
                {lockedFields.map(f => (
                  <span key={f} className="text-xs bg-amber-500/10 text-amber-400 border border-amber-500/30 rounded px-2 py-0.5">{f}</span>
                ))}
              </div>
            </div>
          ) : (
            <div>
              <p className="text-xs text-slate-400 mb-2">
                {t('escrow.fieldsLabel')} <span className="text-slate-600">({selectedFields.length}/8)</span>
              </p>
              <div className="flex flex-wrap gap-1.5">
                {availableFields.map(f => (
                  <button
                    key={f}
                    onClick={() => toggleField(f)}
                    className={`text-xs rounded px-2 py-0.5 border transition-colors ${
                      selectedFields.includes(f)
                        ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                        : 'bg-slate-800 text-slate-500 border-slate-700 hover:border-slate-600'
                    }`}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </div>
          )}

          {ecdsaClaim && (
            <div className="text-xs text-slate-500">
              {t('escrow.ecdsaBinding')}: <span className="text-amber-400 font-mono">{ecdsaClaim}</span>
            </div>
          )}

          {showKeypairGenerator && keypairGenerated && (
            <div className="bg-slate-900 rounded-lg p-3 border border-amber-500/20 space-y-1.5">
              <p className="text-xs text-amber-400 font-medium">{t('escrow.keypairGenerated')}</p>
              <div className="text-xs text-slate-500">
                <span className="text-slate-400">pubkey:</span>{' '}
                <span className="font-mono text-slate-300 break-all">{pubkey.slice(0, 20)}...{pubkey.slice(-8)}</span>
              </div>
              <div className="text-xs text-slate-500">
                <span className="text-slate-400">privkey:</span>{' '}
                <span className="font-mono text-slate-300 break-all">{privkey.slice(0, 20)}...{privkey.slice(-8)}</span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
