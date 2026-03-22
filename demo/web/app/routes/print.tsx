import { createFileRoute } from '@tanstack/react-router'
import { useState, useEffect, useRef } from 'react'
import { useT } from '../i18n'
import QRCode from 'qrcode'
import { encodeProofChunks, LogicalOpFlag } from '../lib/qr-chunking'

export const Route = createFileRoute('/print')({
  component: PrintPage,
})

interface PrintProofData {
  predicate: string
  op?: string
  compressedCbor: string // base64
}

interface QRSection {
  predicate: string
  op?: string
  dataUrls: string[]
  chunkCount: number
  compressedSize: number
}

function PrintPage() {
  const t = useT()

  const [qrImages, setQrImages] = useState<QRSection[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [logicalOp, setLogicalOp] = useState<'single' | 'and' | 'or'>('single')
  const [predicates, setPredicates] = useState<{ claim: string; op: string; publicValue: string; disclosed: boolean }[]>([])
  const [credentialLabel, setCredentialLabel] = useState<string | null>(null)
  const initialized = useRef(false)

  useEffect(() => {
    if (initialized.current) return
    initialized.current = true

    const raw = sessionStorage.getItem('zk-eidas-print-data')
    if (!raw) {
      setError('No proof data. Generate a proof first.')
      setLoading(false)
      return
    }

    const data = JSON.parse(raw) as {
      proofs: PrintProofData[]
      logicalOp?: 'single' | 'and' | 'or'
      predicates?: { claim: string; op: string; publicValue: string; disclosed: boolean }[]
      credentialLabel?: string
    }

    if (!data.proofs || data.proofs.length === 0) {
      setError('No proofs to print.')
      setLoading(false)
      return
    }

    setLogicalOp(data.logicalOp ?? 'single')
    setPredicates(data.predicates ?? [])
    setCredentialLabel(data.credentialLabel ?? null)
    generateQRCodes(data.proofs, data.logicalOp ?? 'single')
  }, [])

  async function generateQRCodes(proofs: PrintProofData[], op: 'single' | 'and' | 'or') {
    try {
      const opFlag = op === 'and' ? LogicalOpFlag.And : op === 'or' ? LogicalOpFlag.Or : LogicalOpFlag.Single

      const allSections: QRSection[] = []

      for (let i = 0; i < proofs.length; i++) {
        const proof = proofs[i]
        const compressed = Uint8Array.from(atob(proof.compressedCbor), c => c.charCodeAt(0))
        const proofId = i + 1
        const chunks = encodeProofChunks(compressed, proofId, i, proofs.length, opFlag)

        const dataUrls: string[] = []
        for (const chunk of chunks) {
          const url = await QRCode.toDataURL([{ data: chunk, mode: 'byte' as const }], {
            errorCorrectionLevel: 'L',
            margin: 1,
            width: 280,
          })
          dataUrls.push(url)
        }

        allSections.push({
          predicate: proof.predicate,
          op: proof.op,
          dataUrls,
          chunkCount: chunks.length,
          compressedSize: compressed.length,
        })
      }

      setQrImages(allSections)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }

  const totalQRs = qrImages.reduce((sum, s) => sum + s.dataUrls.length, 0)
  const totalSize = qrImages.reduce((sum, s) => sum + s.compressedSize, 0)

  if (loading) {
    return (
      <div className="min-h-screen bg-white flex items-center justify-center">
        <p className="text-gray-500">{t('print.generating')}</p>
      </div>
    )
  }

  if (error && qrImages.length === 0) {
    return (
      <div className="min-h-screen bg-slate-900 flex flex-col items-center justify-center gap-6 p-8">
        <div className="bg-red-900/30 border border-red-700 rounded-lg px-8 py-6 max-w-md text-center">
          <p className="text-red-300 text-sm">{error}</p>
        </div>
        <button onClick={() => window.history.back()} className="text-sm text-slate-400 hover:text-white transition-colors">
          &larr; {t('nav.demo')}
        </button>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-white text-black print:p-0 print:m-0">
      {/* Screen-only controls */}
      <div className="print:hidden p-4 bg-slate-100 flex items-center justify-between">
        <button onClick={() => window.history.back()} className="text-blue-600 underline text-sm">
          &larr; {t('nav.demo')}
        </button>
        <button onClick={() => window.print()} className="px-4 py-2 bg-blue-600 text-white rounded text-sm font-medium">
          {t('print.printBtn')}
        </button>
      </div>

      {error && (
        <div className="print:hidden flex flex-col items-center justify-center gap-4 p-12">
          <p className="text-slate-400 text-sm">{error}</p>
          <button onClick={() => window.history.back()} className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg transition-colors">
            &larr; {t('nav.demo')}
          </button>
        </div>
      )}

      {/* Print content — compact layout for paper */}
      <div className="max-w-[210mm] mx-auto px-6 py-4 print:px-8 print:py-3">
        {/* Compact header */}
        <div className="border-b border-gray-300 pb-3 mb-4">
          <div className="flex items-baseline justify-between">
            <h1 className="text-lg font-bold">{t('print.title')}</h1>
            <span className="text-xs text-gray-400 font-mono">zk-eidas.com/verify</span>
          </div>

          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-600">
            {logicalOp !== 'single' && (
              <span className="font-semibold text-gray-800">
                {logicalOp === 'and' ? t('print.allMustVerify') : t('print.anyMustVerify')}
              </span>
            )}
            {credentialLabel && <span>{credentialLabel}</span>}
            <span>{totalQRs} {t('print.qrCount')} · {(totalSize / 1024).toFixed(1)} KB</span>
          </div>

          {predicates.length > 0 && (
            <div className="mt-2">
              <span className="text-xs font-medium text-gray-500">{t('print.predicates')}:</span>
              <table className="mt-1 text-xs text-gray-700 w-full">
                <tbody>
                  {predicates.map((p, i) => (
                    <tr key={i} className={`border-b border-gray-100 last:border-0 ${p.disclosed ? 'bg-blue-50' : ''}`}>
                      <td className="py-0.5 pr-2 font-medium">{p.claim}</td>
                      <td className="py-0.5 pr-2 font-mono text-gray-500">{p.op}</td>
                      <td className={`py-0.5 pr-2 ${p.disclosed ? 'font-semibold text-blue-700' : ''}`}>{p.publicValue}</td>
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

        {/* QR codes — tight grid */}
        {qrImages.map((section, si) => (
          <div key={si} className="mb-4">
            {qrImages.length > 1 && (
              <h2 className="text-sm font-semibold mb-2">
                {t('print.proofSection')} {si + 1}/{qrImages.length}: {section.predicate}
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
  )
}
