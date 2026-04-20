import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { useAccount, useReadContract } from 'wagmi'
import { StepCard } from '../components/StepCard'
import { ESCROW_ARBITRABLE_ADDRESS, ESCROW_ARBITRABLE_ABI } from '../lib/contracts'
import { getLitClient, decryptEscrowFromLit, getSessionSigs } from '../lib/lit'

export const Route = createFileRoute('/resolve')({
  component: ResolvePage,
})

const RULING_LABELS = ['Refused', 'Keep Sealed', 'Reveal Identity'] as const

function ResolvePage() {
  const { address, isConnected } = useAccount()
  const [escrowIdInput, setEscrowIdInput] = useState('')
  const [escrowId, setEscrowId] = useState<string | null>(null)
  const [decrypting, setDecrypting] = useState(false)
  const [decryptError, setDecryptError] = useState('')
  const [decryptedData, setDecryptedData] = useState<Record<string, unknown> | null>(null)

  // Read escrow data
  const { data: escrowData, isError: escrowError, isLoading: escrowLoading } = useReadContract({
    address: ESCROW_ARBITRABLE_ADDRESS,
    abi: ESCROW_ARBITRABLE_ABI,
    functionName: 'escrows',
    args: escrowId !== null ? [BigInt(escrowId)] : undefined,
    query: { enabled: escrowId !== null },
  })

  // Check if connected wallet can decrypt
  const { data: canDecryptResult } = useReadContract({
    address: ESCROW_ARBITRABLE_ADDRESS,
    abi: ESCROW_ARBITRABLE_ABI,
    functionName: 'canDecrypt',
    args: address && escrowId !== null ? [address, BigInt(escrowId)] : undefined,
    query: { enabled: !!address && escrowId !== null },
  })

  // Read Lit cipher reference
  const { data: litCipherRef } = useReadContract({
    address: ESCROW_ARBITRABLE_ADDRESS,
    abi: ESCROW_ARBITRABLE_ABI,
    functionName: 'getLitCipherRef',
    args: escrowId !== null ? [BigInt(escrowId)] : undefined,
    query: { enabled: escrowId !== null },
  })

  function handleLookup() {
    const id = escrowIdInput.trim()
    if (id && !isNaN(Number(id))) {
      setEscrowId(id)
      setDecryptedData(null)
      setDecryptError('')
    }
  }

  async function handleDecrypt() {
    if (!escrowId || !litCipherRef) return
    setDecrypting(true)
    setDecryptError('')
    setDecryptedData(null)
    try {
      // Parse the litCipherRef JSON stored on-chain
      const { ciphertext, dataToEncryptHash } = JSON.parse(litCipherRef as string)

      // Get Lit session sigs (triggers wallet signature)
      const litClient = await getLitClient()
      const sessionSigs = await getSessionSigs(litClient)

      // Decrypt from Lit
      const envelope = await decryptEscrowFromLit(
        ciphertext,
        dataToEncryptHash,
        escrowId,
        sessionSigs,
      )
      setDecryptedData(envelope as Record<string, unknown>)
    } catch (e: any) {
      setDecryptError(e.message || 'Decryption failed')
    } finally {
      setDecrypting(false)
    }
  }

  // Destructure escrow tuple
  const ruling = escrowData?.[5] as bigint | undefined
  const status = escrowData?.[6] as number | undefined

  const rulingLabel = ruling !== undefined ? RULING_LABELS[Number(ruling)] ?? `Unknown (${ruling})` : null
  const hasEscrow = escrowData !== undefined && !escrowError
  const accessGranted = canDecryptResult === true

  // Extract field names from decrypted envelope
  const envelopeEscrow = decryptedData?.identity_escrow as Record<string, unknown> | undefined
  const fieldNames = envelopeEscrow?.field_names as string[] | undefined

  const step1Status = escrowLoading
    ? 'active'
    : hasEscrow
      ? 'complete'
      : escrowError
        ? 'error'
        : 'active'

  const step2Status = !hasEscrow || !accessGranted
    ? 'pending'
    : decryptedData
      ? 'complete'
      : decryptError
        ? 'error'
        : decrypting
          ? 'active'
          : 'active'

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-8 py-12">
      <h2 className="text-2xl font-bold mb-2">Resolve Escrow</h2>
      <p className="text-slate-400 text-sm mb-8">
        Check the Kleros ruling and decrypt the escrowed identity if access is granted.
      </p>

      <div className="space-y-6">
        {/* Step 1: Check Ruling */}
        <StepCard
          step={1}
          title="Check Ruling"
          description="Enter the escrow ID to see the ruling and your access status."
          status={step1Status}
        >
          <div className="flex gap-3">
            <input
              type="number"
              min="0"
              value={escrowIdInput}
              onChange={(e) => setEscrowIdInput(e.target.value)}
              placeholder="Escrow ID"
              className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-300 placeholder-slate-600 focus:outline-none focus:border-indigo-500"
            />
            <button
              onClick={handleLookup}
              disabled={!escrowIdInput.trim()}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-700 disabled:text-slate-500 text-white text-sm font-medium rounded-lg transition-colors"
            >
              Check
            </button>
          </div>

          {escrowLoading && (
            <p className="mt-3 text-slate-400 text-sm">Loading...</p>
          )}

          {escrowError && (
            <p className="mt-3 text-red-400 text-sm">Failed to read escrow. Check the ID and try again.</p>
          )}

          {hasEscrow && (
            <div className="mt-4 bg-slate-800/50 border border-slate-700 rounded-lg p-4 space-y-2">
              <div className="flex items-center gap-2">
                <span className="text-slate-500 text-xs w-16">Ruling</span>
                <span className={`text-sm font-semibold ${
                  Number(ruling) === 2
                    ? 'text-red-400'
                    : Number(ruling) === 1
                      ? 'text-emerald-400'
                      : 'text-slate-400'
                }`}>
                  {status === 2 ? rulingLabel : 'Pending (no ruling yet)'}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-500 text-xs w-16">Access</span>
                {!isConnected ? (
                  <span className="text-amber-400 text-sm">Connect wallet to check</span>
                ) : (
                  <span className={`text-sm font-semibold ${accessGranted ? 'text-emerald-400' : 'text-red-400'}`}>
                    {accessGranted ? 'Granted' : 'Denied'}
                  </span>
                )}
              </div>
            </div>
          )}
        </StepCard>

        {/* Step 2: Decrypt Identity */}
        <StepCard
          step={2}
          title="Decrypt Identity"
          description="Retrieve the Lit-encrypted escrow envelope. Requires access granted by the ruling."
          status={step2Status}
        >
          {!hasEscrow && (
            <p className="text-slate-500 text-sm">Look up an escrow first.</p>
          )}

          {hasEscrow && !isConnected && (
            <p className="text-amber-400 text-sm">Connect your wallet to decrypt.</p>
          )}

          {hasEscrow && isConnected && !accessGranted && (
            <p className="text-red-400 text-sm">
              Your wallet does not have decryption access for this escrow.
            </p>
          )}

          {hasEscrow && isConnected && accessGranted && (
            <>
              <button
                onClick={handleDecrypt}
                disabled={decrypting}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-700 disabled:text-slate-500 text-white text-sm font-medium rounded-lg transition-colors"
              >
                {decrypting ? 'Decrypting...' : 'Decrypt from Lit'}
              </button>
            </>
          )}

          {decryptError && (
            <div className="mt-4 bg-slate-800/50 border border-red-800 rounded-lg p-4">
              <p className="text-red-400 text-sm font-medium mb-1">Decryption failed</p>
              <p className="text-slate-400 text-xs">{decryptError}</p>
            </div>
          )}

          {decryptedData && (
            <div className="mt-4 bg-slate-800/50 border border-emerald-800 rounded-lg p-4">
              <p className="text-emerald-400 text-sm font-medium mb-3">Lit decryption successful</p>

              {fieldNames && fieldNames.length > 0 && (
                <div className="mb-3">
                  <p className="text-slate-400 text-xs mb-1">Encrypted field names:</p>
                  <div className="flex flex-wrap gap-1">
                    {fieldNames.map((name, i) => (
                      <span key={i} className="inline-block bg-slate-700 text-slate-300 px-1.5 py-0.5 rounded text-xs">
                        {name}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div className="bg-slate-900 rounded p-3 overflow-x-auto">
                <pre className="text-xs text-slate-300 font-mono whitespace-pre-wrap">
                  {JSON.stringify(decryptedData, null, 2)}
                </pre>
              </div>

              <p className="mt-3 text-slate-500 text-xs">
                Note: The inner field values are encrypted with ML-KEM-768 (post-quantum). Full decryption requires the escrow authority's secret key.
              </p>
            </div>
          )}
        </StepCard>
      </div>
    </div>
  )
}
