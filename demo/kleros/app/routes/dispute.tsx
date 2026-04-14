import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { useAccount, useReadContract, useWriteContract, useWaitForTransactionReceipt } from 'wagmi'
import { formatEther } from 'viem'
import { StepCard } from '../components/StepCard'
import { ESCROW_ARBITRABLE_ADDRESS, ESCROW_ARBITRABLE_ABI } from '../lib/contracts'

export const Route = createFileRoute('/dispute')({
  component: DisputePage,
})

const STATUS_LABELS = ['Created', 'Disputed', 'Resolved'] as const
const RULING_LABELS = ['Refused', 'Keep Sealed', 'Reveal Identity'] as const

function DisputePage() {
  const { isConnected } = useAccount()
  const [escrowIdInput, setEscrowIdInput] = useState('')
  const [escrowId, setEscrowId] = useState<string | null>(null)

  // Look up escrow data
  const { data: escrowData, isError: escrowError, isLoading: escrowLoading } = useReadContract({
    address: ESCROW_ARBITRABLE_ADDRESS,
    abi: ESCROW_ARBITRABLE_ABI,
    functionName: 'escrows',
    args: escrowId !== null ? [BigInt(escrowId)] : undefined,
    query: { enabled: escrowId !== null },
  })

  // Read arbitration cost
  const { data: arbCost } = useReadContract({
    address: ESCROW_ARBITRABLE_ADDRESS,
    abi: ESCROW_ARBITRABLE_ABI,
    functionName: 'arbitrationCost',
    query: { enabled: escrowId !== null },
  })

  const { writeContract, data: txHash, isPending: isWriting } = useWriteContract()
  const { isLoading: isConfirming, isSuccess: isConfirmed } = useWaitForTransactionReceipt({
    hash: txHash,
  })

  function handleLookup() {
    const id = escrowIdInput.trim()
    if (id && !isNaN(Number(id))) {
      setEscrowId(id)
    }
  }

  function handleCreateDispute() {
    if (!escrowId || !arbCost) return
    writeContract({
      address: ESCROW_ARBITRABLE_ADDRESS,
      abi: ESCROW_ARBITRABLE_ABI,
      functionName: 'createDispute',
      args: [BigInt(escrowId)],
      value: arbCost,
    })
  }

  // Destructure escrow tuple
  const creator = escrowData?.[0] as `0x${string}` | undefined
  const escrowDigest = escrowData?.[3] as `0x${string}` | undefined
  const ruling = escrowData?.[5] as bigint | undefined
  const status = escrowData?.[6] as number | undefined

  const statusLabel = status !== undefined ? STATUS_LABELS[status] ?? 'Unknown' : null
  const rulingLabel = ruling !== undefined ? RULING_LABELS[Number(ruling)] ?? `Unknown (${ruling})` : null

  const hasEscrow = escrowData !== undefined && !escrowError
  const isCreated = status === 0

  const step1Status = escrowLoading
    ? 'active'
    : hasEscrow
      ? 'complete'
      : escrowError
        ? 'error'
        : 'active'

  const step2Status = !hasEscrow || !isCreated
    ? 'pending'
    : isConfirmed
      ? 'complete'
      : isWriting || isConfirming
        ? 'active'
        : 'active'

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-8 py-12">
      <h2 className="text-2xl font-bold mb-2">Dispute Escrow</h2>
      <p className="text-slate-400 text-sm mb-8">
        Look up an escrow and file a Kleros dispute to request identity disclosure.
      </p>

      <div className="space-y-6">
        {/* Step 1: Look Up Escrow */}
        <StepCard
          step={1}
          title="Look Up Escrow"
          description="Enter the escrow ID to view its current status."
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
              Look Up
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
                <span className="text-slate-500 text-xs w-16">Status</span>
                <span className={`text-sm font-medium ${
                  status === 0 ? 'text-blue-400' : status === 1 ? 'text-amber-400' : 'text-emerald-400'
                }`}>
                  {statusLabel}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-500 text-xs w-16">Creator</span>
                <code className="text-slate-300 text-xs">{creator}</code>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-500 text-xs w-16">Digest</span>
                <code className="text-slate-300 text-xs break-all">{escrowDigest}</code>
              </div>

              {status === 2 && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 text-xs w-16">Ruling</span>
                  <span className={`text-sm font-medium ${
                    Number(ruling) === 2 ? 'text-red-400' : Number(ruling) === 1 ? 'text-emerald-400' : 'text-slate-400'
                  }`}>
                    {rulingLabel}
                  </span>
                </div>
              )}
            </div>
          )}
        </StepCard>

        {/* Step 2: Create Dispute */}
        <StepCard
          step={2}
          title="Create Dispute"
          description="File a Kleros dispute for this escrow. Requires the arbitration fee."
          status={step2Status}
        >
          {!hasEscrow && (
            <p className="text-slate-500 text-sm">Look up an escrow first.</p>
          )}

          {hasEscrow && !isCreated && (
            <p className="text-amber-400 text-sm">
              This escrow is already {statusLabel?.toLowerCase()}. Disputes can only be filed on "Created" escrows.
            </p>
          )}

          {hasEscrow && isCreated && (
            <>
              {!isConnected && (
                <p className="text-amber-400 text-sm">Connect your wallet to create a dispute.</p>
              )}

              {isConnected && (
                <>
                  {arbCost !== undefined && (
                    <p className="text-slate-400 text-xs mb-3">
                      Arbitration cost: <code className="text-slate-300">{formatEther(arbCost)} ETH</code>
                    </p>
                  )}

                  <button
                    onClick={handleCreateDispute}
                    disabled={isWriting || isConfirming || isConfirmed || !arbCost}
                    className="px-4 py-2 bg-amber-600 hover:bg-amber-500 disabled:bg-slate-700 disabled:text-slate-500 text-white text-sm font-medium rounded-lg transition-colors"
                  >
                    {isWriting
                      ? 'Confirm in wallet...'
                      : isConfirming
                        ? 'Confirming tx...'
                        : isConfirmed
                          ? 'Dispute Filed'
                          : 'Create Dispute'}
                  </button>
                </>
              )}
            </>
          )}

          {isConfirmed && txHash && (
            <div className="mt-4 bg-slate-800/50 border border-amber-800 rounded-lg p-4">
              <p className="text-amber-400 text-sm font-medium mb-2">Dispute created</p>
              <p className="text-slate-400 text-xs mb-2">
                Tx: <code className="text-slate-300 break-all">{txHash}</code>
              </p>
              <a
                href="/resolve"
                className="text-indigo-400 hover:text-indigo-300 text-sm underline"
              >
                Go to Resolve page &rarr;
              </a>
            </div>
          )}
        </StepCard>
      </div>
    </div>
  )
}
