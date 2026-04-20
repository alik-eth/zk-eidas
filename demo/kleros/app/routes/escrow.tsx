import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { useAccount, useReadContract, useWriteContract, useWaitForTransactionReceipt } from 'wagmi'
import { keccak256, toBytes } from 'viem'
import { StepCard } from '../components/StepCard'
import { ESCROW_ARBITRABLE_ADDRESS, ESCROW_ARBITRABLE_ABI } from '../lib/contracts'
import { encryptEscrowToLit } from '../lib/lit'

export const Route = createFileRoute('/escrow')({
  component: EscrowPage,
})

interface ParsedProof {
  identityEscrow: {
    encrypted_key: number[]
    ciphertexts: number[][]
    tags: number[][]
    field_names: string[]
  }
  escrowDigest: string
  raw: string
}

function EscrowPage() {
  const { address, isConnected } = useAccount()
  const [proofJson, setProofJson] = useState('')
  const [parsed, setParsed] = useState<ParsedProof | null>(null)
  const [parseError, setParseError] = useState('')
  const [encrypting, setEncrypting] = useState(false)
  const [encryptError, setEncryptError] = useState('')
  const [registeredId, setRegisteredId] = useState<string | null>(null)

  // Read escrowCount to predict next ID
  const { data: escrowCount } = useReadContract({
    address: ESCROW_ARBITRABLE_ADDRESS,
    abi: ESCROW_ARBITRABLE_ABI,
    functionName: 'escrowCount',
  })

  const { writeContract, data: txHash, isPending: isWriting } = useWriteContract()
  const { isLoading: isConfirming, isSuccess: isConfirmed } = useWaitForTransactionReceipt({
    hash: txHash,
  })

  function handleParse() {
    setParseError('')
    setParsed(null)
    try {
      const obj = JSON.parse(proofJson)
      if (!obj.identity_escrow) throw new Error('Missing "identity_escrow" field')
      const ie = obj.identity_escrow
      if (!ie.encrypted_key) throw new Error('Missing "identity_escrow.encrypted_key"')
      if (!ie.ciphertexts) throw new Error('Missing "identity_escrow.ciphertexts"')
      if (!ie.tags) throw new Error('Missing "identity_escrow.tags"')
      if (!ie.field_names) throw new Error('Missing "identity_escrow.field_names"')
      if (!obj.escrow_digest) throw new Error('Missing "escrow_digest" field')
      setParsed({
        identityEscrow: ie,
        escrowDigest: obj.escrow_digest,
        raw: proofJson,
      })
    } catch (e: any) {
      setParseError(e.message || 'Invalid JSON')
    }
  }

  async function handleRegister() {
    if (!parsed || !isConnected) return
    setEncryptError('')
    setEncrypting(true)
    try {
      const nextId = (escrowCount ?? BigInt(0)).toString()

      // Encrypt the identity_escrow envelope + escrow_digest to Lit
      const payload = {
        identity_escrow: parsed.identityEscrow,
        escrow_digest: parsed.escrowDigest,
      }
      const { ciphertext, dataToEncryptHash } = await encryptEscrowToLit(payload, nextId)
      const litCipherRef = JSON.stringify({ ciphertext, dataToEncryptHash })

      // Compute proofHash and escrowDigest bytes32
      const proofHash = keccak256(toBytes(parsed.raw))
      const escrowDigest = `0x${parsed.escrowDigest}` as `0x${string}`

      writeContract({
        address: ESCROW_ARBITRABLE_ADDRESS,
        abi: ESCROW_ARBITRABLE_ABI,
        functionName: 'registerEscrow',
        args: [proofHash, escrowDigest, litCipherRef],
      })

      setRegisteredId(nextId)
    } catch (e: any) {
      setEncryptError(e.message || 'Encryption or registration failed')
    } finally {
      setEncrypting(false)
    }
  }

  const step1Status = parsed ? 'complete' : parseError ? 'error' : 'active'
  const step2Status = !parsed
    ? 'pending'
    : isConfirmed
      ? 'complete'
      : encryptError
        ? 'error'
        : encrypting || isWriting || isConfirming
          ? 'active'
          : 'active'

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-8 py-12">
      <h2 className="text-2xl font-bold mb-2">Escrow Identity</h2>
      <p className="text-slate-400 text-sm mb-8">
        Encrypt your ZK proof's identity escrow data to Lit Protocol and register it on-chain.
      </p>

      <div className="space-y-6">
        {/* Step 1: Parse Proof JSON */}
        <StepCard
          step={1}
          title="Parse Proof JSON"
          description="Paste your CompoundProof JSON containing the identity_escrow envelope."
          status={step1Status}
        >
          <textarea
            value={proofJson}
            onChange={(e) => setProofJson(e.target.value)}
            placeholder='{"identity_escrow": {...}, "escrow_digest": "..."}'
            rows={8}
            className="w-full bg-slate-800 border border-slate-700 rounded-lg p-3 text-sm font-mono text-slate-300 placeholder-slate-600 focus:outline-none focus:border-indigo-500 resize-y"
          />
          <button
            onClick={handleParse}
            disabled={!proofJson.trim()}
            className="mt-3 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-700 disabled:text-slate-500 text-white text-sm font-medium rounded-lg transition-colors"
          >
            Parse
          </button>

          {parseError && (
            <p className="mt-3 text-red-400 text-sm">{parseError}</p>
          )}

          {parsed && (
            <div className="mt-4 bg-slate-800/50 border border-slate-700 rounded-lg p-4">
              <p className="text-emerald-400 text-sm font-medium mb-2">Parsed successfully</p>
              <p className="text-slate-400 text-xs mb-1">
                Escrow digest: <code className="text-slate-300">{parsed.escrowDigest.slice(0, 16)}...</code>
              </p>
              <p className="text-slate-400 text-xs">
                Fields: {parsed.identityEscrow.field_names.map((n, i) => (
                  <span key={i} className="inline-block bg-slate-700 text-slate-300 px-1.5 py-0.5 rounded text-xs mr-1 mt-1">{n}</span>
                ))}
              </p>
            </div>
          )}
        </StepCard>

        {/* Step 2: Encrypt & Register */}
        <StepCard
          step={2}
          title="Encrypt & Register"
          description="Encrypt to Lit Protocol and register the escrow on-chain."
          status={step2Status}
        >
          {!isConnected && (
            <p className="text-amber-400 text-sm">Connect your wallet to register an escrow.</p>
          )}

          {isConnected && parsed && (
            <>
              <div className="text-xs text-slate-500 mb-3">
                Connected: <code className="text-slate-400">{address}</code>
                {escrowCount !== undefined && (
                  <span className="ml-3">Next escrow ID: <code className="text-slate-400">{escrowCount.toString()}</code></span>
                )}
              </div>

              <button
                onClick={handleRegister}
                disabled={encrypting || isWriting || isConfirming || isConfirmed}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-700 disabled:text-slate-500 text-white text-sm font-medium rounded-lg transition-colors"
              >
                {encrypting
                  ? 'Encrypting to Lit...'
                  : isWriting
                    ? 'Confirm in wallet...'
                    : isConfirming
                      ? 'Confirming tx...'
                      : isConfirmed
                        ? 'Registered'
                        : 'Encrypt & Register'}
              </button>
            </>
          )}

          {encryptError && (
            <p className="mt-3 text-red-400 text-sm">{encryptError}</p>
          )}

          {isConfirmed && txHash && (
            <div className="mt-4 bg-slate-800/50 border border-emerald-800 rounded-lg p-4">
              <p className="text-emerald-400 text-sm font-medium mb-2">Escrow registered</p>
              <p className="text-slate-400 text-xs mb-1">
                Escrow ID: <code className="text-slate-300">{registeredId}</code>
              </p>
              <p className="text-slate-400 text-xs">
                Tx: <code className="text-slate-300 break-all">{txHash}</code>
              </p>
            </div>
          )}
        </StepCard>
      </div>
    </div>
  )
}
