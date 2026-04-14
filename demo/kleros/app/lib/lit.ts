import { LOCAL_MODE } from './wagmi'

// --- Local mode: no Lit, just base64 encode/decode ---

function localEncrypt(data: string): { ciphertext: string; dataToEncryptHash: string } {
  const ciphertext = btoa(data)
  const dataToEncryptHash = ciphertext.slice(0, 16) // fake hash for local
  return { ciphertext, dataToEncryptHash }
}

function localDecrypt(ciphertext: string): string {
  return atob(ciphertext)
}

// --- Lit Protocol mode ---

let client: any = null

async function getLitClientReal() {
  if (client?.ready) return client
  const { LitNodeClient } = await import('@lit-protocol/lit-node-client')
  const { LitNetwork } = await import('@lit-protocol/constants')
  client = new LitNodeClient({ litNetwork: LitNetwork.DatilTest })
  await client.connect()
  return client
}

// --- Public API (switches on LOCAL_MODE) ---

export async function encryptEscrowToLit(
  escrowPayload: object,
  escrowId: string,
): Promise<{ ciphertext: string; dataToEncryptHash: string }> {
  if (LOCAL_MODE) {
    return localEncrypt(JSON.stringify(escrowPayload))
  }

  const { encryptString } = await import('@lit-protocol/encryption')
  const { ESCROW_ARBITRABLE_ACC } = await import('./contracts')
  const litClient = await getLitClientReal()
  const accessControlConditions = ESCROW_ARBITRABLE_ACC(escrowId)
  const { ciphertext, dataToEncryptHash } = await encryptString(
    { accessControlConditions, dataToEncrypt: JSON.stringify(escrowPayload) },
    litClient,
  )
  return { ciphertext, dataToEncryptHash }
}

export async function decryptEscrowFromLit(
  ciphertext: string,
  _dataToEncryptHash: string,
  escrowId: string,
  sessionSigs: any,
): Promise<object> {
  if (LOCAL_MODE) {
    return JSON.parse(localDecrypt(ciphertext))
  }

  const { decryptToString } = await import('@lit-protocol/encryption')
  const { ESCROW_ARBITRABLE_ACC } = await import('./contracts')
  const litClient = await getLitClientReal()
  const accessControlConditions = ESCROW_ARBITRABLE_ACC(escrowId)
  const decrypted = await decryptToString(
    { accessControlConditions, ciphertext, dataToEncryptHash: _dataToEncryptHash, sessionSigs, chain: 'arbitrumSepolia' },
    litClient,
  )
  return JSON.parse(decrypted)
}

export async function getSessionSigs(_litClient?: any) {
  if (LOCAL_MODE) {
    return {} // not needed locally
  }
  const litClient = _litClient ?? await getLitClientReal()
  return litClient.getSessionSigs({
    chain: 'arbitrumSepolia',
    resourceAbilityRequests: [
      {
        resource: { resource: '*', resourcePrefix: 'lit-accesscontrolcondition' } as any,
        ability: 'access-control-condition-decryption' as any,
      },
    ],
  })
}

export async function getLitClient() {
  if (LOCAL_MODE) return null
  return getLitClientReal()
}
