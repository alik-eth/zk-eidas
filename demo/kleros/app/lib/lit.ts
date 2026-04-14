import { LitNodeClient } from '@lit-protocol/lit-node-client'
import { encryptString, decryptToString } from '@lit-protocol/encryption'
import { LitNetwork } from '@lit-protocol/constants'
import { ESCROW_ARBITRABLE_ACC } from './contracts'

let client: LitNodeClient | null = null

export async function getLitClient(): Promise<LitNodeClient> {
  if (client?.ready) return client
  client = new LitNodeClient({ litNetwork: LitNetwork.DatilTest })
  await client.connect()
  return client
}

export async function encryptEscrowToLit(
  escrowPayload: object,
  escrowId: string,
): Promise<{ ciphertext: string; dataToEncryptHash: string }> {
  const litClient = await getLitClient()
  const accessControlConditions = ESCROW_ARBITRABLE_ACC(escrowId)
  const { ciphertext, dataToEncryptHash } = await encryptString(
    {
      accessControlConditions,
      dataToEncrypt: JSON.stringify(escrowPayload),
    },
    litClient,
  )
  return { ciphertext, dataToEncryptHash }
}

export async function decryptEscrowFromLit(
  ciphertext: string,
  dataToEncryptHash: string,
  escrowId: string,
  sessionSigs: any,
): Promise<object> {
  const litClient = await getLitClient()
  const accessControlConditions = ESCROW_ARBITRABLE_ACC(escrowId)
  const decrypted = await decryptToString(
    {
      accessControlConditions,
      ciphertext,
      dataToEncryptHash,
      sessionSigs,
      chain: 'arbitrumSepolia',
    },
    litClient,
  )
  return JSON.parse(decrypted)
}

export async function getSessionSigs(litClient: LitNodeClient) {
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
