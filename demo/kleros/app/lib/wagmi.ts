import { http, createConfig } from 'wagmi'
import { arbitrumSepolia } from 'wagmi/chains'
import { defineChain } from 'viem'
import { injected } from 'wagmi/connectors'

export const anvil = defineChain({
  id: 31337,
  name: 'Anvil',
  nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
  rpcUrls: { default: { http: ['http://127.0.0.1:8545'] } },
})

export const LOCAL_MODE = true // Set to false for Arbitrum Sepolia + Lit

const localConfig = createConfig({
  chains: [anvil],
  connectors: [injected()],
  transports: { [anvil.id]: http() },
})

const remoteConfig = createConfig({
  chains: [arbitrumSepolia],
  connectors: [injected()],
  transports: { [arbitrumSepolia.id]: http() },
})

export const config = LOCAL_MODE ? localConfig : remoteConfig
