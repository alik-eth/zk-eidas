export const ARBITRUM_SEPOLIA_CHAIN_ID = 421614

// Local Anvil deployment (DeployLocal.s.sol)
export const MOCK_ARBITRATOR_ADDRESS = '0x5FbDB2315678afecb367f032d93F642f64180aa3' as const
export const ESCROW_ARBITRABLE_ADDRESS = '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512' as const

export const MOCK_ARBITRATOR_ABI = [
  {
    type: 'function',
    name: 'rule',
    inputs: [
      { name: 'arbitrable', type: 'address' },
      { name: 'disputeId', type: 'uint256' },
      { name: 'ruling', type: 'uint256' },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'COST',
    inputs: [],
    outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'view',
  },
] as const

export const ESCROW_ARBITRABLE_ABI = [
  {
    type: 'function',
    name: 'registerEscrow',
    inputs: [
      { name: 'proofHash', type: 'bytes32' },
      { name: 'escrowDigest', type: 'bytes32' },
      { name: 'litCipherRef', type: 'string' },
    ],
    outputs: [{ name: 'escrowId', type: 'uint256' }],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'createDispute',
    inputs: [{ name: 'escrowId', type: 'uint256' }],
    outputs: [],
    stateMutability: 'payable',
  },
  {
    type: 'function',
    name: 'canDecrypt',
    inputs: [
      { name: 'caller', type: 'address' },
      { name: 'escrowId', type: 'uint256' },
    ],
    outputs: [{ name: '', type: 'bool' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'escrows',
    inputs: [{ name: '', type: 'uint256' }],
    outputs: [
      { name: 'creator', type: 'address' },
      { name: 'disputant', type: 'address' },
      { name: 'proofHash', type: 'bytes32' },
      { name: 'escrowDigest', type: 'bytes32' },
      { name: 'disputeId', type: 'uint256' },
      { name: 'ruling', type: 'uint256' },
      { name: 'status', type: 'uint8' },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'arbitrationCost',
    inputs: [],
    outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'getLitCipherRef',
    inputs: [{ name: 'escrowId', type: 'uint256' }],
    outputs: [{ name: '', type: 'string' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'escrowCount',
    inputs: [],
    outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'updateLitCipherRef',
    inputs: [
      { name: 'escrowId', type: 'uint256' },
      { name: 'litCipherRef', type: 'string' },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'event',
    name: 'EscrowRegistered',
    inputs: [
      { name: 'escrowId', type: 'uint256', indexed: true },
      { name: 'creator', type: 'address', indexed: true },
    ],
  },
] as const

export const ESCROW_ARBITRABLE_ACC = (escrowId: string) => [{
  conditionType: 'evmContract' as const,
  contractAddress: ESCROW_ARBITRABLE_ADDRESS,
  functionName: 'canDecrypt',
  functionParams: [':userAddress', escrowId],
  functionAbi: {
    name: 'canDecrypt',
    inputs: [
      { name: 'caller', type: 'address' },
      { name: 'escrowId', type: 'uint256' },
    ],
    outputs: [{ name: '', type: 'bool' }],
    stateMutability: 'view',
    type: 'function',
  },
  chain: 'arbitrumSepolia',
  returnValueTest: { comparator: '=', value: 'true' },
}]
