# MegaPot V2 Contracts

[![Coverage Status](https://coveralls.io/repos/github/coordinationlabs/megapot-v2-contracts/badge.svg?branch=main)](https://coveralls.io/github/coordinationlabs/megapot-v2-contracts?branch=main)

MegaPot V2 is a decentralized jackpot protocol where users purchase NFT-based jackpot tickets and liquidity providers fund prize pools. The system uses Pyth Network entropy for provably fair drawings, automatically distributes winnings based on number matches, and includes cross-chain bridge functionality.

## Prerequisites

- Node.js 20+
- Yarn package manager
- Git

## Installation

```bash
git clone <repository-url>
cd megapot-v2-contracts
yarn install
```

## Environment Setup

Copy the example environment file and configure:

```bash
cp .env.example .env
```

Edit `.env` with your configuration:
- `SEPOLIA_RPC_URL`: RPC endpoint for Sepolia testnet
- `PRIVATE_KEY`: Your private key for deployments (without 0x prefix)
- `ETHERSCAN_API_KEY`: API key for contract verification

## Development Commands

### Compilation

```bash
# Clean and compile contracts
yarn build

# Compile only
yarn compile

# Clean artifacts and cache
yarn clean
```

### Testing

#### Basic Testing

```bash
# Run all tests
yarn test

# Run tests with fresh compilation
yarn test:clean

# Run tests without compilation (faster)
yarn test:fast

# Run deployment tests specifically
yarn test:deploys
```
### Coverage

#### Full Coverage (Memory Intensive)

```bash
# Run coverage on all contracts (requires 4GB+ memory)
yarn coverage
```

#### Parallel Coverage (Recommended)

For better performance and memory management, run coverage on specific test groups:

```bash
# Library tests
yarn hardhat coverage --testfiles "test/lib/*.spec.ts"

# Core jackpot contract
yarn hardhat coverage --testfiles "test/jackpot.spec.ts"

# Ecosystem contracts (LP Manager, Bridge, NFT)
yarn hardhat coverage --testfiles "{test/jackpotBridgeManager.spec.ts,test/jackpotLPManager.spec.ts,test/jackpotTicketNFT.spec.ts}"

# Utility contracts (Payout Calculator, Entropy Provider)
yarn hardhat coverage --testfiles "{test/guaranteedMinimumPayoutCalculator.spec.ts,test/scaledEntropyProvider.spec.ts}"
```

#### Memory Considerations

For large coverage, you will need to increase Node.js memory:

```bash
NODE_OPTIONS="--max-old-space-size=6144" yarn coverage
```

#### Coverage Configuration

Coverage excludes interface and mock contracts (see `.solcover.js`). The configuration includes:
- Yul optimizer enabled for accurate gas reporting
- 2-minute timeout for complex test scenarios
- Optimized compiler settings for coverage runs

### Local Development

```bash
# Start local hardhat node
yarn chain

# In another terminal, deploy to local network
yarn deploy:local
```

### Deployment

```bash
# Deploy to testnet (Base Sepolia)
yarn deploy:testnet

# Deploy to mainnet (Base)
yarn deploy:production

# Generate deployment parameters
yarn generate-params
```

## Project Structure

```
contracts/
├── Jackpot.sol                 # Main jackpot contract
├── JackpotLPManager.sol        # Liquidity provider management
├── JackpotBridgeManager.sol    # Cross-chain bridge functionality
├── JackpotTicketNFT.sol        # Ticket NFT contract
├── GuaranteedMinimumPayoutCalculator.sol  # Prize calculations
├── ScaledEntropyProvider.sol   # Randomness provider
├── interfaces/                 # Contract interfaces
├── lib/                       # Utility libraries
└── mocks/                     # Test mock contracts

test/
├── jackpot.spec.ts            # Main contract tests
├── jackpotLPManager.spec.ts   # LP management tests
├── jackpotBridgeManager.spec.ts # Bridge functionality tests
├── lib/                       # Library tests
└── deploys/                   # Deployment tests

utils/
├── deploys.ts                 # Deployment helpers and scripts
├── protocolUtils.ts           # Utilities for interacting with the protocol
├── constants.ts               # Common constants (addresses, config)
├── contracts.ts               # Contract type imports
├── types.ts                   # Shared TypeScript types for protocol objects
├── common/                    # Utilities for blockchain interaction and units
└── test/                      # Fixtures and other utilities for test setup and tear down

```
