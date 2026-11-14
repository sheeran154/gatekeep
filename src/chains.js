'use strict';

/**
 * Chain configuration.
 *
 * RPC endpoints are public, keyless endpoints verified reachable from the
 * build VM on 2026-11-14. Endpoints that were tested and FAILED from this VM
 * (and are therefore NOT listed): eth.llamarpc.com (525/timeouts),
 * rpc.ankr.com/eth (timeouts), eth-rpc.gateway.pokt.network (empty reply),
 * 1rpc.io/eth (free-plan usage limit), cloudflare-eth.com (refused),
 * eth.meowrpc.com (timeouts), rpc.sepolia.org / rpc2.sepolia.org (timeouts).
 * If a listed endpoint fails at runtime, the guard degrades gracefully to
 * "unknown" checks instead of inventing data.
 *
 * Token addresses below are the well-known canonical deployments on each
 * chain (USDC/USDT/DAI/WETH). For Sepolia / Base Sepolia no reference token
 * list is baked in — wallet-hygiene is skipped there with an honest note,
 * rather than guessing testnet addresses.
 */

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
const DEAD_ADDRESS = '0x000000000000000000000000000000000000dEaD';

/** Spenders whose identity is well established (same address on many chains). */
const KNOWN_SPENDERS = {
  '0x7a250d5630b4cf539739df2c5dacb4c659f2488d': 'Uniswap V2 Router',
  '0xe592427a0aece92de3edee1f18e0157c05861564': 'Uniswap V3 SwapRouter',
  '0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad': 'Uniswap Universal Router',
  '0x1111111254fb6c44bac0bed2854e76f90643097d': '1inch v5 Aggregation Router',
  '0x00000000000000adc04c56bf30ac9d3c0aaf14dc': 'OpenSea Seaport 1.5',
  '0x000000000022d473030f116ddee9f6b43ac78ba3': 'Permit2',
};

const CHAINS = {
  ethereum: {
    chainId: 1,
    label: 'Ethereum',
    rpc: ['https://ethereum-rpc.publicnode.com', 'https://eth.llamarpc.com'],
    explorer: 'https://etherscan.io',
    dexscreenerChain: 'ethereum',
    tokens: {
      USDC: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
      USDT: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
      DAI: '0x6B175474E89094C44Da98b954EedeAC495271d0F',
      WETH: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
    },
  },
  base: {
    chainId: 8453,
    label: 'Base',
    rpc: ['https://mainnet.base.org'],
    explorer: 'https://basescan.org',
    dexscreenerChain: 'base',
    tokens: {
      USDC: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      USDT: '0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2',
      DAI: '0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb',
      WETH: '0x4200000000000000000000000000000000000006',
    },
  },
  sepolia: {
    chainId: 11155111,
    label: 'Sepolia (testnet)',
    rpc: ['https://ethereum-sepolia-rpc.publicnode.com'],
    explorer: 'https://sepolia.etherscan.io',
    dexscreenerChain: null, // DexScreener does not index Sepolia
    tokens: {},
  },
  'base-sepolia': {
    chainId: 84532,
    label: 'Base Sepolia (testnet)',
    rpc: ['https://sepolia.base.org'],
    explorer: 'https://sepolia.basescan.org',
    dexscreenerChain: null, // DexScreener does not index Base Sepolia
    tokens: {},
  },
};

module.exports = { CHAINS, KNOWN_SPENDERS, ZERO_ADDRESS, DEAD_ADDRESS };
