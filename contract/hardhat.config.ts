import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
require("dotenv").config();

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 999999,
      },
    },
  },
  networks: {
    sepolia: {
      url:
        `https://eth-sepolia.g.alchemy.com/v2/${process.env.SEPOLIA_ALCHEMY_API_KEY}`,
      accounts: [process.env.SEPOLIA_PRIVATE_KEY!],
    },
    arbitrumSepolia: {
      url:
        `https://arb-sepolia.g.alchemy.com/v2/${process.env.ARBITRUM_SEPOLIA_ALCHEMY_API_KEY}`,
      accounts: [process.env.SEPOLIA_PRIVATE_KEY!],
    },
    arbitrumOne: {
      url:
        `https://arbitrum-mainnet.infura.io/v3/${process.env.ARBITRUM_INFURA_API_KEY}`,
      accounts: [process.env.ETHEREUM_PRIVATE_KEY!],
    },
  },
};

export default config;
