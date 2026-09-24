require("@nomicfoundation/hardhat-toolbox");

const sepoliaRpcUrl = process.env.ARBITRUM_SEPOLIA_RPC_URL;
const sepoliaPrivateKey = process.env.ARBITRUM_SEPOLIA_PRIVATE_KEY;

module.exports = {
  solidity: {
    version: "0.8.28",
    settings: {
      optimizer: { enabled: true, runs: 200 },
      viaIR: true,
    },
  },
  networks: sepoliaRpcUrl && sepoliaPrivateKey ? {
    arbitrumSepolia: {
      url: sepoliaRpcUrl,
      accounts: [sepoliaPrivateKey],
      chainId: 421614,
    },
  } : {},
};
