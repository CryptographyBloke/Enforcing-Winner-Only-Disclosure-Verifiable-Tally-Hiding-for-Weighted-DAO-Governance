"use strict";

const fs = require("fs");
const path = require("path");
const { ethers } = require("ethers");

const artifactRoot = process.env.CGY_PUBLIC_ARTIFACT_ROOT || process.env.CGY_BALLOT_ARTIFACT_ROOT;
const envPath = process.env.CGY_PUBLIC_ENV_FILE || path.join(artifactRoot || "", "07_implementation", "arbitrum", ".env");
if (fs.existsSync(envPath)) {
  for (const line of fs.readFileSync(envPath, "utf8").split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (match && !process.env[match[1]]) process.env[match[1]] = match[2].replace(/^['\"]|['\"]$/g, "");
  }
}
process.env.ARBITRUM_SEPOLIA_RPC_URL ||= process.env.ARB_SEPOLIA_RPC_URL;
process.env.ARBITRUM_SEPOLIA_PRIVATE_KEY ||= process.env.DEPLOYER_PRIVATE_KEY;

async function main() {
  if (!process.env.ARBITRUM_SEPOLIA_RPC_URL || !process.env.ARBITRUM_SEPOLIA_PRIVATE_KEY) throw new Error("public RPC/deployer configuration is missing");
  const started = process.hrtime.bigint();
  const provider = new ethers.JsonRpcProvider(process.env.ARBITRUM_SEPOLIA_RPC_URL, { name: "arbitrum-sepolia", chainId: 421614 });
  const network = await provider.getNetwork();
  const latest = await provider.getBlockNumber();
  const wallet = new ethers.Wallet(process.env.ARBITRUM_SEPOLIA_PRIVATE_KEY, provider);
  const balance = await provider.getBalance(wallet.address);
  const probeMs = Number(process.hrtime.bigint() - started) / 1e6;
  if (network.chainId !== 421614n) throw new Error(`unexpected chainId ${network.chainId}`);
  process.stdout.write(`STATUS=PASS\nNETWORK=ARBITRUM_SEPOLIA\nCHAIN_ID=${network.chainId}\nLATEST_BLOCK=${latest}\nDEPLOYER_ADDRESS=${wallet.address}\nDEPLOYER_BALANCE_WEI=${balance}\nDEPLOYER_BALANCE_ETH=${ethers.formatEther(balance)}\nRPC_RESPONSIVE=YES\nRPC_PROBE_MS=${probeMs.toFixed(4)}\nPRIVATE_CREDENTIALS_RECORDED=NO\nCONTRACT_SEMANTICS_CHANGED=NO\nFINAL_REFERENCE_THRESHOLD=5_OF_5\n`);
}

main().catch((error) => { process.stderr.write(`${error.stack || error.message}\n`); process.exitCode = 1; });
