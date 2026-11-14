// Recompute the backend sealed-board hash of the Sepolia run from the retained chain snapshot, using the
// frozen (pre-release) board library, and compare it with the value recorded in the run manifest.
// Requires ethers 6.13.0:  npm install ethers@6.13.0   (or set NODE_PATH to an existing ethers install).
// Usage (package root):  node tools/verify_board_hash.js
const fs = require("fs"), path = require("path");
const root = path.resolve(__dirname, "..");
const run = path.join(root, "runs", "q5_sepolia_n8_20260923_02");
const snapshot = JSON.parse(fs.readFileSync(path.join(run, "chain_snapshot.json"), "utf8"));
const manifest = JSON.parse(fs.readFileSync(path.join(run, "manifest.json"), "utf8"));
const lib = require(path.join(root, "frozen_source_q5", "07_implementation", "arbitrum", "route009", "lib", "sealed_board.js"));
const board = lib.fromChainSnapshot(snapshot);
const ok = board.sealedBoardHash.toLowerCase() === manifest.sealedBoardHash.toLowerCase();
console.log("recomputed sealedBoardHash:", board.sealedBoardHash);
console.log("recorded   sealedBoardHash:", manifest.sealedBoardHash);
console.log("on-chain accepted-ballot commitment (input to the hash):", snapshot.ballotSetCommitment);
console.log(ok ? "MATCH" : "MISMATCH");
process.exit(ok ? 0 : 1);
