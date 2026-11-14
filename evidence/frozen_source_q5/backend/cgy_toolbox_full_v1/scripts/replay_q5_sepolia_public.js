"use strict";

// Evidence-only public replay. It consumes only public setup, public proofs,
// chain receipts/state, the sealed board, and the retained CGY transcript.
const crypto = require("crypto");
const childProcess = require("child_process");
const fs = require("fs");
const path = require("path");
const repositoryRoot = path.resolve(__dirname, "..", "..", "..");
const { ethers } = require(path.join(repositoryRoot, "backend/cgy_toolbox_full_v1/node_modules/ethers"));
const snarkjs = require(path.join(repositoryRoot, "backend/cgy_toolbox_full_v1/node_modules/snarkjs"));
const { publicSetupFromJson, publicSetupToJson, sourceSessionFromJson, ciphertextFromJson } = require(path.join(repositoryRoot, "backend/cgy_toolbox_full_v1/src/codec"));
const { fromChainSnapshot, serializeSealedBoard } = require(path.join(repositoryRoot, "07_implementation/arbitrum/route009/lib/sealed_board"));
const { admitSealedBoard, assertExactAdmittedInputs } = require(path.join(repositoryRoot, "backend/cgy_toolbox_full_v1/src/accepted_board"));
const { finalReleaseRecordFromJson, verifyFinalRelease } = require(path.join(repositoryRoot, "backend/cgy_toolbox_full_v1/src/final_release"));
const { verifyBroadcastTranscript } = require(path.join(repositoryRoot, "backend/cgy_toolbox_full_v1/src/broadcast_board"));

const root = repositoryRoot;
const runDirectory = path.resolve(process.env.CGY_N8_RUN_DIRECTORY || "");
const artifactRoot = path.resolve(process.env.CGY_BALLOT_ARTIFACT_ROOT || "");
const nativeBinary = process.env.CGY_NATIVE_BIN || path.join(root, "backend/cgy_native/target/release/fc2027-cgy-native.exe");
const EXPECTED_CHAIN_ID = 421614n;

function loadPublicEnv() {
  const envPath = process.env.CGY_PUBLIC_ENV_FILE || path.join(process.env.CGY_PUBLIC_ARTIFACT_ROOT || artifactRoot, "07_implementation", "arbitrum", ".env");
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, "utf8").split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (match && !process.env[match[1]]) process.env[match[1]] = match[2].replace(/^['\"]|['\"]$/g, "");
  }
  process.env.ARBITRUM_SEPOLIA_RPC_URL ||= process.env.ARB_SEPOLIA_RPC_URL;
  process.env.ARBITRUM_SEPOLIA_PRIVATE_KEY ||= process.env.DEPLOYER_PRIVATE_KEY;
}

function readJson(name) { return JSON.parse(fs.readFileSync(path.join(runDirectory, name), "utf8")); }
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function requireCondition(value, message) { if (!value) throw new Error(message); }
function hexBlock(number) { return `0x${BigInt(number).toString(16)}`; }
function wordsFromCiphertexts(ciphertexts) {
  return ciphertexts.flatMap((value) => [value.R.x, value.R.y, value.S.x, value.S.y]);
}
function receiptPublic(receipt) {
  return {
    transactionHash: receipt.hash,
    blockNumber: receipt.blockNumber,
    blockHash: receipt.blockHash,
    transactionIndex: receipt.index,
    gasUsed: receipt.gasUsed.toString(),
    status: receipt.status,
  };
}
function parseAcceptedEvent(iface, receipt) {
  return receipt.logs.map((log) => {
    try { return iface.parseLog(log); } catch (_) { return null; }
  }).find((event) => event && event.name === "BallotAccepted");
}
function contractArtifacts() {
  const pollPath = path.join(artifactRoot, "07_implementation/arbitrum/artifacts/contracts/StrongN8Poll.sol/StrongN8Poll.json");
  const verifierPath = path.join(artifactRoot, "07_implementation/arbitrum/artifacts/contracts/verifier.sol/Groth16Verifier.json");
  return { poll: JSON.parse(fs.readFileSync(pollPath, "utf8")), verifier: JSON.parse(fs.readFileSync(verifierPath, "utf8")) };
}
async function findCreateReceipt(provider, address, startBlock, endBlock) {
  const target = address.toLowerCase();
  // Deployment is issued immediately before the ballot queue in the frozen
  // client. Keep this bounded so a public replay does not scan unrelated RPC
  // history on a free-tier endpoint.
  const begin = Math.max(0, Number(startBlock) - 80);
  const end = Number(endBlock);
  for (let block = begin; block <= end; block += 1) {
    const full = await provider.send("eth_getBlockByNumber", [hexBlock(block), true]);
    if (!full || !Array.isArray(full.transactions)) continue;
    for (const tx of full.transactions) {
      if (tx.to !== null) continue;
      const receipt = await provider.getTransactionReceipt(tx.hash);
      if (receipt && receipt.contractAddress && receipt.contractAddress.toLowerCase() === target) return receipt;
    }
  }
  return null;
}
async function verifyNativeDag({ setup, executionId, tau, bitVectors, entries }) {
  const request = {
    setup: publicSetupToJson(setup),
    executionId,
    tau: Number(tau),
    labelPrefix: "N8",
    bitVectors: bitVectors.map((bits) => bits.map((value) => ({
      R: { x: value.R.x.toString(10), y: value.R.y.toString(10) },
      S: { x: value.S.x.toString(10), y: value.S.y.toString(10) },
    }))),
    gates: entries,
  };
  const child = childProcess.spawnSync(nativeBinary, ["--verify-dag-stdin"], {
    input: `${JSON.stringify(request)}\n`,
    encoding: "utf8",
    maxBuffer: 1024 * 1024 * 1024,
    windowsHide: true,
  });
  requireCondition(!child.error && child.status === 0, `native public DAG verifier failed: ${child.stderr || child.stdout || child.error}`);
  const result = JSON.parse(child.stdout);
  requireCondition(result.gateCount === entries.length && result.gateCount === 134, "native DAG gate count mismatch");
  return result;
}

async function main() {
  loadPublicEnv();
  requireCondition(fs.existsSync(runDirectory), "run directory is missing");
  const started = process.hrtime.bigint();
  const manifest = readJson("manifest.json");
  const setupBytes = fs.readFileSync(path.join(runDirectory, "public_setup.json"));
  const proofsBytes = fs.readFileSync(path.join(runDirectory, "ballot_public_proofs.json"));
  const snapshotBytes = fs.readFileSync(path.join(runDirectory, "chain_snapshot.json"));
  const boardBytes = fs.readFileSync(path.join(runDirectory, "sealed_board.json"));
  const journalBytes = fs.readFileSync(path.join(runDirectory, "gate_transcript.jsonl"));
  const finalBytes = fs.readFileSync(path.join(runDirectory, "final_release.json"));
  requireCondition(sha256(setupBytes) === manifest.publicSetupSha256, "public setup hash mismatch");
  requireCondition(sha256(proofsBytes) === manifest.ballotProofsSha256, "proof manifest hash mismatch");
  requireCondition(sha256(snapshotBytes) === manifest.chainSnapshotSha256, "chain snapshot hash mismatch");
  requireCondition(sha256(boardBytes) === manifest.sealedBoardSha256, "sealed board hash mismatch");
  requireCondition(sha256(journalBytes) === manifest.gateJournalSha256, "CGY journal hash mismatch");
  requireCondition(sha256(finalBytes) === manifest.finalReleaseSha256, "final release hash mismatch");
  const setup = publicSetupFromJson(JSON.parse(setupBytes.toString("utf8")));
  const proofs = JSON.parse(proofsBytes.toString("utf8"));
  const snapshot = JSON.parse(snapshotBytes.toString("utf8"));
  const artifacts = contractArtifacts();
  const vkey = JSON.parse(fs.readFileSync(path.join(artifactRoot, "07_implementation/logs/bit_ballot/groth16/vote_bit_full_8/verification_key.json"), "utf8"));
  const ballotStarted = process.hrtime.bigint();
  for (const proof of proofs) requireCondition(await snarkjs.groth16.verify(vkey, proof.publicSignals, proof.proof), `ballot proof ${proof.index} failed public replay`);
  const ballotProofMs = Number(process.hrtime.bigint() - ballotStarted) / 1e6;

  const provider = new ethers.JsonRpcProvider(process.env.ARBITRUM_SEPOLIA_RPC_URL);
  const network = await provider.getNetwork();
  requireCondition(network.chainId === EXPECTED_CHAIN_ID, "public replay chain id mismatch");
  const poll = new ethers.Contract(snapshot.contract.address, artifacts.poll.abi, provider);
  const verifierCodeHash = ethers.keccak256(await provider.getCode(snapshot.verifier.address));
  const pollCodeHash = ethers.keccak256(await provider.getCode(snapshot.contract.address));
  requireCondition(verifierCodeHash.toLowerCase() === snapshot.verifier.runtimeCodeHash.toLowerCase(), "verifier runtime hash mismatch");
  requireCondition(pollCodeHash.toLowerCase() === snapshot.contract.runtimeCodeHash.toLowerCase(), "poll runtime hash mismatch");

  const chainStarted = process.hrtime.bigint();
  const receipts = [];
  const remoteBallots = [];
  for (let index = 0; index < snapshot.ballots.length; index += 1) {
    const expected = snapshot.ballots[index].provenance;
    const receipt = await provider.getTransactionReceipt(expected.transactionHash);
    requireCondition(receipt && receipt.status === 1, `ballot ${index} receipt unavailable/failed`);
    requireCondition(receipt.blockNumber === expected.blockNumber && receipt.index === expected.transactionIndex && receipt.gasUsed.toString() === expected.gasUsed, `ballot ${index} receipt mismatch`);
    const event = parseAcceptedEvent(poll.interface, receipt);
    requireCondition(event && Number(event.args.ballotIndex) === index, `ballot ${index} acceptance event mismatch`);
    const retained = wordsFromCiphertexts(snapshot.ballots[index].ciphertexts);
    requireCondition(JSON.stringify([...event.args.ciphertext].map(String)) === JSON.stringify(retained), `ballot ${index} accepted coordinates changed`);
    requireCondition(event.args.nullifier.toString() === snapshot.ballots[index].nullifier, `ballot ${index} nullifier mismatch`);
    requireCondition(event.args.ballotLeaf.toLowerCase() === snapshot.ballots[index].leaf.toLowerCase(), `ballot ${index} leaf mismatch`);
    requireCondition(event.args.accumulator.toLowerCase() === snapshot.ballots[index].resultingAccumulator.toLowerCase(), `ballot ${index} accumulator mismatch`);
    const ciphertexts = [];
    const words = [...event.args.ciphertext].map(String);
    for (let bit = 0; bit < 8; bit += 1) ciphertexts.push({
      R: { x: words[4 * bit], y: words[4 * bit + 1] },
      S: { x: words[4 * bit + 2], y: words[4 * bit + 3] },
    });
    const publicReceipt = receiptPublic(receipt);
    receipts.push(publicReceipt);
    remoteBallots.push({ position: index, nullifier: event.args.nullifier.toString(), ciphertexts, leaf: event.args.ballotLeaf, resultingAccumulator: event.args.accumulator, provenance: publicReceipt });
  }
  const claimReceipt = await provider.getTransactionReceipt(manifest.deployment.finalClaim.transactionHash);
  requireCondition(claimReceipt && claimReceipt.status === 1, "final claim receipt unavailable/failed");
  const state = {
    phase: Number(await poll.phase()),
    acceptedBallotCount: Number(await poll.acceptedBallotCount()),
    ballotSetCommitment: await poll.ballotSetCommitment(),
    backendTranscriptHash: await poll.backendTranscriptHash(),
    outcomeBit: Number(await poll.outcomeBit()),
    pollDomain: await poll.POLL_DOMAIN(),
    registryRoot: (await poll.registryRoot()).toString(),
    pollId: (await poll.pollId()).toString(),
    tau: (await poll.tau()).toString(),
    committeePK_X: (await poll.committeePK_X()).toString(),
    committeePK_Y: (await poll.committeePK_Y()).toString(),
  };
  requireCondition(state.phase === 2 && state.acceptedBallotCount === 8, "public poll is not claimed/sealed");
  requireCondition(manifest.profile === "FC2027-CGY-TOOLBOX-FULL-V1-Q5" && manifest.finalReferenceThreshold === "5_OF_5", "Q5 profile manifest mismatch");
  requireCondition(state.ballotSetCommitment.toLowerCase() === snapshot.ballotSetCommitment.toLowerCase(), "public board commitment mismatch");
  requireCondition(state.backendTranscriptHash.toLowerCase() === `0x${manifest.transcriptHash}`.toLowerCase(), "public transcript claim mismatch");
  requireCondition(state.outcomeBit === manifest.resultBit, "public result bit mismatch");
  requireCondition(state.pollDomain.toLowerCase() === snapshot.pollDomain.toLowerCase(), "public poll domain mismatch");
  requireCondition(state.registryRoot === snapshot.pollConfiguration.registryRoot && state.pollId === snapshot.pollConfiguration.pollId && state.tau === String(snapshot.pollConfiguration.tau), "public poll configuration mismatch");
  requireCondition(state.committeePK_X === setup.committeeKey.x.toString(10) && state.committeePK_Y === setup.committeeKey.y.toString(10), "public committee key mismatch");
  const chainMs = Number(process.hrtime.bigint() - chainStarted) / 1e6;

  const sealedBlock = await provider.getBlock(snapshot.ballots[snapshot.ballots.length - 1].provenance.blockNumber);
  requireCondition(sealedBlock, "sealed block unavailable");
  const remoteSnapshot = {
    schema: "arbitrum-n8-chain-snapshot-v1",
    version: "FC2027-CGY-TOOLBOX-FULL-V1",
    source: "Arbitrum Sepolia public testnet RPC/events",
    chainId: network.chainId.toString(),
    contract: { address: snapshot.contract.address, runtimeCodeHash: pollCodeHash },
    verifier: { address: snapshot.verifier.address, runtimeCodeHash: verifierCodeHash },
    pollConfiguration: { protocolTag: await poll.PROTOCOL_TAG(), registryRoot: state.registryRoot, pollId: state.pollId, tau: state.tau, N: 8, L_VOTE: 8, L_AGG: 11 },
    backendBinding: { setupHash: `0x${setup.setupHash}`, committeePK: { x: state.committeePK_X, y: state.committeePK_Y } },
    pollDomain: state.pollDomain,
    ballotSetCommitment: state.ballotSetCommitment,
    sealedBlock: { number: sealedBlock.number, hash: sealedBlock.hash, timestamp: sealedBlock.timestamp },
    ballots: remoteBallots,
  };
  const remoteBoard = fromChainSnapshot(remoteSnapshot);
  const savedBoard = fromChainSnapshot(snapshot);
  requireCondition(remoteBoard.sealedBoardHash.toLowerCase() === savedBoard.sealedBoardHash.toLowerCase(), "public event-reconstructed board hash mismatch");
  const admitted = admitSealedBoard(serializeSealedBoard(remoteBoard), setup);
  const savedAdmitted = admitSealedBoard(boardBytes, setup);
  assertExactAdmittedInputs(admitted, savedAdmitted.ciphertexts);
  requireCondition(admitted.ballotCount === 8, "accepted-board count mismatch");

  const entries = journalBytes.toString("utf8").trimEnd().split("\n").map((line) => JSON.parse(line));
  requireCondition(entries.length === 134 && entries.every((entry) => entry.backend === "RUST"), "public CGY journal shape mismatch");
  for (const entry of entries) {
    sourceSessionFromJson(entry.record.baseSession);
    verifyBroadcastTranscript(entry.record.boardExport);
  }
  const native = await verifyNativeDag({ setup, executionId: manifest.executionId, tau: manifest.tau, bitVectors: admitted.ciphertexts, entries });
  const finalRecord = finalReleaseRecordFromJson(JSON.parse(finalBytes.toString("utf8")));
  const finalVerification = verifyFinalRelease(finalRecord, setup);
  requireCondition(finalVerification.resultBit === manifest.resultBit, "final release result mismatch");
  const transcriptHash = sha256(Buffer.concat([
    Buffer.from("FC2027-CGY-TOOLBOX-FULL-V1/N8-COMPLETE-TRANSCRIPT/V1", "utf8"),
    Buffer.from(setup.setupHash, "hex"),
    Buffer.from(remoteBoard.sealedBoardHash.slice(2), "hex"),
    Buffer.from(sha256(journalBytes), "hex"),
    Buffer.from(sha256(finalBytes), "hex"),
  ]));
  requireCondition(transcriptHash === manifest.transcriptHash, "public transcript hash recomputation mismatch");
  const deploymentReceipts = {
    verifier: await findCreateReceipt(provider, snapshot.verifier.address, snapshot.ballots[0].provenance.blockNumber, snapshot.ballots[snapshot.ballots.length - 1].provenance.blockNumber),
    poll: await findCreateReceipt(provider, snapshot.contract.address, snapshot.ballots[0].provenance.blockNumber, snapshot.ballots[snapshot.ballots.length - 1].provenance.blockNumber),
  };
  const replay = {
    schema: "FC2027-CGY-TOOLBOX-FULL-V1/SEPOLIA-PUBLIC-REPLAY/V1",
    status: "PASS",
    network: "ARBITRUM_SEPOLIA",
    chainId: network.chainId.toString(),
    contract: snapshot.contract.address,
    verifier: snapshot.verifier.address,
    receipts,
    claimReceipt: receiptPublic(claimReceipt),
    deploymentReceipts: Object.fromEntries(Object.entries(deploymentReceipts).map(([key, value]) => [key, value && receiptPublic(value)])),
    acceptedBallots: receipts.length,
    exactChainToBackendBinding: true,
    exactCiphertextCoordinates: receipts.length * 8,
    sourceGatesVerified: native.gateCount,
    finalReleaseVerified: true,
    resultBit: finalVerification.resultBit,
    transcriptHash,
    timing: {
      clock: "process.hrtime.bigint",
      ballotProofReplayMs: ballotProofMs,
      chainReplayMs: chainMs,
      nativePublicReplayMs: Number(native.backendMs || 0),
      replayTotalMs: Number(process.hrtime.bigint() - started) / 1e6,
      transcriptBytes: journalBytes.length + finalBytes.length,
      oracleComputationIncluded: false,
    },
  };
  const outputName = process.env.CGY_PUBLIC_REPLAY_OUTPUT || "public_replay.json";
  fs.writeFileSync(path.join(runDirectory, outputName), `${JSON.stringify(replay, null, 2)}\n`, { flag: "wx" });
  process.stdout.write(`PUBLIC_REPLAY=PASS\nSOURCE_GATES_VERIFIED=${native.gateCount}\nRESULT_BIT=${finalVerification.resultBit}\nFINAL_THRESHOLD=5_OF_5\nREPLAY_TOTAL_MS=${replay.timing.replayTotalMs.toFixed(3)}\n`);
}

main().catch((error) => {
  process.stderr.write(`E_SEPOLIA_PUBLIC_REPLAY: ${error.stack || error.message}\n`);
  process.exitCode = 1;
});
