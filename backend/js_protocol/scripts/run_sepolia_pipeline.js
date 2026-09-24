"use strict";

const childProcess = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const { createRequire } = require("module");
const path = require("path");
const { requireCondition } = require("../src/errors");
const { PROTOCOL_VERSION } = require("../src/group_oracle");
const { provisionFreshTestOnly } = require("../src/threshold_setup");
const { publicSetupToJson } = require("../src/codec");
const { createTrusteeAuthenticationRegistry, CanonicalAtomicBroadcastBoard, canonicalJson } = require("../src/broadcast_board");
const { runConditionalGate, verifyConditionalGateTranscript, conditionalGateRecordToJson } = require("../src/conditional_gate");
const { balancedAggregate, subLTBits, createCiphertextOps } = require("../src/arithmetic");
const { buildLogicalDecisionCiphertext, runFinalRelease, verifyFinalRelease, finalReleaseRecordToJson } = require("../src/final_release");
const { admitSealedBoard, assertExactAdmittedInputs } = require("../src/accepted_board");
const { solidityProof } = require("../src/n8_ballots");
const { runNativeWeightedArithmetic } = require("../../cgy_native/tools/native_arithmetic_scheduler");

const backendRoot = path.resolve(__dirname, "..");
const repositoryRoot = path.resolve(backendRoot, "..", "..");
const artifactRoot = process.env.CGY_BALLOT_ARTIFACT_ROOT;
const arbitrumRoot = path.join(repositoryRoot, "implementation", "arbitrum");
const boardBindingRoot = path.join(repositoryRoot, "implementation", "arbitrum", "board_binding");

function monotonicNow() {
  return process.hrtime.bigint();
}

function elapsedMs(started) {
  return Number(monotonicNow() - started) / 1e6;
}

function distribution(values) {
  requireCondition(Array.isArray(values) && values.length > 0, "E_TIMING_VALUES", "timing distribution is empty");
  const sorted = [...values].sort((left, right) => left - right);
  const percentile = (fraction) => sorted[Math.min(sorted.length - 1, Math.ceil(fraction * sorted.length) - 1)];
  const totalMs = values.reduce((sum, value) => sum + value, 0);
  return Object.freeze({
    count: values.length,
    minMs: sorted[0],
    medianMs: percentile(0.5),
    p95Ms: percentile(0.95),
    maxMs: sorted[sorted.length - 1],
    meanMs: totalMs / values.length,
    totalMs,
  });
}

function required(name, value) {
  requireCondition(typeof value === "string" && value.length > 0, "E_N8_ENV", `${name} is required`);
  return value;
}

function sha256Bytes(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function writeNew(filePath, value) {
  fs.writeFileSync(filePath, Buffer.isBuffer(value) ? value : Buffer.from(String(value), "utf8"), { flag: "wx" });
}

function writeJsonNew(filePath, value) {
  writeNew(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function toCiphertexts(words) {
  const ciphertexts = [];
  for (let bit = 0; bit < 8; bit += 1) {
    ciphertexts.push({
      R: { x: words[4 * bit].toString(), y: words[4 * bit + 1].toString() },
      S: { x: words[4 * bit + 2].toString(), y: words[4 * bit + 3].toString() },
    });
  }
  return ciphertexts;
}

function artifactPaths() {
  const root = required("CGY_BALLOT_ARTIFACT_ROOT", artifactRoot);
  return Object.freeze({
    wasmPath: path.join(root, "implementation", "logs", "bit_ballot", "build", "matrix", "vote_bit_full_8", "O1", "vote_bit_full_8_js", "vote_bit_full_8.wasm"),
    zkeyPath: path.join(root, "implementation", "logs", "bit_ballot", "groth16", "vote_bit_full_8", "vote_bit_full_8_final.zkey"),
    vkeyPath: path.join(root, "implementation", "logs", "bit_ballot", "groth16", "vote_bit_full_8", "verification_key.json"),
  });
}

function contractArtifacts() {
  const root = required("CGY_BALLOT_ARTIFACT_ROOT", artifactRoot);
  const verifierPath = path.join(root, "implementation", "arbitrum", "artifacts", "contracts", "verifier.sol", "Groth16Verifier.json");
  const pollPath = path.join(root, "implementation", "arbitrum", "artifacts", "contracts", "StrongN8Poll.sol", "StrongN8Poll.json");
  requireCondition(fs.existsSync(verifierPath) && fs.existsSync(pollPath), "E_CONTRACT_ARTIFACT", "matching current contract artifacts are missing");
  const verifierBytes = fs.readFileSync(verifierPath);
  const pollBytes = fs.readFileSync(pollPath);
  return Object.freeze({
    verifier: JSON.parse(verifierBytes.toString("utf8")),
    poll: JSON.parse(pollBytes.toString("utf8")),
    hashes: Object.freeze({ verifierSha256: sha256Bytes(verifierBytes), pollSha256: sha256Bytes(pollBytes) }),
  });
}

async function main() {
  const nativeBackend = process.env.CGY_NATIVE_BACKEND === "1";
  const harnessStarted = monotonicNow();
  let sampledPeakRssBytes = process.memoryUsage().rss;
  const sampleRss = () => {
    sampledPeakRssBytes = Math.max(sampledPeakRssBytes, process.memoryUsage().rss);
  };
  const runDirectory = path.resolve(required("CGY_N8_RUN_DIRECTORY", process.env.CGY_N8_RUN_DIRECTORY));
  const oracleDirectory = path.resolve(required("CGY_N8_ORACLE_DIRECTORY", process.env.CGY_N8_ORACLE_DIRECTORY));
  requireCondition(!fs.existsSync(runDirectory), "E_RUN_EXISTS", `refusing to overwrite ${runDirectory}`);
  requireCondition(!fs.existsSync(oracleDirectory), "E_RUN_EXISTS", `refusing to overwrite ${oracleDirectory}`);
  fs.mkdirSync(runDirectory, { recursive: true });
  const startedAt = new Date().toISOString();
  const setupStarted = monotonicNow();
  const setupBundle = provisionFreshTestOnly({ trustees: 5, degree: 4 });
  const setupMs = elapsedMs(setupStarted);
  sampleRss();
  const setup = setupBundle.publicSetup;
  const tau = 500;
  const pollId = required("CGY_SEPOLIA_POLL_ID", process.env.CGY_SEPOLIA_POLL_ID || "");
  const executionId = crypto.randomBytes(32).toString("hex");
  writeJsonNew(path.join(runDirectory, "public_setup.json"), publicSetupToJson(setup));

  const artifacts = artifactPaths();
  const ballotProofWallStarted = monotonicNow();
  const child = childProcess.spawnSync(process.execPath, [path.join(__dirname, "generate_n8_ballots_child.js")], {
    encoding: "utf8",
    env: {
      ...process.env,
      CGY_N8_PUBLIC_DIRECTORY: runDirectory,
      CGY_N8_ORACLE_DIRECTORY: oracleDirectory,
      CGY_N8_COMMITTEE_KEY: JSON.stringify({ x: setup.committeeKey.x.toString(10), y: setup.committeeKey.y.toString(10) }),
      CGY_N8_POLL_ID: pollId,
      CGY_N8_TAU: String(tau),
      CGY_BALLOT_WASM: artifacts.wasmPath,
      CGY_BALLOT_ZKEY: artifacts.zkeyPath,
      CGY_BALLOT_VKEY: artifacts.vkeyPath,
    },
    maxBuffer: 16 * 1024 * 1024,
  });
  writeNew(path.join(runDirectory, "ballot_generation.log"), `${child.stdout || ""}${child.stderr || ""}`);
  requireCondition(child.status === 0, "E_BALLOT_CHILD", `fresh ballot child failed with status ${child.status}`);
  const ballotContext = JSON.parse(fs.readFileSync(path.join(runDirectory, "ballot_public_context.json"), "utf8"));
  const publicProofs = JSON.parse(fs.readFileSync(path.join(runDirectory, "ballot_public_proofs.json"), "utf8"));
  requireCondition(publicProofs.length === 8, "E_BALLOT_COUNT", "fresh proof child did not produce eight ballots");
  const ballotProofGenerationMs = elapsedMs(ballotProofWallStarted);
  const ballotProofProverSumMs = publicProofs.reduce((sum, record) => sum + record.provingMs, 0);
  sampleRss();

  const chainStarted = monotonicNow();
  process.env.HARDHAT_CONFIG = path.join(arbitrumRoot, "hardhat.config.js");
  const requireArbitrum = createRequire(path.join(arbitrumRoot, "package.json"));
  const hre = requireArbitrum("hardhat");
  const { ethers } = hre;
  const { keccak256 } = requireArbitrum("ethers");
  const contracts = contractArtifacts();
  const sealedAuthority = require(path.join(boardBindingRoot, "lib", "sealed_board.js"));
  const [deployer, publisherCandidate] = await ethers.getSigners();
  const publisher = publisherCandidate || deployer;
  const network = await ethers.provider.getNetwork();
  const Verifier = new ethers.ContractFactory(contracts.verifier.abi, contracts.verifier.bytecode, deployer);
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();
  const verifierAddress = await verifier.getAddress();
  const Poll = new ethers.ContractFactory(contracts.poll.abi, contracts.poll.bytecode, deployer);
  const latest = await ethers.provider.getBlock("latest");
  const poll = await Poll.deploy(
    verifierAddress,
    BigInt(ballotContext.registryRoot),
    BigInt(pollId),
    tau,
    publisher.address,
    latest.timestamp + 86400,
    setup.committeeKey.x,
    setup.committeeKey.y,
    `0x${setup.setupHash}`,
  );
  await poll.waitForDeployment();
  const pollAddress = await poll.getAddress();
  const acceptedBallots = [];
  let lastReceipt;
  for (const record of publicProofs) {
    const converted = solidityProof(record);
    const transaction = await poll.submitBallot(converted.a, converted.b, converted.c, converted.publicSignals);
    const receipt = await transaction.wait();
    lastReceipt = receipt;
    const event = receipt.logs.map((log) => {
      try { return poll.interface.parseLog(log); } catch (error) { return null; }
    }).find((candidate) => candidate && candidate.name === "BallotAccepted");
    requireCondition(event, "E_BALLOT_EVENT", `accepted ballot ${record.index} event is missing`);
    acceptedBallots.push({
      position: Number(event.args.ballotIndex),
      nullifier: event.args.nullifier.toString(),
      ciphertexts: toCiphertexts([...event.args.ciphertext]),
      leaf: event.args.ballotLeaf,
      resultingAccumulator: event.args.accumulator,
      provenance: {
        blockNumber: receipt.blockNumber,
        transactionHash: receipt.hash,
        transactionIndex: receipt.index,
        gasUsed: receipt.gasUsed.toString(),
      },
    });
  }
  requireCondition(Number(await poll.acceptedBallotCount()) === 8 && Number(await poll.phase()) === 1, "E_CHAIN_SEAL", "fresh poll did not seal at eight accepted ballots");
  const sealedBlock = await ethers.provider.getBlock(lastReceipt.blockNumber);
  const chainSnapshot = {
    schema: "arbitrum-n8-chain-snapshot-v1",
    version: "-CGY-TOOLBOX-FULL-V1",
    source: "fresh Arbitrum Sepolia public testnet",
    chainId: network.chainId.toString(),
    contract: { address: pollAddress, runtimeCodeHash: keccak256(await ethers.provider.getCode(pollAddress)) },
    verifier: { address: verifierAddress, runtimeCodeHash: keccak256(await ethers.provider.getCode(verifierAddress)) },
    pollConfiguration: { protocolTag: await poll.PROTOCOL_TAG(), registryRoot: ballotContext.registryRoot, pollId, tau: String(tau), N: 8, L_VOTE: 8, L_AGG: 11 },
    backendBinding: { setupHash: `0x${setup.setupHash}`, committeePK: { x: setup.committeeKey.x.toString(10), y: setup.committeeKey.y.toString(10) } },
    pollDomain: await poll.POLL_DOMAIN(),
    ballotSetCommitment: await poll.ballotSetCommitment(),
    sealedBlock: { number: sealedBlock.number, hash: sealedBlock.hash },
    ballots: acceptedBallots,
  };
  writeJsonNew(path.join(runDirectory, "chain_snapshot.json"), chainSnapshot);
  const sealedBoard = sealedAuthority.fromChainSnapshot(chainSnapshot);
  const sealedBytes = sealedAuthority.serializeSealedBoard(sealedBoard);
  writeNew(path.join(runDirectory, "sealed_board.json"), sealedBytes);
  const admitted = admitSealedBoard(sealedBytes, setup);
  assertExactAdmittedInputs(admitted, admitted.ciphertexts);
  const chainAdmissionMs = elapsedMs(chainStarted);
  sampleRss();

  const authentication = createTrusteeAuthenticationRegistry(5);
  const journalPath = path.join(runDirectory, "gate_transcript.jsonl");
  writeNew(journalPath, "");
  let gateIndex = 0;
  let gateTimingsMs = [];
  let nativeGenerationTimingsMs = [];
  let nativeVerificationTimingsMs = [];
  let nativeDagProcessMs = null;
  let nativeDagInternalMs = null;
  let nativeAdapterMs = null;
  let nativeJournalMs = null;
  let operations;
  let aggregate;
  let comparison;
  let cgyTallyBackendMs;
  if (nativeBackend) {
    const tallyStarted = monotonicNow();
    const nativeTally = runNativeWeightedArithmetic({
      bitVectors: admitted.ciphertexts,
      tau,
      setupBundle,
      executionId,
      authentication,
      journalPath,
      labelPrefix: "N8",
    });
    aggregate = nativeTally.aggregate;
    comparison = nativeTally.comparison;
    operations = nativeTally.operations;
    gateIndex = nativeTally.gateCount;
    gateTimingsMs = nativeTally.timing.gateWallMs;
    nativeGenerationTimingsMs = nativeTally.timing.nativeGenerationMs;
    nativeVerificationTimingsMs = nativeTally.timing.nativeVerificationMs;
    nativeDagProcessMs = nativeTally.timing.nativeProcessMs;
    nativeDagInternalMs = nativeTally.timing.nativeBackendMs;
    nativeAdapterMs = nativeTally.timing.nativeAdapterMs;
    nativeJournalMs = nativeTally.timing.nativeJournalMs;
    cgyTallyBackendMs = elapsedMs(tallyStarted);
  } else {
    operations = createCiphertextOps((left, right, label) => {
    const gateStarted = monotonicNow();
    gateIndex += 1;
    const baseSession = Object.freeze({
      protocolVersion: PROTOCOL_VERSION,
      setupHash: setup.setupHash,
      executionId,
      gateId: BigInt(gateIndex),
      invocation: 0n,
    });
    const board = new CanonicalAtomicBroadcastBoard({ setupHash: setup.setupHash, executionId, trusteePublicKeys: authentication.publicKeys });
    const record = runConditionalGate({ setupBundle, baseSession, inputX: left, inputY: right, board, trusteePrivateKeys: authentication.privateKeys });
    verifyConditionalGateTranscript(record);
    const journalRecord = conditionalGateRecordToJson(record);
    fs.appendFileSync(journalPath, `${canonicalJson({ gateIndex, label, backend: nativeBackend ? "RUST" : "JS", record: journalRecord })}\n`, "utf8");
    const gateMs = elapsedMs(gateStarted);
    gateTimingsMs.push(gateMs);
    sampleRss();
    writeJsonNew(path.join(runDirectory, `progress_${String(gateIndex).padStart(3, "0")}.json`), { gateIndex, label, gateMs, backend: nativeBackend ? "RUST" : "JS", at: new Date().toISOString(), boardTranscriptHash: record.boardExport.transcriptHash });
    process.stdout.write(`CGY_N8_GATE=${gateIndex} LABEL=${label}\n`);
    return record.output;
    });
    const tallyStarted = monotonicNow();
    aggregate = balancedAggregate(admitted.ciphertexts, operations, "N8_WEIGHTED_SUM");
    requireCondition(aggregate.length === 11, "E_N8_AGGREGATE_WIDTH", "n=8 aggregate is not eleven bits");
    const thresholdBits = Array.from({ length: 11 }, (_, bit) => operations.publicBit((tau >> bit) & 1));
    comparison = subLTBits(aggregate, thresholdBits, operations, "N8_THRESHOLD");
    cgyTallyBackendMs = elapsedMs(tallyStarted);
  }
  requireCondition(gateIndex === 134, "E_N8_GATE_COUNT", `expected 134 source gates, received ${gateIndex}`);
  const logicalDecision = buildLogicalDecisionCiphertext(comparison, operations);
  const finalSession = Object.freeze({
    protocolVersion: PROTOCOL_VERSION,
    setupHash: setup.setupHash,
    executionId,
    gateId: BigInt(gateIndex + 1),
    invocation: 0n,
  });
  const finalBoard = new CanonicalAtomicBroadcastBoard({ setupHash: setup.setupHash, executionId, trusteePublicKeys: authentication.publicKeys });
  const finalReleaseStarted = monotonicNow();
  const finalRelease = runFinalRelease({
    setupBundle,
    session: finalSession,
    logicalDecision,
    board: finalBoard,
    trusteePrivateKeys: authentication.privateKeys,
    shareTrusteeIds: [1, 2, 3, 4, 5],
  });
  verifyFinalRelease(finalRelease, setup);
  const finalReleaseMs = elapsedMs(finalReleaseStarted);
  sampleRss();
  const finalReleaseBytes = Buffer.from(canonicalJson(finalReleaseRecordToJson(finalRelease)), "utf8");
  writeNew(path.join(runDirectory, "final_release.json"), finalReleaseBytes);
  const gateJournalBytes = fs.readFileSync(journalPath);
  const transcriptBytes = gateJournalBytes.length + finalReleaseBytes.length;
  const transcriptHash = sha256Bytes(Buffer.concat([
    Buffer.from("-CGY-TOOLBOX-FULL-V1/N8-COMPLETE-TRANSCRIPT/V1", "utf8"),
    Buffer.from(setup.setupHash, "hex"),
    Buffer.from(sealedBoard.sealedBoardHash.slice(2), "hex"),
    Buffer.from(sha256Bytes(gateJournalBytes), "hex"),
    Buffer.from(sha256Bytes(finalReleaseBytes), "hex"),
  ]));
  const resultPublicationStarted = monotonicNow();
  const claim = await poll.connect(publisher).publishOutcomeClaim(chainSnapshot.ballotSetCommitment, `0x${transcriptHash}`, finalRelease.resultBit);
  const claimReceipt = await claim.wait();
  requireCondition(Number(await poll.outcomeBit()) === finalRelease.resultBit, "E_CHAIN_CLAIM", "published result differs from source final release");
  const resultPublicationMs = elapsedMs(resultPublicationStarted);
  const gateDistribution = distribution(gateTimingsMs);
  const producerTotalMs = elapsedMs(harnessStarted);
  const manifest = {
    schema: "winner-only-disclosure/sepolia-manifest/v1",
    profile: "winner-only-disclosure/five-of-five/v1",
    previousReferenceThreshold: "3_OF_5",
    finalReferenceThreshold: "5_OF_5",
    protocolVersion: PROTOCOL_VERSION,
    tallyBackend: nativeBackend ? "RUST-NATIVE" : "JS-REFERENCE",
    startedAt,
    completedAt: new Date().toISOString(),
    executionId,
    setupHash: setup.setupHash,
    sealedBoardHash: sealedBoard.sealedBoardHash,
    gateCount: gateIndex,
    tau,
    resultBit: finalRelease.resultBit,
    shareTrusteeIds: finalRelease.shareTrusteeIds,
    artifactHashes: ballotContext.artifactHashes,
    contractArtifactHashes: contracts.hashes,
    publicSetupSha256: sha256Bytes(fs.readFileSync(path.join(runDirectory, "public_setup.json"))),
    ballotProofsSha256: sha256Bytes(fs.readFileSync(path.join(runDirectory, "ballot_public_proofs.json"))),
    chainSnapshotSha256: sha256Bytes(fs.readFileSync(path.join(runDirectory, "chain_snapshot.json"))),
    sealedBoardSha256: sha256Bytes(sealedBytes),
    gateJournalSha256: sha256Bytes(gateJournalBytes),
    finalReleaseSha256: sha256Bytes(finalReleaseBytes),
    transcriptHash,
    deployment: {
      chainId: network.chainId.toString(),
      verifierAddress,
      pollAddress,
      acceptedBallots: acceptedBallots.map((ballot) => ballot.provenance),
      finalClaim: { transactionHash: claimReceipt.hash, blockNumber: claimReceipt.blockNumber, gasUsed: claimReceipt.gasUsed.toString() },
    },
    normalProtocolReceivedCleartextOracle: false,
    productionDkgClaimed: false,
    retries: 0,
    timing: {
      clock: "process.hrtime.bigint",
      setupMs,
      ballotProofGenerationMs,
      ballotProofProverSumMs,
      chainAdmissionMs,
      cgyTallyBackendMs,
      nativeGateGeneration: nativeBackend ? distribution(nativeGenerationTimingsMs) : null,
      nativeGateVerification: nativeBackend ? distribution(nativeVerificationTimingsMs) : null,
      nativeDagProcessMs,
      nativeDagInternalMs,
      nativeAdapterMs,
      nativeJournalMs,
      conditionalGate: gateDistribution,
      finalReleaseMs,
      resultPublicationMs,
      producerTotalMs,
      transcriptBytes,
      sampledPeakRssBytes,
      oracleComputationIncluded: false,
    },
  };
  writeJsonNew(path.join(runDirectory, "manifest.json"), manifest);
  process.stdout.write(`NEW_CGY_N8_EXECUTION=PASS\nRUN_DIRECTORY=${runDirectory}\nTRANSCRIPT_HASH=${transcriptHash}\nRESULT_BIT=${finalRelease.resultBit}\nRETRIES=0\nPRODUCER_TOTAL_MS=${producerTotalMs.toFixed(3)}\nTRANSCRIPT_BYTES=${transcriptBytes}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.code || "E_CGY_N8"}: ${error.stack || error.message}\n`);
  process.exitCode = 1;
});
