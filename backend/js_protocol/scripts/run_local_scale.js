"use strict";

// Five-trustee application-only admission profile for native scale measurements. It
// preserves the ballot relation, Groth16 verifier, registry/nullifier checks,
// and exact ciphertext coordinates, while replacing only the bounded N=8
// blockchain transport with a sealed local board.

const crypto = require("crypto");
const childProcess = require("child_process");
const fs = require("fs");
const path = require("path");
const readline = require("readline");
const { provisionFreshTestOnly } = require("../src/threshold_setup");
const { publicSetupToJson, ciphertextFromJson } = require("../src/codec");
const { admitLocalProofBoard } = require("../src/local_admission");
const { createTrusteeAuthenticationRegistry, CanonicalAtomicBroadcastBoard, canonicalJson, verifyBroadcastTranscript } = require("../src/broadcast_board");
const { buildLogicalDecisionCiphertext, runFinalRelease, verifyFinalRelease, finalReleaseRecordToJson } = require("../src/final_release");
const { ciphertextEquals } = require("../src/elgamal");
const { runNativeWeightedArithmetic } = require("../../cgy_native/tools/native_arithmetic_scheduler");
const { verifyNativeDag, verifyNativeDagFile } = require("../../cgy_native/tools/native_gate_bridge");
const { pack } = require("../../cgy_native/tools/compact_transcript");
const { PROTOCOL_VERSION } = require("../src/group_oracle");
const repositoryRoot = path.resolve(__dirname, "..", "..", "..");

function required(name) {
  if (!process.env[name]) throw new Error(`E_LOCAL_SCALE_ENV: ${name} is required`);
  return process.env[name];
}

function now() { return process.hrtime.bigint(); }
function seconds(start) { return Number(now() - start) / 1e9; }
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
async function sha256File(filePath) {
  const digest = crypto.createHash("sha256");
  for await (const chunk of fs.createReadStream(filePath)) digest.update(chunk);
  return digest.digest("hex");
}
function writeNew(filePath, value) {
  const json = JSON.stringify(value, (key, item) => typeof item === "bigint" ? item.toString(10) : item, 2);
  fs.writeFileSync(filePath, `${json}\n`, { encoding: "utf8", flag: "wx" });
}

async function inspectJournalStream(journalPath) {
  const digest = crypto.createHash("sha256");
  let bytes = 0;
  let gateCount = 0;
  const input = fs.createReadStream(journalPath, { encoding: "utf8" });
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  try {
    for await (const line of lines) {
      if (line.length === 0) continue;
      const raw = Buffer.from(`${line}\n`, "utf8");
      bytes += raw.length;
      digest.update(raw);
      const entry = JSON.parse(line);
      verifyBroadcastTranscript(entry.record.boardExport);
      gateCount += 1;
    }
  } finally {
    lines.close();
    input.destroy();
  }
  return Object.freeze({ bytes, gateCount, sha256: digest.digest("hex") });
}

function artifacts(root) {
  return {
    wasmPath: path.join(root, "implementation", "logs", "bit_ballot", "build", "matrix", "vote_bit_full_8", "O1", "vote_bit_full_8_js", "vote_bit_full_8.wasm"),
    zkeyPath: path.join(root, "implementation", "logs", "bit_ballot", "groth16", "vote_bit_full_8", "vote_bit_full_8_final.zkey"),
    vkeyPath: path.join(root, "implementation", "logs", "bit_ballot", "groth16", "vote_bit_full_8", "verification_key.json"),
  };
}

function graphShape(count) {
  const shapes = { 8: [134, 72, 4], 64: [1086, 147, 32], 256: [4350, 207, 128], 1024: [17406, 275, 512] };
  return shapes[count] || [null, null, null];
}

async function main() {
  const totalStarted = now();
  const count = Number(required("CGY_LOCAL_N"));
  if (![8, 64, 1024].includes(count)) throw new Error("E_LOCAL_SCALE_N: supported values are 8, 64, and 1024");
  const runDirectory = path.resolve(repositoryRoot, required("CGY_LOCAL_RUN_DIRECTORY"));
  const oracleDirectory = path.resolve(repositoryRoot, process.env.CGY_N8_ORACLE_DIRECTORY || `${runDirectory}_oracle`);
  if (fs.existsSync(runDirectory)) throw new Error(`E_LOCAL_RUN_EXISTS: refusing to overwrite ${runDirectory}`);
  if (fs.existsSync(oracleDirectory)) throw new Error(`E_LOCAL_ORACLE_EXISTS: refusing to overwrite ${oracleDirectory}`);
  const oracleRelative = path.relative(runDirectory, oracleDirectory);
  if (oracleRelative === "" || (!oracleRelative.startsWith("..") && !path.isAbsolute(oracleRelative))) {
    throw new Error("E_LOCAL_ORACLE_SEPARATION: oracle directory must be outside the protocol run directory");
  }
  fs.mkdirSync(runDirectory, { recursive: true });
  const artifactRoot = required("CGY_BALLOT_ARTIFACT_ROOT");
  const setupStarted = now();
  const setupBundle = provisionFreshTestOnly({ trustees: 5, degree: 4 });
  const setupSeconds = seconds(setupStarted);
  const executionId = crypto.randomBytes(32).toString("hex");
  // The unchanged ballot relation represents pollId as a field element, so
  // the local reference profile must use the same canonical decimal encoding.
  // Keep the profile fresh without introducing a new relation or admission
  // rule.
  const pollId = String(900000000 + count + (Date.now() % 1000000));
  const tau = Math.floor(count * 255 / 4);
  const ballotArtifacts = artifacts(artifactRoot);
  const publicSetup = publicSetupToJson(setupBundle.publicSetup);
  writeNew(path.join(runDirectory, "public_setup.json"), publicSetup);
  const ballotStarted = now();
  const ballotChild = childProcess.spawnSync(process.execPath, [path.join(__dirname, "generate_local_ballots_child.js")], {
    encoding: "utf8",
    env: {
      ...process.env,
      CGY_LOCAL_BALLOT_DIRECTORY: runDirectory,
      CGY_N8_ORACLE_DIRECTORY: oracleDirectory,
      CGY_LOCAL_N: String(count),
      CGY_LOCAL_TAU: String(tau),
      CGY_LOCAL_POLL_ID: pollId,
      CGY_N8_COMMITTEE_KEY: JSON.stringify({
        x: setupBundle.publicSetup.committeeKey.x.toString(10),
        y: setupBundle.publicSetup.committeeKey.y.toString(10),
      }),
      CGY_BALLOT_WASM: ballotArtifacts.wasmPath,
      CGY_BALLOT_ZKEY: ballotArtifacts.zkeyPath,
      CGY_BALLOT_VKEY: ballotArtifacts.vkeyPath,
    },
    maxBuffer: 16 * 1024 * 1024,
    windowsHide: true,
  });
  if (ballotChild.error || ballotChild.status !== 0) {
    throw new Error(`E_LOCAL_BALLOT_CHILD: ballot generator failed (${ballotChild.status}): ${ballotChild.stderr || ballotChild.error || "no child error"}`);
  }
  const ballotSeconds = seconds(ballotStarted);
  const publicProofs = JSON.parse(fs.readFileSync(path.join(runDirectory, "ballot_public_proofs.json"), "utf8"));
  const ballotContext = JSON.parse(fs.readFileSync(path.join(runDirectory, "ballot_public_context.json"), "utf8"));
  if (ballotContext.count !== count || ballotContext.pollId !== pollId) throw new Error("E_LOCAL_BALLOT_CONTEXT: generated ballot context mismatch");
  const registryRoot = BigInt(ballotContext.registryRoot);
  const admissionStarted = now();
  const admitted = await admitLocalProofBoard({
    publicProofs,
    verificationKey: JSON.parse(fs.readFileSync(ballotArtifacts.vkeyPath, "utf8")),
    registryRoot,
    pollId,
    committeeKey: setupBundle.publicSetup.committeeKey,
    count,
  });
  const admissionSeconds = seconds(admissionStarted);
  writeNew(path.join(runDirectory, "local_admission_board.json"), { ...admitted.board, sealedBoardHash: admitted.sealedBoardHash });
  const authentication = createTrusteeAuthenticationRegistry(5);
  const journalPath = path.join(runDirectory, "gate_transcript.jsonl");
  fs.writeFileSync(journalPath, "", { flag: "wx" });
  const backendStarted = now();
  const tally = runNativeWeightedArithmetic({
    bitVectors: admitted.ciphertexts,
    tau,
    setupBundle,
    executionId,
    authentication,
    journalPath,
    labelPrefix: `N${count}`,
    streamJournal: process.env.CGY_NATIVE_STREAM_JOURNAL === "1" || count >= 1024,
    streamNative: count >= 1024 || process.env.CGY_NATIVE_STREAM_NATIVE === "1",
    nativeTranscriptPath: path.join(runDirectory, "native_gate_records.jsonl"),
  });
  const backendSeconds = seconds(backendStarted);
  const logical = buildLogicalDecisionCiphertext(tally.comparison, tally.operations);
  const finalSession = Object.freeze({ protocolVersion: PROTOCOL_VERSION, setupHash: setupBundle.publicSetup.setupHash, executionId, gateId: BigInt(tally.gateCount + 1), invocation: 0n });
  const finalBoard = new CanonicalAtomicBroadcastBoard({ setupHash: setupBundle.publicSetup.setupHash, executionId, trusteePublicKeys: authentication.publicKeys });
  const finalStarted = now();
  const release = runFinalRelease({ setupBundle, session: finalSession, logicalDecision: logical, board: finalBoard, trusteePrivateKeys: authentication.privateKeys, shareTrusteeIds: [1, 2, 3, 4, 5] });
  verifyFinalRelease(release, setupBundle.publicSetup);
  const finalSeconds = seconds(finalStarted);
  const finalBytes = Buffer.from(canonicalJson(finalReleaseRecordToJson(release)), "utf8");
  fs.writeFileSync(path.join(runDirectory, "final_release.json"), finalBytes, { flag: "wx" });
  const replayStarted = now();
  let replay;
  let journalInfo;
  if (count >= 1024) {
    journalInfo = await inspectJournalStream(journalPath);
    replay = verifyNativeDagFile({ setup: setupBundle.publicSetup, executionId, bitVectors: admitted.ciphertexts, tau, labelPrefix: `N${count}`, transcriptPath: journalPath });
    if (journalInfo.gateCount !== tally.gateCount) throw new Error("E_LOCAL_JOURNAL_GATE_COUNT");
  } else {
    const journalBytesForReplay = fs.readFileSync(journalPath);
    const entries = journalBytesForReplay.toString("utf8").trimEnd().split("\n").map((line) => JSON.parse(line));
    for (const entry of entries) verifyBroadcastTranscript(entry.record.boardExport);
    replay = verifyNativeDag({ setup: setupBundle.publicSetup, executionId, bitVectors: admitted.ciphertexts, tau, labelPrefix: `N${count}`, gates: entries });
    journalInfo = { bytes: journalBytesForReplay.length, sha256: sha256(journalBytesForReplay), gateCount: entries.length };
  }
  const replaySeconds = seconds(replayStarted);
  if (!ciphertextEquals(ciphertextFromJson(replay.result), logical.ciphertext)) throw new Error("E_LOCAL_REPLAY_RESULT_MISMATCH");
  const transcriptHash = sha256(Buffer.concat([Buffer.from(`${PROTOCOL_VERSION}/LOCAL-COMPLETE-TRANSCRIPT/V1`), Buffer.from(setupBundle.publicSetup.setupHash, "hex"), Buffer.from(admitted.sealedBoardHash, "hex"), Buffer.from(journalInfo.sha256, "hex"), Buffer.from(sha256(finalBytes), "hex")]));
  const compactPath = path.join(runDirectory, "gate_transcript.compact.bin");
  const compactStarted = now();
  const compactInfo = await pack(journalPath, compactPath);
  const compactEncodingSeconds = seconds(compactStarted);
  if (compactInfo.inputSha256 !== journalInfo.sha256 || compactInfo.inputBytes !== journalInfo.bytes) {
    throw new Error("E_LOCAL_COMPACT_TRANSCRIPT: compact encoding changed canonical journal bytes");
  }
  const compactSha256 = await sha256File(compactPath);
  const [gates, depth, maxReadyWidth] = graphShape(count);
  const manifest = {
    schema: "winner-only-disclosure/local-scale-manifest/v1",
    profile: "winner-only-disclosure/five-of-five/v1",
    previousReferenceThreshold: "3_OF_5",
    finalReferenceThreshold: "5_OF_5",
    protocolVersion: PROTOCOL_VERSION,
    count,
    executionId,
    setupHash: setupBundle.publicSetup.setupHash,
    sealedBoardHash: admitted.sealedBoardHash,
    registryRoot: registryRoot.toString(10),
    tau,
    gates: tally.gateCount,
    derivedGates: gates,
    depth,
    maxReadyWidth,
    resultBit: release.resultBit,
    transcriptHash,
    normalProtocolReceivedCleartextOracle: false,
    canonicalJournalBytes: journalInfo.bytes,
    compactTranscriptBytes: compactInfo.compactBytes,
    compactTranscriptSha256: compactSha256,
    finalReleaseBytes: finalBytes.length,
    canonicalTranscriptBytes: journalInfo.bytes + finalBytes.length,
    timing: {
      setupSeconds,
      ballotProvingSeconds: ballotSeconds,
      admissionSeconds,
      backendSeconds,
      finalReleaseSeconds: finalSeconds,
      replaySeconds,
      compactEncodingSeconds,
      totalSeconds: seconds(totalStarted),
      native: tally.timing,
    },
    hashes: {
      publicSetupSha256: sha256(fs.readFileSync(path.join(runDirectory, "public_setup.json"))),
      proofsSha256: sha256(fs.readFileSync(path.join(runDirectory, "ballot_public_proofs.json"))),
      admissionSha256: sha256(fs.readFileSync(path.join(runDirectory, "local_admission_board.json"))),
      journalSha256: journalInfo.sha256,
      compactTranscriptSha256: compactSha256,
      finalSha256: sha256(finalBytes),
    },
  };
  writeNew(path.join(runDirectory, "manifest.json"), manifest);
  process.stdout.write(`LOCAL_NATIVE_EXECUTION=PASS\nN=${count}\nGATES=${tally.gateCount}\nBACKEND_SECONDS=${backendSeconds.toFixed(3)}\nREPLAY_SECONDS=${replaySeconds.toFixed(3)}\nCANONICAL_TRANSCRIPT_BYTES=${manifest.canonicalTranscriptBytes}\nCOMPACT_TRANSCRIPT_BYTES=${compactInfo.compactBytes}\nORACLE_INPUTS_ISOLATED=YES\nFINAL_THRESHOLD=5_OF_5\n`);
}

main().then(() => process.exit(0)).catch((error) => { process.stderr.write(`${error.code || "E_LOCAL_SCALE"}: ${error.stack || error.message}\n`); process.exit(1); });
