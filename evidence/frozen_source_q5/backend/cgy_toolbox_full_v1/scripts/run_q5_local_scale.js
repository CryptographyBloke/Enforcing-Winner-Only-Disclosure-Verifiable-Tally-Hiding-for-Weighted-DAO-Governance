"use strict";

// Q5 local application-only admission profile for native scale measurements.  It
// preserves the ballot relation, Groth16 verifier, registry/nullifier checks,
// and exact ciphertext coordinates, while replacing only the bounded N=8
// blockchain transport with a sealed local board.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const readline = require("readline");
const { provisionFreshTestOnly } = require("../src/threshold_setup");
const { publicSetupToJson, ciphertextFromJson } = require("../src/codec");
const { prepareFreshBallots } = require("../src/n8_ballots");
const { admitLocalProofBoard } = require("../src/local_admission");
const { createTrusteeAuthenticationRegistry, CanonicalAtomicBroadcastBoard, canonicalJson, verifyBroadcastTranscript } = require("../src/broadcast_board");
const { buildLogicalDecisionCiphertext, runFinalRelease, verifyFinalRelease, finalReleaseRecordToJson } = require("../src/final_release");
const { ciphertextEquals } = require("../src/elgamal");
const { runNativeWeightedArithmetic } = require("../../cgy_native/tools/native_arithmetic_scheduler");
const { verifyNativeDag, verifyNativeDagFile } = require("../../cgy_native/tools/native_gate_bridge");
const { PROTOCOL_VERSION } = require("../src/group_oracle");

function required(name) {
  if (!process.env[name]) throw new Error(`E_LOCAL_SCALE_ENV: ${name} is required`);
  return process.env[name];
}

function now() { return process.hrtime.bigint(); }
function seconds(start) { return Number(now() - start) / 1e9; }
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
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
    wasmPath: path.join(root, "07_implementation", "logs", "bit_ballot", "build", "matrix", "vote_bit_full_8", "O1", "vote_bit_full_8_js", "vote_bit_full_8.wasm"),
    zkeyPath: path.join(root, "07_implementation", "logs", "bit_ballot", "groth16", "vote_bit_full_8", "vote_bit_full_8_final.zkey"),
    vkeyPath: path.join(root, "07_implementation", "logs", "bit_ballot", "groth16", "vote_bit_full_8", "verification_key.json"),
  };
}

function graphShape(count) {
  const shapes = { 8: [134, 72, 4], 64: [1086, 147, 32], 256: [4350, 207, 128], 1024: [17406, 275, 512] };
  return shapes[count] || [null, null, null];
}

async function main() {
  const count = Number(required("CGY_LOCAL_N"));
  const runDirectory = path.resolve(required("CGY_LOCAL_RUN_DIRECTORY"));
  if (fs.existsSync(runDirectory)) throw new Error(`E_LOCAL_RUN_EXISTS: refusing to overwrite ${runDirectory}`);
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
  const votes = Array.from({ length: count }, (_, index) => (index * 7 + 1) % 2);
  const weights = Array.from({ length: count }, (_, index) => (index * 37 + 11) % 256);
  const ballotStarted = now();
  const generated = await prepareFreshBallots({
    count,
    committeeKey: setupBundle.publicSetup.committeeKey,
    pollId,
    votes,
    weights,
    artifacts: artifacts(artifactRoot),
  });
  const ballotSeconds = seconds(ballotStarted);
  const publicSetup = publicSetupToJson(setupBundle.publicSetup);
  writeNew(path.join(runDirectory, "public_setup.json"), publicSetup);
  writeNew(path.join(runDirectory, "ballot_public_proofs.json"), generated.publicProofs);
  writeNew(path.join(runDirectory, "ballot_public_context.json"), {
    schema: "FC2027-CGY-TOOLBOX-FULL-V1/LOCAL-BALLOT-PUBLIC-CONTEXT/V1",
    count,
    registryRoot: generated.registryRoot.toString(10),
    pollId,
    committeeKey: { x: setupBundle.publicSetup.committeeKey.x.toString(10), y: setupBundle.publicSetup.committeeKey.y.toString(10) },
  });
  const admissionStarted = now();
  const admitted = await admitLocalProofBoard({
    publicProofs: generated.publicProofs,
    verificationKey: JSON.parse(fs.readFileSync(artifacts(artifactRoot).vkeyPath, "utf8")),
    registryRoot: generated.registryRoot,
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
    // The n=256 JSONL is larger than Node's single-string limit.  Use the same
    // already-existing lossless streaming path as n=1024; transcript bytes and
    // verifier semantics are unchanged.
    streamJournal: process.env.CGY_NATIVE_STREAM_JOURNAL === "1" || count >= 256,
    streamNative: count >= 256 || process.env.CGY_NATIVE_STREAM_NATIVE === "1",
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
  if (count >= 256) {
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
  const oracleResult = generated.oracleWeightedSum >= tau ? 1 : 0;
  if (!ciphertextEquals(ciphertextFromJson(replay.result), logical.ciphertext)) throw new Error("E_LOCAL_REPLAY_RESULT_MISMATCH");
  if (release.resultBit !== oracleResult) throw new Error("E_LOCAL_ORACLE_MISMATCH");
  const transcriptHash = sha256(Buffer.concat([Buffer.from(`${PROTOCOL_VERSION}/LOCAL-COMPLETE-TRANSCRIPT/V1`), Buffer.from(setupBundle.publicSetup.setupHash, "hex"), Buffer.from(admitted.sealedBoardHash, "hex"), Buffer.from(journalInfo.sha256, "hex"), Buffer.from(sha256(finalBytes), "hex")]));
  const [gates, depth, maxReadyWidth] = graphShape(count);
  const manifest = {
    schema: "FC2027-CGY-TOOLBOX-FULL-V1-Q5/LOCAL-SCALE-MANIFEST/V1",
    profile: "FC2027-CGY-TOOLBOX-FULL-V1-Q5",
    previousReferenceThreshold: "3_OF_5",
    finalReferenceThreshold: "5_OF_5",
    protocolVersion: PROTOCOL_VERSION,
    count,
    executionId,
    setupHash: setupBundle.publicSetup.setupHash,
    registryRoot: generated.registryRoot.toString(10),
    tau,
    gates: tally.gateCount,
    derivedGates: gates,
    depth,
    maxReadyWidth,
    resultBit: release.resultBit,
    oracleResult,
    transcriptHash,
    timing: { setupSeconds, ballotSeconds, admissionSeconds, backendSeconds, replaySeconds, finalReleaseSeconds: finalSeconds, totalSeconds: setupSeconds + ballotSeconds + admissionSeconds + backendSeconds + replaySeconds + finalSeconds, transcriptBytes: journalInfo.bytes + finalBytes.length, native: tally.timing },
    hashes: { publicSetupSha256: sha256(fs.readFileSync(path.join(runDirectory, "public_setup.json"))), proofsSha256: sha256(fs.readFileSync(path.join(runDirectory, "ballot_public_proofs.json"))), admissionSha256: sha256(fs.readFileSync(path.join(runDirectory, "local_admission_board.json"))), journalSha256: journalInfo.sha256, finalSha256: sha256(finalBytes) },
  };
  writeNew(path.join(runDirectory, "manifest.json"), manifest);
  process.stdout.write(`Q5_LOCAL_NATIVE_EXECUTION=PASS\nN=${count}\nGATES=${tally.gateCount}\nBACKEND_SECONDS=${backendSeconds.toFixed(3)}\nREPLAY_SECONDS=${replaySeconds.toFixed(3)}\nORACLE_MATCH=YES\nPUBLIC_REPLAY=PASS\nFINAL_THRESHOLD=5_OF_5\n`);
}

main().then(() => process.exit(0)).catch((error) => { process.stderr.write(`${error.code || "E_LOCAL_SCALE"}: ${error.stack || error.message}\n`); process.exit(1); });
