"use strict";

// Evaluation-only comparator. It refuses to open oracle inputs until the
// independent public replay has passed and agrees with the producer manifest.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const repositoryRoot = path.resolve(__dirname, "..", "..", "..");
const runDirectory = path.resolve(repositoryRoot, process.env.CGY_LOCAL_RUN_DIRECTORY || process.env.CGY_N8_RUN_DIRECTORY || "");
const oracleDirectory = path.resolve(repositoryRoot, process.env.CGY_N8_ORACLE_DIRECTORY || `${runDirectory}_oracle`);

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function requireCondition(value, message) {
  if (!value) throw new Error(`E_ORACLE_COMPARE: ${message}`);
}

function main() {
  requireCondition(fs.existsSync(runDirectory), "public run directory is missing");
  const manifest = readJson(path.join(runDirectory, "manifest.json"));
  const replayName = process.env.CGY_PUBLIC_REPLAY_FILE || "public_replay.json";
  const replay = readJson(path.join(runDirectory, replayName));
  requireCondition(replay.status === "PASS", "independent public replay has not passed");
  requireCondition(replay.transcriptHash === manifest.transcriptHash, "replay transcript hash does not match the producer manifest");
  requireCondition(replay.resultBit === manifest.resultBit, "replay result bit does not match the producer manifest");
  const relativeOracle = path.relative(runDirectory, oracleDirectory);
  requireCondition(relativeOracle !== "" && (relativeOracle.startsWith("..") || path.isAbsolute(relativeOracle)), "oracle directory must be isolated outside the public run directory");

  // Oracle data is intentionally accessed only after the replay checks above.
  const oraclePath = path.join(oracleDirectory, "cleartext_oracle_inputs.json");
  const oracleBytes = fs.readFileSync(oraclePath);
  const oracle = JSON.parse(oracleBytes.toString("utf8"));
  requireCondition(Array.isArray(oracle.votes) && Array.isArray(oracle.weights), "oracle inputs are malformed");
  requireCondition(oracle.votes.length === manifest.count && oracle.weights.length === manifest.count, "oracle input length does not match ballot count");
  requireCondition(Number.isSafeInteger(oracle.tau) && oracle.tau === manifest.tau, "oracle threshold does not match protocol manifest");
  requireCondition(oracle.votes.every((vote) => vote === 0 || vote === 1), "oracle vote vector is malformed");
  requireCondition(oracle.weights.every((weight) => Number.isInteger(weight) && weight >= 0 && weight <= 255), "oracle weight vector is malformed");
  const weightedSum = oracle.votes.reduce((sum, vote, index) => sum + vote * oracle.weights[index], 0);
  const oracleResultBit = weightedSum >= oracle.tau ? 1 : 0;
  const matched = oracleResultBit === replay.resultBit;
  const replaySeconds = replay.timing && Number.isFinite(replay.timing.replaySeconds)
    ? replay.timing.replaySeconds
    : Number(replay.timing && replay.timing.replayTotalMs || 0) / 1000;
  const timing = manifest.timing || {};
  const producerSeconds = Number(timing.totalSeconds || 0);
  const summary = {
    schema: "winner-only-disclosure/benchmark-summary/v1",
    n: manifest.count,
    gateCount: manifest.gates,
    dagDepth: manifest.depth,
    maximumReadyWidth: manifest.maxReadyWidth,
    ballotProvingWallSeconds: timing.ballotProvingSeconds,
    admissionWallSeconds: timing.admissionSeconds,
    backendWallSeconds: timing.backendSeconds,
    releaseWallSeconds: timing.finalReleaseSeconds,
    producerReplayWallSeconds: timing.replaySeconds,
    independentReplayWallSeconds: replaySeconds,
    producerTotalWallSeconds: producerSeconds,
    totalWallSecondsIncludingIndependentReplay: producerSeconds + replaySeconds,
    canonicalTranscriptBytes: manifest.canonicalTranscriptBytes,
    compactTranscriptBytes: manifest.compactTranscriptBytes,
    finalResultBit: replay.resultBit,
    oracleResultBit,
    oracleMatchesProtocol: matched,
    oracleInputsSha256: crypto.createHash("sha256").update(oracleBytes).digest("hex"),
  };
  fs.writeFileSync(path.join(runDirectory, "benchmark_summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
  process.stdout.write(`ORACLE_COMPARISON=${matched ? "PASS" : "FAIL"}\nN=${manifest.count}\nRESULT_BIT=${replay.resultBit}\nORACLE_RESULT_BIT=${oracleResultBit}\nORACLE_INPUTS_ISOLATED=YES\n`);
  if (!matched) process.exitCode = 1;
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error.code || "E_ORACLE_COMPARE"}: ${error.message}\n`);
  process.exitCode = 1;
}
