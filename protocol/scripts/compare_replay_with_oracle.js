"use strict";

// Evaluation-only comparator. It refuses to open oracle inputs until the
// independent public replay has passed and agrees with the producer manifest.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const repositoryRoot = path.resolve(__dirname, "..", "..");
const runDirectory = path.resolve(repositoryRoot, process.env.CGY_LOCAL_RUN_DIRECTORY || process.env.CGY_N8_RUN_DIRECTORY || "");
const oracleDirectory = path.resolve(repositoryRoot, process.env.CGY_N8_ORACLE_DIRECTORY || `${runDirectory}_oracle`);

function requireCondition(value, message) {
  if (!value) throw new Error(`E_ORACLE_COMPARE: ${message}`);
}

function firstFinite(...values) {
  return values.find((value) => Number.isFinite(value)) ?? null;
}

function main() {
  requireCondition(fs.existsSync(runDirectory), "public run directory is missing");
  const manifestPath = path.join(runDirectory, "manifest.json");
  const manifestBytes = fs.readFileSync(manifestPath);
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const replayName = process.env.CGY_PUBLIC_REPLAY_FILE || "public_replay.json";
  const replayPath = path.join(runDirectory, replayName);
  const replayBytes = fs.readFileSync(replayPath);
  const replay = JSON.parse(replayBytes.toString("utf8"));
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
  const count = Number.isSafeInteger(manifest.count)
    ? manifest.count
    : (Array.isArray(manifest.deployment?.acceptedBallots) ? manifest.deployment.acceptedBallots.length : null);
  requireCondition(Number.isSafeInteger(count) && count > 0, "manifest ballot count is missing");
  requireCondition(oracle.votes.length === count && oracle.weights.length === count, "oracle input length does not match ballot count");
  requireCondition(Number.isSafeInteger(oracle.tau) && oracle.tau === manifest.tau, "oracle threshold does not match protocol manifest");
  requireCondition(oracle.votes.every((vote) => vote === 0 || vote === 1), "oracle vote vector is malformed");
  requireCondition(oracle.weights.every((weight) => Number.isInteger(weight) && weight >= 0 && weight <= 255), "oracle weight vector is malformed");
  const comparisonStarted = process.hrtime.bigint();
  const weightedSum = oracle.votes.reduce((sum, vote, index) => sum + vote * oracle.weights[index], 0);
  const oracleResultBit = weightedSum >= oracle.tau ? 1 : 0;
  const matched = oracleResultBit === replay.resultBit;
  const replaySeconds = replay.timing && Number.isFinite(replay.timing.replaySeconds)
    ? replay.timing.replaySeconds
    : Number(replay.timing && replay.timing.replayTotalMs || 0) / 1000;
  const timing = manifest.timing || {};
  const producerSeconds = firstFinite(timing.totalSeconds, Number(timing.producerTotalMs) / 1000) ?? 0;
  const replayMs = firstFinite(replay.timing && replay.timing.replayTotalMs, replaySeconds * 1000) ?? 0;
  const comparisonMs = Number(process.hrtime.bigint() - comparisonStarted) / 1e6;
  const replaySha256 = crypto.createHash("sha256").update(replayBytes).digest("hex");
  const summary = {
    schema: "winner-only-disclosure/benchmark-summary/v1",
    n: count,
    gateCount: firstFinite(manifest.gates, manifest.gateCount),
    dagDepth: manifest.depth,
    maximumReadyWidth: manifest.maxReadyWidth,
    ballotProvingWallSeconds: firstFinite(timing.ballotProvingSeconds, Number(timing.ballotProofGenerationMs) / 1000),
    admissionWallSeconds: firstFinite(timing.admissionSeconds, Number(timing.chainAdmissionMs) / 1000),
    backendWallSeconds: firstFinite(timing.backendSeconds, Number(timing.cgyTallyBackendMs) / 1000),
    releaseWallSeconds: firstFinite(timing.finalReleaseSeconds, Number(timing.finalReleaseMs) / 1000),
    producerReplayWallSeconds: firstFinite(timing.replaySeconds),
    independentReplayWallSeconds: replaySeconds,
    producerTotalWallSeconds: producerSeconds,
    totalWallSecondsIncludingIndependentReplay: producerSeconds + replaySeconds,
    fullPipelineVerificationSeconds: producerSeconds + replaySeconds + comparisonMs / 1000,
    oracleComparisonSeconds: comparisonMs / 1000,
    canonicalTranscriptBytes: firstFinite(manifest.canonicalTranscriptBytes, timing.transcriptBytes),
    compactTranscriptBytes: firstFinite(manifest.compactTranscriptBytes),
    finalResultBit: replay.resultBit,
    oracleResultBit,
    oracleMatchesProtocol: matched,
  };
  const summaryBytes = Buffer.from(`${JSON.stringify(summary, null, 2)}\n`);
  fs.writeFileSync(path.join(runDirectory, "benchmark_summary.json"), summaryBytes);
  manifest.validation = {
    ...(manifest.validation || {}),
    publicReplay: { status: "PASS", sha256: replaySha256 },
    oracleComparison: {
      status: matched ? "PASS" : "FAIL",
      matchesReleasedBit: matched,
      finalResultBit: replay.resultBit,
      oracleResultBit,
      inputsIsolated: true,
      summarySha256: crypto.createHash("sha256").update(summaryBytes).digest("hex"),
    },
  };
  manifest.timing = {
    ...timing,
    independentReplayMs: replayMs,
    oracleComparisonMs: comparisonMs,
    fullPipelineVerificationMs: producerSeconds * 1000 + replayMs + comparisonMs,
  };
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  process.stdout.write(`ORACLE_COMPARISON=${matched ? "PASS" : "FAIL"}\nN=${count}\nRESULT_BIT=${replay.resultBit}\nORACLE_RESULT_BIT=${oracleResultBit}\nORACLE_INPUTS_ISOLATED=YES\n`);
  if (!matched) process.exitCode = 1;
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error.code || "E_ORACLE_COMPARE"}: ${error.message}\n`);
  process.exitCode = 1;
}
