"use strict";

const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");

function csv(value) {
  const text = value === null || value === undefined ? "" : String(value);
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function parseArgs(argv) {
  const options = { runs: path.join(root, "runs"), output: path.join(root, "runs", "network-02-summary.csv") };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--runs") options.runs = path.resolve(root, argv[++index]);
    else if (argv[index] === "--output") options.output = path.resolve(root, argv[++index]);
    else throw new Error(`unknown argument ${argv[index]}`);
  }
  return options;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const rows = [];
  for (const entry of fs.readdirSync(options.runs, { withFileTypes: true })) {
    if (!entry.isDirectory() || !entry.name.startsWith("network-02_tcp_replay_")) continue;
    const runRoot = path.join(options.runs, entry.name);
    const manifestPath = path.join(runRoot, "network_manifest.json");
    if (!fs.existsSync(manifestPath)) continue;
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    const timing = manifest.timing;
    const network = manifest.communication;
    const replayPath = path.join(runRoot, "replay", "public", "public_replay.json");
    const comparisonPath = path.join(runRoot, "replay", "public", "benchmark_summary.json");
    const replay = fs.existsSync(replayPath) ? JSON.parse(fs.readFileSync(replayPath, "utf8")) : {};
    const comparison = fs.existsSync(comparisonPath) ? JSON.parse(fs.readFileSync(comparisonPath, "utf8")) : {};
    const replayMs = timing.independentPublicReplayMs ?? replay.timing?.replayTotalMs ?? (replay.timing?.replaySeconds || 0) * 1000;
    const oracleMs = timing.oracleComparisonMs ?? (comparison.oracleComparisonSeconds || 0) * 1000;
    rows.push({
      runId: manifest.runId,
      n: manifest.experiment.n,
      gates: manifest.experiment.gates,
      depth: manifest.experiment.depth,
      mode: manifest.mode,
      oneWayDelayMs: manifest.configuredDelay.oneWayDelayMs,
      targetRttMs: manifest.configuredDelay.nominalTargetRttMs,
      measuredRttMedianMs: timing.measuredRttMs.median,
      measuredRttP95Ms: timing.measuredRttMs.p95,
      transportWallSeconds: timing.transportWallMs / 1000,
      inProcessBoardSeconds: timing.inProcessBoardControlMs / 1000,
      tcpOverControlSeconds: timing.tcpMinusInProcessBoardMs / 1000,
      sourceBackendSeconds: manifest.sourceRunPerformance?.backendSeconds,
      sourceFullPipelineSeconds: manifest.sourceRunPerformance?.totalSeconds,
      independentReplaySeconds: replayMs / 1000,
      oracleComparisonSeconds: oracleMs / 1000,
      barriers: manifest.experiment.observedBarriers,
      logicalSubmissions: manifest.experiment.logicalSubmissions,
      applicationFrames: network.applicationFramesReceivedByBoard + network.applicationFramesSentByBoard,
      applicationBytes: network.applicationBytesReceivedByBoard + network.applicationBytesSentByBoard,
      durableEventLogBytes: network.durableEventLogBytes,
      publicReplay: manifest.verification.publicReplay,
      oracleComparison: manifest.verification.oracleComparison || "NOT_RECORDED",
      canonicalJournalPreserved: manifest.verification.canonicalJournalPreserved,
    });
  }
  rows.sort((left, right) => left.n - right.n || left.oneWayDelayMs - right.oneWayDelayMs || left.runId.localeCompare(right.runId));
  const columns = Object.keys(rows[0] || { runId: "" });
  fs.mkdirSync(path.dirname(options.output), { recursive: true });
  const output = [columns.join(","), ...rows.map((row) => columns.map((column) => csv(row[column])).join(","))].join("\n") + "\n";
  fs.writeFileSync(options.output, output, { flag: fs.existsSync(options.output) ? "w" : "wx" });
  process.stdout.write(`NETWORK_SUMMARY_ROWS=${rows.length}\nOUTPUT=${path.relative(root, options.output)}\n`);
}

try { main(); }
catch (error) {
  process.stderr.write(`NETWORK_SUMMARY_ERROR=${error.stack || error.message}\n`);
  process.exitCode = 1;
}
