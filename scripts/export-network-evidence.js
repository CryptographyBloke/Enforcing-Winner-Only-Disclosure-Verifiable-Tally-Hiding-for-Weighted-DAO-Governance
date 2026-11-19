"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const publicFiles = [
  "public_replay.json",
  "benchmark_summary.json",
  "final_release.json",
  "gate_transcript.jsonl",
  "manifest.json",
  "verification.json",
  "ballot_public_context.json",
  "ballot_public_proofs.json",
  "local_admission_board.json",
  "public_setup.json",
  "verification_key.json",
];
const logFiles = [
  "board.stdout.log",
  "board.stderr.log",
  "public-replay.log",
  "public-replay.stderr.log",
  "oracle-comparison.log",
  "oracle-comparison.stderr.log",
  ...Array.from({ length: 5 }, (_, index) => `trustee-${index + 1}.stdout.log`),
  ...Array.from({ length: 5 }, (_, index) => `trustee-${index + 1}.stderr.log`),
  ...Array.from({ length: 5 }, (_, index) => `trustee-${index + 1}.result.json`),
];

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function parseArgs(argv) {
  const options = { runsRoot: path.join(root, "runs"), runIds: null };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--runs-root") options.runsRoot = path.resolve(root, argv[++index]);
    else if (argv[index] === "--runs") options.runIds = argv[++index].split(",").map((value) => value.trim()).filter(Boolean);
    else throw new Error(`unknown argument ${argv[index]}`);
  }
  return options;
}

function copyAllowlisted(sourceDirectory, outputDirectory, allowlist) {
  const copied = [];
  for (const name of allowlist) {
    const source = path.join(sourceDirectory, name);
    if (!fs.existsSync(source) || !fs.statSync(source).isFile()) continue;
    const target = path.join(outputDirectory, name);
    fs.copyFileSync(source, target, fs.constants.COPYFILE_EXCL);
    copied.push({ path: path.relative(root, target).split(path.sep).join("/"), bytes: fs.statSync(target).size, sha256: sha256File(target) });
  }
  return copied;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const candidateIds = options.runIds || fs.readdirSync(options.runsRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name.startsWith("network-02_tcp_replay_"))
    .filter((entry) => fs.existsSync(path.join(options.runsRoot, entry.name, "network_manifest.json")))
    .map((entry) => entry.name);
  const selected = candidateIds.map((id) => {
    const runRoot = path.join(options.runsRoot, id);
    const manifestPath = path.join(runRoot, "network_manifest.json");
    if (!fs.existsSync(manifestPath)) throw new Error(`run is incomplete and cannot be exported: ${id}`);
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    if (manifest.verification.publicReplay !== "PASS" || manifest.verification.oracleComparison !== "PASS") {
      throw new Error(`run has not passed public replay and oracle comparison: ${id}`);
    }
    return { id, runRoot, manifest };
  });
  if (selected.length === 0) throw new Error("no verified network runs were selected");

  const now = new Date();
  const exportId = `network-02_public_export_${now.toISOString().replace(/[-:.TZ]/g, "").slice(0, 14)}_${crypto.randomBytes(3).toString("hex")}`;
  const outputRoot = path.join(options.runsRoot, exportId);
  fs.mkdirSync(outputRoot, { recursive: false });
  const exportedRuns = [];
  for (const { id, runRoot, manifest } of selected) {
    const targetRoot = path.join(outputRoot, id);
    const transportTarget = path.join(targetRoot, "transport");
    const replayTarget = path.join(targetRoot, "replay", "public");
    const logsTarget = path.join(targetRoot, "logs");
    for (const directory of [transportTarget, replayTarget, logsTarget]) fs.mkdirSync(directory, { recursive: true });
    const copied = [
      ...copyAllowlisted(runRoot, targetRoot, ["network_manifest.json"]),
      ...copyAllowlisted(path.join(runRoot, "transport"), transportTarget, ["board-summary.json", "canonical-board-events.jsonl", "canonical-board-export.json"]),
      ...copyAllowlisted(path.join(runRoot, "replay", "public"), replayTarget, publicFiles),
      ...copyAllowlisted(path.join(runRoot, "logs"), logsTarget, logFiles),
    ];
    if (!copied.some((file) => file.path.endsWith("public_replay.json"))) throw new Error(`public replay result is missing for ${id}`);
    exportedRuns.push({ runId: id, n: manifest.experiment.n, delayMs: manifest.configuredDelay.oneWayDelayMs, mode: manifest.mode, publicFiles: copied });
  }

  const header = ["runId", "n", "oneWayDelayMs", "targetRttMs", "measuredRttMedianMs", "measuredRttP95Ms", "transportWallSeconds", "inProcessBoardSeconds", "independentReplaySeconds", "oracleComparisonSeconds", "barriers", "logicalSubmissions", "applicationFrames", "applicationBytes", "publicReplay", "oracleComparison"];
  const csv = [header.join(","), ...selected.map(({ id, runRoot, manifest }) => {
    const replayPath = path.join(runRoot, "replay", "public", "public_replay.json");
    const comparisonPath = path.join(runRoot, "replay", "public", "benchmark_summary.json");
    const replay = JSON.parse(fs.readFileSync(replayPath, "utf8"));
    const comparison = JSON.parse(fs.readFileSync(comparisonPath, "utf8"));
    const replaySeconds = manifest.timing.independentPublicReplayMs !== undefined
      ? manifest.timing.independentPublicReplayMs / 1000
      : (replay.timing?.replayTotalMs ?? (replay.timing?.replaySeconds || 0) * 1000) / 1000;
    const oracleSeconds = manifest.timing.oracleComparisonMs !== undefined
      ? manifest.timing.oracleComparisonMs / 1000
      : comparison.oracleComparisonSeconds || 0;
    const values = [id, manifest.experiment.n, manifest.configuredDelay.oneWayDelayMs, manifest.configuredDelay.nominalTargetRttMs, manifest.timing.measuredRttMs.median, manifest.timing.measuredRttMs.p95, manifest.timing.transportWallMs / 1000, manifest.timing.inProcessBoardControlMs / 1000, replaySeconds, oracleSeconds, manifest.experiment.observedBarriers, manifest.experiment.logicalSubmissions, manifest.communication.applicationFramesReceivedByBoard + manifest.communication.applicationFramesSentByBoard, manifest.communication.applicationBytesReceivedByBoard + manifest.communication.applicationBytesSentByBoard, manifest.verification.publicReplay, manifest.verification.oracleComparison];
    return values.map((value) => value === null || value === undefined ? "" : String(value)).join(",");
  })].join("\n") + "\n";
  fs.writeFileSync(path.join(outputRoot, "summary.csv"), csv, { flag: "wx" });
  const commands = selected.map(({ id, runRoot, manifest }) => {
    const sourceRun = manifest.sourceRunPath || (manifest.experiment.n === 8
      ? "runs/2026-11-19_local_n8_8665073c/public"
      : "runs/2026-11-19_local_n64_network02b/public");
    return `$sourceRun = '${sourceRun}'; node protocol/scripts/run_tcp_transcript_transport.js --source-run $sourceRun --one-way-delay-ms ${manifest.configuredDelay.oneWayDelayMs}  # ${id}`;
  }).join("\n");
  fs.writeFileSync(path.join(outputRoot, "REPRODUCE.txt"), `Windows PowerShell / Bash commands\nRun a fresh local experiment and public replay first; keep its private oracle directory outside the public run tree.\n\n${commands}\n\nExport allowlist excludes private/oracle, workload inputs, private shares, witnesses, and environment files. TCP byte totals are application framing bytes.\n`, { flag: "wx" });
  const index = {
    schema: "winner-only-disclosure/network-public-export/v1",
    createdAtUtc: now.toISOString(),
    host: `${os.platform()} ${os.arch()}`,
    exportRoot: path.relative(root, outputRoot).split(path.sep).join("/"),
    exportedRuns,
    summaryCsvSha256: sha256File(path.join(outputRoot, "summary.csv")),
    reproduceCommandsSha256: sha256File(path.join(outputRoot, "REPRODUCE.txt")),
  };
  fs.writeFileSync(path.join(outputRoot, "export-index.json"), `${JSON.stringify(index, null, 2)}\n`, { flag: "wx" });
  process.stdout.write(`NETWORK_PUBLIC_EXPORT=${path.relative(root, outputRoot)}\nRUNS=${selected.length}\n`);
}

try { main(); }
catch (error) {
  process.stderr.write(`NETWORK_EXPORT_ERROR=${error.stack || error.message}\n`);
  process.exitCode = 1;
}
