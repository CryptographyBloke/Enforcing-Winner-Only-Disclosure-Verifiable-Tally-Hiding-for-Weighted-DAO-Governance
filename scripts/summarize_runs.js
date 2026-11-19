"use strict";

const fs = require("node:fs");
const path = require("node:path");

const repositoryRoot = path.resolve(__dirname, "..");

function readJson(filePath) { return JSON.parse(fs.readFileSync(filePath, "utf8")); }

function readFreshRuns(runsRoot = path.join(repositoryRoot, "runs")) {
  if (!fs.existsSync(runsRoot)) return [];
  const rows = [];
  for (const entry of fs.readdirSync(runsRoot, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const publicDirectory = path.join(runsRoot, entry.name, "public");
    const manifestPath = path.join(publicDirectory, "manifest.json");
    const performancePath = path.join(publicDirectory, "performance.json");
    const verificationPath = path.join(publicDirectory, "verification.json");
    if (![manifestPath, performancePath, verificationPath].every(fs.existsSync)) continue;
    const manifest = readJson(manifestPath);
    const performance = readJson(performancePath);
    const verification = readJson(verificationPath);
    if (!manifest.runId || manifest.execution !== "local" || verification.status !== "PASS") continue;
    rows.push({ runId: manifest.runId, manifest, performance, verification });
  }
  return rows.sort((left, right) => left.manifest.count - right.manifest.count || left.runId.localeCompare(right.runId));
}

function markdown(rows) {
  const heading = "| n | gates | depth | proving | admission | backend | release | replay | total | verification |\n|---:|---:|---:|---:|---:|---:|---:|---:|---:|:---:|";
  const values = rows.map(({ performance }) => `| ${performance.n} | ${performance.gates} | ${performance.scheduledDepth} | ${performance.provingSeconds.toFixed(3)}s | ${performance.admissionSeconds.toFixed(3)}s | ${performance.backendSeconds.toFixed(3)}s | ${performance.releaseSeconds.toFixed(3)}s | ${performance.independentReplaySeconds.toFixed(3)}s | ${performance.totalPipelineSeconds.toFixed(3)}s | ${performance.verification} |`);
  return `# Fresh cleaned-workspace experiments\n\nValues are parsed from new run artifacts. Historical Q5 records are not mixed into this table.\n\n${heading}\n${values.join("\n")}\n`;
}

function csv(rows) {
  const fields = ["run_id", "n", "gates", "depth", "proving_seconds", "admission_seconds", "backend_seconds", "release_seconds", "replay_seconds", "total_seconds", "verification"];
  const values = rows.map(({ runId, performance }) => [runId, performance.n, performance.gates, performance.scheduledDepth, performance.provingSeconds, performance.admissionSeconds, performance.backendSeconds, performance.releaseSeconds, performance.independentReplaySeconds, performance.totalPipelineSeconds, performance.verification].join(","));
  return `${fields.join(",")}\n${values.join("\n")}\n`;
}

function main(argv) {
  const formatIndex = argv.indexOf("--format");
  const format = formatIndex >= 0 ? argv[formatIndex + 1] : "markdown";
  const outputIndex = argv.indexOf("--output");
  const output = outputIndex >= 0 ? path.resolve(repositoryRoot, argv[outputIndex + 1]) : null;
  const runsIndex = argv.indexOf("--runs");
  const runsRoot = runsIndex >= 0 ? path.resolve(repositoryRoot, argv[runsIndex + 1]) : path.join(repositoryRoot, "runs");
  if (!(["markdown", "csv"].includes(format))) throw new Error("--format must be markdown or csv");
  if (outputIndex >= 0 && !argv[outputIndex + 1]) throw new Error("--output requires a file path");
  if (runsIndex >= 0 && !argv[runsIndex + 1]) throw new Error("--runs requires a directory path");
  const rows = readFreshRuns(runsRoot);
  const result = format === "csv" ? csv(rows) : markdown(rows);
  if (output) fs.writeFileSync(output, result, { flag: "wx" });
  else process.stdout.write(result);
}

if (require.main === module) {
  try { main(process.argv.slice(2)); }
  catch (error) { process.stderr.write(`SUMMARY_FAILED: ${error.message}\n`); process.exit(1); }
}

module.exports = { readFreshRuns, markdown, csv };
