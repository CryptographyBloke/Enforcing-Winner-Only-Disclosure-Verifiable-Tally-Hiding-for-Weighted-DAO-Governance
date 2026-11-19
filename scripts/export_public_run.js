"use strict";

const fs = require("node:fs");
const path = require("node:path");

const PUBLIC_FILES = [
  "manifest.json", "performance.json", "verification.json", "benchmark_summary.json", "public_replay.json",
  "public_setup.json", "verification_key.json", "ballot_public_proofs.json", "ballot_public_context.json",
  "local_admission_board.json", "final_release.json", "gate_transcript.jsonl", "gate_transcript.compact.bin",
];
const repositoryRoot = path.resolve(__dirname, "..");

function exportPublicRun(sourcePublicDirectory, destination) {
  const source = path.resolve(repositoryRoot, sourcePublicDirectory);
  const output = path.resolve(repositoryRoot, destination);
  const relativeOutput = path.relative(path.join(repositoryRoot, "runs"), output);
  if (relativeOutput.startsWith("..") || path.isAbsolute(relativeOutput)) {
    throw new Error("public exports must be written under this repository's runs/ directory");
  }
  if (!fs.existsSync(path.join(source, "manifest.json"))) throw new Error("public run manifest is missing");
  if (fs.existsSync(output)) throw new Error(`refusing to overwrite existing export: ${output}`);
  const verification = JSON.parse(fs.readFileSync(path.join(source, "verification.json"), "utf8"));
  const summary = JSON.parse(fs.readFileSync(path.join(source, "benchmark_summary.json"), "utf8"));
  if (verification.status !== "PASS" || summary.oracleMatchesProtocol !== true) {
    throw new Error("export is allowed only after public replay and isolated oracle comparison pass");
  }
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.mkdirSync(output, { recursive: false });
  const copied = [];
  for (const name of PUBLIC_FILES) {
    const filePath = path.join(source, name);
    if (!fs.existsSync(filePath)) continue;
    fs.copyFileSync(filePath, path.join(output, name), fs.constants.COPYFILE_EXCL);
    copied.push(name);
  }
  const unsafe = copied.filter((name) => /oracle|wtns|witness|secret|share|\.zkey$|\.seed$|\.key$/i.test(name));
  if (unsafe.length > 0) throw new Error(`export contains a private or setup artifact: ${unsafe.join(", ")}`);
  fs.writeFileSync(path.join(output, "EXPORT_README.md"), "This directory contains public verification artifacts from one completed local run. It excludes private oracle inputs, ballot witnesses, secret shares, proving keys, and build caches. The run is local and uses test-only Groth16 setup.\n", { flag: "wx" });
  return copied;
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length !== 4 || args[0] !== "--run" || args[2] !== "--out") {
    process.stderr.write("Usage: node scripts/export_public_run.js --run runs/<id>/public --out <new-directory>\n");
    process.exit(2);
  }
  try {
    const copied = exportPublicRun(args[1], args[3]);
    process.stdout.write(`PUBLIC_EXPORT=PASS\nFILES=${copied.length}\nOUTPUT=${path.resolve(args[3])}\n`);
  } catch (error) {
    process.stderr.write(`PUBLIC_EXPORT=FAIL\n${error.message}\n`);
    process.exit(1);
  }
}

module.exports = { exportPublicRun };
