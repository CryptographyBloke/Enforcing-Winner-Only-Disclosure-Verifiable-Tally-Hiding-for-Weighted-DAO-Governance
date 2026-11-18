"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { assertExpectedShape } = require("./experiment_config");

function readJson(filePath) { return JSON.parse(fs.readFileSync(filePath, "utf8")); }

function verifyRun(publicDirectory) {
  const manifest = readJson(path.join(publicDirectory, "manifest.json"));
  assertExpectedShape(manifest);
  if (manifest.profile !== "winner-only-disclosure/five-of-five/v1"
      || manifest.finalReferenceThreshold !== "5_OF_5") {
    throw new Error("run does not use the five-of-five reference profile");
  }
  if (manifest.parameters && (manifest.parameters.trustees !== 5
      || manifest.parameters.shamirPolynomialDegree !== 4
      || manifest.parameters.decryptionThreshold !== 5
      || manifest.parameters.voteBits !== 8)) {
    throw new Error("run cryptographic parameters differ from the five-of-five reference profile");
  }
  const replay = readJson(path.join(publicDirectory, "public_replay.json"));
  if (replay.status !== "PASS" || replay.oracleRead !== false
      || replay.transcriptHash !== manifest.transcriptHash
      || replay.gateCount !== manifest.gates) {
    throw new Error("independent public replay did not validate the manifest and transcript");
  }
  for (const name of ["public_setup.json", "ballot_public_proofs.json", "ballot_public_context.json",
    "local_admission_board.json", "final_release.json", "gate_transcript.jsonl", "verification_key.json"]) {
    if (!fs.existsSync(path.join(publicDirectory, name))) throw new Error(`missing public replay input: ${name}`);
  }
  if (fs.existsSync(path.join(publicDirectory, "cleartext_oracle_inputs.json"))
      || fs.existsSync(path.join(publicDirectory, "private"))) {
    throw new Error("private oracle data must remain outside the public directory");
  }
  return manifest;
}

if (require.main === module) {
  const runIndex = process.argv.indexOf("--run");
  if (runIndex < 0 || !process.argv[runIndex + 1]) {
    process.stderr.write("Usage: node scripts/verify-results.js --run <run>/public\n");
    process.exit(2);
  }
  try {
    const manifest = verifyRun(path.resolve(process.argv[runIndex + 1]));
    process.stdout.write(`RESULTS_VERIFIED=PASS\nN=${manifest.count}\nGATES=${manifest.gates}\nDEPTH=${manifest.depth}\n`);
  } catch (error) {
    process.stderr.write(`RESULTS_VERIFIED=FAIL\n${error.message}\n`);
    process.exit(1);
  }
}

module.exports = { verifyRun };
