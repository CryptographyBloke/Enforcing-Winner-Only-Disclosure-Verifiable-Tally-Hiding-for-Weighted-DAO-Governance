"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { parseArgs, updateRun } = require("./reproduce");
const { verifyRun } = require("./verify-results");
const { readFreshRuns, markdown } = require("./summarize_runs");
const { exportPublicRun } = require("./export_public_run");

function writeJson(filePath, value) { fs.writeFileSync(filePath, `${JSON.stringify(value)}\n`); }

test("reproduction CLI accepts the documented four-size syntax", () => {
  assert.deepEqual(parseArgs(["--sizes", "8,64,256,1024"]).sizes, [8, 64, 256, 1024]);
  assert.deepEqual(parseArgs(["--sizes", "8", "--build-artifacts"]).sizes, [8]);
  assert.throws(() => parseArgs(["--sizes", "8,16"]), /supported sizes are/);
});

test("run enrichment records the verification-key hash and only marks verified stages after oracle pass", (t) => {
  const publicDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "winner-only-enrich-"));
  t.after(() => fs.rmSync(publicDirectory, { recursive: true, force: true }));
  const vkey = Buffer.from("public verification key\n");
  fs.writeFileSync(path.join(publicDirectory, "verification_key.json"), vkey);
  writeJson(path.join(publicDirectory, "manifest.json"), {
    count: 256, gates: 4350, derivedGates: 4350, depth: 207, maxReadyWidth: 128, tau: 16320,
    profile: "winner-only-disclosure/five-of-five/v1", finalReferenceThreshold: "5_OF_5",
    transcriptHash: "abc", hashes: {},
    timing: { ballotProvingSeconds: 1, admissionSeconds: 2, backendSeconds: 3, finalReleaseSeconds: 4, replaySeconds: 5 },
  });
  writeJson(path.join(publicDirectory, "ballot_public_context.json"), {
    artifactHashes: { wasmSha256: "wasm-hash", zkeySha256: "zkey-hash", vkeySha256: "vkey-context-hash" },
  });
  writeJson(path.join(publicDirectory, "public_replay.json"), { status: "PASS", timing: { replaySeconds: 6 } });
  writeJson(path.join(publicDirectory, "benchmark_summary.json"), { oracleMatchesProtocol: true, oracleResultBit: 1 });

  const result = updateRun(publicDirectory, "run-256-test", 256, {
    trustees: 5, shamirDegree: 4, decryptionThreshold: 5, voteBits: 8,
    localScaleTauRule: "floor(255*n/4)", referenceThresholdTau: 500, referenceBallotCount: 8,
  }, {
    node: "v24", npm: "11", rustc: "rustc 1.98.1", cargo: "cargo 1.98.1", circom: "circom 2.1.6",
  }, { commit: "deadbeef", workingTreeDirty: false }, { fullPipelineSeconds: 20 });

  assert.equal(result.manifest.results.oracleComparison, "PASS");
  assert.equal(result.manifest.hashes.verificationKeySha256, crypto.createHash("sha256").update(vkey).digest("hex"));
  assert.equal(result.performance.independentReplaySeconds, 6);
  assert.equal(JSON.parse(fs.readFileSync(path.join(publicDirectory, "verification.json"), "utf8")).status, "PASS");
});

test("result verifier checks actual public replay, five-of-five profile, and structure", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "winner-only-verify-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const manifest = {
    count: 256, gates: 4350, derivedGates: 4350, depth: 207, maxReadyWidth: 128, tau: 16320,
    profile: "winner-only-disclosure/five-of-five/v1", finalReferenceThreshold: "5_OF_5",
    transcriptHash: "abc", parameters: { trustees: 5, shamirPolynomialDegree: 4, decryptionThreshold: 5, voteBits: 8 },
  };
  writeJson(path.join(root, "manifest.json"), manifest);
  writeJson(path.join(root, "public_replay.json"), { status: "PASS", oracleRead: false, transcriptHash: "abc", gateCount: 4350 });
  for (const name of ["public_setup.json", "ballot_public_proofs.json", "ballot_public_context.json", "local_admission_board.json", "final_release.json", "gate_transcript.jsonl", "verification_key.json"]) {
    fs.writeFileSync(path.join(root, name), "public\n");
  }
  assert.equal(verifyRun(root).count, 256);
  assert.throws(() => {
    writeJson(path.join(root, "cleartext_oracle_inputs.json"), { votes: [1] });
    verifyRun(root);
  }, /private oracle data/);
});

test("summary reads fresh run files and public export excludes private oracle inputs", (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "winner-only-fresh-runs-"));
  const publicDirectory = path.join(tempRoot, "runs", "one-run", "public");
  fs.mkdirSync(publicDirectory, { recursive: true });
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const runId = `test_${crypto.randomBytes(4).toString("hex")}`;
  writeJson(path.join(publicDirectory, "manifest.json"), { runId, execution: "local", count: 8 });
  writeJson(path.join(publicDirectory, "performance.json"), {
    n: 8, gates: 134, scheduledDepth: 72, provingSeconds: 1, admissionSeconds: 2,
    backendSeconds: 3, releaseSeconds: 4, independentReplaySeconds: 5, totalPipelineSeconds: 15, verification: "PASS",
  });
  writeJson(path.join(publicDirectory, "verification.json"), { status: "PASS" });
  const rows = readFreshRuns(path.join(tempRoot, "runs"));
  assert.equal(rows.length, 1);
  assert.match(markdown(rows), /\| 8 \| 134 \| 72 \|/);

  writeJson(path.join(publicDirectory, "benchmark_summary.json"), { oracleMatchesProtocol: true });
  for (const name of ["manifest.json", "performance.json", "verification.json", "benchmark_summary.json", "public_replay.json", "verification_key.json", "cleartext_oracle_inputs.json"]) {
    fs.writeFileSync(path.join(publicDirectory, name), name);
  }
  writeJson(path.join(publicDirectory, "verification.json"), { status: "PASS" });
  writeJson(path.join(publicDirectory, "benchmark_summary.json"), { oracleMatchesProtocol: true });
  const exportName = `test-export-${crypto.randomBytes(4).toString("hex")}`;
  const output = path.join("runs", exportName);
  const absoluteOutput = path.resolve(__dirname, "..", output);
  const relativeUnderRuns = path.relative(path.resolve(__dirname, "..", "runs"), absoluteOutput);
  assert.equal(relativeUnderRuns.startsWith(".."), false);
  t.after(() => fs.rmSync(absoluteOutput, { recursive: true, force: true }));
  exportPublicRun(publicDirectory, output);
  assert.equal(fs.existsSync(path.join(absoluteOutput, "cleartext_oracle_inputs.json")), false);
  assert.equal(fs.existsSync(path.join(absoluteOutput, "verification_key.json")), true);
});
