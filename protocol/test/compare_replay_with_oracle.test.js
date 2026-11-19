"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { test } = require("node:test");

const repositoryRoot = path.resolve(__dirname, "../..");
const comparator = path.join(repositoryRoot, "protocol", "scripts", "compare_replay_with_oracle.js");

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function createSepoliaFixture(t, oracleVotes) {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "winner-only-oracle-comparison-"));
  t.after(() => fs.rmSync(temporaryRoot, { recursive: true, force: true }));
  const publicDirectory = path.join(temporaryRoot, "public");
  const privateOracleDirectory = path.join(temporaryRoot, "private-oracle");
  fs.mkdirSync(publicDirectory);
  fs.mkdirSync(privateOracleDirectory);

  const transcriptHash = "a".repeat(64);
  writeJson(path.join(publicDirectory, "manifest.json"), {
    schema: "winner-only-disclosure/sepolia-manifest/v1",
    transcriptHash,
    resultBit: 1,
    tau: 500,
    gateCount: 134,
    depth: 72,
    maxReadyWidth: 4,
    timing: {
      producerTotalMs: 1000,
      transcriptBytes: 4096,
      ballotProofGenerationMs: 100,
      chainAdmissionMs: 50,
      cgyTallyBackendMs: 300,
      finalReleaseMs: 20,
    },
    deployment: { acceptedBallots: Array.from({ length: 8 }, (_, position) => ({ position })) },
  });
  writeJson(path.join(publicDirectory, "public_replay.json"), {
    status: "PASS",
    transcriptHash,
    resultBit: 1,
    timing: { replayTotalMs: 500 },
  });
  writeJson(path.join(privateOracleDirectory, "cleartext_oracle_inputs.json"), {
    votes: oracleVotes,
    weights: Array.from({ length: 8 }, () => 80),
    tau: 500,
  });
  return { publicDirectory, privateOracleDirectory };
}

function compareFixture(fixture) {
  return spawnSync(process.execPath, [comparator], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      CGY_LOCAL_RUN_DIRECTORY: "",
      CGY_N8_RUN_DIRECTORY: fixture.publicDirectory,
      CGY_N8_ORACLE_DIRECTORY: fixture.privateOracleDirectory,
    },
  });
}

test("compares an Arbitrum Sepolia manifest after public replay and records safe results", (t) => {
  const fixture = createSepoliaFixture(t, Array.from({ length: 8 }, () => 1));
  const result = compareFixture(fixture);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /ORACLE_COMPARISON=PASS/);
  assert.match(result.stdout, /N=8/);

  const summary = JSON.parse(fs.readFileSync(path.join(fixture.publicDirectory, "benchmark_summary.json"), "utf8"));
  assert.equal(summary.n, 8);
  assert.equal(summary.gateCount, 134);
  assert.equal(summary.dagDepth, 72);
  assert.equal(summary.maximumReadyWidth, 4);
  assert.equal(summary.independentReplayWallSeconds, 0.5);
  assert.equal(summary.oracleMatchesProtocol, true);
  assert.equal(Object.hasOwn(summary, "votes"), false);
  assert.equal(Object.hasOwn(summary, "weights"), false);

  const manifest = JSON.parse(fs.readFileSync(path.join(fixture.publicDirectory, "manifest.json"), "utf8"));
  assert.equal(manifest.validation.publicReplay.status, "PASS");
  assert.equal(manifest.validation.oracleComparison.status, "PASS");
  assert.equal(manifest.validation.oracleComparison.inputsIsolated, true);
  assert.equal(Object.hasOwn(manifest, "votes"), false);
  assert.equal(Object.hasOwn(manifest, "weights"), false);
});

test("records a failed oracle comparison and exits nonzero", (t) => {
  const fixture = createSepoliaFixture(t, Array.from({ length: 8 }, () => 0));
  const result = compareFixture(fixture);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /ORACLE_COMPARISON=FAIL/);
  const manifest = JSON.parse(fs.readFileSync(path.join(fixture.publicDirectory, "manifest.json"), "utf8"));
  assert.equal(manifest.validation.publicReplay.status, "PASS");
  assert.equal(manifest.validation.oracleComparison.status, "FAIL");
  assert.equal(manifest.validation.oracleComparison.oracleResultBit, 0);
});

test("does not read oracle inputs before a passing public replay", (t) => {
  const fixture = createSepoliaFixture(t, Array.from({ length: 8 }, () => 1));
  fs.writeFileSync(path.join(fixture.publicDirectory, "public_replay.json"), JSON.stringify({ status: "FAIL" }));
  fs.rmSync(fixture.privateOracleDirectory, { recursive: true, force: true });
  const result = compareFixture(fixture);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /public replay has not passed/);
});
