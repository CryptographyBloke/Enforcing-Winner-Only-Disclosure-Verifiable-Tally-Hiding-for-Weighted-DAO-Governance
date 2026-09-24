"use strict";

// Local functional setup only. This deliberately creates a throwaway Groth16
// setup; it is not a production ceremony and must never be published.
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const childProcess = require("child_process");

const root = path.resolve(__dirname, "..", "..");
const source = path.join(root, "circuits", "prototypes", "strong_bit", "vote_bit_full_8.circom");
const circomlibRoot = path.join(root, "circuits", "node_modules");
const artifactsRoot = path.join(root, "implementation", "logs", "bit_ballot");
const compileDirectory = path.join(artifactsRoot, "build", "matrix", "vote_bit_full_8", "O1");
const zkeyDirectory = path.join(artifactsRoot, "groth16", "vote_bit_full_8");
const outputPrefix = path.join(compileDirectory, "vote_bit_full_8");
const r1csPath = `${outputPrefix}.r1cs`;
const symPath = `${outputPrefix}.sym`;
const wasmPath = path.join(compileDirectory, "vote_bit_full_8_js", "vote_bit_full_8.wasm");
const finalZkeyPath = path.join(zkeyDirectory, "vote_bit_full_8_final.zkey");
const initialZkey = path.join(zkeyDirectory, "vote_bit_full_8_initial.zkey");
const vkeyPath = path.join(zkeyDirectory, "verification_key.json");
const snarkjsCli = path.join(root, "backend", "js_protocol", "node_modules", "snarkjs", "build", "cli.cjs");

function fail(message) { throw new Error(`E_BALLOT_BUILD: ${message}`); }

function run(binary, args, stage, options = {}) {
  process.stdout.write(`${stage} ...\n`);
  const result = childProcess.spawnSync(binary, args, {
    cwd: root,
    encoding: "utf8",
    windowsHide: true,
    maxBuffer: 32 * 1024 * 1024,
    ...options,
  });
  if (result.error || result.status !== 0) {
    const detail = result.error ? result.error.message : `${result.stdout || ""}${result.stderr || ""}`;
    fail(`${path.basename(binary)} exited with ${result.status}: ${detail}`);
  }
  return result.stdout || "";
}

function removeIfPresent(filePath) {
  if (fs.existsSync(filePath)) fs.rmSync(filePath, { force: true });
}

function main() {
  const circom = process.env.CIRCOM_BIN || "circom";
  const version = run(circom, ["--version"], "Checking Circom version").trim();
  if (!version.includes("2.1.6")) fail(`Circom 2.1.6 is required; found ${version}`);
  if (!fs.existsSync(snarkjsCli)) fail("run npm ci in backend/js_protocol first");
  fs.mkdirSync(compileDirectory, { recursive: true });
  fs.mkdirSync(zkeyDirectory, { recursive: true });
  for (const generated of [r1csPath, symPath, wasmPath, initialZkey, finalZkeyPath, vkeyPath]) {
    if (fs.existsSync(generated)) fail(`refusing to overwrite ${path.relative(root, generated)}`);
  }

  run(circom, [source, "--r1cs", "--wasm", "--sym", "--O1", "-l", circomlibRoot, "-o", compileDirectory], "Compiling the ballot circuit");
  const info = run(process.execPath, [snarkjsCli, "r1cs", "info", r1csPath], "Reading the constraint count");
  const constraintsMatch = info.match(/(?:#\s*of\s*)?Constraints\s*:\s*(\d+)/i);
  if (!constraintsMatch) fail("could not read constraint count from snarkjs r1cs info output");
  const constraints = Number(constraintsMatch[1]);
  const power = Math.ceil(Math.log2(constraints)) + 1;
  if (!Number.isInteger(power) || power < 10 || power > 28) fail(`derived powers-of-tau power ${power} is outside the supported local range`);

  const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "-test-ptau-"));
  const ptau0 = path.join(temporaryDirectory, "pot0.ptau");
  const ptau1 = path.join(temporaryDirectory, "pot1.ptau");
  const phase2 = path.join(temporaryDirectory, "pot_final.ptau");
  try {
    run(process.execPath, [snarkjsCli, "powersoftau", "new", "bn128", String(power), ptau0], "Creating temporary test powers-of-tau");
    run(process.execPath, [snarkjsCli, "powersoftau", "contribute", ptau0, ptau1, "--name=local-test-only", `-e=${crypto.randomBytes(64).toString("hex")}`], "Contributing fresh test-only randomness");
    run(process.execPath, [snarkjsCli, "powersoftau", "prepare", "phase2", ptau1, phase2], "Preparing phase two test parameters");
    run(process.execPath, [snarkjsCli, "groth16", "setup", r1csPath, phase2, initialZkey], "Generating a local test-only Groth16 key");
    run(process.execPath, [snarkjsCli, "zkey", "contribute", initialZkey, finalZkeyPath, "--name=local-test-only", `-e=${crypto.randomBytes(64).toString("hex")}`], "Adding fresh test-only key randomness");
    run(process.execPath, [snarkjsCli, "zkey", "export", "verificationkey", finalZkeyPath, vkeyPath], "Exporting the local verification key");
  } finally {
    removeIfPresent(initialZkey);
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
  process.stdout.write(`BALLOT_ARTIFACTS=READY\nCIRCOM=${version}\nCONSTRAINTS=${constraints}\nTEST_ONLY_PTAU_POWER=${power}\nWASM=${path.relative(root, wasmPath)}\nZKEY=${path.relative(root, finalZkeyPath)}\nVKEY=${path.relative(root, vkeyPath)}\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
