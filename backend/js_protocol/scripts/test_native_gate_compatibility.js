"use strict";

const childProcess = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const repositoryRoot = path.resolve(__dirname, "../../..");
const nativeBinary = process.env.CGY_NATIVE_BIN || path.join(
  repositoryRoot,
  "backend",
  "cgy_native",
  "target",
  "release",
  process.platform === "win32" ? "cgy-native.exe" : "cgy-native",
);
const fixtureRoot = path.join(repositoryRoot, "backend", "cgy_native", "testdata");
const jsFixture = path.join(fixtureRoot, "javascript_single_gate.json");
const rustFixture = path.join(fixtureRoot, "rust_single_gate.json");
const jsVerifier = path.join(repositoryRoot, "backend", "cgy_native", "tools", "deterministic_gate_fixture.js");

function run(binary, args, input = undefined) {
  const result = childProcess.spawnSync(binary, args, {
    input,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    windowsHide: true,
  });
  if (result.error || result.status !== 0) {
    throw new Error(`${path.basename(binary)} failed (${result.status}): ${result.stderr || result.error || "no error output"}`);
  }
  return result.stdout.trim();
}

if (!fs.existsSync(nativeBinary)) throw new Error(`native binary missing: ${nativeBinary}; build it with cargo build --release`);
const javascriptTranscript = fs.readFileSync(jsFixture, "utf8");
run(nativeBinary, ["--verify-stdin"], javascriptTranscript);
const javascriptResult = run(process.execPath, [jsVerifier, "verify", rustFixture]);
if (javascriptResult !== "JS_VERIFIES_RUST_GATE=PASS") throw new Error("JavaScript did not verify the Rust gate transcript");
process.stdout.write("JS_GATE_VERIFIED_BY_RUST=PASS\nRUST_GATE_VERIFIED_BY_JS=PASS\n");
