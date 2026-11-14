"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..", "..", "..");
const externalRoot = process.env.CGY_PUBLIC_ARTIFACT_ROOT || "D:\\31831\\Desktop\\THproto-master";
const files = [];
function add(label, filePath) {
  if (!fs.existsSync(filePath)) throw new Error(`missing production artifact: ${filePath}`);
  const bytes = fs.readFileSync(filePath);
  files.push({ label, bytes: bytes.length, sha256: crypto.createHash("sha256").update(bytes).digest("hex") });
}
function addDirectory(label, directory, suffix = null) {
  for (const name of fs.readdirSync(directory).sort()) {
    const filePath = path.join(directory, name);
    if (fs.statSync(filePath).isFile() && (!suffix || name.endsWith(suffix))) add(`${label}/${name}`, filePath);
  }
}

add("backend/cgy_native/Cargo.toml", path.join(root, "backend/cgy_native/Cargo.toml"));
add("backend/cgy_native/Cargo.lock", path.join(root, "backend/cgy_native/Cargo.lock"));
addDirectory("backend/cgy_native/src", path.join(root, "backend/cgy_native/src"), ".rs");
addDirectory("backend/cgy_toolbox_full_v1/src", path.join(root, "backend/cgy_toolbox_full_v1/src"), ".js");
for (const relative of [
  "backend/cgy_toolbox_full_v1/package.json",
  "backend/cgy_toolbox_full_v1/package-lock.json",
  "backend/cgy_toolbox_full_v1/scripts/run_q5_local_scale.js",
  "backend/cgy_toolbox_full_v1/scripts/run_q5_sepolia_pipeline.js",
  "backend/cgy_toolbox_full_v1/scripts/replay_q5_sepolia_public.js",
  "backend/cgy_toolbox_full_v1/scripts/sepolia_q5_preflight.js",
  "backend/cgy_toolbox_full_v1/scripts/compare_q5_oracle.js",
  "backend/cgy_toolbox_full_v1/scripts/write_q5_provenance.js",
  "backend/cgy_toolbox_full_v1/scripts/write_q5_source_manifest.js",
  "backend/cgy_toolbox_full_v1/test/q5_threshold.test.js",
  "backend/cgy_toolbox_full_v1/test/q5_final_release.test.js",
  "backend/cgy_native/tools/deterministic_gate_q5.js",
]) add(relative, path.join(root, relative));
for (const relative of [
  "07_implementation/logs/bit_ballot/build/matrix/vote_bit_full_8/O1/vote_bit_full_8_js/vote_bit_full_8.wasm",
  "07_implementation/logs/bit_ballot/groth16/vote_bit_full_8/vote_bit_full_8_final.zkey",
  "07_implementation/logs/bit_ballot/groth16/vote_bit_full_8/verification_key.json",
  "07_implementation/arbitrum/artifacts/contracts/verifier.sol/Groth16Verifier.json",
  "07_implementation/arbitrum/artifacts/contracts/StrongN8Poll.sol/StrongN8Poll.json",
]) add(`external/${relative}`, path.join(externalRoot, relative));

const output = [
  "# FC2027 Q5 production source manifest",
  "PROFILE=FC2027-CGY-TOOLBOX-FULL-V1-Q5",
  "SOURCE_PARENT_COMMIT=0d49fed671ce33037a1b2d0a5b6007c3a5d17b97",
  "THRESHOLD_PARAMETER=TRUSTEES_5_DEGREE_4_THRESHOLD_5",
  ...files.map((entry) => `${entry.sha256}  ${entry.bytes}  ${entry.label}`),
  "",
].join("\n");
const outputPath = path.join(root, "CGY_Q5_PRODUCTION_SOURCE_MANIFEST.sha256");
fs.writeFileSync(outputPath, output, { flag: "wx" });
const digest = crypto.createHash("sha256").update(output, "utf8").digest("hex");
process.stdout.write(`SOURCE_MANIFEST_SHA256=${digest}\nFILES=${files.length}\nCARGO_LOCK_SHA256=${files.find((entry) => entry.label.endsWith("Cargo.lock")).sha256}\n`);
