"use strict";

const fs = require("fs");
const path = require("path");
const { prepareFreshBallots } = require("../src/n8_ballots");

function required(name) {
  if (!process.env[name]) throw new Error(`E_CHILD_ENV: ${name} is required`);
  return process.env[name];
}

function writeNew(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
}

async function main() {
  const publicDirectory = path.resolve(required("CGY_LOCAL_BALLOT_DIRECTORY"));
  const oracleDirectory = path.resolve(required("CGY_N8_ORACLE_DIRECTORY"));
  fs.mkdirSync(oracleDirectory, { recursive: false });
  const count = Number(required("CGY_LOCAL_N"));
  const tau = Number(required("CGY_LOCAL_TAU"));
  const pollId = required("CGY_LOCAL_POLL_ID");
  const committeeKeyValue = JSON.parse(required("CGY_N8_COMMITTEE_KEY"));
  const committeeKey = { x: BigInt(committeeKeyValue.x), y: BigInt(committeeKeyValue.y) };
  const votes = Array.from({ length: count }, (_, index) => (index * 7 + 1) % 2);
  const weights = Array.from({ length: count }, (_, index) => (index * 37 + 11) % 256);
  const generated = await prepareFreshBallots({
    count,
    committeeKey,
    pollId,
    votes,
    weights,
    artifacts: {
      wasmPath: required("CGY_BALLOT_WASM"),
      zkeyPath: required("CGY_BALLOT_ZKEY"),
      vkeyPath: required("CGY_BALLOT_VKEY"),
    },
  });

  writeNew(path.join(publicDirectory, "ballot_public_proofs.json"), generated.publicProofs);
  writeNew(path.join(publicDirectory, "ballot_public_context.json"), {
    schema: "-CGY-TOOLBOX-FULL-V1/LOCAL-BALLOT-PUBLIC-CONTEXT/V1",
    count,
    registryRoot: generated.registryRoot.toString(10),
    pollId,
    committeeKey: { x: committeeKey.x.toString(10), y: committeeKey.y.toString(10) },
    artifactHashes: {
      wasmSha256: generated.artifacts.wasmSha256,
      zkeySha256: generated.artifacts.zkeySha256,
      vkeySha256: generated.artifacts.vkeySha256,
    },
  });
  writeNew(path.join(oracleDirectory, "cleartext_oracle_inputs.json"), {
    schema: "-CGY-TOOLBOX-FULL-V1/ISOLATED-CLEARTEXT-ORACLE-INPUTS/V1",
    votes,
    weights,
    tau,
  });
  process.stdout.write(`FRESH_BALLOT_PROOFS=PASS\nN=${count}\nORACLE_INPUTS_ISOLATED=YES\n`);
}

main().then(() => process.exit(0)).catch((error) => {
  process.stderr.write(`${error.code || "E_BALLOT_CHILD"}: ${error.stack || error.message}\n`);
  process.exit(1);
});
