"use strict";

const fs = require("fs");
const path = require("path");
const { prepareFreshN8Ballots } = require("../src/n8_ballots");

function required(name) {
  if (!process.env[name]) throw new Error(`E_CHILD_ENV: ${name} is required`);
  return process.env[name];
}

function writeNew(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
}

async function main() {
  const publicDirectory = path.resolve(required("CGY_N8_PUBLIC_DIRECTORY"));
  const oracleDirectory = path.resolve(required("CGY_N8_ORACLE_DIRECTORY"));
  fs.mkdirSync(oracleDirectory, { recursive: false });
  const committeeKey = JSON.parse(required("CGY_N8_COMMITTEE_KEY"));
  const pollId = required("CGY_N8_POLL_ID");
  const tau = Number(required("CGY_N8_TAU"));
  const votes = [1, 0, 1, 1, 0, 1, 0, 1];
  const weights = [211, 19, 87, 43, 251, 129, 73, 33];
  const generated = await prepareFreshN8Ballots({
    committeeKey: { x: BigInt(committeeKey.x), y: BigInt(committeeKey.y) },
    pollId,
    votes,
    weights,
    artifacts: {
      wasmPath: required("CGY_BALLOT_WASM"),
      zkeyPath: required("CGY_BALLOT_ZKEY"),
      vkeyPath: required("CGY_BALLOT_VKEY"),
    },
  });
  writeNew(path.join(publicDirectory, "ballot_public_proofs.json"), generated.publicProofs.map((record) => ({
    index: record.index,
    proof: record.proof,
    publicSignals: record.publicSignals,
    provingMs: record.provingMs,
  })));
  writeNew(path.join(publicDirectory, "ballot_public_context.json"), {
    schema: "-CGY-TOOLBOX-FULL-V1/BALLOT-PUBLIC-CONTEXT/V1",
    registryRoot: generated.registryRoot.toString(10),
    pollId: String(pollId),
    committeeKey,
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
  fs.writeSync(process.stdout.fd, "FRESH_BALLOT_PROOFS=PASS\nORACLE_INPUTS_ISOLATED=YES\n");
}

main().then(() => {
  // SnarkJS may retain an idle worker handle after all proof artifacts and the
  // isolated oracle have been durably written. This test-only process owns no
  // protocol state, so terminate its completed boundary explicitly.
  process.exit(0);
}).catch((error) => {
  process.stderr.write(`${error.code || "E_BALLOT_CHILD"}: ${error.stack || error.message}\n`);
  process.exit(1);
});
