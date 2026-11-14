"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const runDirectory = path.resolve(process.env.CGY_N8_RUN_DIRECTORY || "");
const oracleDirectory = path.resolve(process.env.CGY_N8_ORACLE_DIRECTORY || `${runDirectory}_oracle`);
const manifest = JSON.parse(fs.readFileSync(path.join(runDirectory, "manifest.json"), "utf8"));
const oracleBytes = fs.readFileSync(path.join(oracleDirectory, "cleartext_oracle.json"));
const oracle = JSON.parse(oracleBytes.toString("utf8"));
if (manifest.resultBit !== oracle.resultBit) throw new Error("Q5 oracle mismatch");
const output = {
  schema: "FC2027-CGY-TOOLBOX-FULL-V1-Q5/ISOLATED-ORACLE-COMPARISON/V1",
  resultBit: manifest.resultBit,
  oracleResult: oracle.resultBit,
  match: true,
  oracleArtifactSha256: crypto.createHash("sha256").update(oracleBytes).digest("hex"),
  oracleComputationIncludedInProtocol: false,
};
const outputPath = path.join(runDirectory, "oracle_comparison_q5.json");
fs.writeFileSync(outputPath, `${JSON.stringify(output, null, 2)}\n`, { flag: "wx" });
process.stdout.write(`ORACLE_MATCH=YES\nORACLE_ARTIFACT_SHA256=${output.oracleArtifactSha256}\n`);
