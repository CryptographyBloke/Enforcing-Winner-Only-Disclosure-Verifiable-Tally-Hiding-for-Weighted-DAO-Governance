"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const group = require("../../js_protocol/src/group");

const runDirectory = path.resolve(process.env.CGY_NATIVE_VECTOR_RUN || "");
if (!process.env.CGY_NATIVE_VECTOR_RUN || !fs.existsSync(runDirectory)) {
  throw new Error("CGY_NATIVE_VECTOR_RUN must identify an existing source-conforming n=8 run");
}

const setup = JSON.parse(fs.readFileSync(path.join(runDirectory, "public_setup.json"), "utf8"));
const board = JSON.parse(fs.readFileSync(path.join(runDirectory, "sealed_board.json"), "utf8"));
const firstGate = JSON.parse(fs.readFileSync(path.join(runDirectory, "gate_transcript.jsonl"), "utf8").split(/\r?\n/)[0]).record;
const point = (value) => group.point(BigInt(value.x), BigInt(value.y));
const encode = (value) => ({
  x: value.x.toString(10),
  y: value.y.toString(10),
  le64: group.encodePoint(value).toString("hex"),
});
const randomScalar = BigInt(`0x${crypto.createHash("sha256")
  .update("-CGY-NATIVE-COMPAT/RANDOM-SCALAR/V1")
  .digest("hex")}`) % group.SUBGROUP_ORDER;
const committeeH = point(setup.committeeKey);
const sampleR = point(board.ballots[0].ciphertexts[0].R);
const sampleS = point(board.ballots[0].ciphertexts[0].S);

const vectors = {
  schema: "-CGY-NATIVE/BABYJUB-COMPAT-V1",
  source: {
    profile: "-CGY-TOOLBOX-FULL-V1",
    setupHash: setup.setupHash,
    transcriptHash: JSON.parse(fs.readFileSync(path.join(runDirectory, "manifest.json"), "utf8")).transcriptHash,
  },
  fieldPrime: group.FIELD_PRIME.toString(10),
  subgroupOrder: group.SUBGROUP_ORDER.toString(10),
  randomScalar: randomScalar.toString(10),
  points: {
    identity: encode(group.IDENTITY),
    base8: encode(group.BASE8),
    twoBase8: encode(group.scalarMultiply(group.BASE8, 2n)),
    randomBase8: encode(group.scalarMultiply(group.BASE8, randomScalar)),
    committeeH: encode(committeeH),
    sampleCiphertextR: encode(sampleR),
    sampleCiphertextS: encode(sampleS),
    sampleHtilde: encode(point(firstGate.htilde)),
    sampleAddition: encode(group.addPoints(sampleR, sampleS)),
    sampleNegation: encode(group.negatePoint(sampleR)),
    sampleScalarMultiplication: encode(group.scalarMultiply(committeeH, randomScalar)),
  },
};

process.stdout.write(`${JSON.stringify(vectors, null, 2)}\n`);
