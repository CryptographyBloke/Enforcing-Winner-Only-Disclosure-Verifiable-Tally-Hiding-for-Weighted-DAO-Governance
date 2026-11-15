"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { fork } = require("child_process");
const { buildPoseidon, buildBabyjub } = require("circomlibjs");
const snarkjs = require("snarkjs");
const { requireCondition } = require("./errors");
const { randomScalar } = require("./scalars");
const { mapWithLimit, ballotProofConcurrency } = require("./bounded_concurrency");

const DEPTH = 10;
const PROVE_WORKER = path.join(__dirname, "..", "scripts", "prove_ballot_worker.js");

// Prove one ballot in a fresh process. The witness travels over the IPC channel only.
function proveInChildProcess(input, artifacts) {
  return new Promise((resolve, reject) => {
    const child = fork(PROVE_WORKER, [], { stdio: ["ignore", "inherit", "inherit", "ipc"] });
    let answered = false;
    child.once("message", (message) => {
      answered = true;
      if (message && message.ok) resolve({ proof: message.proof, publicSignals: message.publicSignals });
      else reject(new Error(`E_BALLOT_PROVER: ${message && message.message}`));
    });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (!answered) reject(new Error(`E_BALLOT_PROVER: proof process exited with code ${code} before answering`));
    });
    child.send({ input, wasmPath: artifacts.wasmPath, zkeyPath: artifacts.zkeyPath });
  });
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function requireArtifacts(artifacts) {
  requireCondition(artifacts && typeof artifacts === "object", "E_BALLOT_ARTIFACT", "ballot artifact paths are missing");
  for (const key of ["wasmPath", "zkeyPath", "vkeyPath"]) {
    requireCondition(typeof artifacts[key] === "string" && fs.existsSync(artifacts[key]), "E_BALLOT_ARTIFACT", `${key} does not exist`);
  }
  return Object.freeze({
    ...artifacts,
    wasmSha256: sha256File(artifacts.wasmPath),
    zkeySha256: sha256File(artifacts.zkeyPath),
    vkeySha256: sha256File(artifacts.vkeyPath),
  });
}

async function prepareFreshN8Ballots({ committeeKey, pollId, votes, weights, artifacts, count = 8 }) {
  const checkedArtifacts = requireArtifacts(artifacts);
  requireCondition(Number.isInteger(count) && count > 0 && count <= (2 ** DEPTH), "E_BALLOT_COUNT", `local ballot profile supports 1..${2 ** DEPTH} ballots`);
  requireCondition(Array.isArray(votes) && votes.length === count && votes.every((value) => value === 0 || value === 1), "E_BALLOT_VOTES", `ballot profile requires ${count} vote bits`);
  requireCondition(Array.isArray(weights) && weights.length === count && weights.every((value) => Number.isInteger(value) && value >= 0 && value <= 255), "E_BALLOT_WEIGHTS", `ballot profile requires ${count} uint8 weights`);
  const poseidon = await buildPoseidon();
  const H = (values) => poseidon.F.toObject(poseidon(values));
  const babyjub = await buildBabyjub();
  const F = babyjub.F;
  const PK = [F.e(committeeKey.x), F.e(committeeKey.y)];
  const identities = [];
  const used = new Set();
  while (identities.length < count) {
    const secret = randomScalar({ nonzero: true });
    if (!used.has(secret.toString(10))) {
      used.add(secret.toString(10));
      identities.push(secret);
    }
  }
  const records = identities.map((identitySecret, index) => ({
    identitySecret,
    weight: BigInt(weights[index]),
    vote: BigInt(votes[index]),
    idCommit: H([identitySecret]),
  }));
  records.forEach((record) => { record.leaf = H([record.idCommit, record.weight]); });
  const leaves = new Array(2 ** DEPTH).fill(0n);
  records.forEach((record, index) => { leaves[index] = record.leaf; });
  const levels = [leaves];
  for (let level = 0; level < DEPTH; level += 1) {
    const previous = levels[level];
    const next = [];
    for (let index = 0; index < previous.length; index += 2) next.push(H([previous[index], previous[index + 1]]));
    levels.push(next);
  }
  const registryRoot = levels[DEPTH][0];

  function merklePath(position) {
    const pathElements = [];
    const pathIndices = [];
    let index = position;
    for (let level = 0; level < DEPTH; level += 1) {
      pathElements.push(levels[level][index ^ 1].toString(10));
      pathIndices.push(index & 1);
      index >>= 1;
    }
    return { pathElements, pathIndices };
  }

  const inputs = records.map((record, index) => ({
    identitySecret: record.identitySecret.toString(10),
    weight: record.weight.toString(10),
    vote: record.vote.toString(10),
    ...merklePath(index),
    r: Array.from({ length: 8 }, () => randomScalar({ nonzero: true }).toString(10)),
    root: registryRoot.toString(10),
    pollId: String(pollId),
    PK: [F.toString(PK[0]), F.toString(PK[1])],
  }));
  const verificationKey = JSON.parse(fs.readFileSync(checkedArtifacts.vkeyPath, "utf8"));
  // With concurrency 1 the proofs run one after another in this process, exactly as before. With more, each proof
  // runs in its own child process (see scripts/prove_ballot_worker.js) and at most `concurrency` run at once.
  // `publicProofs[i]` always belongs to ballot i, whatever order the proofs finish in, because the board order is
  // the order of the ballots. `provingMs` is the duration of that one proof, so with concurrency the durations overlap.
  const concurrency = Math.min(ballotProofConcurrency(), inputs.length);
  const publicProofs = await mapWithLimit(inputs, concurrency, async (input, index) => {
    const started = process.hrtime.bigint();
    const { proof, publicSignals } = concurrency === 1
      ? await snarkjs.groth16.fullProve(input, checkedArtifacts.wasmPath, checkedArtifacts.zkeyPath)
      : await proveInChildProcess(input, checkedArtifacts);
    requireCondition(await snarkjs.groth16.verify(verificationKey, publicSignals, proof), "E_BALLOT_PROOF", `fresh ballot ${index} failed independent Groth16 verification`);
    requireCondition(publicSignals[33] === registryRoot.toString(10), "E_BALLOT_ROOT", `fresh ballot ${index} registry root mismatch`);
    requireCondition(publicSignals[34] === String(pollId), "E_BALLOT_POLL", `fresh ballot ${index} poll mismatch`);
    requireCondition(publicSignals[35] === F.toString(PK[0]) && publicSignals[36] === F.toString(PK[1]), "E_BALLOT_PK", `fresh ballot ${index} committee key mismatch`);
    const record = Object.freeze({ index, proof, publicSignals, provingMs: Number(process.hrtime.bigint() - started) / 1e6 });
    input.identitySecret = "DESTROYED_TEST_ONLY_WITNESS";
    input.r.fill("DESTROYED_TEST_ONLY_RANDOMNESS");
    input.pathElements.fill("DESTROYED_TEST_ONLY_PATH");
    return record;
  });
  records.length = 0;
  identities.length = 0;
  return Object.freeze({
    registryRoot,
    publicProofs: Object.freeze(publicProofs),
    artifacts: checkedArtifacts,
  });
}

function solidityProof(record) {
  return Object.freeze({
    a: [BigInt(record.proof.pi_a[0]), BigInt(record.proof.pi_a[1])],
    b: [
      [BigInt(record.proof.pi_b[0][1]), BigInt(record.proof.pi_b[0][0])],
      [BigInt(record.proof.pi_b[1][1]), BigInt(record.proof.pi_b[1][0])],
    ],
    c: [BigInt(record.proof.pi_c[0]), BigInt(record.proof.pi_c[1])],
    publicSignals: record.publicSignals.map(BigInt),
  });
}

module.exports = Object.freeze({ DEPTH, requireArtifacts, prepareFreshN8Ballots, prepareFreshBallots: prepareFreshN8Ballots, solidityProof });
