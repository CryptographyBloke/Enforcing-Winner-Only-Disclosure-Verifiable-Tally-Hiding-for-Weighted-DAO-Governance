"use strict";

// Application-only local admission profile for scale measurements.  It uses
// the unchanged Groth16 relation, public signals, registry/nullifier checks,
// and accepted ciphertext encoding; it replaces only the bounded N=8 chain
// transport with a deterministic sealed local board for N=64/1024.

const crypto = require("crypto");
const snarkjs = require("snarkjs");
const { requireCondition } = require("./errors");
const { validateAcceptedCiphertext } = require("./elgamal");
const { canonicalJson } = require("./broadcast_board");

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function ciphertextsFromSignals(publicSignals) {
  requireCondition(Array.isArray(publicSignals) && publicSignals.length >= 37, "E_LOCAL_SIGNALS", "ballot public-signal vector is incomplete");
  const ciphertexts = [];
  for (let bit = 0; bit < 8; bit += 1) {
    const offset = 1 + bit * 4;
    const ciphertext = {
      R: { x: BigInt(publicSignals[offset]), y: BigInt(publicSignals[offset + 1]) },
      S: { x: BigInt(publicSignals[offset + 2]), y: BigInt(publicSignals[offset + 3]) },
    };
    validateAcceptedCiphertext(ciphertext);
    ciphertexts.push(ciphertext);
  }
  return Object.freeze(ciphertexts);
}

async function admitLocalProofBoard({ publicProofs, verificationKey, registryRoot, pollId, committeeKey, count }) {
  requireCondition(Array.isArray(publicProofs) && publicProofs.length === count, "E_LOCAL_COUNT", "local proof count does not match profile");
  const seenNullifiers = new Set();
  const ballots = [];
  for (let index = 0; index < publicProofs.length; index += 1) {
    const proof = publicProofs[index];
    requireCondition(proof.index === index, "E_LOCAL_ORDER", "local proof order is not canonical");
    requireCondition(await snarkjs.groth16.verify(verificationKey, proof.publicSignals, proof.proof), "E_LOCAL_PROOF", `local proof ${index} failed verification`);
    requireCondition(proof.publicSignals[33] === String(registryRoot), "E_LOCAL_ROOT", `local proof ${index} registry root mismatch`);
    requireCondition(proof.publicSignals[34] === String(pollId), "E_LOCAL_POLL", `local proof ${index} poll id mismatch`);
    requireCondition(proof.publicSignals[35] === committeeKey.x.toString(10) && proof.publicSignals[36] === committeeKey.y.toString(10), "E_LOCAL_KEY", `local proof ${index} committee key mismatch`);
    const nullifier = String(proof.publicSignals[0]);
    requireCondition(!seenNullifiers.has(nullifier), "E_LOCAL_NULLIFIER", `local proof ${index} has a duplicate nullifier`);
    seenNullifiers.add(nullifier);
    ballots.push(Object.freeze({ position: index, nullifier, ciphertexts: ciphertextsFromSignals(proof.publicSignals) }));
  }
  const board = Object.freeze({
    schema: "-CGY-TOOLBOX-FULL-V1/LOCAL-ADMISSION-BOARD/V1",
    profile: `N${count}`,
    registryRoot: String(registryRoot),
    pollId: String(pollId),
    committeeKey: { x: committeeKey.x.toString(10), y: committeeKey.y.toString(10) },
    ballots,
  });
  const sealedBoardHash = sha256(canonicalJson(board));
  return Object.freeze({ board, sealedBoardHash, ciphertexts: Object.freeze(ballots.map((ballot) => ballot.ciphertexts)) });
}

module.exports = Object.freeze({ admitLocalProofBoard, ciphertextsFromSignals });
