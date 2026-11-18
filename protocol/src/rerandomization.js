"use strict";

const { requireCondition } = require("./errors");
const { randomScalar } = require("./scalars");
const { validateCiphertext, ciphertextHash, addCiphertexts, ciphertextEquals } = require("./elgamal");
const { proveZeroEncryption, verifyZeroEncryption } = require("./proofs");
const { signSubmission } = require("./broadcast_board");
const {
  exactKeys,
  ciphertextToJson,
  ciphertextFromJson,
  zeroProofToJson,
  zeroProofFromJson,
  sourceSessionToJson,
  canonicalPayload,
  parseCanonicalPayload,
} = require("./codec");

const RERANDOMIZATION_MESSAGE_KIND = "CGY_ALGORITHM_63_ZERO_ENCRYPTION";

function slotFor(sourceSession, phase, trusteeId) {
  return Object.freeze({
    protocolVersion: sourceSession.protocolVersion,
    setupHash: sourceSession.setupHash,
    executionId: sourceSession.executionId,
    gateId: sourceSession.gateId,
    invocation: sourceSession.invocation,
    phase,
    trusteeId,
  });
}

function encodeContributionMessage(sourceSession, input, contribution, proof) {
  return canonicalPayload({
    kind: RERANDOMIZATION_MESSAGE_KIND,
    sourceSession: sourceSessionToJson(sourceSession),
    inputHash: ciphertextHash(input),
    contribution: ciphertextToJson(contribution),
    proof: zeroProofToJson(proof),
  });
}

function decodeContributionMessage(payload) {
  const value = parseCanonicalPayload(payload);
  exactKeys(value, ["kind", "sourceSession", "inputHash", "contribution", "proof"], "E_RERANDOMIZATION_MESSAGE");
  requireCondition(value.kind === RERANDOMIZATION_MESSAGE_KIND, "E_RERANDOMIZATION_MESSAGE_KIND", "wrong rerandomization message kind");
  return Object.freeze({
    kind: value.kind,
    sourceSession: value.sourceSession,
    inputHash: value.inputHash,
    contribution: ciphertextFromJson(value.contribution),
    proof: zeroProofFromJson(value.proof),
  });
}

function verifyRerandomizationVector({ setup, sourceSession, input, vector }) {
  const checkedInput = validateCiphertext(input);
  requireCondition(Array.isArray(vector) && vector.length === setup.trustees, "E_RERANDOMIZATION_VECTOR", "Algorithm 63 requires one contribution from every trustee");
  let output = checkedInput;
  for (let index = 0; index < vector.length; index += 1) {
    const entry = vector[index];
    requireCondition(entry.trusteeId === index + 1, "E_RERANDOMIZATION_ORDER", "rerandomization vector is not in trustee order");
    const decoded = decodeContributionMessage(entry.payload);
    requireCondition(decoded.inputHash === ciphertextHash(checkedInput), "E_RERANDOMIZATION_INPUT", "zero-encryption proof is bound to another input ciphertext");
    const expectedSession = sourceSessionToJson(sourceSession);
    requireCondition(JSON.stringify(decoded.sourceSession) === JSON.stringify(expectedSession), "E_RERANDOMIZATION_SESSION", "zero-encryption proof is bound to another source session");
    verifyZeroEncryption({ setup, sourceSession, input: checkedInput, contribution: decoded.contribution, proof: decoded.proof });
    output = addCiphertexts(output, decoded.contribution);
  }
  return Object.freeze({ valid: true, output });
}

function runRerandomization({ setup, sourceSession, input, board, trusteePrivateKeys, phase }) {
  const checkedInput = validateCiphertext(input);
  requireCondition(Array.isArray(trusteePrivateKeys) && trusteePrivateKeys.length === setup.trustees, "E_RERANDOMIZATION_TRUSTEES", "missing trustee authentication keys");
  board.definePhase({ gateId: sourceSession.gateId, invocation: sourceSession.invocation, phase });
  for (let trusteeId = 1; trusteeId <= setup.trustees; trusteeId += 1) {
    const randomness = randomScalar();
    const generated = proveZeroEncryption({ setup, sourceSession, input: checkedInput, randomness });
    const payload = encodeContributionMessage(sourceSession, checkedInput, generated.contribution, generated);
    const slot = slotFor(sourceSession, phase, trusteeId);
    const signature = signSubmission(trusteePrivateKeys[trusteeId - 1].privateKey, slot, payload);
    board.submit({ slot, payload, signature });
  }
  const view = board.readPhase({ gateId: sourceSession.gateId, invocation: sourceSession.invocation, phase });
  requireCondition(view.status === "SEALED", "E_RERANDOMIZATION_WAIT", "Algorithm 63 synchronous broadcast is incomplete");
  const verified = verifyRerandomizationVector({ setup, sourceSession, input: checkedInput, vector: view.vector });
  return Object.freeze({ phase, sourceSession, input: checkedInput, output: verified.output, vector: view.vector });
}

function verifyRerandomizationRecord({ setup, record }) {
  const verified = verifyRerandomizationVector({
    setup,
    sourceSession: record.sourceSession,
    input: record.input,
    vector: record.vector,
  });
  requireCondition(ciphertextEquals(verified.output, record.output), "E_RERANDOMIZATION_OUTPUT", "recorded rerandomization output is wrong");
  return Object.freeze({ valid: true, output: verified.output });
}

module.exports = Object.freeze({
  RERANDOMIZATION_MESSAGE_KIND,
  slotFor,
  encodeContributionMessage,
  decodeContributionMessage,
  verifyRerandomizationVector,
  runRerandomization,
  verifyRerandomizationRecord,
});
