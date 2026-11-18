"use strict";

const { requireCondition } = require("./errors");
const {
  SUBGROUP_ORDER,
  BASE8,
  IDENTITY,
  PointRole,
  addPoints,
  negatePoint,
  scalarMultiply,
  validatePoint,
  encodePoint,
  pointEquals,
  isIdentity,
} = require("./group");
const { randomScalar, scalar, scalarMod } = require("./scalars");
const {
  ciphertext,
  validateCiphertext,
  encodeCiphertext,
  ciphertextEquals,
  addCiphertexts,
  scaleCiphertext,
} = require("./elgamal");
const { encodeSourceSession } = require("./group_oracle");
const { hashToScalar } = require("./hash_to_scalar");

const PROOF_DOMAINS = Object.freeze({
  MASKING: "-CGY-TOOLBOX-FULL-V1/CGY/ALGORITHM-9/POK-CSZ/V1",
  ZERO_ENCRYPTION: "-CGY-TOOLBOX-FULL-V1/CGY/ALGORITHM-63/ZERO-ENCRYPTION/V1",
});

function encZero(committeeKey, randomness) {
  const key = validatePoint(committeeKey, PointRole.COMMITTEE_KEY);
  scalar(randomness);
  return ciphertext(scalarMultiply(BASE8, randomness), scalarMultiply(key, randomness));
}

function rerandomizeCiphertext(value, committeeKey, randomness) {
  return addCiphertexts(validateCiphertext(value), encZero(committeeKey, randomness));
}

function signedRerandomize(value, sign, committeeKey, randomness) {
  requireCondition(sign === 1 || sign === -1, "E_MASK_SIGN", "mask sign must be +1 or -1");
  const signed = sign === 1 ? validateCiphertext(value) : scaleCiphertext(value, SUBGROUP_ORDER - 1n);
  return rerandomizeCiphertext(signed, committeeKey, randomness);
}

function maskingChallenge(setup, sourceSession, previousX, previousY, nextX, nextY, proofCommitments) {
  return hashToScalar(PROOF_DOMAINS.MASKING, [
    encodeSourceSession(sourceSession),
    encodePoint(BASE8, PointRole.GENERATOR),
    encodePoint(setup.committeeKey, PointRole.COMMITTEE_KEY),
    encodeCiphertext(previousX),
    encodeCiphertext(previousY),
    encodeCiphertext(nextX),
    encodeCiphertext(nextY),
    encodeCiphertext(proofCommitments.cPlusX),
    encodeCiphertext(proofCommitments.cPlusY),
    encodeCiphertext(proofCommitments.cMinusX),
    encodeCiphertext(proofCommitments.cMinusY),
    encodePoint(proofCommitments.cPlusE, PointRole.PROOF_ELEMENT),
    encodePoint(proofCommitments.cMinusE, PointRole.PROOF_ELEMENT),
  ]);
}

function branchDelta(next, previous, branch) {
  const signedPrevious = branch === 1 ? previous : scaleCiphertext(previous, SUBGROUP_ORDER - 1n);
  return addCiphertexts(next, scaleCiphertext(signedPrevious, SUBGROUP_ORDER - 1n));
}

function simulateCiphertextCommitment(committeeKey, response, statementDelta, branchChallenge) {
  return addCiphertexts(encZero(committeeKey, response), scaleCiphertext(statementDelta, scalarMod(-branchChallenge)));
}

function simulatePointCommitment(base, response, statement, branchChallenge) {
  return addPoints(scalarMultiply(base, response), negatePoint(scalarMultiply(statement, branchChallenge)));
}

function proveMaskingTransition({ setup, sourceSession, htilde, previousX, previousY, nextX, nextY, e, sign, rX, rY }) {
  validatePoint(htilde, PointRole.AUXILIARY);
  validatePoint(e, PointRole.PROOF_ELEMENT);
  requireCondition(sign === 1 || sign === -1, "E_MASK_SIGN", "mask sign must be +1 or -1");
  scalar(rX);
  scalar(rY);
  requireCondition(ciphertextEquals(nextX, signedRerandomize(previousX, sign, setup.committeeKey, rX)), "E_MASK_WITNESS_X", "X transition does not match witness");
  requireCondition(ciphertextEquals(nextY, signedRerandomize(previousY, sign, setup.committeeKey, rY)), "E_MASK_WITNESS_Y", "Y transition does not match witness");
  requireCondition(pointEquals(e, scalarMultiply(htilde, rX)), "E_MASK_WITNESS_E", "auxiliary element does not match X randomness");

  const alpha = randomScalar();
  const beta = randomScalar();
  const fakeChallenge = randomScalar();
  const fakeResponseX = randomScalar();
  const fakeResponseY = randomScalar();
  const realCommitments = {
    X: encZero(setup.committeeKey, alpha),
    Y: encZero(setup.committeeKey, beta),
    E: scalarMultiply(htilde, alpha),
  };
  const fakeBranch = -sign;
  const fakeCommitments = {
    X: simulateCiphertextCommitment(setup.committeeKey, fakeResponseX, branchDelta(nextX, previousX, fakeBranch), fakeChallenge),
    Y: simulateCiphertextCommitment(setup.committeeKey, fakeResponseY, branchDelta(nextY, previousY, fakeBranch), fakeChallenge),
    E: simulatePointCommitment(htilde, fakeResponseX, e, fakeChallenge),
  };
  const commitments = sign === 1
    ? { cPlusX: realCommitments.X, cPlusY: realCommitments.Y, cMinusX: fakeCommitments.X, cMinusY: fakeCommitments.Y, cPlusE: realCommitments.E, cMinusE: fakeCommitments.E }
    : { cPlusX: fakeCommitments.X, cPlusY: fakeCommitments.Y, cMinusX: realCommitments.X, cMinusY: realCommitments.Y, cPlusE: fakeCommitments.E, cMinusE: realCommitments.E };
  const totalChallenge = maskingChallenge(setup, sourceSession, previousX, previousY, nextX, nextY, commitments);
  const realChallenge = scalarMod(totalChallenge - fakeChallenge);
  const realResponseX = scalarMod(alpha + rX * realChallenge);
  const realResponseY = scalarMod(beta + rY * realChallenge);
  return Object.freeze({
    ...commitments,
    dPlus: sign === 1 ? realChallenge : fakeChallenge,
    dMinus: sign === 1 ? fakeChallenge : realChallenge,
    aPlusX: sign === 1 ? realResponseX : fakeResponseX,
    aPlusY: sign === 1 ? realResponseY : fakeResponseY,
    aMinusX: sign === 1 ? fakeResponseX : realResponseX,
    aMinusY: sign === 1 ? fakeResponseY : realResponseY,
  });
}

function verifyMaskingTransition({ setup, sourceSession, htilde, previousX, previousY, nextX, nextY, e, proof }) {
  validateCiphertext(previousX);
  validateCiphertext(previousY);
  validateCiphertext(nextX);
  validateCiphertext(nextY);
  requireCondition(!isIdentity(nextX.R), "E_MASK_X_IDENTITY", "Algorithm 10 rejects an X ciphertext with identity first component");
  validatePoint(htilde, PointRole.AUXILIARY);
  validatePoint(e, PointRole.PROOF_ELEMENT);
  const commitments = {
    cPlusX: validateCiphertext(proof.cPlusX),
    cPlusY: validateCiphertext(proof.cPlusY),
    cMinusX: validateCiphertext(proof.cMinusX),
    cMinusY: validateCiphertext(proof.cMinusY),
    cPlusE: validatePoint(proof.cPlusE, PointRole.PROOF_ELEMENT),
    cMinusE: validatePoint(proof.cMinusE, PointRole.PROOF_ELEMENT),
  };
  for (const value of [proof.dPlus, proof.dMinus, proof.aPlusX, proof.aPlusY, proof.aMinusX, proof.aMinusY]) scalar(value);
  const totalChallenge = maskingChallenge(setup, sourceSession, previousX, previousY, nextX, nextY, commitments);
  requireCondition(scalarMod(proof.dPlus + proof.dMinus) === totalChallenge, "E_MASK_CHALLENGE", "Algorithm 10 branch challenges do not sum to the oracle challenge");
  for (const [branch, challenge, responseX, responseY, commitmentX, commitmentY, commitmentE] of [
    [1, proof.dPlus, proof.aPlusX, proof.aPlusY, commitments.cPlusX, commitments.cPlusY, commitments.cPlusE],
    [-1, proof.dMinus, proof.aMinusX, proof.aMinusY, commitments.cMinusX, commitments.cMinusY, commitments.cMinusE],
  ]) {
    requireCondition(ciphertextEquals(simulateCiphertextCommitment(setup.committeeKey, responseX, branchDelta(nextX, previousX, branch), challenge), commitmentX), "E_MASK_PROOF_X", `Algorithm 10 X equation failed for branch ${branch}`);
    requireCondition(ciphertextEquals(simulateCiphertextCommitment(setup.committeeKey, responseY, branchDelta(nextY, previousY, branch), challenge), commitmentY), "E_MASK_PROOF_Y", `Algorithm 10 Y equation failed for branch ${branch}`);
    requireCondition(pointEquals(simulatePointCommitment(htilde, responseX, e, challenge), commitmentE), "E_MASK_PROOF_E", `Algorithm 10 auxiliary equation failed for branch ${branch}`);
  }
  return Object.freeze({ valid: true });
}

function zeroEncryptionChallenge(setup, sourceSession, input, contribution, commitment) {
  return hashToScalar(PROOF_DOMAINS.ZERO_ENCRYPTION, [
    encodeSourceSession(sourceSession),
    encodePoint(BASE8, PointRole.GENERATOR),
    encodePoint(setup.committeeKey, PointRole.COMMITTEE_KEY),
    encodeCiphertext(input),
    encodeCiphertext(contribution),
    encodeCiphertext(commitment),
  ]);
}

function proveZeroEncryption({ setup, sourceSession, input, randomness }) {
  scalar(randomness);
  const contribution = encZero(setup.committeeKey, randomness);
  const alpha = randomScalar();
  const commitment = encZero(setup.committeeKey, alpha);
  const challenge = zeroEncryptionChallenge(setup, sourceSession, input, contribution, commitment);
  const response = scalarMod(alpha + randomness * challenge);
  return Object.freeze({ contribution, commitment, response });
}

function verifyZeroEncryption({ setup, sourceSession, input, contribution, proof }) {
  validateCiphertext(input);
  validateCiphertext(contribution);
  validateCiphertext(proof.commitment);
  scalar(proof.response);
  const challenge = zeroEncryptionChallenge(setup, sourceSession, input, contribution, proof.commitment);
  const expected = addCiphertexts(encZero(setup.committeeKey, proof.response), scaleCiphertext(contribution, scalarMod(-challenge)));
  requireCondition(ciphertextEquals(expected, proof.commitment), "E_ZERO_ENCRYPTION_PROOF", "Algorithm 63 zero-encryption proof failed");
  return Object.freeze({ valid: true });
}

module.exports = Object.freeze({
  PROOF_DOMAINS,
  encZero,
  rerandomizeCiphertext,
  signedRerandomize,
  maskingChallenge,
  proveMaskingTransition,
  verifyMaskingTransition,
  zeroEncryptionChallenge,
  proveZeroEncryption,
  verifyZeroEncryption,
});
