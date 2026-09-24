"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { BASE8, addPoints, scalarMultiply } = require("../src/group");
const { encryptScalar, addCiphertexts } = require("../src/elgamal");
const { PROTOCOL_VERSION, deriveAuxiliaryPoint } = require("../src/group_oracle");
const { provisionFreshTestOnly } = require("../src/threshold_setup");
const {
  signedRerandomize,
  proveMaskingTransition,
  verifyMaskingTransition,
  proveZeroEncryption,
  verifyZeroEncryption,
} = require("../src/proofs");

function expectCode(fn, code) {
  assert.throws(fn, (error) => error && error.code === code);
}

function fixture() {
  const setup = provisionFreshTestOnly().publicSetup;
  const sourceSession = Object.freeze({
    protocolVersion: PROTOCOL_VERSION,
    setupHash: setup.setupHash,
    executionId: "ab".repeat(32),
    gateId: 5n,
    invocation: 2n,
  });
  const htilde = deriveAuxiliaryPoint(sourceSession, setup.committeeKey).point;
  const previousX = encryptScalar(setup.committeeKey, 1n, 1111n);
  const previousY = encryptScalar(setup.committeeKey, 0n, 2222n);
  return { setup, sourceSession, htilde, previousX, previousY };
}

for (const sign of [1, -1]) {
  test(`Algorithms 9-10 verify every equation for sign ${sign}`, () => {
    const { setup, sourceSession, htilde, previousX, previousY } = fixture();
    const rX = sign === 1 ? 3333n : 5555n;
    const rY = sign === 1 ? 4444n : 6666n;
    const nextX = signedRerandomize(previousX, sign, setup.committeeKey, rX);
    const nextY = signedRerandomize(previousY, sign, setup.committeeKey, rY);
    const e = scalarMultiply(htilde, rX);
    const proof = proveMaskingTransition({ setup, sourceSession, htilde, previousX, previousY, nextX, nextY, e, sign, rX, rY });
    assert.deepEqual(verifyMaskingTransition({ setup, sourceSession, htilde, previousX, previousY, nextX, nextY, e, proof }), { valid: true });
  });
}

test("altered auxiliary element, proof response, and source session reject", () => {
  const { setup, sourceSession, htilde, previousX, previousY } = fixture();
  const rX = 7777n;
  const rY = 8888n;
  const nextX = signedRerandomize(previousX, 1, setup.committeeKey, rX);
  const nextY = signedRerandomize(previousY, 1, setup.committeeKey, rY);
  const e = scalarMultiply(htilde, rX);
  const proof = proveMaskingTransition({ setup, sourceSession, htilde, previousX, previousY, nextX, nextY, e, sign: 1, rX, rY });
  expectCode(() => verifyMaskingTransition({ setup, sourceSession, htilde, previousX, previousY, nextX, nextY, e: addPoints(e, BASE8), proof }), "E_MASK_PROOF_E");
  expectCode(() => verifyMaskingTransition({ setup, sourceSession, htilde, previousX, previousY, nextX, nextY, e, proof: { ...proof, aPlusX: (proof.aPlusX + 1n) % require("../src/group").SUBGROUP_ORDER } }), "E_MASK_PROOF_X");
  expectCode(() => verifyMaskingTransition({ setup, sourceSession: { ...sourceSession, invocation: 3n }, htilde, previousX, previousY, nextX, nextY, e, proof }), "E_MASK_CHALLENGE");
});

test("Algorithm 63 zero-encryption proof binds key, input, contribution, and session", () => {
  const { setup, sourceSession, previousX } = fixture();
  const generated = proveZeroEncryption({ setup, sourceSession, input: previousX, randomness: 9999n });
  assert.deepEqual(verifyZeroEncryption({ setup, sourceSession, input: previousX, contribution: generated.contribution, proof: generated }), { valid: true });
  expectCode(() => verifyZeroEncryption({ setup, sourceSession: { ...sourceSession, gateId: 6n }, input: previousX, contribution: generated.contribution, proof: generated }), "E_ZERO_ENCRYPTION_PROOF");
  expectCode(() => verifyZeroEncryption({ setup, sourceSession, input: addCiphertexts(previousX, generated.contribution), contribution: generated.contribution, proof: generated }), "E_ZERO_ENCRYPTION_PROOF");
  expectCode(() => verifyZeroEncryption({ setup, sourceSession, input: previousX, contribution: addCiphertexts(generated.contribution, generated.contribution), proof: generated }), "E_ZERO_ENCRYPTION_PROOF");
});
