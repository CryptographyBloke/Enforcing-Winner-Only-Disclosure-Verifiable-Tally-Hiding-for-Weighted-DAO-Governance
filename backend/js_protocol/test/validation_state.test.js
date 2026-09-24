"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { encryptScalar } = require("../src/elgamal");
const { PROTOCOL_VERSION } = require("../src/group_oracle");
const { provisionFreshTestOnly, verifySecretShare } = require("../src/threshold_setup");
const {
  receive,
  markProofValidated,
  markBroadcastAgreed,
  markRerandomizationValidated,
  authorizeForDecryption,
  emitPartialShare,
  isAuthorizedForDecryption,
  isPartialShare,
} = require("../src/validation_state");
const { createPartialDecryptionShare } = require("../src/threshold_decryption");

function expectCode(fn, code) {
  assert.throws(fn, (error) => error && error.code === code);
}

function fixture() {
  const provisioned = provisionFreshTestOnly();
  const setup = provisioned.publicSetup;
  const ciphertext = encryptScalar(setup.committeeKey, 1n, 4567n);
  const context = Object.freeze({
    protocolVersion: PROTOCOL_VERSION,
    setupHash: setup.setupHash,
    executionId: "88".repeat(32),
    gateId: 12n,
    invocation: 1n,
    phase: "FINAL_RELEASE_RERANDOMIZED",
    purpose: "FINAL_DECISION",
  });
  return { provisioned, setup, ciphertext, context };
}

test("only the exact explicit state sequence reaches PartialShare", () => {
  const { provisioned, setup, ciphertext, context } = fixture();
  const secret = verifySecretShare(setup, provisioned.secretShares[0]);
  const received = receive(ciphertext, context, { acceptedBoardHash: "99".repeat(32) });
  const proofValidated = markProofValidated(received, { valid: true, statementHash: "aa".repeat(32) });
  const broadcastAgreed = markBroadcastAgreed(proofValidated, { agreed: true, transcriptHash: "bb".repeat(32) });
  const rerandomizationValidated = markRerandomizationValidated(broadcastAgreed, ciphertext, { valid: true, transcriptHash: "cc".repeat(32) });
  const authorized = authorizeForDecryption(rerandomizationValidated, { authorized: true, policy: "FINAL_DECISION_ONLY" });
  const partial = createPartialDecryptionShare(setup, authorized, secret);
  assert.equal(isAuthorizedForDecryption(authorized), true);
  assert.equal(isPartialShare(partial), true);
});

test("raw and every pre-authorization state reject partial-share emission", () => {
  const { provisioned, setup, ciphertext, context } = fixture();
  const secret = verifySecretShare(setup, provisioned.secretShares[0]);
  const received = receive(ciphertext, context, { acceptedBoardHash: "99".repeat(32) });
  const proofValidated = markProofValidated(received, { valid: true });
  const broadcastAgreed = markBroadcastAgreed(proofValidated, { agreed: true });
  const rerandomizationValidated = markRerandomizationValidated(broadcastAgreed, ciphertext, { valid: true });
  for (const value of [ciphertext, received, proofValidated, broadcastAgreed, rerandomizationValidated]) {
    expectCode(() => createPartialDecryptionShare(setup, value, secret), "E_STATE_PARTIAL_INPUT");
    expectCode(() => emitPartialShare(value, { trusteeId: 1 }), "E_STATE_PARTIAL_INPUT");
  }
});

test("invalid proof, absent agreement, malformed rerandomization, and denied policy fail explicitly", () => {
  const { ciphertext, context } = fixture();
  const received = receive(ciphertext, context, { acceptedBoardHash: "99".repeat(32) });
  expectCode(() => markProofValidated(received, { valid: false }), "E_PROOF_INVALID");
  expectCode(() => markProofValidated(ciphertext, { valid: true }), "E_STATE_PROOF_INPUT");
  const proofValidated = markProofValidated(received, { valid: true });
  expectCode(() => markBroadcastAgreed(proofValidated, { agreed: false }), "E_BROADCAST_NOT_AGREED");
  expectCode(() => markBroadcastAgreed(received, { agreed: true }), "E_STATE_BROADCAST_INPUT");
  const broadcastAgreed = markBroadcastAgreed(proofValidated, { agreed: true });
  expectCode(() => markRerandomizationValidated(broadcastAgreed, ciphertext, { valid: false }), "E_RERANDOMIZATION_INVALID");
  expectCode(() => markRerandomizationValidated(proofValidated, ciphertext, { valid: true }), "E_STATE_RERANDOMIZATION_INPUT");
  const rerandomizationValidated = markRerandomizationValidated(broadcastAgreed, ciphertext, { valid: true });
  expectCode(() => authorizeForDecryption(rerandomizationValidated, { authorized: false }), "E_DECRYPTION_POLICY");
  expectCode(() => authorizeForDecryption(broadcastAgreed, { authorized: true }), "E_STATE_AUTHORIZATION_INPUT");
});
