"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {
  BASE8,
  addPoints,
  pointEquals,
} = require("../src/group");
const { encryptScalar } = require("../src/elgamal");
const { PROTOCOL_VERSION } = require("../src/group_oracle");
const {
  provisionFreshTestOnly,
  verifySecretShare,
} = require("../src/threshold_setup");
const {
  receive,
  markProofValidated,
  markBroadcastAgreed,
  markRerandomizationValidated,
  authorizeForDecryption,
  emitPartialShare,
} = require("../src/validation_state");
const {
  createPartialDecryptionShare,
  verifyPartialDecryptionShare,
  combineVerifiedPartialDecryptions,
} = require("../src/threshold_decryption");

function expectCode(fn, code) {
  assert.throws(fn, (error) => error && error.code === code);
}

function makeAuthorization(setup, ciphertext, invocation = 0n) {
  const context = Object.freeze({
    protocolVersion: PROTOCOL_VERSION,
    setupHash: setup.setupHash,
    executionId: "33".repeat(32),
    gateId: 9n,
    invocation,
    phase: "FINAL_RELEASE_RERANDOMIZED",
    purpose: "FINAL_DECISION",
  });
  const received = receive(ciphertext, context, { source: "TEST_SEALED_BOARD" });
  const proofValidated = markProofValidated(received, { valid: true, verifier: "TEST_FIXTURE" });
  const broadcastAgreed = markBroadcastAgreed(proofValidated, { agreed: true, transcriptHash: "44".repeat(32) });
  const rerandomized = markRerandomizationValidated(broadcastAgreed, ciphertext, { valid: true, algorithm: 63 });
  return authorizeForDecryption(rerandomized, { authorized: true, policy: "FINAL_DECISION_ONLY" });
}

test("Algorithm 65 proof and every 3-of-5 quorum decrypt the authorized ciphertext", () => {
  const provisioned = provisionFreshTestOnly();
  const setup = provisioned.publicSetup;
  const target = encryptScalar(setup.committeeKey, 1n, 12345n);
  const authorization = makeAuthorization(setup, target);
  const verifiedSecrets = provisioned.secretShares.map((share) => verifySecretShare(setup, share));
  const verifiedPartials = verifiedSecrets.map((share) => {
    const emitted = createPartialDecryptionShare(setup, authorization, share);
    return verifyPartialDecryptionShare(setup, authorization, emitted);
  });
  const quorums = [
    [0, 1, 2], [0, 1, 3], [0, 1, 4], [0, 2, 3], [0, 2, 4],
    [0, 3, 4], [1, 2, 3], [1, 2, 4], [1, 3, 4], [2, 3, 4],
  ];
  for (const indices of quorums) {
    const plaintextPoint = combineVerifiedPartialDecryptions(setup, authorization, indices.map((index) => verifiedPartials[index]));
    assert.equal(pointEquals(plaintextPoint, BASE8), true);
  }
});

test("partial share emission has no raw-ciphertext entry point", () => {
  const provisioned = provisionFreshTestOnly();
  const setup = provisioned.publicSetup;
  const target = encryptScalar(setup.committeeKey, 0n, 999n);
  const secret = verifySecretShare(setup, provisioned.secretShares[0]);
  expectCode(() => createPartialDecryptionShare(setup, target, secret), "E_STATE_PARTIAL_INPUT");
});

test("wrong session, ciphertext, trustee duplication, bad proof, and short quorum reject", () => {
  const provisioned = provisionFreshTestOnly();
  const setup = provisioned.publicSetup;
  const firstCiphertext = encryptScalar(setup.committeeKey, 1n, 111n);
  const secondCiphertext = encryptScalar(setup.committeeKey, 1n, 222n);
  const firstAuthorization = makeAuthorization(setup, firstCiphertext, 1n);
  const secondAuthorization = makeAuthorization(setup, secondCiphertext, 2n);
  const secrets = provisioned.secretShares.map((share) => verifySecretShare(setup, share));
  const emitted = secrets.map((share) => createPartialDecryptionShare(setup, firstAuthorization, share));
  const verified = emitted.map((share) => verifyPartialDecryptionShare(setup, firstAuthorization, share));

  expectCode(() => verifyPartialDecryptionShare(setup, secondAuthorization, emitted[0]), "E_PARTIAL_SESSION");
  const badProof = emitPartialShare(firstAuthorization, {
    ...emitted[0].payload,
    cG: addPoints(emitted[0].payload.cG, BASE8),
  });
  expectCode(() => verifyPartialDecryptionShare(setup, firstAuthorization, badProof), "E_PARTIAL_PROOF");
  expectCode(() => combineVerifiedPartialDecryptions(setup, firstAuthorization, verified.slice(0, 2)), "E_THRESHOLD_INSUFFICIENT");
  expectCode(() => combineVerifiedPartialDecryptions(setup, firstAuthorization, [verified[0], verified[0], verified[1]]), "E_DUPLICATE_TRUSTEE");
  expectCode(() => combineVerifiedPartialDecryptions(setup, secondAuthorization, verified.slice(0, 3)), "E_PARTIAL_SESSION");
});
