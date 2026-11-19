"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { BASE8, addPoints, pointEquals, scalarMultiply } = require("../src/group");
const { encryptScalar } = require("../src/elgamal");
const { PROTOCOL_VERSION } = require("../src/group_oracle");
const {
  provisionFreshTestOnly,
  verifyPublicSetup,
  verifySecretShare,
  interpolateScalarAtZero,
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

function makeAuthorization(setup, ciphertext, executionId = "35".repeat(32)) {
  const context = Object.freeze({
    protocolVersion: PROTOCOL_VERSION,
    setupHash: setup.setupHash,
    executionId,
    gateId: 9n,
    invocation: 0n,
    phase: "THRESHOLD_TEST_FIVE_OF_FIVE",
    purpose: "FINAL_DECISION",
  });
  const received = receive(ciphertext, context, { source: "test_board" });
  const proofValidated = markProofValidated(received, { valid: true, verifier: "test_fixture" });
  const broadcastAgreed = markBroadcastAgreed(proofValidated, { agreed: true, transcriptHash: "44".repeat(32) });
  const rerandomized = markRerandomizationValidated(broadcastAgreed, ciphertext, { valid: true, algorithm: 63 });
  return authorizeForDecryption(rerandomized, { authorized: true, policy: "final_output_only" });
}

test("five-of-five setup is degree-4 with a 5-of-5 reconstruction boundary", () => {
  const bundle = provisionFreshTestOnly({ trustees: 5, degree: 4 });
  const setup = verifyPublicSetup(bundle.publicSetup);
  assert.equal(setup.trustees, 5);
  assert.equal(setup.degree, 4);
  assert.equal(setup.threshold, 5);
  const verified = bundle.secretShares.map((share) => verifySecretShare(setup, share));
  assert.equal(verified.length, 5);
  assert.equal(pointEquals(scalarMultiply(BASE8, interpolateScalarAtZero(setup, verified)), setup.committeeKey), true);
  expectCode(() => interpolateScalarAtZero(setup, verified.slice(0, 4)), "E_THRESHOLD_INSUFFICIENT");
  expectCode(() => interpolateScalarAtZero(setup, [verified[0], verified[0], verified[1], verified[2], verified[3]]), "E_DUPLICATE_TRUSTEE");
  const foreign = provisionFreshTestOnly({ trustees: 5, degree: 4 });
  expectCode(() => verifySecretShare(setup, foreign.secretShares[4]), "E_SHARE_SETUP");
  expectCode(() => verifySecretShare(setup, { ...bundle.secretShares[4], value: bundle.secretShares[4].value + 1n }), "E_SECRET_SHARE_VALUE");
});

test("Algorithm 65 opening requires all five verified partial shares", () => {
  const bundle = provisionFreshTestOnly({ trustees: 5, degree: 4 });
  const setup = verifyPublicSetup(bundle.publicSetup);
  const target = encryptScalar(setup.committeeKey, 1n, 12345n);
  const authorization = makeAuthorization(setup, target);
  const secrets = bundle.secretShares.map((share) => verifySecretShare(setup, share));
  const emitted = secrets.map((share) => createPartialDecryptionShare(setup, authorization, share));
  const verified = emitted.map((share) => verifyPartialDecryptionShare(setup, authorization, share));
  assert.equal(pointEquals(combineVerifiedPartialDecryptions(setup, authorization, verified), BASE8), true);
  expectCode(() => combineVerifiedPartialDecryptions(setup, authorization, verified.slice(0, 3)), "E_THRESHOLD_INSUFFICIENT");
  expectCode(() => combineVerifiedPartialDecryptions(setup, authorization, verified.slice(0, 4)), "E_THRESHOLD_INSUFFICIENT");
  expectCode(() => combineVerifiedPartialDecryptions(setup, authorization, [verified[0], verified[1], verified[2], verified[4], verified[4]]), "E_DUPLICATE_TRUSTEE");
  const alteredFifth = emitPartialShare(authorization, { ...emitted[4].payload, w: addPoints(emitted[4].payload.w, BASE8) });
  expectCode(() => verifyPartialDecryptionShare(setup, authorization, alteredFifth), "E_PARTIAL_PROOF");
  expectCode(() => combineVerifiedPartialDecryptions(setup, authorization, [...verified.slice(0, 4), alteredFifth]), "E_PARTIAL_NOT_VERIFIED");
  const secondCiphertext = encryptScalar(setup.committeeKey, 0n, 12346n);
  const secondAuthorization = makeAuthorization(setup, secondCiphertext);
  const secondSecrets = bundle.secretShares.map((share) => verifySecretShare(setup, share));
  const wrongCiphertextShare = createPartialDecryptionShare(setup, secondAuthorization, secondSecrets[4]);
  expectCode(() => verifyPartialDecryptionShare(setup, authorization, wrongCiphertextShare), "E_PARTIAL_SESSION");
  const alteredCiphertextBinding = emitPartialShare(authorization, { ...emitted[4].payload, ciphertextHash: "00".repeat(32) });
  expectCode(() => verifyPartialDecryptionShare(setup, authorization, alteredCiphertextBinding), "E_PARTIAL_CIPHERTEXT");
  const secondSessionAuthorization = makeAuthorization(setup, target, "36".repeat(32));
  const wrongSessionShare = createPartialDecryptionShare(setup, secondSessionAuthorization, secrets[4]);
  expectCode(() => verifyPartialDecryptionShare(setup, authorization, wrongSessionShare), "E_PARTIAL_SESSION");
  const foreignBundle = provisionFreshTestOnly({ trustees: 5, degree: 4 });
  const foreignSetup = verifyPublicSetup(foreignBundle.publicSetup);
  const foreignAuthorization = makeAuthorization(foreignSetup, target);
  const foreignSecret = verifySecretShare(foreignSetup, foreignBundle.secretShares[4]);
  const foreignShare = createPartialDecryptionShare(foreignSetup, foreignAuthorization, foreignSecret);
  expectCode(() => verifyPartialDecryptionShare(setup, authorization, foreignShare), "E_PARTIAL_SESSION");
});

test("five-of-five public setup rejects an altered fifth trustee verification key", () => {
  const bundle = provisionFreshTestOnly({ trustees: 5, degree: 4 });
  const keys = bundle.publicSetup.verificationKeys.slice();
  keys[4] = Object.freeze({ trusteeId: 5, point: addPoints(keys[4].point, BASE8) });
  expectCode(() => verifyPublicSetup({ ...bundle.publicSetup, verificationKeys: keys }), "E_SETUP_INCONSISTENT");
});
