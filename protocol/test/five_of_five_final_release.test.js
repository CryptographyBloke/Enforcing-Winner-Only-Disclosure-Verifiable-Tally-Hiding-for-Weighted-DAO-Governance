"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { PROTOCOL_VERSION } = require("../src/group_oracle");
const { encryptScalar, addCiphertexts } = require("../src/elgamal");
const { createCiphertextOps } = require("../src/arithmetic");
const { provisionFreshTestOnly } = require("../src/threshold_setup");
const { createTrusteeAuthenticationRegistry, CanonicalAtomicBroadcastBoard } = require("../src/broadcast_board");
const { buildLogicalDecisionCiphertext, runFinalRelease, verifyFinalRelease } = require("../src/final_release");

function fixture(borrowBit) {
  const setupBundle = provisionFreshTestOnly({ trustees: 5, degree: 4 });
  const setup = setupBundle.publicSetup;
  const auth = createTrusteeAuthenticationRegistry(5);
  const session = Object.freeze({
    protocolVersion: PROTOCOL_VERSION,
    setupHash: setup.setupHash,
    executionId: "35".repeat(32),
    gateId: 999n,
    invocation: 0n,
  });
  const board = new CanonicalAtomicBroadcastBoard({ setupHash: setup.setupHash, executionId: session.executionId, trusteePublicKeys: auth.publicKeys });
  const Q = encryptScalar(setup.committeeKey, BigInt(borrowBit), 3001n);
  const CStar = encryptScalar(setup.committeeKey, 0n, 3002n);
  const D = addCiphertexts(Q, CStar);
  const comparison = Object.freeze({ borrow: Q, terminal: Object.freeze({ Q, D, CStar }) });
  const ops = createCiphertextOps(() => { throw new Error("gate must not be called while constructing C_b"); });
  const logicalDecision = buildLogicalDecisionCiphertext(comparison, ops);
  return { setupBundle, setup, auth, session, board, logicalDecision };
}

test("final release uses exactly all five threshold shares", () => {
  const run = fixture(0);
  const record = runFinalRelease({
    setupBundle: run.setupBundle,
    session: run.session,
    logicalDecision: run.logicalDecision,
    board: run.board,
    trusteePrivateKeys: run.auth.privateKeys,
    shareTrusteeIds: [1, 2, 3, 4, 5],
  });
  assert.equal(record.resultBit, 1);
  assert.deepEqual(record.shareTrusteeIds, [1, 2, 3, 4, 5]);
  assert.equal(verifyFinalRelease(record, run.setup).valid, true);
});

test("final release rejects a four-share quorum", () => {
  const run = fixture(1);
  assert.throws(() => runFinalRelease({
    setupBundle: run.setupBundle,
    session: run.session,
    logicalDecision: run.logicalDecision,
    board: run.board,
    trusteePrivateKeys: run.auth.privateKeys,
    shareTrusteeIds: [1, 2, 3, 4],
  }), (error) => error && error.code === "E_RELEASE_QUORUM");
});
