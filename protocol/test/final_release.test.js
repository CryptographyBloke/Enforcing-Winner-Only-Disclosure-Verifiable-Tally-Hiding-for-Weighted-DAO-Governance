"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { PROTOCOL_VERSION } = require("../src/group_oracle");
const { encryptScalar, addCiphertexts } = require("../src/elgamal");
const { createCiphertextOps } = require("../src/arithmetic");
const { provisionFreshTestOnly } = require("../src/threshold_setup");
const { createTrusteeAuthenticationRegistry, CanonicalAtomicBroadcastBoard } = require("../src/broadcast_board");
const {
  buildLogicalDecisionCiphertext,
  runFinalRelease,
  verifyFinalRelease,
  finalReleaseRecordToJson,
  finalReleaseRecordFromJson,
} = require("../src/final_release");
const { canonicalJson } = require("../src/broadcast_board");

function fixture(borrowBit) {
  const setupBundle = provisionFreshTestOnly();
  const setup = setupBundle.publicSetup;
  const auth = createTrusteeAuthenticationRegistry(5);
  const session = Object.freeze({
    protocolVersion: PROTOCOL_VERSION,
    setupHash: setup.setupHash,
    executionId: "34".repeat(32),
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
  return { setupBundle, setup, auth, session, board, comparison, logicalDecision };
}

test("source final release rerandomizes C_b and uses an arbitrary valid 3-of-5 quorum", () => {
  const run = fixture(0);
  const record = runFinalRelease({
    setupBundle: run.setupBundle,
    session: run.session,
    logicalDecision: run.logicalDecision,
    board: run.board,
    trusteePrivateKeys: run.auth.privateKeys,
    shareTrusteeIds: [1, 3, 5],
  });
  assert.equal(record.resultBit, 1);
  assert.deepEqual(record.shareTrusteeIds, [1, 3, 5]);
  assert.equal(verifyFinalRelease(record, run.setup).valid, true);
  const publicRecord = finalReleaseRecordFromJson(JSON.parse(canonicalJson(finalReleaseRecordToJson(record))));
  assert.equal(verifyFinalRelease(publicRecord, run.setup).valid, true);
});

test("release API rejects raw C_*, inconsistent Q, and changed result bit", () => {
  const run = fixture(1);
  assert.throws(() => runFinalRelease({
    setupBundle: run.setupBundle,
    session: run.session,
    logicalDecision: run.comparison.terminal.CStar,
    board: run.board,
    trusteePrivateKeys: run.auth.privateKeys,
  }), (error) => error.code === "E_RELEASE_INPUT");

  const ops = createCiphertextOps(() => { throw new Error("unused"); });
  assert.throws(() => buildLogicalDecisionCiphertext({
    borrow: run.comparison.borrow,
    terminal: { ...run.comparison.terminal, D: addCiphertexts(run.comparison.terminal.D, encryptScalar(run.setup.committeeKey, 0n, 99n)) },
  }, ops), (error) => error.code === "E_TERMINAL_IDENTITY");

  const clean = fixture(1);
  const record = runFinalRelease({
    setupBundle: clean.setupBundle,
    session: clean.session,
    logicalDecision: clean.logicalDecision,
    board: clean.board,
    trusteePrivateKeys: clean.auth.privateKeys,
  });
  assert.equal(record.resultBit, 0);
  assert.throws(() => verifyFinalRelease({ ...record, resultBit: 1 }, clean.setup), (error) => error.code === "E_FINAL_RESULT");
});
