"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {
  BASE8,
  IDENTITY,
  addPoints,
  negatePoint,
  scalarMultiply,
  pointEquals,
} = require("../src/group");
const {
  encryptScalar,
  addCiphertexts,
} = require("../src/elgamal");
const { PROTOCOL_VERSION } = require("../src/group_oracle");
const {
  provisionFreshTestOnly,
  verifySecretShare,
  interpolateScalarAtZero,
} = require("../src/threshold_setup");
const {
  createTrusteeAuthenticationRegistry,
  CanonicalAtomicBroadcastBoard,
} = require("../src/broadcast_board");
const {
  runConditionalGate,
  verifyConditionalGateTranscript,
  serializeConditionalGateTranscript,
  parseConditionalGateTranscript,
} = require("../src/conditional_gate");

function decryptForTestOnly(setupBundle, value) {
  const setup = setupBundle.publicSetup;
  const shares = setupBundle.secretShares.slice(0, 3).map((share) => verifySecretShare(setup, share));
  const secret = interpolateScalarAtZero(setup, shares);
  return addPoints(value.S, negatePoint(scalarMultiply(value.R, secret)));
}

function runGate(x, y, executionByte, gateId) {
  const setupBundle = provisionFreshTestOnly();
  const auth = createTrusteeAuthenticationRegistry(5);
  const baseSession = Object.freeze({
    protocolVersion: PROTOCOL_VERSION,
    setupHash: setupBundle.publicSetup.setupHash,
    executionId: executionByte.repeat(64),
    gateId: BigInt(gateId),
    invocation: 0n,
  });
  const board = new CanonicalAtomicBroadcastBoard({
    setupHash: baseSession.setupHash,
    executionId: baseSession.executionId,
    trusteePublicKeys: auth.publicKeys,
  });
  const inputX = encryptScalar(setupBundle.publicSetup.committeeKey, BigInt(x), 1234n + BigInt(gateId));
  const inputY = encryptScalar(setupBundle.publicSetup.committeeKey, BigInt(y), 5678n + BigInt(gateId));
  const record = runConditionalGate({ setupBundle, baseSession, inputX, inputY, board, trusteePrivateKeys: auth.privateKeys });
  return { setupBundle, record };
}

test("one complete source gate independently replays for selector one", () => {
  const { setupBundle, record } = runGate(7, 1, "d", 20);
  const replay = verifyConditionalGateTranscript(record);
  assert.equal(replay.valid, true);
  const serialized = serializeConditionalGateTranscript(record);
  const parsed = parseConditionalGateTranscript(serialized);
  assert.equal(verifyConditionalGateTranscript(parsed).valid, true);
  assert.equal(pointEquals(decryptForTestOnly(setupBundle, record.output), scalarMultiply(BASE8, 7n)), true);
  assert.equal(record.maskingRecords.length, 5);
  assert.equal(record.xRerandomization.vector.length, 5);
  assert.equal(record.yRerandomization.vector.length, 5);
  assert.equal(record.partialVector.length, 5);
});

test("one complete source gate independently replays for selector zero", () => {
  const { setupBundle, record } = runGate(7, 0, "e", 21);
  assert.equal(verifyConditionalGateTranscript(record).valid, true);
  assert.equal(pointEquals(decryptForTestOnly(setupBundle, record.output), IDENTITY), true);
});

test("altered auxiliary element, rerandomization output, result, and board transcript reject", () => {
  const { record } = runGate(3, 1, "f", 22);
  assert.throws(() => verifyConditionalGateTranscript({ ...record, htilde: addPoints(record.htilde, BASE8) }), (error) => error.code === "E_GATE_AUXILIARY");
  assert.throws(() => verifyConditionalGateTranscript({ ...record, xRerandomization: { ...record.xRerandomization, output: addCiphertexts(record.xRerandomization.output, record.xRerandomization.vector.length ? encryptScalar(record.setup.committeeKey, 0n, 17n) : record.inputX) } }), (error) => error.code === "E_RERANDOMIZATION_OUTPUT");
  assert.throws(() => verifyConditionalGateTranscript({ ...record, output: addCiphertexts(record.output, encryptScalar(record.setup.committeeKey, 0n, 19n)) }), (error) => error.code === "E_GATE_OUTPUT");
  const tamperedBoard = { ...record.boardExport, transcriptHash: "00".repeat(32) };
  assert.throws(() => verifyConditionalGateTranscript({ ...record, boardExport: tamperedBoard }), (error) => error.code === "E_TRANSCRIPT_HASH");
});
