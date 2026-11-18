"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { PROTOCOL_VERSION } = require("../src/group_oracle");
const { encryptScalar, ciphertextEquals } = require("../src/elgamal");
const { provisionFreshTestOnly } = require("../src/threshold_setup");
const { createTrusteeAuthenticationRegistry, CanonicalAtomicBroadcastBoard } = require("../src/broadcast_board");
const { runRerandomization, verifyRerandomizationRecord } = require("../src/rerandomization");

test("Algorithm 63 all-trustee synchronous rerandomization verifies", () => {
  const setup = provisionFreshTestOnly().publicSetup;
  const auth = createTrusteeAuthenticationRegistry(5);
  const sourceSession = Object.freeze({
    protocolVersion: PROTOCOL_VERSION,
    setupHash: setup.setupHash,
    executionId: "cd".repeat(32),
    gateId: 4n,
    invocation: 1n,
  });
  const board = new CanonicalAtomicBroadcastBoard({ setupHash: setup.setupHash, executionId: sourceSession.executionId, trusteePublicKeys: auth.publicKeys });
  const input = encryptScalar(setup.committeeKey, 1n, 3456n);
  const record = runRerandomization({ setup, sourceSession, input, board, trusteePrivateKeys: auth.privateKeys, phase: "GATE_X_RERANDOMIZATION" });
  assert.equal(record.vector.length, 5);
  assert.equal(ciphertextEquals(record.output, input), false);
  assert.deepEqual(verifyRerandomizationRecord({ setup, record }), { valid: true, output: record.output });
});
