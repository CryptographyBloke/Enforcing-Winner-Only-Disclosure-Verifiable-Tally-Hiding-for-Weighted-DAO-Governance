"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {
  PROTOCOL_VERSION,
} = require("../src/group_oracle");
const {
  createTrusteeAuthenticationRegistry,
  signSubmission,
  CanonicalAtomicBroadcastBoard,
  verifyBroadcastTranscript,
  canonicalJson,
} = require("../src/broadcast_board");

const SETUP_HASH = "55".repeat(32);
const EXECUTION_ID = "66".repeat(32);

function expectCode(fn, code) {
  assert.throws(fn, (error) => error && error.code === code);
}

function createFixture() {
  const auth = createTrusteeAuthenticationRegistry(5);
  const board = new CanonicalAtomicBroadcastBoard({
    setupHash: SETUP_HASH,
    executionId: EXECUTION_ID,
    trusteePublicKeys: auth.publicKeys,
  });
  board.definePhase({ gateId: 1n, invocation: 0n, phase: "RERANDOMIZATION_COMMIT" });
  board.definePhase({ gateId: 1n, invocation: 0n, phase: "RERANDOMIZATION_REVEAL", dependsOnPhase: "RERANDOMIZATION_COMMIT" });
  return { auth, board };
}

function slot(phase, trusteeId, overrides = {}) {
  return Object.freeze({
    protocolVersion: PROTOCOL_VERSION,
    setupHash: SETUP_HASH,
    executionId: EXECUTION_ID,
    gateId: 1n,
    invocation: 0n,
    phase,
    trusteeId,
    ...overrides,
  });
}

function submit(board, auth, phase, trusteeId, payloadText) {
  const targetSlot = slot(phase, trusteeId);
  const payload = Buffer.from(payloadText, "utf8");
  const signature = signSubmission(auth.privateKeys[trusteeId - 1].privateKey, targetSlot, payload);
  return board.submit({ slot: targetSlot, payload, signature });
}

test("synchronous contributions stay hidden and reveal once in trustee order", () => {
  const { auth, board } = createFixture();
  const order = [5, 2, 4, 1, 3];
  for (let index = 0; index < order.length; index += 1) {
    const trusteeId = order[index];
    const status = submit(board, auth, "RERANDOMIZATION_COMMIT", trusteeId, `commit-${trusteeId}`);
    if (index < order.length - 1) {
      assert.equal(status.status, "STAGED");
      const view = board.readPhase({ gateId: 1n, invocation: 0n, phase: "RERANDOMIZATION_COMMIT" });
      assert.equal(view.status, "WAIT");
      assert.equal(Object.hasOwn(view, "vector"), false);
    } else {
      assert.equal(status.status, "SEALED");
    }
  }
  const view = board.readPhase({ gateId: 1n, invocation: 0n, phase: "RERANDOMIZATION_COMMIT" });
  assert.equal(view.status, "SEALED");
  assert.deepEqual(view.vector.map((entry) => entry.trusteeId), [1, 2, 3, 4, 5]);
  assert.deepEqual(view.vector.map((entry) => entry.payload.toString()), ["commit-1", "commit-2", "commit-3", "commit-4", "commit-5"]);
});

test("reveal cannot be submitted or observed before commit barrier", () => {
  const { auth, board } = createFixture();
  const early = submit(board, auth, "RERANDOMIZATION_REVEAL", 1, "reveal-1");
  assert.deepEqual(early, { status: "WAIT", code: "WAIT_COMMIT_BARRIER" });
  for (let trusteeId = 1; trusteeId <= 5; trusteeId += 1) submit(board, auth, "RERANDOMIZATION_COMMIT", trusteeId, `commit-${trusteeId}`);
  for (let trusteeId = 1; trusteeId <= 4; trusteeId += 1) submit(board, auth, "RERANDOMIZATION_REVEAL", trusteeId, `reveal-${trusteeId}`);
  const hidden = board.readPhase({ gateId: 1n, invocation: 0n, phase: "RERANDOMIZATION_REVEAL" });
  assert.equal(hidden.status, "WAIT");
  assert.equal(Object.hasOwn(hidden, "vector"), false);
  submit(board, auth, "RERANDOMIZATION_REVEAL", 5, "reveal-5");
  assert.deepEqual(board.readPhase({ gateId: 1n, invocation: 0n, phase: "RERANDOMIZATION_REVEAL" }).vector.map((entry) => entry.trusteeId), [1, 2, 3, 4, 5]);
});

test("identical retry is idempotent and conflicting retry deterministically aborts", () => {
  const { auth, board } = createFixture();
  const first = submit(board, auth, "RERANDOMIZATION_COMMIT", 1, "commit-1");
  assert.equal(first.idempotent, false);
  const duplicate = submit(board, auth, "RERANDOMIZATION_COMMIT", 1, "commit-1");
  assert.deepEqual(duplicate, { status: "STAGED", idempotent: true });
  expectCode(() => submit(board, auth, "RERANDOMIZATION_COMMIT", 1, "conflict"), "ABORT_EQUIVOCATION");
  assert.equal(board.readPhase({ gateId: 1n, invocation: 0n, phase: "RERANDOMIZATION_COMMIT" }).status, "ABORT");
  expectCode(() => submit(board, auth, "RERANDOMIZATION_COMMIT", 2, "commit-2"), "E_BOARD_ABORTED");
});

test("authentication, trustee identity, and stale context are enforced", () => {
  const { auth, board } = createFixture();
  const target = slot("RERANDOMIZATION_COMMIT", 1);
  const payload = Buffer.from("commit-1");
  const forged = signSubmission(auth.privateKeys[1].privateKey, target, payload);
  expectCode(() => board.submit({ slot: target, payload, signature: forged }), "E_TRUSTEE_AUTH");
  const stale = slot("RERANDOMIZATION_COMMIT", 1, { executionId: "77".repeat(32) });
  const staleSignature = signSubmission(auth.privateKeys[0].privateKey, stale, payload);
  expectCode(() => board.submit({ slot: stale, payload, signature: staleSignature }), "E_BOARD_CONTEXT");
});

test("canonical signed transcript replays and detects payload, signature, and ordering tampering", () => {
  const { auth, board } = createFixture();
  for (let trusteeId = 5; trusteeId >= 1; trusteeId -= 1) submit(board, auth, "RERANDOMIZATION_COMMIT", trusteeId, `commit-${trusteeId}`);
  for (let trusteeId = 5; trusteeId >= 1; trusteeId -= 1) submit(board, auth, "RERANDOMIZATION_REVEAL", trusteeId, `reveal-${trusteeId}`);
  const exported = board.exportTranscript();
  assert.deepEqual(verifyBroadcastTranscript(exported), { valid: true, transcriptHash: exported.transcriptHash });

  const payloadTamper = structuredClone(exported.transcript);
  payloadTamper.phases[0].submissions[0].payloadHex = Buffer.from("tamper").toString("hex");
  const payloadCanonical = canonicalJson(payloadTamper);
  expectCode(() => verifyBroadcastTranscript({ transcript: payloadTamper, canonical: payloadCanonical, transcriptHash: require("crypto").createHash("sha256").update(payloadCanonical).digest("hex") }), "E_TRANSCRIPT_PAYLOAD");

  const orderTamper = structuredClone(exported.transcript);
  orderTamper.phases[0].submissions.reverse();
  const orderCanonical = canonicalJson(orderTamper);
  expectCode(() => verifyBroadcastTranscript({ transcript: orderTamper, canonical: orderCanonical, transcriptHash: require("crypto").createHash("sha256").update(orderCanonical).digest("hex") }), "E_TRANSCRIPT_TRUSTEE_ORDER");

  const signatureTamper = structuredClone(exported.transcript);
  signatureTamper.phases[0].submissions[0].signatureBase64 = Buffer.alloc(64).toString("base64");
  const signatureCanonical = canonicalJson(signatureTamper);
  expectCode(() => verifyBroadcastTranscript({ transcript: signatureTamper, canonical: signatureCanonical, transcriptHash: require("crypto").createHash("sha256").update(signatureCanonical).digest("hex") }), "E_TRANSCRIPT_SIGNATURE");
});
