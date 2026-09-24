"use strict";

// Application-layer adapter for the frozen native gate.  Rust owns all
// group/proof equations; this module only puts the public native records into
// the existing canonical-board and typed-verification envelope.

const {
  sourceSessionFromJson,
  publicSetupFromJson,
  ciphertextFromJson,
  pointFromJson,
  maskingProofFromJson,
  zeroProofFromJson,
} = require("../../js_protocol/src/codec");
const {
  encodeMaskingMessage,
  maskingPhase,
  partialDecryptionPhase,
  encodePartialMessage,
  verifyConditionalGateTranscript,
} = require("../../js_protocol/src/conditional_gate");
const {
  encodeContributionMessage,
} = require("../../js_protocol/src/rerandomization");
const {
  receive,
  markProofValidated,
  markBroadcastAgreed,
  markRerandomizationValidated,
  authorizeForDecryption,
} = require("../../js_protocol/src/validation_state");
const { ciphertextHash } = require("../../js_protocol/src/elgamal");
const { PROTOCOL_VERSION } = require("../../js_protocol/src/group_oracle");
const { canonicalJson } = require("../../js_protocol/src/broadcast_board");
const crypto = require("crypto");

const CIPHERTEXT_DOMAIN = "-CGY-TOOLBOX-FULL-V1/ELGAMAL-CIPHERTEXT/V1";
const AUTHORIZATION_DOMAIN = "-CGY-TOOLBOX-FULL-V1/DECRYPTION-AUTHORIZATION/V1";
const MASKING_MESSAGE_KIND = "CGY_ALGORITHMS_9_10_MASKING_TRANSITION";
const RERANDOMIZATION_MESSAGE_KIND = "CGY_ALGORITHM_63_ZERO_ENCRYPTION";
const PARTIAL_MESSAGE_KIND = "CGY_ALGORITHM_65_PARTIAL_DECRYPTION";

function rawPointBytes(point) {
  const output = Buffer.alloc(64);
  for (const [offset, value] of [[0, point.x], [32, point.y]]) {
    let scalar = BigInt(value);
    for (let index = 0; index < 32; index += 1) {
      output[offset + index] = Number(scalar & 0xffn);
      scalar >>= 8n;
    }
    if (scalar !== 0n) throw new Error("native point coordinate exceeds field encoding");
  }
  return output;
}

function rawCiphertextBytes(ciphertext) {
  return Buffer.concat([rawPointBytes(ciphertext.R), rawPointBytes(ciphertext.S)]);
}

function rawCiphertextHash(ciphertext) {
  return crypto.createHash("sha256")
    .update(Buffer.from(CIPHERTEXT_DOMAIN, "utf8"))
    .update(rawCiphertextBytes(ciphertext))
    .digest("hex");
}

function lp(value) {
  const bytes = Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

function rawExecutionContext(session, phase, purpose) {
  const gate = Buffer.alloc(8);
  gate.writeBigUInt64BE(BigInt(session.gateId));
  const invocation = Buffer.alloc(8);
  invocation.writeBigUInt64BE(BigInt(session.invocation));
  return Buffer.concat([
    lp(PROTOCOL_VERSION),
    Buffer.from(session.setupHash, "hex"),
    Buffer.from(session.executionId, "hex"),
    gate,
    invocation,
    lp(phase),
    lp(purpose),
  ]);
}

function rawAuthorizationId(session, ciphertext) {
  return crypto.createHash("sha256")
    .update(lp(AUTHORIZATION_DOMAIN))
    .update(rawExecutionContext(session, "GATE_SELECTOR_DECRYPTION", "CGY_GATE_SELECTOR"))
    .update(rawCiphertextBytes(ciphertext))
    .digest("hex");
}

function nativeTrustedPayloads(nativeGate, board, trusteePrivateKeys) {
  const setup = nativeGate.setup;
  const maskingSession = nativeGate.maskingSession;
  const sign = (session, phase, trusteeId, payload) => signAndSubmit(board, session, phase, trusteeId, payload, trusteePrivateKeys);
  for (let index = 0; index < nativeGate.masking.length; index += 1) {
    const trusteeId = index + 1;
    const entry = nativeGate.masking[index];
    const phase = `MASKING_${String(trusteeId).padStart(2, "0")}`;
    const payload = Buffer.from(canonicalJson({
      kind: MASKING_MESSAGE_KIND,
      sourceSession: maskingSession,
      previousX: entry.previousX,
      previousY: entry.previousY,
      nextX: entry.nextX,
      e: entry.e,
      nextY: entry.nextY,
      proof: entry.proof,
    }), "utf8");
    board.definePhase({ gateId: maskingSession.gateId, invocation: maskingSession.invocation, phase, dependsOnPhase: trusteeId === 1 ? null : `MASKING_${String(trusteeId - 1).padStart(2, "0")}`, requiredTrusteeIds: [trusteeId] });
    sign(maskingSession, phase, trusteeId, payload);
  }
  function rerandomize(field, phase) {
    const sourceSession = field.sourceSession;
    board.definePhase({ gateId: sourceSession.gateId, invocation: sourceSession.invocation, phase });
    const inputHash = rawCiphertextHash(field.input);
    for (let index = 0; index < field.records.length; index += 1) {
      const trusteeId = index + 1;
      const entry = field.records[index];
      const payload = Buffer.from(canonicalJson({
        kind: RERANDOMIZATION_MESSAGE_KIND,
        sourceSession,
        inputHash,
        contribution: entry.contribution,
        proof: entry.proof,
      }), "utf8");
      sign(sourceSession, phase, trusteeId, payload);
    }
  }
  rerandomize(nativeGate.xRerandomization, "GATE_X_RERANDOMIZATION");
  rerandomize(nativeGate.yRerandomization, "GATE_Y_DECRYPT_RERANDOMIZATION");
  const boardBeforeShares = board.exportTranscript();
  const authorizationId = rawAuthorizationId(nativeGate.partialSession, nativeGate.yRerandomization.output);
  const ciphertextHash = rawCiphertextHash(nativeGate.yRerandomization.output);
  for (let index = 0; index < nativeGate.partialShares.length; index += 1) {
    const trusteeId = index + 1;
    const entry = nativeGate.partialShares[index];
    const phase = `GATE_Y_PARTIAL_DECRYPTION_${String(trusteeId).padStart(2, "0")}`;
    const payload = Buffer.from(canonicalJson({
      kind: PARTIAL_MESSAGE_KIND,
      setupHash: setup.setupHash,
      authorizationId,
      ciphertextHash,
      trusteeId,
      w: entry.w,
      cG: entry.cG,
      cU: entry.cU,
      a: entry.a,
    }), "utf8");
    board.definePhase({ gateId: nativeGate.partialSession.gateId, invocation: nativeGate.partialSession.invocation, phase, requiredTrusteeIds: [trusteeId] });
    sign(nativeGate.partialSession, phase, trusteeId, payload);
  }
  return boardBeforeShares;
}

function adaptNativeGateTrusted({ nativeGate, board, trusteePrivateKeys }) {
  nativeTrustedPayloads(nativeGate, board, trusteePrivateKeys);
  return Object.freeze({ output: nativeGate.output, boardExport: board.exportTranscript() });
}

function slotFor(session, phase, trusteeId) {
  return {
    protocolVersion: session.protocolVersion,
    setupHash: session.setupHash,
    executionId: session.executionId,
    gateId: session.gateId,
    invocation: session.invocation,
    phase,
    trusteeId,
  };
}

function signAndSubmit(board, session, phase, trusteeId, payload, trusteePrivateKeys) {
  const { signSubmission } = require("../../js_protocol/src/broadcast_board");
  const slot = slotFor(session, phase, trusteeId);
  const signature = signSubmission(trusteePrivateKeys[trusteeId - 1].privateKey, slot, payload);
  board.submit({ slot, payload, signature });
}

function selectorAuthorization({ setup, baseSession, maskedY, rerandomizedY, boardHash }) {
  const tdSession = sourceSessionFromJson(baseSession);
  const context = Object.freeze({
    protocolVersion: PROTOCOL_VERSION,
    setupHash: setup.setupHash,
    executionId: tdSession.executionId,
    gateId: tdSession.gateId,
    invocation: tdSession.invocation,
    phase: "GATE_SELECTOR_DECRYPTION",
    purpose: "CGY_GATE_SELECTOR",
  });
  const received = receive(maskedY, context, { source: "CGY_MASKING_CHAIN", ciphertextHash: ciphertextHash(maskedY) });
  const proofValidated = markProofValidated(received, { valid: true, verifier: "ALGORITHMS_9_10" });
  const broadcastAgreed = markBroadcastAgreed(proofValidated, { agreed: true, transcriptHash: boardHash });
  const rerandomizationValidated = markRerandomizationValidated(broadcastAgreed, rerandomizedY, { valid: true, verifier: "ALGORITHM_63" });
  return Object.freeze({
    tdSession,
    authorization: authorizeForDecryption(rerandomizationValidated, { authorized: true, policy: "CGY_GATE_SELECTOR_ONLY" }),
  });
}

function adaptNativeGate({ nativeGate, board, trusteePrivateKeys, setup: setupOverride = null, verifyJs = false }) {
  // The native DAG validates the public setup once before executing any gate.
  // Reusing that already-verified object avoids repeating five trustee-key
  // consistency scalar multiplications for every transcript record.
  const setup = setupOverride || publicSetupFromJson(nativeGate.setup);
  const baseSession = sourceSessionFromJson(nativeGate.baseSession);
  const maskingSession = sourceSessionFromJson(nativeGate.maskingSession);
  const inputX = ciphertextFromJson(nativeGate.inputX);
  const inputY = ciphertextFromJson(nativeGate.inputY);
  const htilde = pointFromJson(nativeGate.htilde);

  const maskingRecords = [];
  for (let index = 0; index < nativeGate.masking.length; index += 1) {
    const trusteeId = index + 1;
    const entry = nativeGate.masking[index];
    const previousX = ciphertextFromJson(entry.previousX);
    const previousY = ciphertextFromJson(entry.previousY);
    const nextX = ciphertextFromJson(entry.nextX);
    const nextY = ciphertextFromJson(entry.nextY);
    const e = pointFromJson(entry.e);
    const proof = maskingProofFromJson({
      cPlusX: entry.proof.cPlusX,
      cPlusY: entry.proof.cPlusY,
      cMinusX: entry.proof.cMinusX,
      cMinusY: entry.proof.cMinusY,
      cPlusE: entry.proof.cPlusE,
      cMinusE: entry.proof.cMinusE,
      dPlus: entry.proof.dPlus,
      dMinus: entry.proof.dMinus,
      aPlusX: entry.proof.aPlusX,
      aPlusY: entry.proof.aPlusY,
      aMinusX: entry.proof.aMinusX,
      aMinusY: entry.proof.aMinusY,
    });
    const payload = encodeMaskingMessage(maskingSession, previousX, previousY, nextX, e, nextY, proof);
    const phase = maskingPhase(trusteeId);
    board.definePhase({
      gateId: maskingSession.gateId,
      invocation: maskingSession.invocation,
      phase,
      dependsOnPhase: trusteeId === 1 ? null : maskingPhase(trusteeId - 1),
      requiredTrusteeIds: [trusteeId],
    });
    signAndSubmit(board, maskingSession, phase, trusteeId, payload, trusteePrivateKeys);
    const view = board.readPhase({ gateId: maskingSession.gateId, invocation: maskingSession.invocation, phase });
    if (view.status !== "SEALED") throw new Error(`E_NATIVE_MASK_BOARD_${trusteeId}`);
    maskingRecords.push(view.vector[0]);
  }

  function adaptRerandomization(field, phase) {
    const sourceSession = sourceSessionFromJson(field.sourceSession);
    const input = ciphertextFromJson(field.input);
    const output = ciphertextFromJson(field.output);
    board.definePhase({ gateId: sourceSession.gateId, invocation: sourceSession.invocation, phase });
    for (let index = 0; index < field.records.length; index += 1) {
      const trusteeId = index + 1;
      const entry = field.records[index];
      const contribution = ciphertextFromJson(entry.contribution);
      const proof = zeroProofFromJson(entry.proof);
      const payload = encodeContributionMessage(sourceSession, input, contribution, proof);
      signAndSubmit(board, sourceSession, phase, trusteeId, payload, trusteePrivateKeys);
    }
    const view = board.readPhase({ gateId: sourceSession.gateId, invocation: sourceSession.invocation, phase });
    if (view.status !== "SEALED") throw new Error(`E_NATIVE_RERANDOMIZATION_BOARD_${phase}`);
    return Object.freeze({ phase, sourceSession, input, output, vector: view.vector });
  }

  const xRerandomization = adaptRerandomization(nativeGate.xRerandomization, "GATE_X_RERANDOMIZATION");
  const yRerandomization = adaptRerandomization(nativeGate.yRerandomization, "GATE_Y_DECRYPT_RERANDOMIZATION");
  const boardBeforeShares = board.exportTranscript();
  const { tdSession, authorization } = selectorAuthorization({
    setup,
    baseSession: nativeGate.partialSession,
    maskedY: ciphertextFromJson(nativeGate.masking[nativeGate.masking.length - 1].nextY),
    rerandomizedY: yRerandomization.output,
    boardHash: boardBeforeShares.transcriptHash,
  });

  const partialVector = [];
  for (let index = 0; index < nativeGate.partialShares.length; index += 1) {
    const trusteeId = index + 1;
    const entry = nativeGate.partialShares[index];
    const payload = encodePartialMessage({
      payload: {
        setupHash: setup.setupHash,
        authorizationId: authorization.authorizationId,
        ciphertextHash: authorization.ciphertextHash,
        trusteeId,
        w: pointFromJson(entry.w),
        cG: pointFromJson(entry.cG),
        cU: pointFromJson(entry.cU),
        a: BigInt(entry.a),
      },
    });
    const phase = partialDecryptionPhase(trusteeId);
    board.definePhase({ gateId: tdSession.gateId, invocation: tdSession.invocation, phase, requiredTrusteeIds: [trusteeId] });
    signAndSubmit(board, tdSession, phase, trusteeId, payload, trusteePrivateKeys);
    const view = board.readPhase({ gateId: tdSession.gateId, invocation: tdSession.invocation, phase });
    if (view.status !== "SEALED") throw new Error(`E_NATIVE_PARTIAL_BOARD_${trusteeId}`);
    partialVector.push(view.vector[0]);
  }

  const output = ciphertextFromJson(nativeGate.output);
  const record = Object.freeze({
    protocolVersion: nativeGate.protocolVersion || PROTOCOL_VERSION,
    setup,
    baseSession,
    inputX,
    inputY,
    htilde,
    htildeCounter: nativeGate.htildeCounter,
    maskingSession,
    maskingRecords: Object.freeze(maskingRecords),
    maskedX: ciphertextFromJson(nativeGate.masking[nativeGate.masking.length - 1].nextX),
    maskedY: ciphertextFromJson(nativeGate.masking[nativeGate.masking.length - 1].nextY),
    xRerandomization,
    yRerandomization,
    partialSession: tdSession,
    partialVector: Object.freeze(partialVector),
    preShareBoardHash: boardBeforeShares.transcriptHash,
    openedSign: nativeGate.openedSign,
    output,
    boardExport: board.exportTranscript(),
  });
  if (verifyJs) verifyConditionalGateTranscript(record);
  return record;
}

module.exports = Object.freeze({ adaptNativeGate, adaptNativeGateTrusted });
