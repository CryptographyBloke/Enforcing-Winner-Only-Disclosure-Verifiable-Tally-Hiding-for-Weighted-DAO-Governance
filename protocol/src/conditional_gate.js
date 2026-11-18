"use strict";

const crypto = require("crypto");
const { requireCondition } = require("./errors");
const {
  SUBGROUP_ORDER,
  BASE8,
  IDENTITY,
  PointRole,
  addPoints,
  negatePoint,
  scalarMultiply,
  validatePoint,
  pointEquals,
} = require("./group");
const { randomScalar, scalar, scalarMod } = require("./scalars");
const {
  ciphertext,
  validateCiphertext,
  ciphertextHash,
  ciphertextEquals,
  addCiphertexts,
  scaleCiphertext,
} = require("./elgamal");
const { deriveAuxiliaryPoint, PROTOCOL_VERSION } = require("./group_oracle");
const {
  signedRerandomize,
  proveMaskingTransition,
  verifyMaskingTransition,
} = require("./proofs");
const {
  signSubmission,
  verifyBroadcastTranscript,
  canonicalJson,
} = require("./broadcast_board");
const {
  runRerandomization,
  verifyRerandomizationRecord,
} = require("./rerandomization");
const {
  receive,
  markProofValidated,
  markBroadcastAgreed,
  markRerandomizationValidated,
  authorizeForDecryption,
  emitPartialShare,
} = require("./validation_state");
const {
  verifySecretShare,
  verifyPublicSetup,
} = require("./threshold_setup");
const {
  createPartialDecryptionShare,
  verifyPartialDecryptionShare,
  combineVerifiedPartialDecryptions,
} = require("./threshold_decryption");
const {
  exactKeys,
  decimalBigint,
  pointToJson,
  pointFromJson,
  ciphertextToJson,
  ciphertextFromJson,
  maskingProofToJson,
  maskingProofFromJson,
  sourceSessionToJson,
  sourceSessionFromJson,
  publicSetupToJson,
  publicSetupFromJson,
  canonicalPayload,
  parseCanonicalPayload,
} = require("./codec");

const MASKING_MESSAGE_KIND = "CGY_ALGORITHMS_9_10_MASKING_TRANSITION";
const PARTIAL_MESSAGE_KIND = "CGY_ALGORITHM_65_PARTIAL_DECRYPTION";
const INVERSE_TWO = (SUBGROUP_ORDER + 1n) / 2n;

function subSession(base, offset) {
  const invocation = BigInt(base.invocation) * 16n + BigInt(offset);
  requireCondition(invocation <= 0xffffffffffffffffn, "E_GATE_INVOCATION", "derived source invocation exceeds uint64");
  return Object.freeze({
    protocolVersion: PROTOCOL_VERSION,
    setupHash: base.setupHash,
    executionId: base.executionId,
    gateId: BigInt(base.gateId),
    invocation,
  });
}

function maskingPhase(trusteeId) {
  return `MASKING_${String(trusteeId).padStart(2, "0")}`;
}

function partialDecryptionPhase(trusteeId) {
  return `GATE_Y_PARTIAL_DECRYPTION_${String(trusteeId).padStart(2, "0")}`;
}

function slotFor(sourceSession, phase, trusteeId) {
  return Object.freeze({
    protocolVersion: sourceSession.protocolVersion,
    setupHash: sourceSession.setupHash,
    executionId: sourceSession.executionId,
    gateId: sourceSession.gateId,
    invocation: sourceSession.invocation,
    phase,
    trusteeId,
  });
}

function encodeMaskingMessage(sourceSession, previousX, previousY, nextX, e, nextY, proof) {
  return canonicalPayload({
    kind: MASKING_MESSAGE_KIND,
    sourceSession: sourceSessionToJson(sourceSession),
    previousX: ciphertextToJson(previousX),
    previousY: ciphertextToJson(previousY),
    nextX: ciphertextToJson(nextX),
    e: pointToJson(e),
    nextY: ciphertextToJson(nextY),
    proof: maskingProofToJson(proof),
  });
}

function decodeMaskingMessage(payload) {
  const value = parseCanonicalPayload(payload);
  exactKeys(value, ["kind", "sourceSession", "previousX", "previousY", "nextX", "e", "nextY", "proof"], "E_MASK_MESSAGE");
  requireCondition(value.kind === MASKING_MESSAGE_KIND, "E_MASK_MESSAGE_KIND", "wrong masking message kind");
  return Object.freeze({
    sourceSession: value.sourceSession,
    previousX: ciphertextFromJson(value.previousX),
    previousY: ciphertextFromJson(value.previousY),
    nextX: ciphertextFromJson(value.nextX),
    e: pointFromJson(value.e),
    nextY: ciphertextFromJson(value.nextY),
    proof: maskingProofFromJson(value.proof),
  });
}

function encodePartialMessage(partialShare) {
  const proof = partialShare.payload;
  return canonicalPayload({
    kind: PARTIAL_MESSAGE_KIND,
    setupHash: proof.setupHash,
    authorizationId: proof.authorizationId,
    ciphertextHash: proof.ciphertextHash,
    trusteeId: proof.trusteeId,
    w: pointToJson(proof.w),
    cG: pointToJson(proof.cG),
    cU: pointToJson(proof.cU),
    a: proof.a.toString(10),
  });
}

function decodePartialMessage(payload) {
  const value = parseCanonicalPayload(payload);
  exactKeys(value, ["kind", "setupHash", "authorizationId", "ciphertextHash", "trusteeId", "w", "cG", "cU", "a"], "E_PARTIAL_MESSAGE");
  requireCondition(value.kind === PARTIAL_MESSAGE_KIND, "E_PARTIAL_MESSAGE_KIND", "wrong partial-decryption message kind");
  return Object.freeze({
    setupHash: value.setupHash,
    authorizationId: value.authorizationId,
    ciphertextHash: value.ciphertextHash,
    trusteeId: value.trusteeId,
    w: pointFromJson(value.w),
    cG: pointFromJson(value.cG),
    cU: pointFromJson(value.cU),
    a: decimalBigint(value.a, "partial response"),
  });
}

function randomSign() {
  return (crypto.randomBytes(1)[0] & 1) === 0 ? 1 : -1;
}

function initialSignedSelector(inputY) {
  const encryptionOfMinusOne = ciphertext(IDENTITY, negatePoint(BASE8));
  return addCiphertexts(encryptionOfMinusOne, scaleCiphertext(inputY, 2n));
}

function verifyMaskingRecords({ setup, sourceSession, htilde, inputX, inputY, records }) {
  requireCondition(Array.isArray(records) && records.length === setup.trustees, "E_MASK_VECTOR", "one masking record per trustee is required");
  let previousX = validateCiphertext(inputX);
  let previousY = initialSignedSelector(validateCiphertext(inputY));
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    requireCondition(record.trusteeId === index + 1, "E_MASK_ORDER", "masking records are not in trustee order");
    const decoded = decodeMaskingMessage(record.payload);
    requireCondition(JSON.stringify(decoded.sourceSession) === JSON.stringify(sourceSessionToJson(sourceSession)), "E_MASK_SESSION", "masking record belongs to another source session");
    requireCondition(ciphertextEquals(decoded.previousX, previousX) && ciphertextEquals(decoded.previousY, previousY), "E_MASK_PREDECESSOR", "masking predecessor does not match the agreed chain");
    verifyMaskingTransition({
      setup,
      sourceSession,
      htilde,
      previousX,
      previousY,
      nextX: decoded.nextX,
      nextY: decoded.nextY,
      e: decoded.e,
      proof: decoded.proof,
    });
    previousX = decoded.nextX;
    previousY = decoded.nextY;
  }
  return Object.freeze({ valid: true, finalX: previousX, finalY: previousY });
}

function boardVectorFor(exportedBoard, sourceSession, phase) {
  const phaseRecord = exportedBoard.transcript.phases.find((entry) => (
    entry.gateId === sourceSession.gateId.toString(10)
      && entry.invocation === sourceSession.invocation.toString(10)
      && entry.phase === phase
  ));
  requireCondition(phaseRecord && phaseRecord.status === "SEALED", "E_GATE_BOARD_PHASE", `sealed board phase ${phase} is missing`);
  return Object.freeze(phaseRecord.submissions.map((entry) => Object.freeze({
    trusteeId: entry.trusteeId,
    payload: Buffer.from(entry.payloadHex, "hex"),
  })));
}

function boardPrefixHashBeforePartialDecryptions(exportedBoard, sourceSession) {
  const transcript = structuredClone(exportedBoard.transcript);
  const before = transcript.phases.length;
  transcript.phases = transcript.phases.filter((entry) => !(
    entry.gateId === sourceSession.gateId.toString(10)
      && entry.invocation === sourceSession.invocation.toString(10)
      && entry.phase.startsWith("GATE_Y_PARTIAL_DECRYPTION_")
  ));
  requireCondition(transcript.phases.length === before - exportedBoard.transcript.trustees, "E_GATE_PREFIX_PHASE", "partial-decryption phases are missing or duplicated");
  return crypto.createHash("sha256").update(canonicalJson(transcript)).digest("hex");
}

function makeSelectorAuthorization({ setup, baseSession, inputY, rerandomizedY, boardHash }) {
  const tdSession = subSession(baseSession, 3);
  const context = Object.freeze({
    protocolVersion: PROTOCOL_VERSION,
    setupHash: setup.setupHash,
    executionId: baseSession.executionId,
    gateId: baseSession.gateId,
    invocation: tdSession.invocation,
    phase: "GATE_SELECTOR_DECRYPTION",
    purpose: "CGY_GATE_SELECTOR",
  });
  const received = receive(inputY, context, { source: "CGY_MASKING_CHAIN", ciphertextHash: ciphertextHash(inputY) });
  const proofValidated = markProofValidated(received, { valid: true, verifier: "ALGORITHMS_9_10" });
  const broadcastAgreed = markBroadcastAgreed(proofValidated, { agreed: true, transcriptHash: boardHash });
  const rerandomizationValidated = markRerandomizationValidated(broadcastAgreed, rerandomizedY, { valid: true, verifier: "ALGORITHM_63" });
  return Object.freeze({
    tdSession,
    authorization: authorizeForDecryption(rerandomizationValidated, { authorized: true, policy: "CGY_GATE_SELECTOR_ONLY" }),
  });
}

function runConditionalGate({ setupBundle, baseSession, inputX, inputY, board, trusteePrivateKeys }) {
  const setup = verifyPublicSetup(setupBundle.publicSetup);
  requireCondition(setupBundle.secretShares.length === setup.trustees, "E_GATE_SHARES", "gate run requires each trustee's setup share");
  const X = validateCiphertext(inputX);
  const Y = validateCiphertext(inputY);
  const maskingSession = subSession(baseSession, 0);
  const auxiliary = deriveAuxiliaryPoint(maskingSession, setup.committeeKey);
  let previousX = X;
  let previousY = initialSignedSelector(Y);
  const maskingRecords = [];
  for (let trusteeId = 1; trusteeId <= setup.trustees; trusteeId += 1) {
    const phase = maskingPhase(trusteeId);
    board.definePhase({
      gateId: maskingSession.gateId,
      invocation: maskingSession.invocation,
      phase,
      dependsOnPhase: trusteeId === 1 ? null : maskingPhase(trusteeId - 1),
      requiredTrusteeIds: [trusteeId],
    });
    const sign = randomSign();
    const rX = randomScalar();
    const rY = randomScalar();
    const nextX = signedRerandomize(previousX, sign, setup.committeeKey, rX);
    const nextY = signedRerandomize(previousY, sign, setup.committeeKey, rY);
    const e = scalarMultiply(auxiliary.point, rX);
    const proof = proveMaskingTransition({ setup, sourceSession: maskingSession, htilde: auxiliary.point, previousX, previousY, nextX, nextY, e, sign, rX, rY });
    const payload = encodeMaskingMessage(maskingSession, previousX, previousY, nextX, e, nextY, proof);
    const slot = slotFor(maskingSession, phase, trusteeId);
    const signature = signSubmission(trusteePrivateKeys[trusteeId - 1].privateKey, slot, payload);
    board.submit({ slot, payload, signature });
    const view = board.readPhase({ gateId: maskingSession.gateId, invocation: maskingSession.invocation, phase });
    requireCondition(view.status === "SEALED", "E_MASK_WAIT", "masking transition was not broadcast-agreed");
    maskingRecords.push(view.vector[0]);
    previousX = nextX;
    previousY = nextY;
  }
  const maskingVerified = verifyMaskingRecords({ setup, sourceSession: maskingSession, htilde: auxiliary.point, inputX: X, inputY: Y, records: maskingRecords });

  const xRerandomization = runRerandomization({
    setup,
    sourceSession: subSession(baseSession, 1),
    input: maskingVerified.finalX,
    board,
    trusteePrivateKeys,
    phase: "GATE_X_RERANDOMIZATION",
  });
  const yRerandomization = runRerandomization({
    setup,
    sourceSession: subSession(baseSession, 2),
    input: maskingVerified.finalY,
    board,
    trusteePrivateKeys,
    phase: "GATE_Y_DECRYPT_RERANDOMIZATION",
  });

  const boardBeforeShares = board.exportTranscript();
  const { tdSession, authorization } = makeSelectorAuthorization({
    setup,
    baseSession,
    inputY: maskingVerified.finalY,
    rerandomizedY: yRerandomization.output,
    boardHash: boardBeforeShares.transcriptHash,
  });
  const partialVector = [];
  for (let trusteeId = 1; trusteeId <= setup.trustees; trusteeId += 1) {
    const phase = partialDecryptionPhase(trusteeId);
    board.definePhase({ gateId: tdSession.gateId, invocation: tdSession.invocation, phase, requiredTrusteeIds: [trusteeId] });
    const verifiedSecret = verifySecretShare(setup, setupBundle.secretShares[trusteeId - 1]);
    const partial = createPartialDecryptionShare(setup, authorization, verifiedSecret);
    const payload = encodePartialMessage(partial);
    const slot = slotFor(tdSession, phase, trusteeId);
    const signature = signSubmission(trusteePrivateKeys[trusteeId - 1].privateKey, slot, payload);
    board.submit({ slot, payload, signature });
    const view = board.readPhase({ gateId: tdSession.gateId, invocation: tdSession.invocation, phase });
    requireCondition(view.status === "SEALED", "E_PARTIAL_WAIT", `partial-decryption share ${trusteeId} is unavailable`);
    partialVector.push(view.vector[0]);
  }
  const verifiedPartials = partialVector.map((entry) => {
    const payload = decodePartialMessage(entry.payload);
    requireCondition(payload.trusteeId === entry.trusteeId, "E_PARTIAL_TRUSTEE_BINDING", "partial message trustee mismatch");
    return verifyPartialDecryptionShare(setup, authorization, emitPartialShare(authorization, payload));
  });
  const openedPoint = combineVerifiedPartialDecryptions(setup, authorization, verifiedPartials.slice(0, setup.threshold));
  const negativeBase = negatePoint(BASE8);
  let openedSign;
  if (pointEquals(openedPoint, BASE8)) openedSign = 1;
  else if (pointEquals(openedPoint, negativeBase)) openedSign = -1;
  else throw new Error("E_GATE_SELECTOR_OPENING: Algorithm 67 decrypted value is not +Base8 or -Base8");

  const signedRerandomizedX = openedSign === 1
    ? xRerandomization.output
    : scaleCiphertext(xRerandomization.output, SUBGROUP_ORDER - 1n);
  const output = scaleCiphertext(addCiphertexts(X, signedRerandomizedX), INVERSE_TWO);
  const boardExport = board.exportTranscript();
  return Object.freeze({
    protocolVersion: PROTOCOL_VERSION,
    setup,
    baseSession: Object.freeze({ ...baseSession }),
    inputX: X,
    inputY: Y,
    htilde: auxiliary.point,
    htildeCounter: auxiliary.counter,
    maskingSession,
    maskingRecords: Object.freeze(maskingRecords),
    maskedX: maskingVerified.finalX,
    maskedY: maskingVerified.finalY,
    xRerandomization,
    yRerandomization,
    partialSession: tdSession,
    partialVector: Object.freeze(partialVector),
    preShareBoardHash: boardBeforeShares.transcriptHash,
    openedSign,
    output,
    boardExport,
  });
}

function verifyConditionalGateTranscript(record) {
  const setup = verifyPublicSetup(record.setup);
  verifyBroadcastTranscript(record.boardExport);
  const X = validateCiphertext(record.inputX);
  const Y = validateCiphertext(record.inputY);
  const expectedMaskingSession = subSession(record.baseSession, 0);
  requireCondition(JSON.stringify(sourceSessionToJson(record.maskingSession)) === JSON.stringify(sourceSessionToJson(expectedMaskingSession)), "E_GATE_MASK_SESSION", "masking session derivation mismatch");
  const auxiliary = deriveAuxiliaryPoint(record.maskingSession, setup.committeeKey);
  requireCondition(auxiliary.counter === record.htildeCounter && pointEquals(auxiliary.point, record.htilde), "E_GATE_AUXILIARY", "auxiliary group-oracle output mismatch");

  const maskingRecords = [];
  for (let trusteeId = 1; trusteeId <= setup.trustees; trusteeId += 1) {
    const vector = boardVectorFor(record.boardExport, record.maskingSession, maskingPhase(trusteeId));
    requireCondition(vector.length === 1 && vector[0].trusteeId === trusteeId, "E_GATE_MASK_BOARD", "masking board slot mismatch");
    maskingRecords.push(vector[0]);
  }
  const masking = verifyMaskingRecords({ setup, sourceSession: record.maskingSession, htilde: record.htilde, inputX: X, inputY: Y, records: maskingRecords });
  requireCondition(ciphertextEquals(masking.finalX, record.maskedX) && ciphertextEquals(masking.finalY, record.maskedY), "E_GATE_MASK_OUTPUT", "recorded masking output mismatch");

  const xVector = boardVectorFor(record.boardExport, record.xRerandomization.sourceSession, record.xRerandomization.phase);
  requireCondition(record.xRerandomization.phase === "GATE_X_RERANDOMIZATION", "E_GATE_X_RERANDOMIZATION_PHASE", "wrong X rerandomization phase");
  requireCondition(JSON.stringify(sourceSessionToJson(record.xRerandomization.sourceSession)) === JSON.stringify(sourceSessionToJson(subSession(record.baseSession, 1))), "E_GATE_X_RERANDOMIZATION_SESSION", "wrong X rerandomization source session");
  const xRerandomization = { ...record.xRerandomization, vector: xVector };
  verifyRerandomizationRecord({ setup, record: xRerandomization });
  requireCondition(ciphertextEquals(xRerandomization.input, masking.finalX), "E_GATE_X_RERANDOMIZATION_INPUT", "X rerandomization starts from the wrong masked ciphertext");
  const yVector = boardVectorFor(record.boardExport, record.yRerandomization.sourceSession, record.yRerandomization.phase);
  requireCondition(record.yRerandomization.phase === "GATE_Y_DECRYPT_RERANDOMIZATION", "E_GATE_Y_RERANDOMIZATION_PHASE", "wrong Y rerandomization phase");
  requireCondition(JSON.stringify(sourceSessionToJson(record.yRerandomization.sourceSession)) === JSON.stringify(sourceSessionToJson(subSession(record.baseSession, 2))), "E_GATE_Y_RERANDOMIZATION_SESSION", "wrong Y rerandomization source session");
  const yRerandomization = { ...record.yRerandomization, vector: yVector };
  verifyRerandomizationRecord({ setup, record: yRerandomization });
  requireCondition(ciphertextEquals(yRerandomization.input, masking.finalY), "E_GATE_Y_RERANDOMIZATION_INPUT", "Y rerandomization starts from the wrong masked ciphertext");

  const { tdSession, authorization } = makeSelectorAuthorization({
    setup,
    baseSession: record.baseSession,
    inputY: masking.finalY,
    rerandomizedY: yRerandomization.output,
    boardHash: record.preShareBoardHash,
  });
  requireCondition(JSON.stringify(sourceSessionToJson(tdSession)) === JSON.stringify(sourceSessionToJson(record.partialSession)), "E_GATE_PARTIAL_SESSION", "partial-decryption session mismatch");
  requireCondition(boardPrefixHashBeforePartialDecryptions(record.boardExport, tdSession) === record.preShareBoardHash, "E_GATE_PREFIX_HASH", "partial-decryption authorization is bound to the wrong board prefix");
  const partialVector = [];
  for (let trusteeId = 1; trusteeId <= setup.trustees; trusteeId += 1) {
    const vector = boardVectorFor(record.boardExport, tdSession, partialDecryptionPhase(trusteeId));
    requireCondition(vector.length === 1 && vector[0].trusteeId === trusteeId, "E_GATE_PARTIAL_BOARD", "partial-decryption board slot mismatch");
    partialVector.push(vector[0]);
  }
  const verifiedPartials = partialVector.map((entry) => {
    const payload = decodePartialMessage(entry.payload);
    requireCondition(payload.trusteeId === entry.trusteeId, "E_PARTIAL_TRUSTEE_BINDING", "partial message trustee mismatch");
    return verifyPartialDecryptionShare(setup, authorization, emitPartialShare(authorization, payload));
  });
  const openedPoint = combineVerifiedPartialDecryptions(setup, authorization, verifiedPartials.slice(0, setup.threshold));
  const expectedOpenedPoint = record.openedSign === 1 ? BASE8 : negatePoint(BASE8);
  requireCondition((record.openedSign === 1 || record.openedSign === -1) && pointEquals(openedPoint, expectedOpenedPoint), "E_GATE_OPENED_SIGN", "opened masked selector mismatch");
  const signedX = record.openedSign === 1 ? xRerandomization.output : scaleCiphertext(xRerandomization.output, SUBGROUP_ORDER - 1n);
  const expectedOutput = scaleCiphertext(addCiphertexts(X, signedX), INVERSE_TWO);
  requireCondition(ciphertextEquals(expectedOutput, record.output), "E_GATE_OUTPUT", "Algorithm 67 output identity failed");
  return Object.freeze({ valid: true, output: expectedOutput, boardTranscriptHash: record.boardExport.transcriptHash });
}

function rerandomizationToJson(record) {
  return {
    phase: record.phase,
    sourceSession: sourceSessionToJson(record.sourceSession),
    input: ciphertextToJson(record.input),
    output: ciphertextToJson(record.output),
  };
}

function rerandomizationFromJson(value) {
  exactKeys(value, ["phase", "sourceSession", "input", "output"], "E_CODEC_RERANDOMIZATION");
  return Object.freeze({
    phase: value.phase,
    sourceSession: sourceSessionFromJson(value.sourceSession),
    input: ciphertextFromJson(value.input),
    output: ciphertextFromJson(value.output),
  });
}

function conditionalGateRecordToJson(record) {
  return {
    schema: "-CGY-TOOLBOX-FULL-V1/SINGLE-GATE-TRANSCRIPT/V1",
    protocolVersion: record.protocolVersion,
    setup: publicSetupToJson(record.setup),
    baseSession: sourceSessionToJson(record.baseSession),
    inputX: ciphertextToJson(record.inputX),
    inputY: ciphertextToJson(record.inputY),
    htilde: pointToJson(record.htilde),
    htildeCounter: record.htildeCounter,
    maskingSession: sourceSessionToJson(record.maskingSession),
    maskedX: ciphertextToJson(record.maskedX),
    maskedY: ciphertextToJson(record.maskedY),
    xRerandomization: rerandomizationToJson(record.xRerandomization),
    yRerandomization: rerandomizationToJson(record.yRerandomization),
    partialSession: sourceSessionToJson(record.partialSession),
    preShareBoardHash: record.preShareBoardHash,
    openedSign: record.openedSign,
    output: ciphertextToJson(record.output),
    boardExport: record.boardExport,
  };
}

function conditionalGateRecordFromJson(value) {
  const keys = ["schema", "protocolVersion", "setup", "baseSession", "inputX", "inputY", "htilde", "htildeCounter", "maskingSession", "maskedX", "maskedY", "xRerandomization", "yRerandomization", "partialSession", "preShareBoardHash", "openedSign", "output", "boardExport"];
  exactKeys(value, keys, "E_CODEC_GATE_TRANSCRIPT");
  requireCondition(value.schema === "-CGY-TOOLBOX-FULL-V1/SINGLE-GATE-TRANSCRIPT/V1", "E_CODEC_GATE_SCHEMA", "single-gate transcript schema mismatch");
  requireCondition(value.protocolVersion === PROTOCOL_VERSION, "E_PROTOCOL_VERSION", "single-gate protocol mismatch");
  requireCondition(Number.isInteger(value.htildeCounter) && value.htildeCounter >= 0, "E_CODEC_COUNTER", "auxiliary counter is invalid");
  requireCondition(value.openedSign === 1 || value.openedSign === -1, "E_CODEC_SIGN", "opened sign is invalid");
  exactKeys(value.boardExport, ["transcript", "canonical", "transcriptHash"], "E_CODEC_BOARD_EXPORT");
  requireCondition(canonicalJson(value.boardExport.transcript) === value.boardExport.canonical, "E_TRANSCRIPT_CANONICAL", "embedded board canonical bytes mismatch");
  return Object.freeze({
    protocolVersion: value.protocolVersion,
    setup: publicSetupFromJson(value.setup),
    baseSession: sourceSessionFromJson(value.baseSession),
    inputX: ciphertextFromJson(value.inputX),
    inputY: ciphertextFromJson(value.inputY),
    htilde: pointFromJson(value.htilde, PointRole.AUXILIARY),
    htildeCounter: value.htildeCounter,
    maskingSession: sourceSessionFromJson(value.maskingSession),
    maskedX: ciphertextFromJson(value.maskedX),
    maskedY: ciphertextFromJson(value.maskedY),
    xRerandomization: rerandomizationFromJson(value.xRerandomization),
    yRerandomization: rerandomizationFromJson(value.yRerandomization),
    partialSession: sourceSessionFromJson(value.partialSession),
    preShareBoardHash: value.preShareBoardHash,
    openedSign: value.openedSign,
    output: ciphertextFromJson(value.output),
    boardExport: value.boardExport,
  });
}

function serializeConditionalGateTranscript(record) {
  return canonicalJson(conditionalGateRecordToJson(record));
}

function parseConditionalGateTranscript(serialized) {
  const raw = Buffer.isBuffer(serialized) ? serialized.toString("utf8") : String(serialized);
  const text = raw.endsWith("\r\n") ? raw.slice(0, -2) : (raw.endsWith("\n") ? raw.slice(0, -1) : raw);
  requireCondition(raw === text || raw === `${text}\n` || raw === `${text}\r\n`, "E_CODEC_TRAILING_DATA", "single-gate transcript has noncanonical trailing data");
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    throw new Error(`E_CODEC_JSON: ${error.message}`);
  }
  requireCondition(canonicalJson(value) === text, "E_CODEC_NONCANONICAL", "single-gate transcript is not canonical JSON");
  return conditionalGateRecordFromJson(value);
}

module.exports = Object.freeze({
  MASKING_MESSAGE_KIND,
  PARTIAL_MESSAGE_KIND,
  INVERSE_TWO,
  subSession,
  maskingPhase,
  partialDecryptionPhase,
  encodeMaskingMessage,
  decodeMaskingMessage,
  encodePartialMessage,
  decodePartialMessage,
  initialSignedSelector,
  verifyMaskingRecords,
  runConditionalGate,
  verifyConditionalGateTranscript,
  boardPrefixHashBeforePartialDecryptions,
  boardVectorFor,
  conditionalGateRecordToJson,
  conditionalGateRecordFromJson,
  serializeConditionalGateTranscript,
  parseConditionalGateTranscript,
});
