"use strict";

const crypto = require("crypto");
const { requireCondition } = require("./errors");
const { BASE8, IDENTITY, pointEquals } = require("./group");
const {
  validateCiphertext,
  ciphertextEquals,
  addCiphertexts,
  negateCiphertext,
  ciphertextHash,
} = require("./elgamal");
const { decisionFromBorrow } = require("./arithmetic");
const { PROTOCOL_VERSION } = require("./group_oracle");
const { verifyPublicSetup, verifySecretShare } = require("./threshold_setup");
const { runRerandomization, verifyRerandomizationRecord } = require("./rerandomization");
const {
  receive,
  markProofValidated,
  markBroadcastAgreed,
  markRerandomizationValidated,
  authorizeForDecryption,
  emitPartialShare,
} = require("./validation_state");
const {
  createPartialDecryptionShare,
  verifyPartialDecryptionShare,
  combineVerifiedPartialDecryptions,
} = require("./threshold_decryption");
const { signSubmission, verifyBroadcastTranscript, canonicalJson } = require("./broadcast_board");
const {
  encodePartialMessage,
  decodePartialMessage,
  boardVectorFor,
} = require("./conditional_gate");
const {
  exactKeys,
  ciphertextToJson,
  ciphertextFromJson,
  sourceSessionToJson,
  sourceSessionFromJson,
} = require("./codec");

const LOGICAL_TOKEN = Symbol("LogicalDecisionCiphertext");

class LogicalDecisionCiphertext {
  constructor(token, value, comparisonBinding) {
    requireCondition(token === LOGICAL_TOKEN, "E_LOGICAL_DECISION_CONSTRUCTION", "logical decision ciphertext is opaque");
    this.ciphertext = value;
    this.comparisonBinding = comparisonBinding;
    Object.freeze(this);
  }
}

function buildLogicalDecisionCiphertext(comparison, ops) {
  requireCondition(comparison && comparison.terminal, "E_COMPARISON_RESULT", "comparison result is missing terminal identity");
  const borrow = validateCiphertext(comparison.borrow);
  requireCondition(ciphertextEquals(borrow, comparison.terminal.Q), "E_TERMINAL_Q", "terminal Q differs from the final borrow");
  const recomputedQ = addCiphertexts(comparison.terminal.D, negateCiphertext(comparison.terminal.CStar));
  requireCondition(ciphertextEquals(recomputedQ, borrow), "E_TERMINAL_IDENTITY", "Q=D-C_* does not hold");
  const decision = validateCiphertext(decisionFromBorrow(borrow, ops));
  return new LogicalDecisionCiphertext(LOGICAL_TOKEN, decision, Object.freeze({
    qHash: ciphertextHash(borrow),
    dHash: ciphertextHash(comparison.terminal.D),
    cStarHash: ciphertextHash(comparison.terminal.CStar),
  }));
}

function finalPartialPhase(trusteeId) {
  return `FINAL_DECISION_PARTIAL_DECRYPTION_${String(trusteeId).padStart(2, "0")}`;
}

function slotFor(session, phase, trusteeId) {
  return Object.freeze({
    protocolVersion: session.protocolVersion,
    setupHash: session.setupHash,
    executionId: session.executionId,
    gateId: session.gateId,
    invocation: session.invocation,
    phase,
    trusteeId,
  });
}

function releaseAuthorization({ setup, session, logicalCiphertext, rerandomized, boardHash }) {
  const context = Object.freeze({
    protocolVersion: PROTOCOL_VERSION,
    setupHash: setup.setupHash,
    executionId: session.executionId,
    gateId: session.gateId,
    invocation: session.invocation,
    phase: "FINAL_DECISION_RELEASE",
    purpose: "FINAL_DECISION",
  });
  const received = receive(logicalCiphertext, context, { source: "LOGICAL_DECISION", ciphertextHash: ciphertextHash(logicalCiphertext) });
  const proofValidated = markProofValidated(received, { valid: true, verifier: "WEIGHTED_COMPARISON_TRANSCRIPT" });
  const broadcastAgreed = markBroadcastAgreed(proofValidated, { agreed: true, transcriptHash: boardHash });
  const rerandomizationValidated = markRerandomizationValidated(broadcastAgreed, rerandomized, { valid: true, verifier: "ALGORITHM_63" });
  return authorizeForDecryption(rerandomizationValidated, { authorized: true, policy: "FINAL_LOGICAL_DECISION_ONLY" });
}

function prefixHashBeforeFinalShares(boardExport, session, expectedShareCount) {
  const transcript = structuredClone(boardExport.transcript);
  const before = transcript.phases.length;
  transcript.phases = transcript.phases.filter((entry) => !(
    entry.gateId === session.gateId.toString(10)
      && entry.invocation === session.invocation.toString(10)
      && entry.phase.startsWith("FINAL_DECISION_PARTIAL_DECRYPTION_")
  ));
  requireCondition(before - transcript.phases.length === expectedShareCount, "E_FINAL_PREFIX_PHASES", "final partial-share phase set is incomplete");
  return crypto.createHash("sha256").update(canonicalJson(transcript)).digest("hex");
}

function runFinalRelease({ setupBundle, session, logicalDecision, board, trusteePrivateKeys, shareTrusteeIds = [1, 2, 3] }) {
  const setup = verifyPublicSetup(setupBundle.publicSetup);
  requireCondition(logicalDecision instanceof LogicalDecisionCiphertext, "E_RELEASE_INPUT", "final release accepts only LogicalDecisionCiphertext");
  requireCondition(Array.isArray(shareTrusteeIds) && shareTrusteeIds.length === setup.threshold, "E_RELEASE_QUORUM", "final release requires exactly the decryption threshold");
  requireCondition(new Set(shareTrusteeIds).size === shareTrusteeIds.length, "E_DUPLICATE_TRUSTEE", "final release quorum contains a duplicate trustee");
  const rerandomization = runRerandomization({
    setup,
    sourceSession: session,
    input: logicalDecision.ciphertext,
    board,
    trusteePrivateKeys,
    phase: "FINAL_DECISION_RERANDOMIZATION",
  });
  const preShareBoard = board.exportTranscript();
  const authorization = releaseAuthorization({
    setup,
    session,
    logicalCiphertext: logicalDecision.ciphertext,
    rerandomized: rerandomization.output,
    boardHash: preShareBoard.transcriptHash,
  });
  const emittedEntries = [];
  for (const trusteeId of shareTrusteeIds) {
    requireCondition(Number.isInteger(trusteeId) && trusteeId >= 1 && trusteeId <= setup.trustees, "E_TRUSTEE_ID", "final release quorum contains an invalid trustee");
    const phase = finalPartialPhase(trusteeId);
    board.definePhase({ gateId: session.gateId, invocation: session.invocation, phase, requiredTrusteeIds: [trusteeId] });
    const verifiedSecret = verifySecretShare(setup, setupBundle.secretShares[trusteeId - 1]);
    const partial = createPartialDecryptionShare(setup, authorization, verifiedSecret);
    const payload = encodePartialMessage(partial);
    const slot = slotFor(session, phase, trusteeId);
    const signature = signSubmission(trusteePrivateKeys[trusteeId - 1].privateKey, slot, payload);
    board.submit({ slot, payload, signature });
    emittedEntries.push(board.readPhase({ gateId: session.gateId, invocation: session.invocation, phase }).vector[0]);
  }
  const verifiedById = new Map(emittedEntries.map((entry) => {
    const payload = decodePartialMessage(entry.payload);
    requireCondition(payload.trusteeId === entry.trusteeId, "E_PARTIAL_TRUSTEE_BINDING", "final partial-share trustee mismatch");
    return [entry.trusteeId, verifyPartialDecryptionShare(setup, authorization, emitPartialShare(authorization, payload))];
  }));
  const quorum = shareTrusteeIds.map((trusteeId) => {
    requireCondition(verifiedById.has(trusteeId), "E_RELEASE_QUORUM", `trustee ${trusteeId} share is unavailable`);
    return verifiedById.get(trusteeId);
  });
  const openedPoint = combineVerifiedPartialDecryptions(setup, authorization, quorum);
  let resultBit;
  if (pointEquals(openedPoint, IDENTITY)) resultBit = 0;
  else if (pointEquals(openedPoint, BASE8)) resultBit = 1;
  else throw new Error("E_FINAL_RESULT_RANGE: final logical ciphertext did not decrypt to a bit");
  return Object.freeze({
    session,
    logicalCiphertext: logicalDecision.ciphertext,
    comparisonBinding: logicalDecision.comparisonBinding,
    rerandomization,
    preShareBoardHash: preShareBoard.transcriptHash,
    shareTrusteeIds: Object.freeze(Array.from(shareTrusteeIds)),
    resultBit,
    boardExport: board.exportTranscript(),
  });
}

function verifyFinalRelease(record, setup) {
  verifyPublicSetup(setup);
  verifyBroadcastTranscript(record.boardExport);
  requireCondition(record.rerandomization.phase === "FINAL_DECISION_RERANDOMIZATION", "E_FINAL_RERANDOMIZATION_PHASE", "wrong final rerandomization phase");
  const vector = boardVectorFor(record.boardExport, record.session, record.rerandomization.phase);
  const rerandomization = { ...record.rerandomization, vector };
  verifyRerandomizationRecord({ setup, record: rerandomization });
  requireCondition(ciphertextEquals(record.logicalCiphertext, rerandomization.input), "E_FINAL_RERANDOMIZATION_INPUT", "final rerandomization input is not the logical decision ciphertext");
  requireCondition(prefixHashBeforeFinalShares(record.boardExport, record.session, record.shareTrusteeIds.length) === record.preShareBoardHash, "E_FINAL_PREFIX_HASH", "final shares are authorized against the wrong board prefix");
  const authorization = releaseAuthorization({
    setup,
    session: record.session,
    logicalCiphertext: record.logicalCiphertext,
    rerandomized: rerandomization.output,
    boardHash: record.preShareBoardHash,
  });
  requireCondition(Array.isArray(record.shareTrusteeIds) && record.shareTrusteeIds.length === setup.threshold && new Set(record.shareTrusteeIds).size === setup.threshold, "E_RELEASE_QUORUM", "recorded final quorum is invalid");
  const verifiedById = new Map();
  for (const trusteeId of record.shareTrusteeIds) {
    requireCondition(Number.isInteger(trusteeId) && trusteeId >= 1 && trusteeId <= setup.trustees, "E_TRUSTEE_ID", "recorded final quorum contains an invalid trustee");
    const phaseVector = boardVectorFor(record.boardExport, record.session, finalPartialPhase(trusteeId));
    requireCondition(phaseVector.length === 1 && phaseVector[0].trusteeId === trusteeId, "E_FINAL_SHARE_BOARD", "final partial-share slot mismatch");
    const payload = decodePartialMessage(phaseVector[0].payload);
    requireCondition(payload.trusteeId === trusteeId, "E_PARTIAL_TRUSTEE_BINDING", "final partial-share trustee mismatch");
    verifiedById.set(trusteeId, verifyPartialDecryptionShare(setup, authorization, emitPartialShare(authorization, payload)));
  }
  const openedPoint = combineVerifiedPartialDecryptions(setup, authorization, record.shareTrusteeIds.map((trusteeId) => verifiedById.get(trusteeId)));
  const expectedPoint = record.resultBit === 0 ? IDENTITY : BASE8;
  requireCondition((record.resultBit === 0 || record.resultBit === 1) && pointEquals(openedPoint, expectedPoint), "E_FINAL_RESULT", "released result bit does not match verified threshold decryption");
  return Object.freeze({ valid: true, resultBit: record.resultBit, boardTranscriptHash: record.boardExport.transcriptHash });
}

function finalReleaseRecordToJson(record) {
  return {
    schema: "-CGY-TOOLBOX-FULL-V1/FINAL-RELEASE-TRANSCRIPT/V1",
    session: sourceSessionToJson(record.session),
    logicalCiphertext: ciphertextToJson(record.logicalCiphertext),
    comparisonBinding: record.comparisonBinding,
    rerandomization: {
      phase: record.rerandomization.phase,
      sourceSession: sourceSessionToJson(record.rerandomization.sourceSession),
      input: ciphertextToJson(record.rerandomization.input),
      output: ciphertextToJson(record.rerandomization.output),
    },
    preShareBoardHash: record.preShareBoardHash,
    shareTrusteeIds: Array.from(record.shareTrusteeIds),
    resultBit: record.resultBit,
    boardExport: record.boardExport,
  };
}

function finalReleaseRecordFromJson(value) {
  exactKeys(value, ["schema", "session", "logicalCiphertext", "comparisonBinding", "rerandomization", "preShareBoardHash", "shareTrusteeIds", "resultBit", "boardExport"], "E_CODEC_FINAL_RELEASE");
  requireCondition(value.schema === "-CGY-TOOLBOX-FULL-V1/FINAL-RELEASE-TRANSCRIPT/V1", "E_CODEC_FINAL_SCHEMA", "final release transcript schema mismatch");
  exactKeys(value.comparisonBinding, ["qHash", "dHash", "cStarHash"], "E_CODEC_COMPARISON_BINDING");
  exactKeys(value.rerandomization, ["phase", "sourceSession", "input", "output"], "E_CODEC_FINAL_RERANDOMIZATION");
  exactKeys(value.boardExport, ["transcript", "canonical", "transcriptHash"], "E_CODEC_FINAL_BOARD");
  requireCondition(canonicalJson(value.boardExport.transcript) === value.boardExport.canonical, "E_TRANSCRIPT_CANONICAL", "final release board canonical bytes mismatch");
  requireCondition(Array.isArray(value.shareTrusteeIds), "E_CODEC_FINAL_QUORUM", "final release quorum is not an array");
  requireCondition(value.resultBit === 0 || value.resultBit === 1, "E_CODEC_FINAL_RESULT", "final release result is not a bit");
  return Object.freeze({
    session: sourceSessionFromJson(value.session),
    logicalCiphertext: ciphertextFromJson(value.logicalCiphertext),
    comparisonBinding: Object.freeze({ ...value.comparisonBinding }),
    rerandomization: Object.freeze({
      phase: value.rerandomization.phase,
      sourceSession: sourceSessionFromJson(value.rerandomization.sourceSession),
      input: ciphertextFromJson(value.rerandomization.input),
      output: ciphertextFromJson(value.rerandomization.output),
    }),
    preShareBoardHash: value.preShareBoardHash,
    shareTrusteeIds: Object.freeze(Array.from(value.shareTrusteeIds)),
    resultBit: value.resultBit,
    boardExport: value.boardExport,
  });
}

module.exports = Object.freeze({
  LogicalDecisionCiphertext,
  buildLogicalDecisionCiphertext,
  finalPartialPhase,
  runFinalRelease,
  verifyFinalRelease,
  finalReleaseRecordToJson,
  finalReleaseRecordFromJson,
});
