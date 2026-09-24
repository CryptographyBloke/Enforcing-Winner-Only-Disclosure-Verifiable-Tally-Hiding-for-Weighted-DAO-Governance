"use strict";

// Reference runner for the Rust weighted DAG. JavaScript adapts native gate records
// into the canonical trustee-board journal and releases records incrementally
// for large local scale runs.
const { runNativeDag, runNativeDagStream } = require("./native_gate_bridge");
const { adaptNativeGateTrusted } = require("./native_gate_adapter");
const { addCiphertexts, scaleCiphertext } = require("../../js_protocol/src/elgamal");
const { BASE8, IDENTITY } = require("../../js_protocol/src/group");
const { ciphertextFromJson } = require("../../js_protocol/src/codec");
const { CanonicalAtomicBroadcastBoard, canonicalJson } = require("../../js_protocol/src/broadcast_board");
const { appendFileSync, statSync, openSync, readSync, closeSync, unlinkSync } = require("fs");

function publicBit(bit) {
  if (bit === 0) return { R: IDENTITY, S: IDENTITY };
  return { R: IDENTITY, S: BASE8 };
}

function* jsonLinesSync(filePath) {
  const fd = openSync(filePath, "r");
  const chunk = Buffer.allocUnsafe(1024 * 1024);
  let carry = "";
  try {
    while (true) {
      const count = readSync(fd, chunk, 0, chunk.length, null);
      if (count === 0) break;
      carry += chunk.subarray(0, count).toString("utf8");
      const lines = carry.split("\n");
      carry = lines.pop();
      for (const line of lines) if (line.length !== 0) yield JSON.parse(line);
    }
    if (carry.length !== 0) yield JSON.parse(carry);
  } finally {
    closeSync(fd);
  }
}

function runNativeWeightedArithmeticStream({ bitVectors, tau, setupBundle, executionId, authentication, journalPath, labelPrefix = "N8", nativeTranscriptPath }) {
  const native = runNativeDagStream({ setupBundle, executionId, bitVectors, tau, labelPrefix, transcriptPath: nativeTranscriptPath });
  const adaptationStarted = process.hrtime.bigint();
  const gateWallTimingsMs = Array.isArray(native.timing.gateGenerationMs)
    ? native.timing.gateGenerationMs.map((value, index) => Number(value) + Number(native.timing.gateVerificationMs[index] || 0))
    : [];
  const nativeGenerationTimingsMs = Array.isArray(native.timing.gateGenerationMs) ? native.timing.gateGenerationMs.map(Number) : [];
  const nativeVerificationTimingsMs = Array.isArray(native.timing.gateVerificationMs) ? native.timing.gateVerificationMs.map(Number) : [];
  if (statSync(journalPath).size !== 0) throw new Error("E_NATIVE_JOURNAL_NOT_EMPTY");
  const journalStarted = process.hrtime.bigint();
  let journalChunk = "";
  let gateCount = 0;
  for (const entry of jsonLinesSync(native.transcriptPath)) {
    const board = new CanonicalAtomicBroadcastBoard({
      setupHash: setupBundle.publicSetup.setupHash,
      executionId,
      trusteePublicKeys: authentication.publicKeys,
    });
    const adapted = adaptNativeGateTrusted({ nativeGate: entry.record, board, trusteePrivateKeys: authentication.privateKeys });
    journalChunk += `${canonicalJson({ gateIndex: Number(entry.gateIndex), label: entry.label, backend: "RUST", record: { ...entry.record, boardExport: adapted.boardExport } })}\n`;
    if (journalChunk.length >= 4 * 1024 * 1024) {
      appendFileSync(journalPath, journalChunk, { encoding: "utf8" });
      journalChunk = "";
    }
    gateCount += 1;
  }
  if (journalChunk.length !== 0) appendFileSync(journalPath, journalChunk, { encoding: "utf8" });
  unlinkSync(native.transcriptPath);
  const journalMs = Number(process.hrtime.bigint() - journalStarted) / 1e6;
  if (gateCount !== Number(native.gateCount)) throw new Error("E_NATIVE_STREAM_GATE_COUNT");
  return finishNativeWeightedArithmetic({ native, setupBundle, executionId, journalPath, adaptationStarted, journalMs, gateWallTimingsMs, nativeGenerationTimingsMs, nativeVerificationTimingsMs });
}

function runNativeWeightedArithmetic({ bitVectors, tau, setupBundle, executionId, authentication, journalPath, labelPrefix = "N8", streamJournal = false, streamNative = false, nativeTranscriptPath = null }) {
  if (streamNative) return runNativeWeightedArithmeticStream({ bitVectors, tau, setupBundle, executionId, authentication, journalPath, labelPrefix, nativeTranscriptPath });
  const native = runNativeDag({ setupBundle, executionId, bitVectors, tau, labelPrefix });
  const adaptationStarted = process.hrtime.bigint();
  const gateWallTimingsMs = Array.isArray(native.timing.gateGenerationMs)
    ? native.timing.gateGenerationMs.map((value, index) => Number(value) + Number(native.timing.gateVerificationMs[index] || 0))
    : [];
  const nativeGenerationTimingsMs = Array.isArray(native.timing.gateGenerationMs) ? native.timing.gateGenerationMs.map(Number) : [];
  const nativeVerificationTimingsMs = Array.isArray(native.timing.gateVerificationMs) ? native.timing.gateVerificationMs.map(Number) : [];
  if (statSync(journalPath).size !== 0) throw new Error("E_NATIVE_JOURNAL_NOT_EMPTY");
  const nativeGates = native.gates;
  if (!streamJournal) {
    const records = nativeGates.map((entry) => {
      const board = new CanonicalAtomicBroadcastBoard({
        setupHash: setupBundle.publicSetup.setupHash,
        executionId,
        trusteePublicKeys: authentication.publicKeys,
      });
      const adapted = adaptNativeGateTrusted({ nativeGate: entry.record, board, trusteePrivateKeys: authentication.privateKeys });
      return {
        gateIndex: Number(entry.gateIndex),
        label: entry.label,
        backend: "RUST",
        record: { ...entry.record, boardExport: adapted.boardExport },
      };
    });
    const ordered = records.sort((left, right) => left.gateIndex - right.gateIndex);
    const journalStarted = process.hrtime.bigint();
    appendFileSync(journalPath, `${ordered.map((entry) => canonicalJson(entry)).join("\n")}\n`, { encoding: "utf8" });
    const journalMs = Number(process.hrtime.bigint() - journalStarted) / 1e6;
    return finishNativeWeightedArithmetic({ native, setupBundle, executionId, journalPath, adaptationStarted, journalMs, gateWallTimingsMs, nativeGenerationTimingsMs, nativeVerificationTimingsMs });
  }
  // Large local runs adapt records in canonical gate order and release each
  // native record as soon as its board envelope has been added.
  const journalStarted = process.hrtime.bigint();
  let journalChunk = "";
  for (let index = 0; index < nativeGates.length; index += 1) {
    const entry = nativeGates[index];
    const board = new CanonicalAtomicBroadcastBoard({
      setupHash: setupBundle.publicSetup.setupHash,
      executionId,
      trusteePublicKeys: authentication.publicKeys,
    });
    const adapted = adaptNativeGateTrusted({ nativeGate: entry.record, board, trusteePrivateKeys: authentication.privateKeys });
    const journalEntry = {
      gateIndex: Number(entry.gateIndex),
      label: entry.label,
      backend: "RUST",
      record: { ...entry.record, boardExport: adapted.boardExport },
    };
    journalChunk += `${canonicalJson(journalEntry)}\n`;
    if (journalChunk.length >= 4 * 1024 * 1024) {
      appendFileSync(journalPath, journalChunk, { encoding: "utf8" });
      journalChunk = "";
    }
    nativeGates[index] = null;
  }
  if (journalChunk.length !== 0) appendFileSync(journalPath, journalChunk, { encoding: "utf8" });
  const journalMs = Number(process.hrtime.bigint() - journalStarted) / 1e6;
  return finishNativeWeightedArithmetic({ native, setupBundle, executionId, journalPath, adaptationStarted, journalMs, gateWallTimingsMs, nativeGenerationTimingsMs, nativeVerificationTimingsMs });
}

function finishNativeWeightedArithmetic({ native, setupBundle, executionId, journalPath, adaptationStarted, journalMs, gateWallTimingsMs, nativeGenerationTimingsMs, nativeVerificationTimingsMs }) {
  const parseVector = (values) => Object.freeze(values.map((value) => ciphertextFromJson(value)));
  const comparison = Object.freeze({
    difference: parseVector(native.comparison.difference),
    borrow: ciphertextFromJson(native.comparison.borrow),
    terminal: Object.freeze({
      D: ciphertextFromJson(native.comparison.terminal.D),
      CStar: ciphertextFromJson(native.comparison.terminal.CStar),
      Q: ciphertextFromJson(native.comparison.terminal.Q),
    }),
  });
  return Object.freeze({
    aggregate: parseVector(native.aggregate),
    comparison,
    result: ciphertextFromJson(native.result),
    gateCount: Number(native.gateCount),
    depth: Number(native.aggregateDepth),
    operations: Object.freeze({ add: addCiphertexts, scale: (value, factor) => scaleCiphertext(value, factor), publicBit }),
    timing: Object.freeze({
      gateWallMs: Object.freeze(gateWallTimingsMs),
      nativeGenerationMs: Object.freeze(nativeGenerationTimingsMs),
      nativeVerificationMs: Object.freeze(nativeVerificationTimingsMs),
      nativeBackendMs: Number(native.timing.backendMs),
      nativeProcessMs: Number(native.__nativeProcessMs),
      nativeAdapterMs: Number(adaptationStarted ? process.hrtime.bigint() - adaptationStarted : 0n) / 1e6 - journalMs,
      nativeJournalMs: journalMs,
      nativeGateGenerationTotalMs: Number(native.timing.gateGenerationMsTotal || nativeGenerationTimingsMs.reduce((sum, value) => sum + value, 0)),
      nativeGateVerificationTotalMs: Number(native.timing.gateVerificationMsTotal || nativeVerificationTimingsMs.reduce((sum, value) => sum + value, 0)),
    }),
  });
}

module.exports = Object.freeze({ runNativeWeightedArithmetic });
