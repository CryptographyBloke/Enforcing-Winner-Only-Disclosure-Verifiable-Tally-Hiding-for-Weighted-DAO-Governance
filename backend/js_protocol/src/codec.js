"use strict";

const { requireCondition } = require("./errors");
const {
  BASE8,
  PointRole,
  point,
  validatePoint,
} = require("./group");
const { ciphertext, validateCiphertext } = require("./elgamal");
const { canonicalJson } = require("./broadcast_board");
const { SETUP_KIND, verifyPublicSetup } = require("./threshold_setup");
const { PROTOCOL_VERSION } = require("./group_oracle");

function exactKeys(value, keys, code) {
  requireCondition(value && typeof value === "object" && !Array.isArray(value), code, "value must be an object");
  const actual = Object.keys(value);
  requireCondition(actual.length === keys.length && keys.every((key, index) => actual[index] === key), code, `expected ordered fields ${keys.join(",")}`);
}

function decimalBigint(value, label) {
  requireCondition(typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value), "E_CODEC_INTEGER", `${label} is not canonical decimal`);
  return BigInt(value);
}

function pointToJson(value) {
  return { x: value.x.toString(10), y: value.y.toString(10) };
}

function pointFromJson(value, role = PointRole.PROOF_ELEMENT) {
  exactKeys(value, ["x", "y"], "E_CODEC_POINT");
  return validatePoint(point(decimalBigint(value.x, "point.x"), decimalBigint(value.y, "point.y")), role);
}

function ciphertextToJson(value) {
  const checked = validateCiphertext(value);
  return { R: pointToJson(checked.R), S: pointToJson(checked.S) };
}

function ciphertextFromJson(value) {
  exactKeys(value, ["R", "S"], "E_CODEC_CIPHERTEXT");
  return validateCiphertext(ciphertext(pointFromJson(value.R), pointFromJson(value.S)));
}

function maskingProofToJson(proof) {
  return {
    cPlusX: ciphertextToJson(proof.cPlusX),
    cPlusY: ciphertextToJson(proof.cPlusY),
    cMinusX: ciphertextToJson(proof.cMinusX),
    cMinusY: ciphertextToJson(proof.cMinusY),
    cPlusE: pointToJson(proof.cPlusE),
    cMinusE: pointToJson(proof.cMinusE),
    dPlus: proof.dPlus.toString(10),
    dMinus: proof.dMinus.toString(10),
    aPlusX: proof.aPlusX.toString(10),
    aPlusY: proof.aPlusY.toString(10),
    aMinusX: proof.aMinusX.toString(10),
    aMinusY: proof.aMinusY.toString(10),
  };
}

function maskingProofFromJson(value) {
  const keys = ["cPlusX", "cPlusY", "cMinusX", "cMinusY", "cPlusE", "cMinusE", "dPlus", "dMinus", "aPlusX", "aPlusY", "aMinusX", "aMinusY"];
  exactKeys(value, keys, "E_CODEC_MASK_PROOF");
  return Object.freeze({
    cPlusX: ciphertextFromJson(value.cPlusX),
    cPlusY: ciphertextFromJson(value.cPlusY),
    cMinusX: ciphertextFromJson(value.cMinusX),
    cMinusY: ciphertextFromJson(value.cMinusY),
    cPlusE: pointFromJson(value.cPlusE),
    cMinusE: pointFromJson(value.cMinusE),
    dPlus: decimalBigint(value.dPlus, "dPlus"),
    dMinus: decimalBigint(value.dMinus, "dMinus"),
    aPlusX: decimalBigint(value.aPlusX, "aPlusX"),
    aPlusY: decimalBigint(value.aPlusY, "aPlusY"),
    aMinusX: decimalBigint(value.aMinusX, "aMinusX"),
    aMinusY: decimalBigint(value.aMinusY, "aMinusY"),
  });
}

function zeroProofToJson(value) {
  return { commitment: ciphertextToJson(value.commitment), response: value.response.toString(10) };
}

function zeroProofFromJson(value) {
  exactKeys(value, ["commitment", "response"], "E_CODEC_ZERO_PROOF");
  return Object.freeze({ commitment: ciphertextFromJson(value.commitment), response: decimalBigint(value.response, "response") });
}

function sourceSessionToJson(value) {
  return {
    protocolVersion: value.protocolVersion,
    setupHash: value.setupHash,
    executionId: value.executionId,
    gateId: value.gateId.toString(10),
    invocation: value.invocation.toString(10),
  };
}

function sourceSessionFromJson(value) {
  exactKeys(value, ["protocolVersion", "setupHash", "executionId", "gateId", "invocation"], "E_CODEC_SOURCE_SESSION");
  requireCondition(value.protocolVersion === PROTOCOL_VERSION, "E_PROTOCOL_VERSION", "source session protocol mismatch");
  return Object.freeze({
    protocolVersion: value.protocolVersion,
    setupHash: value.setupHash,
    executionId: value.executionId,
    gateId: decimalBigint(value.gateId, "gateId"),
    invocation: decimalBigint(value.invocation, "invocation"),
  });
}

function publicSetupToJson(setup) {
  verifyPublicSetup(setup);
  return {
    protocolVersion: setup.protocolVersion,
    kind: setup.kind,
    trustees: setup.trustees,
    degree: setup.degree,
    threshold: setup.threshold,
    generator: pointToJson(setup.generator),
    committeeKey: pointToJson(setup.committeeKey),
    coefficientCommitments: setup.coefficientCommitments.map(pointToJson),
    verificationKeys: setup.verificationKeys.map((entry) => ({ trusteeId: entry.trusteeId, point: pointToJson(entry.point) })),
    setupHash: setup.setupHash,
  };
}

function publicSetupFromJson(value) {
  exactKeys(value, ["protocolVersion", "kind", "trustees", "degree", "threshold", "generator", "committeeKey", "coefficientCommitments", "verificationKeys", "setupHash"], "E_CODEC_SETUP");
  requireCondition(value.protocolVersion === PROTOCOL_VERSION && value.kind === SETUP_KIND, "E_CODEC_SETUP_PROFILE", "setup profile mismatch");
  const setup = Object.freeze({
    protocolVersion: value.protocolVersion,
    kind: value.kind,
    trustees: value.trustees,
    degree: value.degree,
    threshold: value.threshold,
    generator: pointFromJson(value.generator, PointRole.GENERATOR),
    committeeKey: pointFromJson(value.committeeKey, PointRole.COMMITTEE_KEY),
    coefficientCommitments: Object.freeze(value.coefficientCommitments.map((entry) => pointFromJson(entry))),
    verificationKeys: Object.freeze(value.verificationKeys.map((entry) => {
      exactKeys(entry, ["trusteeId", "point"], "E_CODEC_VERIFICATION_KEY");
      return Object.freeze({ trusteeId: entry.trusteeId, point: pointFromJson(entry.point, PointRole.TRUSTEE_VERIFICATION_KEY) });
    })),
    setupHash: value.setupHash,
  });
  requireCondition(setup.generator.x === BASE8.x && setup.generator.y === BASE8.y, "E_SETUP_GENERATOR", "setup generator mismatch");
  return verifyPublicSetup(setup);
}

function canonicalPayload(value) {
  return Buffer.from(canonicalJson(value), "utf8");
}

function parseCanonicalPayload(payload) {
  const text = Buffer.from(payload).toString("utf8");
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(`E_CODEC_JSON: ${error.message}`);
  }
  requireCondition(canonicalJson(parsed) === text, "E_CODEC_NONCANONICAL", "payload is not canonical JSON");
  return parsed;
}

module.exports = Object.freeze({
  exactKeys,
  decimalBigint,
  pointToJson,
  pointFromJson,
  ciphertextToJson,
  ciphertextFromJson,
  maskingProofToJson,
  maskingProofFromJson,
  zeroProofToJson,
  zeroProofFromJson,
  sourceSessionToJson,
  sourceSessionFromJson,
  publicSetupToJson,
  publicSetupFromJson,
  canonicalPayload,
  parseCanonicalPayload,
});
