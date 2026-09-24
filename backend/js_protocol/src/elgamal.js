"use strict";

const crypto = require("crypto");
const { requireCondition } = require("./errors");
const {
  BASE8,
  PointRole,
  addPoints,
  negatePoint,
  scalarMultiply,
  validatePoint,
  encodePoint,
  pointEquals,
} = require("./group");
const { scalar, scalarMod } = require("./scalars");

const CIPHERTEXT_DOMAIN = "-CGY-TOOLBOX-FULL-V1/ELGAMAL-CIPHERTEXT/V1";

function ciphertext(R, S) {
  return Object.freeze({ R, S });
}

function validateCiphertext(value) {
  requireCondition(value && typeof value === "object", "E_CIPHERTEXT", "ciphertext is missing");
  return ciphertext(
    validatePoint(value.R, PointRole.PROOF_ELEMENT),
    validatePoint(value.S, PointRole.CIPHERTEXT_S),
  );
}

function validateAcceptedCiphertext(value) {
  requireCondition(value && typeof value === "object", "E_CIPHERTEXT", "ciphertext is missing");
  return ciphertext(
    validatePoint(value.R, PointRole.CIPHERTEXT_R),
    validatePoint(value.S, PointRole.CIPHERTEXT_S),
  );
}

function encodeCiphertext(value) {
  const checked = validateCiphertext(value);
  return Buffer.concat([
    encodePoint(checked.R, PointRole.PROOF_ELEMENT),
    encodePoint(checked.S, PointRole.CIPHERTEXT_S),
  ]);
}

function ciphertextHash(value) {
  return crypto.createHash("sha256")
    .update(Buffer.from(CIPHERTEXT_DOMAIN, "utf8"))
    .update(encodeCiphertext(value))
    .digest("hex");
}

function ciphertextEquals(left, right) {
  return pointEquals(left.R, right.R) && pointEquals(left.S, right.S);
}

function encryptScalar(committeeKey, message, randomness) {
  const key = validatePoint(committeeKey, PointRole.COMMITTEE_KEY);
  scalar(message);
  scalar(randomness);
  return ciphertext(
    scalarMultiply(BASE8, randomness),
    addPoints(scalarMultiply(BASE8, message), scalarMultiply(key, randomness)),
  );
}

function addCiphertexts(left, right) {
  const a = validateCiphertext(left);
  const b = validateCiphertext(right);
  return ciphertext(addPoints(a.R, b.R), addPoints(a.S, b.S));
}

function negateCiphertext(value) {
  const checked = validateCiphertext(value);
  return ciphertext(negatePoint(checked.R), negatePoint(checked.S));
}

function subtractCiphertexts(left, right) {
  return addCiphertexts(left, negateCiphertext(right));
}

function scaleCiphertext(value, factor) {
  const checked = validateCiphertext(value);
  const k = scalarMod(factor);
  return ciphertext(scalarMultiply(checked.R, k), scalarMultiply(checked.S, k));
}

module.exports = Object.freeze({
  CIPHERTEXT_DOMAIN,
  ciphertext,
  validateCiphertext,
  validateAcceptedCiphertext,
  encodeCiphertext,
  ciphertextHash,
  ciphertextEquals,
  encryptScalar,
  addCiphertexts,
  negateCiphertext,
  subtractCiphertexts,
  scaleCiphertext,
});
