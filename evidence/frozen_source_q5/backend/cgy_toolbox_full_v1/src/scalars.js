"use strict";

const crypto = require("crypto");
const { requireCondition } = require("./errors");
const { SUBGROUP_ORDER, mod } = require("./group");

const SCALAR_SAMPLE_BYTES = 32;
const SCALAR_SAMPLE_SPACE = 1n << 256n;
const SCALAR_SAMPLE_LIMIT = SCALAR_SAMPLE_SPACE - (SCALAR_SAMPLE_SPACE % SUBGROUP_ORDER);

function bigEndianToBigint(input) {
  const hex = Buffer.from(input).toString("hex");
  return BigInt(`0x${hex || "0"}`);
}

function randomScalar({ nonzero = false } = {}) {
  for (;;) {
    const candidate = bigEndianToBigint(crypto.randomBytes(SCALAR_SAMPLE_BYTES));
    if (candidate >= SCALAR_SAMPLE_LIMIT) continue;
    const value = candidate % SUBGROUP_ORDER;
    if (!nonzero || value !== 0n) return value;
  }
}

function scalarInverse(value) {
  const normalized = mod(value, SUBGROUP_ORDER);
  requireCondition(normalized !== 0n, "E_SCALAR_INVERSE_ZERO", "zero has no scalar inverse");
  let exponent = SUBGROUP_ORDER - 2n;
  let base = normalized;
  let result = 1n;
  while (exponent > 0n) {
    if ((exponent & 1n) === 1n) result = (result * base) % SUBGROUP_ORDER;
    base = (base * base) % SUBGROUP_ORDER;
    exponent >>= 1n;
  }
  return result;
}

function scalar(value) {
  requireCondition(typeof value === "bigint", "E_SCALAR_TYPE", "scalar must be a bigint");
  requireCondition(value >= 0n && value < SUBGROUP_ORDER, "E_SCALAR_RANGE", "scalar is outside [0,q)");
  return value;
}

module.exports = Object.freeze({
  randomScalar,
  scalarInverse,
  scalar,
  scalarMod: (value) => mod(value, SUBGROUP_ORDER),
});
