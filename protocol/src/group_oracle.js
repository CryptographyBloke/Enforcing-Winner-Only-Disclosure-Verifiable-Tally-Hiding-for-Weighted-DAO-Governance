"use strict";

const crypto = require("crypto");
const { requireCondition } = require("./errors");
const {
  FIELD_PRIME,
  BASE8,
  PointRole,
  bigintToLittleEndian,
  littleEndianToBigint,
  encodePoint,
  point,
  recoverXFromY,
  validatePoint,
} = require("./group");

const PROTOCOL_VERSION = "-CGY-TOOLBOX-FULL-V1";
const DOMAINS = Object.freeze({
  AUXILIARY_GROUP_ORACLE: "-CGY-TOOLBOX-FULL-V1/H_G/AUXILIARY/V1",
  SOURCE_SESSION_ENCODING: "-CGY-TOOLBOX-FULL-V1/SOURCE-SESSION/V1",
  POINT_ENCODING: "-CGY-TOOLBOX-FULL-V1/BABYJUB-AFFINE-LE64/V1",
});
const HASH_TO_GROUP_EXPANSION_BYTES = 33;
const MAX_COUNTER = 0xffffffff;

function u32be(value) {
  requireCondition(Number.isInteger(value) && value >= 0 && value <= 0xffffffff, "E_U32", "value is not an unsigned 32-bit integer");
  const output = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return output;
}

function u64be(value, label) {
  const n = typeof value === "bigint" ? value : BigInt(value);
  requireCondition(n >= 0n && n <= 0xffffffffffffffffn, "E_U64", `${label} is outside unsigned 64-bit range`);
  const output = Buffer.alloc(8);
  output.writeBigUInt64BE(n);
  return output;
}

function lengthPrefix(value) {
  const bytes = Buffer.from(value);
  return Buffer.concat([u32be(bytes.length), bytes]);
}

function decodeFixedHex(value, label) {
  requireCondition(typeof value === "string" && /^[0-9a-f]{64}$/.test(value), "E_HASH_ENCODING", `${label} must be 32 bytes of lowercase hexadecimal`);
  return Buffer.from(value, "hex");
}

function encodeSourceSession(session) {
  requireCondition(session && typeof session === "object", "E_SOURCE_SESSION", "source session must be an object");
  const keys = Object.keys(session);
  const expected = ["protocolVersion", "setupHash", "executionId", "gateId", "invocation"];
  requireCondition(keys.length === expected.length && expected.every((key, index) => keys[index] === key), "E_SOURCE_SESSION_FIELDS", "source session fields must be in canonical protocolVersion,setupHash,executionId,gateId,invocation order");
  requireCondition(session.protocolVersion === PROTOCOL_VERSION, "E_PROTOCOL_VERSION", "source session protocol version mismatch");
  return Buffer.concat([
    lengthPrefix(Buffer.from(DOMAINS.SOURCE_SESSION_ENCODING, "utf8")),
    lengthPrefix(Buffer.from(session.protocolVersion, "utf8")),
    decodeFixedHex(session.setupHash, "setupHash"),
    decodeFixedHex(session.executionId, "executionId"),
    u64be(session.gateId, "gateId"),
    u64be(session.invocation, "invocation"),
  ]);
}

function auxiliaryOraclePreimage(session, committeeKey, counter) {
  const checkedKey = validatePoint(committeeKey, PointRole.COMMITTEE_KEY);
  return Buffer.concat([
    lengthPrefix(Buffer.from(DOMAINS.AUXILIARY_GROUP_ORACLE, "utf8")),
    lengthPrefix(encodeSourceSession(session)),
    lengthPrefix(Buffer.from(DOMAINS.POINT_ENCODING, "utf8")),
    encodePoint(BASE8, PointRole.GENERATOR),
    encodePoint(checkedKey, PointRole.COMMITTEE_KEY),
    u32be(counter),
  ]);
}

function shakeCandidate(preimage) {
  return crypto.createHash("shake256", { outputLength: HASH_TO_GROUP_EXPANSION_BYTES })
    .update(preimage)
    .digest();
}

function deriveAuxiliaryPoint(session, committeeKey) {
  for (let counter = 0; counter <= MAX_COUNTER; counter += 1) {
    const expanded = shakeCandidate(auxiliaryOraclePreimage(session, committeeKey, counter));
    const y = littleEndianToBigint(expanded.subarray(0, 32));
    if (y >= FIELD_PRIME) continue;
    const sign = expanded[32] & 1;
    const x = recoverXFromY(y, sign);
    if (x === null) continue;
    try {
      const auxiliary = validatePoint(point(x, y), PointRole.AUXILIARY);
      return Object.freeze({ point: auxiliary, counter });
    } catch (error) {
      if (["E_POINT_SUBGROUP", "E_POINT_IDENTITY"].includes(error.code)) continue;
      throw error;
    }
  }
  throw new Error("E_AUXILIARY_ORACLE_EXHAUSTED: no valid subgroup point found");
}

module.exports = Object.freeze({
  PROTOCOL_VERSION,
  DOMAINS,
  HASH_TO_GROUP_EXPANSION_BYTES,
  encodeSourceSession,
  auxiliaryOraclePreimage,
  deriveAuxiliaryPoint,
  bigintToLittleEndian,
});
