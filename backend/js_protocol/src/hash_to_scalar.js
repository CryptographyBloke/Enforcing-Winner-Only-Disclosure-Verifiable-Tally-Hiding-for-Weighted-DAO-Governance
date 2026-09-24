"use strict";

const crypto = require("crypto");
const { requireCondition } = require("./errors");
const { SUBGROUP_ORDER } = require("./group");

function u32be(value) {
  requireCondition(Number.isInteger(value) && value >= 0 && value <= 0xffffffff, "E_HASH_U32", "hash counter/length is outside uint32 range");
  const output = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return output;
}

function lp(value) {
  const bytes = Buffer.from(value);
  return Buffer.concat([u32be(bytes.length), bytes]);
}

function littleEndianToBigint(bytes) {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) value = (value << 8n) + BigInt(bytes[index]);
  return value;
}

function hashToScalar(domain, parts) {
  requireCondition(typeof domain === "string" && domain.length > 0, "E_HASH_DOMAIN", "scalar hash domain is missing");
  requireCondition(Array.isArray(parts), "E_HASH_PARTS", "scalar hash parts must be an array");
  const prefix = Buffer.concat([
    lp(Buffer.from(domain, "utf8")),
    u32be(parts.length),
    ...parts.map((part) => lp(part)),
  ]);
  for (let counter = 0; counter <= 0xffffffff; counter += 1) {
    const candidate = littleEndianToBigint(crypto.createHash("shake256", { outputLength: 32 })
      .update(prefix)
      .update(u32be(counter))
      .digest());
    if (candidate < SUBGROUP_ORDER) return candidate;
  }
  throw new Error("E_HASH_TO_SCALAR_EXHAUSTED: rejection sampler exhausted");
}

module.exports = Object.freeze({ hashToScalar });
