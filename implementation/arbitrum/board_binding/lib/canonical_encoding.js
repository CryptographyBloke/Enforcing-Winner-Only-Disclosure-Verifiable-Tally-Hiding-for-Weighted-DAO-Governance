"use strict";

const fs = require("fs");
const path = require("path");
const { getAddress, isHexString } = require("ethers");

function invariant(condition, code, message) {
  if (!condition) {
    const error = new Error(`${code}: ${message}`);
    error.code = code;
    throw error;
  }
}

function canonicalDecimal(value, label = "integer") {
  const text = typeof value === "bigint" ? value.toString() : String(value);
  invariant(/^(0|[1-9][0-9]*)$/.test(text), "E_CANONICAL_INTEGER", `${label} must be canonical unsigned decimal`);
  return text;
}

function canonicalUint(value, bits, label = "integer") {
  const text = canonicalDecimal(value, label);
  const integer = BigInt(text);
  invariant(integer < (1n << BigInt(bits)), "E_INTEGER_RANGE", `${label} does not fit uint${bits}`);
  return text;
}

function canonicalBytes32(value, label = "bytes32") {
  invariant(typeof value === "string" && isHexString(value, 32), "E_BYTES32", `${label} must be exactly 32 bytes`);
  return value.toLowerCase();
}

function canonicalAddress(value, label = "address") {
  try {
    return getAddress(value).toLowerCase();
  } catch (error) {
    invariant(false, "E_ADDRESS", `${label} is not a canonical Ethereum address`);
  }
}

function canonicalJson(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    invariant(Number.isSafeInteger(value), "E_JSON_NUMBER", "canonical JSON accepts only safe integers");
    return String(value);
  }
  if (typeof value === "bigint") return JSON.stringify(value.toString());
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return JSON.stringify(`0x${Buffer.from(value).toString("hex")}`);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  invariant(typeof value === "object", "E_JSON_TYPE", `unsupported canonical JSON type ${typeof value}`);
  const keys = Object.keys(value).sort();
  invariant(keys.every((key) => value[key] !== undefined), "E_JSON_UNDEFINED", "canonical JSON forbids undefined values");
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function jsonSafe(value) {
  if (typeof value === "bigint") return value.toString();
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return `0x${Buffer.from(value).toString("hex")}`;
  if (value instanceof Map) return Object.fromEntries([...value.entries()].map(([key, item]) => [String(key), jsonSafe(item)]));
  if (Array.isArray(value)) return value.map(jsonSafe);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).filter(([key]) => key !== "_private").map(([key, item]) => [key, jsonSafe(item)]));
  }
  return value;
}

function atomicWriteJson(filePath, value) {
  const absolute = path.resolve(filePath);
  const directory = path.dirname(absolute);
  fs.mkdirSync(directory, { recursive: true });
  const temporary = path.join(directory, `.${path.basename(absolute)}.${process.pid}.${Date.now()}.tmp`);
  const bytes = Buffer.from(`${JSON.stringify(jsonSafe(value), null, 2)}\n`, "utf8");
  const flags = fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_SYNC;
  const handle = fs.openSync(temporary, flags, 0o600);
  try {
    fs.writeFileSync(handle, bytes);
  } finally {
    fs.closeSync(handle);
  }
  fs.renameSync(temporary, absolute);
}

module.exports = {
  invariant,
  canonicalDecimal,
  canonicalUint,
  canonicalBytes32,
  canonicalAddress,
  canonicalJson,
  jsonSafe,
  atomicWriteJson,
};
