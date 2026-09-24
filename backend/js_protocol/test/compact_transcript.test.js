"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { test } = require("node:test");
const { canonicalJson } = require("../src/broadcast_board");
const { pack, unpack } = require("../../cgy_native/tools/compact_transcript");

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

test("canonical JSONL round-trips byte-for-byte through the compact codec", async (t) => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "cgy-compact-roundtrip-"));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const fixturePath = path.join(__dirname, "fixtures", "source_single_gate_v1.json");
  const canonical = Buffer.from(`${canonicalJson(JSON.parse(fs.readFileSync(fixturePath, "utf8")))}\n`, "utf8");
  const inputPath = path.join(temporary, "canonical_encoding.jsonl");
  const compactPath = path.join(temporary, "transcript.compact.bin");
  const decodedPath = path.join(temporary, "decoded.jsonl");
  fs.writeFileSync(inputPath, canonical);

  const packed = await pack(inputPath, compactPath);
  const unpacked = await unpack(compactPath, decodedPath);
  const decoded = fs.readFileSync(decodedPath);
  assert.equal(packed.inputSha256, sha256(canonical));
  assert.equal(unpacked.outputSha256, sha256(canonical));
  assert.deepEqual(decoded, canonical);
});

test("compact codec rejects a malformed header", async (t) => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "cgy-public-transcript-"));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const malformedPath = path.join(temporary, "malformed.compact.bin");
  fs.writeFileSync(malformedPath, Buffer.alloc(32));

  await assert.rejects(
    unpack(malformedPath, path.join(temporary, "canonical_encoding.jsonl")),
    /compact transcript magic mismatch/,
  );
});
