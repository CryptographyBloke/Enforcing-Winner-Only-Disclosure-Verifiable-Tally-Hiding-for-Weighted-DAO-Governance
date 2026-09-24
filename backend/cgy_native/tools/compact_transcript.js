"use strict";

// Evidence-storage codec only.  The canonical JSONL transcript remains the
// hash/challenge input; this versioned framing compresses independent chunks
// without changing, merging, or reordering any gate record.

const crypto = require("crypto");
const fs = require("fs");
const zlib = require("zlib");

const MAGIC = Buffer.from("-CGY-COMPACT-TRANSCRIPT/V1\0", "utf8");
const CHUNK_BYTES = 4 * 1024 * 1024;

function required(value, label) {
  if (!value) throw new Error(`${label} is required`);
  return value;
}

function u32(value) {
  const result = Buffer.allocUnsafe(4);
  result.writeUInt32BE(value, 0);
  return result;
}

function writeAll(fd, value) {
  let offset = 0;
  while (offset < value.length) offset += fs.writeSync(fd, value, offset, value.length - offset);
}

async function pack(inputPath, outputPath) {
  const fd = fs.openSync(outputPath, "wx");
  writeAll(fd, MAGIC);
  const digest = crypto.createHash("sha256");
  let inputBytes = 0;
  let compactBytes = MAGIC.length;
  let chunk = [];
  let chunkBytes = 0;
  const flush = () => {
    if (chunkBytes === 0) return;
    const raw = Buffer.from(chunk.join(""), "utf8");
    const compressed = zlib.deflateRawSync(raw, { level: 6 });
    writeAll(fd, u32(raw.length));
    writeAll(fd, u32(compressed.length));
    writeAll(fd, compressed);
    compactBytes += 8 + compressed.length;
    chunk = [];
    chunkBytes = 0;
  };
  try {
    const input = fs.createReadStream(inputPath, { encoding: "utf8" });
    input.on("data", (text) => {
      const bytes = Buffer.byteLength(text, "utf8");
      inputBytes += bytes;
      digest.update(Buffer.from(text, "utf8"));
      chunk.push(text);
      chunkBytes += bytes;
      if (chunkBytes >= CHUNK_BYTES) flush();
    });
    await new Promise((resolve, reject) => {
      input.once("end", resolve);
      input.once("error", reject);
    });
    flush();
  } finally {
    fs.closeSync(fd);
  }
  return { inputBytes, compactBytes, inputSha256: digest.digest("hex") };
}

async function unpack(inputPath, outputPath = null) {
  const digest = crypto.createHash("sha256");
  const outputFd = outputPath ? fs.openSync(outputPath, "wx") : null;
  let pending = Buffer.alloc(0);
  let magicChecked = false;
  let outputBytes = 0;
  const consume = () => {
    if (!magicChecked) {
      if (pending.length < MAGIC.length) return;
      if (!pending.subarray(0, MAGIC.length).equals(MAGIC)) throw new Error("compact transcript magic mismatch");
      pending = pending.subarray(MAGIC.length);
      magicChecked = true;
    }
    while (pending.length >= 8) {
      const rawLength = pending.readUInt32BE(0);
      const compressedLength = pending.readUInt32BE(4);
      if (rawLength > CHUNK_BYTES || compressedLength > CHUNK_BYTES + 65536) throw new Error("compact transcript frame exceeds size limit");
      if (pending.length < 8 + compressedLength) return;
      const raw = zlib.inflateRawSync(pending.subarray(8, 8 + compressedLength));
      if (raw.length !== rawLength) throw new Error("compact transcript frame length mismatch");
      digest.update(raw);
      outputBytes += raw.length;
      if (outputFd !== null) writeAll(outputFd, raw);
      pending = pending.subarray(8 + compressedLength);
    }
  };
  try {
    for await (const chunk of fs.createReadStream(inputPath)) {
      pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk]);
      consume();
    }
    if (!magicChecked || pending.length !== 0) throw new Error("compact transcript truncated frame");
  } finally {
    if (outputFd !== null) fs.closeSync(outputFd);
  }
  return { outputBytes, outputSha256: digest.digest("hex") };
}

async function main() {
  const mode = process.argv[2];
  if (mode === "pack") {
    const result = await pack(required(process.argv[3], "input path"), required(process.argv[4], "output path"));
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return;
  }
  if (mode === "verify") {
    const result = await unpack(required(process.argv[3], "compact path"), process.argv[4] || null);
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return;
  }
  throw new Error("usage: compact_transcript.js pack <jsonl> <compact> | verify <compact> [jsonl-out]");
}

if (require.main === module) {
  main().catch((error) => { process.stderr.write(`${error.stack || error.message}\n`); process.exit(1); });
}

module.exports = Object.freeze({ pack, unpack, MAGIC });
