#!/usr/bin/env node
"use strict";
// Recompute the transcript hash H(T) of the retained Arbitrum Sepolia run and compare it with the value
// recorded in the run manifest and in the on-chain outcome claim (data/sepolia_identifiers.json).
//
//   H(T) = SHA-256( "FC2027-CGY-TOOLBOX-FULL-V1/N8-COMPLETE-TRANSCRIPT/V1"
//                   || setupHash || sealedBoardHash || SHA-256(gate journal) || SHA-256(final release) )
//
// The gate journal is stored in the lossless compact encoding (gate_transcript.compact.bin, 7.4 MB). It is
// not in the git tree; it is an asset of the GitHub release "blocksys2027-evidence-v1". The retained
// bundle was written by the pre-release source, so both the compact-file magic and the H(T) prefix keep the
// "FC2027" string. The public repository head dropped that prefix (see README "Which source produced the runs").
//
// Needs only Node.js 20 or later. No key, no network, no npm install.
// Usage (from the repository root):
//   node evidence/tools/verify_transcript_hash.js <path/to/gate_transcript.compact.bin>
// Exit code 0 only if every comparison matches.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const root = path.resolve(__dirname, "..");
const runDir = path.join(root, "runs", "q5_sepolia_n8_20260923_02");
const MAGIC = Buffer.from("FC2027-CGY-COMPACT-TRANSCRIPT/V1\0", "utf8");
const HT_PREFIX = "FC2027-CGY-TOOLBOX-FULL-V1/N8-COMPLETE-TRANSCRIPT/V1";
const CHUNK_BYTES = 4 * 1024 * 1024;

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));

function unpackToHash(file) {
  const bytes = fs.readFileSync(file);
  if (!bytes.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error("compact transcript magic mismatch (expected the pre-release FC2027 magic)");
  }
  const digest = crypto.createHash("sha256");
  let offset = MAGIC.length, outputBytes = 0;
  while (offset < bytes.length) {
    if (offset + 8 > bytes.length) throw new Error("truncated frame header");
    const rawLength = bytes.readUInt32BE(offset);
    const compressedLength = bytes.readUInt32BE(offset + 4);
    if (rawLength > CHUNK_BYTES || compressedLength > CHUNK_BYTES + 65536) throw new Error("frame exceeds size limit");
    if (offset + 8 + compressedLength > bytes.length) throw new Error("truncated frame body");
    const raw = zlib.inflateRawSync(bytes.subarray(offset + 8, offset + 8 + compressedLength));
    if (raw.length !== rawLength) throw new Error("frame length mismatch");
    digest.update(raw);
    outputBytes += raw.length;
    offset += 8 + compressedLength;
  }
  return { outputBytes, journalSha256: digest.digest("hex") };
}

function main() {
  const file = process.argv[2];
  if (!file) {
    console.error("usage: node evidence/tools/verify_transcript_hash.js <path/to/gate_transcript.compact.bin>");
    process.exit(2);
  }
  const manifest = readJson(path.join(runDir, "manifest.json"));
  const ids = readJson(path.join(root, "data", "sepolia_identifiers.json"));
  const finalBytes = fs.readFileSync(path.join(runDir, "final_release.json"));

  const { outputBytes, journalSha256 } = unpackToHash(file);
  const finalSha256 = sha256(finalBytes);
  const ht = sha256(Buffer.concat([
    Buffer.from(HT_PREFIX, "utf8"),
    Buffer.from(manifest.setupHash, "hex"),
    Buffer.from(manifest.sealedBoardHash.replace(/^0x/, ""), "hex"),
    Buffer.from(journalSha256, "hex"),
    Buffer.from(finalSha256, "hex"),
  ]));

  const checks = [
    ["gate journal SHA-256 equals manifest.gateJournalSha256", journalSha256, manifest.gateJournalSha256],
    ["final_release.json SHA-256 equals manifest.finalReleaseSha256", finalSha256, manifest.finalReleaseSha256],
    ["recomputed H(T) equals manifest.transcriptHash", ht, manifest.transcriptHash],
    ["recomputed H(T) equals the H(T) in the on-chain claim record", ht, ids["transcriptHash_claimed_H(T)"]],
  ];
  let bad = 0;
  console.log(`unpacked journal: ${outputBytes} bytes`);
  for (const [label, got, want] of checks) {
    const ok = got.toLowerCase() === String(want).toLowerCase();
    bad += ok ? 0 : 1;
    console.log(`${ok ? "OK  " : "FAIL"} ${label}\n       got  ${got}\n       want ${want}`);
  }
  console.log(bad === 0 ? "TRANSCRIPT_HASH=MATCH" : "TRANSCRIPT_HASH=MISMATCH");
  process.exit(bad === 0 ? 0 : 1);
}

main();
