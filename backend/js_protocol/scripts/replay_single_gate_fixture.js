"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const {
  parseConditionalGateTranscript,
  verifyConditionalGateTranscript,
} = require("../src/conditional_gate");

const fixturePath = path.join(__dirname, "..", "test", "fixtures", "source_single_gate_v1.json");
const bytes = fs.readFileSync(fixturePath);
const record = parseConditionalGateTranscript(bytes);
const result = verifyConditionalGateTranscript(record);
process.stdout.write(`SOURCE_SINGLE_GATE_PASS=${result.valid ? "YES" : "NO"}\n`);
process.stdout.write(`SINGLE_GATE_INDEPENDENT_REPLAY=${result.valid ? "PASS" : "FAIL"}\n`);
process.stdout.write(`FIXTURE_SHA256=${crypto.createHash("sha256").update(bytes).digest("hex")}\n`);
process.stdout.write(`BOARD_TRANSCRIPT_HASH=${result.boardTranscriptHash}\n`);
