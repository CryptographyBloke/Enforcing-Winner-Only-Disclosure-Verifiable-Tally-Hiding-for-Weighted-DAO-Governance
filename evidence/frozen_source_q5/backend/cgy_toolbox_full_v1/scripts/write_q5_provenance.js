"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const runDirectory = path.resolve(process.env.CGY_N8_RUN_DIRECTORY || "");
const snapshot = JSON.parse(fs.readFileSync(path.join(runDirectory, "chain_snapshot.json"), "utf8"));
const replay = JSON.parse(fs.readFileSync(path.join(runDirectory, "public_replay_q5.json"), "utf8"));
const records = snapshot.ballots.map((ballot, index) => ({
  index,
  position: ballot.position,
  transactionHash: ballot.provenance.transactionHash,
  blockNumber: ballot.provenance.blockNumber,
  transactionIndex: ballot.provenance.transactionIndex,
  gasUsed: ballot.provenance.gasUsed,
  status: replay.receipts[index].status,
  nullifier: ballot.nullifier,
  ciphertexts: ballot.ciphertexts,
}));
const jsonl = `${records.map((record) => JSON.stringify(record)).join("\n")}\n`;
const output = path.join(runDirectory, "sepolia_ballot_transactions.jsonl");
fs.writeFileSync(output, jsonl, { flag: "wx" });
const receiptOutput = path.join(runDirectory, "sepolia_ballot_receipts.jsonl");
const receipts = `${replay.receipts.map((record, index) => JSON.stringify({ index, ...record })).join("\n")}\n`;
fs.writeFileSync(receiptOutput, receipts, { flag: "wx" });
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
process.stdout.write(`BALLOT_PROVENANCE_RECORDS=${records.length}\nBALLOT_JSONL_SHA256=${hash(jsonl)}\nRECEIPT_JSONL_SHA256=${hash(receipts)}\n`);
