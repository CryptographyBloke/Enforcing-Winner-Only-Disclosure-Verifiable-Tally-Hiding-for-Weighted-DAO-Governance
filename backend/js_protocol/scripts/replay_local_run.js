"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const readline = require("readline");
const { admitLocalProofBoard } = require("../src/local_admission");
const { ciphertextFromJson, publicSetupFromJson } = require("../src/codec");
const { ciphertextEquals } = require("../src/elgamal");
const { finalReleaseRecordFromJson, verifyFinalRelease } = require("../src/final_release");
const { verifyBroadcastTranscript } = require("../src/broadcast_board");
const { verifyNativeDagFile } = require("../../cgy_native/tools/native_gate_bridge");

const repositoryRoot = path.resolve(__dirname, "../../..");
const runDirectory = path.resolve(repositoryRoot, process.env.CGY_LOCAL_RUN_DIRECTORY || "");
const artifactRoot = path.resolve(process.env.CGY_BALLOT_ARTIFACT_ROOT || repositoryRoot);

function required(value, name) {
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

async function inspectJournal(journalPath) {
  const digest = crypto.createHash("sha256");
  let bytes = 0;
  let gateCount = 0;
  const input = fs.createReadStream(journalPath, { encoding: "utf8" });
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  try {
    for await (const line of lines) {
      if (line.length === 0) continue;
      const raw = Buffer.from(`${line}\n`, "utf8");
      const entry = JSON.parse(line);
      if (entry.backend !== "RUST") throw new Error(`E_LOCAL_REPLAY_BACKEND: gate ${gateCount + 1} is not marked RUST`);
      verifyBroadcastTranscript(entry.record.boardExport);
      digest.update(raw);
      bytes += raw.length;
      gateCount += 1;
    }
  } finally {
    lines.close();
    input.destroy();
  }
  return { bytes, gateCount, sha256: digest.digest("hex") };
}

async function main() {
  const replayStarted = process.hrtime.bigint();
  required(process.env.CGY_LOCAL_RUN_DIRECTORY, "CGY_LOCAL_RUN_DIRECTORY");
  const manifest = readJson(path.join(runDirectory, "manifest.json"));
  if (manifest.profile !== "winner-only-disclosure/five-of-five/v1" || manifest.finalReferenceThreshold !== "5_OF_5") {
    throw new Error("E_LOCAL_REPLAY_PROFILE: run is not the five-of-five reference profile");
  }
  const setupBytes = fs.readFileSync(path.join(runDirectory, "public_setup.json"));
  const proofBytes = fs.readFileSync(path.join(runDirectory, "ballot_public_proofs.json"));
  const contextBytes = fs.readFileSync(path.join(runDirectory, "ballot_public_context.json"));
  const admissionBytes = fs.readFileSync(path.join(runDirectory, "local_admission_board.json"));
  const finalBytes = fs.readFileSync(path.join(runDirectory, "final_release.json"));
  const journalPath = path.join(runDirectory, "gate_transcript.jsonl");
  const hashes = manifest.hashes;
  if (sha256(setupBytes) !== hashes.publicSetupSha256) throw new Error("E_LOCAL_REPLAY_SETUP_HASH: public setup changed");
  if (sha256(proofBytes) !== hashes.proofsSha256) throw new Error("E_LOCAL_REPLAY_PROOF_HASH: public proofs changed");
  if (sha256(admissionBytes) !== hashes.admissionSha256) throw new Error("E_LOCAL_REPLAY_ADMISSION_HASH: accepted board changed");
  if (sha256(finalBytes) !== hashes.finalSha256) throw new Error("E_LOCAL_REPLAY_RELEASE_HASH: final release changed");

  const setup = publicSetupFromJson(JSON.parse(setupBytes.toString("utf8")));
  const context = JSON.parse(contextBytes.toString("utf8"));
  const publicProofs = JSON.parse(proofBytes.toString("utf8"));
  const verificationKeyPath = path.join(artifactRoot, "implementation", "logs", "bit_ballot", "groth16", "vote_bit_full_8", "verification_key.json");
  const admitted = await admitLocalProofBoard({
    publicProofs,
    verificationKey: readJson(verificationKeyPath),
    registryRoot: BigInt(context.registryRoot),
    pollId: context.pollId,
    committeeKey: setup.committeeKey,
    count: manifest.count,
  });
  const savedBoard = JSON.parse(admissionBytes.toString("utf8"));
  if (admitted.sealedBoardHash !== savedBoard.sealedBoardHash || admitted.sealedBoardHash !== manifest.sealedBoardHash) {
    throw new Error("E_LOCAL_REPLAY_BOARD_HASH: regenerated accepted board differs");
  }

  const journal = await inspectJournal(journalPath);
  if (journal.gateCount !== manifest.gates || journal.sha256 !== hashes.journalSha256) {
    throw new Error("E_LOCAL_REPLAY_JOURNAL: canonical gate journal differs from manifest");
  }
  const native = verifyNativeDagFile({
    setup,
    executionId: manifest.executionId,
    bitVectors: admitted.ciphertexts,
    tau: manifest.tau,
    labelPrefix: `N${manifest.count}`,
    transcriptPath: journalPath,
  });
  const finalRelease = finalReleaseRecordFromJson(JSON.parse(finalBytes.toString("utf8")));
  if (!ciphertextEquals(ciphertextFromJson(native.result), finalRelease.logicalCiphertext)) throw new Error("E_LOCAL_REPLAY_RESULT_CIPHERTEXT: tally result ciphertext differs");
  const release = verifyFinalRelease(finalRelease, setup);
  if (release.resultBit !== manifest.resultBit) throw new Error("E_LOCAL_REPLAY_RESULT_BIT: final release result differs");

  const transcriptHash = sha256(Buffer.concat([
    Buffer.from(`${manifest.protocolVersion}/LOCAL-COMPLETE-TRANSCRIPT/V1`, "utf8"),
    Buffer.from(setup.setupHash, "hex"),
    Buffer.from(admitted.sealedBoardHash, "hex"),
    Buffer.from(journal.sha256, "hex"),
    Buffer.from(sha256(finalBytes), "hex"),
  ]));
  if (transcriptHash !== manifest.transcriptHash) throw new Error("E_LOCAL_REPLAY_TRANSCRIPT_HASH: complete transcript hash differs");

  const result = {
    schema: "winner-only-disclosure/local-public-replay/v1",
    status: "PASS",
    count: manifest.count,
    gateCount: native.gateCount,
    finalThreshold: "5_OF_5",
    sealedBoardHash: admitted.sealedBoardHash,
    transcriptHash,
    timing: { replaySeconds: Number(process.hrtime.bigint() - replayStarted) / 1e9 },
    resultBit: release.resultBit,
    oracleRead: false,
  };
  fs.writeFileSync(path.join(runDirectory, "public_replay.json"), `${JSON.stringify(result, null, 2)}\n`);
  process.stdout.write(`LOCAL_PUBLIC_REPLAY=PASS\nN=${result.count}\nSOURCE_GATES_VERIFIED=${result.gateCount}\nRESULT_BIT=${result.resultBit}\nORACLE_READ=NO\n`);
  process.exit(0);
}

main().catch((error) => {
  process.stderr.write(`${error.code || "E_LOCAL_PUBLIC_REPLAY"}: ${error.stack || error.message}\n`);
  process.exit(1);
});
