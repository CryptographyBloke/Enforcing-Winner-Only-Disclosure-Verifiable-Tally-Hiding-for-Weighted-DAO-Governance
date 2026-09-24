"use strict";

const assert = require("node:assert/strict");
const path = require("path");
const test = require("node:test");
const { BASE8, IDENTITY } = require("../src/group");
const { encryptScalar } = require("../src/elgamal");
const { provisionFreshTestOnly } = require("../src/threshold_setup");
const {
  admitSealedBoard,
  firstAuthorizedCiphertext,
  assertExactAdmittedInputs,
  assertFirstTransformationInput,
} = require("../src/accepted_board");

const sealedBoard = require(path.resolve(__dirname, "..", "..", "..", "implementation", "arbitrum", "board_binding", "lib", "sealed_board.js"));

function affine(value) {
  return { x: value.x.toString(10), y: value.y.toString(10) };
}

function boardFixture({ setupBundle = provisionFreshTestOnly(), setupHash, committeeKey, ciphertextOverride } = {}) {
  const setup = setupBundle.publicSetup;
  const ballots = [];
  for (let ballotIndex = 0; ballotIndex < 2; ballotIndex += 1) {
    const ciphertexts = [];
    for (let bitIndex = 0; bitIndex < 8; bitIndex += 1) {
      const encrypted = encryptScalar(setup.committeeKey, BigInt((ballotIndex + bitIndex) & 1), BigInt(1 + ballotIndex * 8 + bitIndex));
      ciphertexts.push({ R: affine(encrypted.R), S: affine(encrypted.S) });
    }
    ballots.push({ position: ballotIndex, nullifier: String(100 + ballotIndex), ciphertexts });
  }
  if (ciphertextOverride) ballots[ciphertextOverride.ballot].ciphertexts[ciphertextOverride.bit] = ciphertextOverride.value;
  const board = sealedBoard.fromChainSnapshot({
    chainId: "31337",
    contract: { address: "0x1000000000000000000000000000000000000001" },
    verifier: { address: "0x2000000000000000000000000000000000000002" },
    pollConfiguration: { pollId: "7", registryRoot: "123" },
    backendBinding: {
      setupHash: setupHash || `0x${setup.setupHash}`,
      committeePK: affine(committeeKey || setup.committeeKey),
    },
    pollDomain: `0x${"31".repeat(32)}`,
    ballotSetCommitment: `0x${"42".repeat(32)}`,
    ballots,
  });
  return { setupBundle, setup, board, bytes: sealedBoard.serializeSealedBoard(board) };
}

test("backend inputs equal every chain-accepted ciphertext coordinate position by position", () => {
  const run = boardFixture();
  const accepted = admitSealedBoard(run.bytes, run.setup);
  const authoritative = sealedBoard.backendInputsFromSealedBoard(run.board).map((ballot) => ballot.map((value) => ({
    R: { x: value.R[0], y: value.R[1] },
    S: { x: value.S[0], y: value.S[1] },
  })));
  assert.equal(accepted.sealedBoardHash, run.board.sealedBoardHash);
  assert.equal(assertExactAdmittedInputs(accepted, authoritative), accepted);
  for (let ballot = 0; ballot < 2; ballot += 1) {
    for (let bit = 0; bit < 8; bit += 1) {
      const exact = firstAuthorizedCiphertext(accepted, ballot, bit);
      assert.equal(exact.R.x.toString(10), run.board.ballots[ballot].ciphertexts[bit].R.x);
      assert.equal(exact.R.y.toString(10), run.board.ballots[ballot].ciphertexts[bit].R.y);
      assert.equal(exact.S.x.toString(10), run.board.ballots[ballot].ciphertexts[bit].S.x);
      assert.equal(exact.S.y.toString(10), run.board.ballots[ballot].ciphertexts[bit].S.y);
      assert.equal(assertFirstTransformationInput(accepted, ballot, bit, exact), exact);
    }
  }
});

test("wrong setup, committee key, and nonaccepted first input reject", () => {
  const run = boardFixture();
  const wrongSetupBoard = boardFixture({ setupBundle: run.setupBundle, setupHash: `0x${"00".repeat(32)}` });
  assert.throws(() => admitSealedBoard(wrongSetupBoard.bytes, run.setup), (error) => error.code === "E_ADMISSION_SETUP");

  const wrongKeyBoard = boardFixture({ setupBundle: run.setupBundle, committeeKey: BASE8 });
  assert.throws(() => admitSealedBoard(wrongKeyBoard.bytes, run.setup), (error) => error.code === "E_ADMISSION_KEY");

  const accepted = admitSealedBoard(run.bytes, run.setup);
  const replacement = encryptScalar(run.setup.committeeKey, 1n, 99n);
  assert.throws(() => assertFirstTransformationInput(accepted, 0, 0, replacement), (error) => error.code === "E_FIRST_TRANSFORMATION_INPUT");
  const candidate = accepted.ciphertexts.map((ballot) => Array.from(ballot));
  candidate[1][7] = replacement;
  assert.throws(() => assertExactAdmittedInputs(accepted, candidate), (error) => error.code === "E_EXACT_INPUT_CIPHERTEXT");
});

test("reordered, replaced, hash-tampered, and identity-R board artifacts reject", () => {
  const run = boardFixture();
  const changed = JSON.parse(run.bytes.toString("utf8"));
  changed.ballots[0].ciphertexts[0] = changed.ballots[0].ciphertexts[1];
  assert.throws(() => admitSealedBoard(Buffer.from(JSON.stringify(changed)), run.setup), (error) => error.code === "E_SEALED_BOARD_HASH");

  const reordered = JSON.parse(run.bytes.toString("utf8"));
  [reordered.ballots[0], reordered.ballots[1]] = [reordered.ballots[1], reordered.ballots[0]];
  assert.throws(() => admitSealedBoard(Buffer.from(JSON.stringify(reordered)), run.setup), (error) => error.code === "E_BALLOT_ORDER");

  const wrongHash = JSON.parse(run.bytes.toString("utf8"));
  wrongHash.sealedBoardHash = `0x${"ff".repeat(32)}`;
  assert.throws(() => admitSealedBoard(Buffer.from(JSON.stringify(wrongHash)), run.setup), (error) => error.code === "E_SEALED_BOARD_HASH");

  const identityBoard = boardFixture({
    setupBundle: run.setupBundle,
    ciphertextOverride: {
      ballot: 0,
      bit: 0,
      value: { R: affine(IDENTITY), S: affine(BASE8) },
    },
  });
  assert.throws(() => admitSealedBoard(identityBoard.bytes, run.setup), (error) => error.code === "E_POINT_IDENTITY");
});
