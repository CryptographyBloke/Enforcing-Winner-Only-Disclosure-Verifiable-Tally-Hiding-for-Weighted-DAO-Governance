"use strict";

const crypto = require("crypto");
const fs = require("fs");
const Module = require("module");
const path = require("path");
const { requireCondition } = require("./errors");
const { PointRole, point, pointEquals, validatePoint } = require("./group");
const { ciphertextEquals, validateAcceptedCiphertext } = require("./elgamal");
const { verifyPublicSetup } = require("./threshold_setup");

const SEALED_BOARD_IMPLEMENTATION_SHA256 = "8813cd11d67c3c3f221c93c1b4d69334a912eb99611b3afc912c53b1b17ac0e8";
const CANONICAL_ENCODING_SHA256 = "d21e9d8082fcccd6df4c004b4102468a80f965bdbd1c0d2d7ff8571c01981ade";
const ACCEPTED_BOARDS = new WeakSet();

const backendRoot = path.resolve(__dirname, "..");
const boardBindingRoot = path.resolve(__dirname, "..", "..", "..", "implementation", "arbitrum", "board_binding");
const sealedBoardPath = path.join(boardBindingRoot, "lib", "sealed_board.js");
const canonicalEncodingPath = path.join(boardBindingRoot, "lib", "canonical_encoding.js");

function sourceSha256(filePath) {
  const source = fs.readFileSync(filePath, "utf8").replace(/\r\n/g, "\n");
  return crypto.createHash("sha256").update(source, "utf8").digest("hex");
}

function loadBoardBindingImplementation() {
  requireCondition(sourceSha256(sealedBoardPath) === SEALED_BOARD_IMPLEMENTATION_SHA256, "E_BOARD_AUTHORITY_SOURCE", "sealed-board implementation differs from its pinned source hash");
  requireCondition(sourceSha256(canonicalEncodingPath) === CANONICAL_ENCODING_SHA256, "E_BOARD_AUTHORITY_SOURCE", "canonical encoding implementation differs from its pinned source hash");

  // Keep the board-binding implementation pinned. NODE_PATH supplies its
  // pinned ethers dependency from this isolated package without changing that tree.
  const localModules = path.join(backendRoot, "node_modules");
  const existing = process.env.NODE_PATH ? process.env.NODE_PATH.split(path.delimiter) : [];
  if (!existing.includes(localModules)) {
    process.env.NODE_PATH = [localModules, ...existing].filter(Boolean).join(path.delimiter);
    Module._initPaths();
  }
  return require(sealedBoardPath);
}

const boardAuthority = loadBoardBindingImplementation();

class AcceptedBoardInputs {
  constructor(board, ciphertexts) {
    this.schema = board.schema;
    this.version = board.version;
    this.setupHash = board.setupHash;
    this.sealedBoardHash = board.sealedBoardHash;
    this.ballotCount = board.ballots.length;
    this.ciphertexts = Object.freeze(ciphertexts.map((ballot) => Object.freeze(Array.from(ballot))));
    Object.freeze(this);
    ACCEPTED_BOARDS.add(this);
  }
}

function requireAcceptedBoard(value) {
  requireCondition(value instanceof AcceptedBoardInputs && ACCEPTED_BOARDS.has(value), "E_ACCEPTED_BOARD_TYPE", "value is not an admitted sealed-board input set");
  return value;
}

function toAcceptedCiphertext(value) {
  return validateAcceptedCiphertext({
    R: point(value.R[0], value.R[1]),
    S: point(value.S[0], value.S[1]),
  });
}

function admitSealedBoard(serializedBoard, publicSetup) {
  const setup = verifyPublicSetup(publicSetup);
  const board = boardAuthority.deserializeSealedBoard(serializedBoard);
  requireCondition(board.setupHash === `0x${setup.setupHash}`, "E_ADMISSION_SETUP", "sealed board is bound to another CGY setup");
  const boardKey = validatePoint(point(BigInt(board.committeePK.x), BigInt(board.committeePK.y)), PointRole.COMMITTEE_KEY);
  requireCondition(pointEquals(boardKey, setup.committeeKey), "E_ADMISSION_KEY", "sealed-board committee key differs from the CGY setup key");

  const authoritativeInputs = boardAuthority.backendInputsFromSealedBoard(board);
  requireCondition(authoritativeInputs.length === board.ballots.length, "E_ADMISSION_COUNT", "authoritative input count differs from the sealed board");
  const admitted = authoritativeInputs.map((ballot, ballotIndex) => {
    requireCondition(ballot.length === 8, "E_ADMISSION_WIDTH", `accepted ballot ${ballotIndex} does not contain eight ciphertexts`);
    return ballot.map((value, bitIndex) => {
      const ciphertext = toAcceptedCiphertext(value);
      const source = board.ballots[ballotIndex].ciphertexts[bitIndex];
      requireCondition(ciphertext.R.x.toString(10) === source.R.x
        && ciphertext.R.y.toString(10) === source.R.y
        && ciphertext.S.x.toString(10) === source.S.x
        && ciphertext.S.y.toString(10) === source.S.y,
      "E_ADMISSION_COORDINATE", `accepted ciphertext ${ballotIndex}:${bitIndex} changed during admission`);
      return ciphertext;
    });
  });
  return new AcceptedBoardInputs(board, admitted);
}

function firstAuthorizedCiphertext(acceptedBoard, ballotIndex, bitIndex) {
  const accepted = requireAcceptedBoard(acceptedBoard);
  requireCondition(Number.isInteger(ballotIndex) && ballotIndex >= 0 && ballotIndex < accepted.ciphertexts.length, "E_BALLOT_INDEX", "ballot index is outside the accepted board");
  requireCondition(Number.isInteger(bitIndex) && bitIndex >= 0 && bitIndex < 8, "E_BIT_INDEX", "bit index is outside the accepted ballot");
  return accepted.ciphertexts[ballotIndex][bitIndex];
}

function assertExactAdmittedInputs(acceptedBoard, candidateInputs) {
  const accepted = requireAcceptedBoard(acceptedBoard);
  requireCondition(Array.isArray(candidateInputs) && candidateInputs.length === accepted.ciphertexts.length, "E_EXACT_INPUT_COUNT", "backend input ballot count differs from the sealed board");
  for (let ballotIndex = 0; ballotIndex < accepted.ciphertexts.length; ballotIndex += 1) {
    const candidateBallot = candidateInputs[ballotIndex];
    requireCondition(Array.isArray(candidateBallot) && candidateBallot.length === 8, "E_EXACT_INPUT_WIDTH", `backend ballot ${ballotIndex} does not have eight ciphertexts`);
    for (let bitIndex = 0; bitIndex < 8; bitIndex += 1) {
      const candidate = validateAcceptedCiphertext(candidateBallot[bitIndex]);
      requireCondition(ciphertextEquals(candidate, accepted.ciphertexts[ballotIndex][bitIndex]), "E_EXACT_INPUT_CIPHERTEXT", `backend input ${ballotIndex}:${bitIndex} differs from the chain-accepted ciphertext`);
    }
  }
  return accepted;
}

function assertFirstTransformationInput(acceptedBoard, ballotIndex, bitIndex, candidate) {
  const exact = firstAuthorizedCiphertext(acceptedBoard, ballotIndex, bitIndex);
  requireCondition(ciphertextEquals(validateAcceptedCiphertext(candidate), exact), "E_FIRST_TRANSFORMATION_INPUT", `first transformation input ${ballotIndex}:${bitIndex} is not the exact accepted ciphertext`);
  return exact;
}

module.exports = Object.freeze({
  SEALED_BOARD_IMPLEMENTATION_SHA256,
  CANONICAL_ENCODING_SHA256,
  AcceptedBoardInputs,
  admitSealedBoard,
  firstAuthorizedCiphertext,
  assertExactAdmittedInputs,
  assertFirstTransformationInput,
});
