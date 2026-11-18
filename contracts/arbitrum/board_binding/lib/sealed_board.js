"use strict";

const {
  AbiCoder,
  keccak256,
  toUtf8Bytes,
} = require("ethers");
const {
  invariant,
  canonicalAddress,
  canonicalBytes32,
  canonicalDecimal,
  canonicalJson,
} = require("./canonical_encoding.js");

const SCHEMA = "winner-only-disclosure-sealed-board-v1";
const VERSION = "WINNER-ONLY-DISCLOSURE-SEALED-BOARD/V1";
const DOMAIN = "/winner-only-disclosure/sealed-board/hash/v1";
const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const abi = AbiCoder.defaultAbiCoder();

function canonicalField(value, label) {
  const text = canonicalDecimal(value, label);
  invariant(BigInt(text) < FIELD_MODULUS, "E_FIELD_RANGE", `${label} is outside the canonical BabyJub/BN254 field`);
  return text;
}

function exactKeys(value, keys, label) {
  invariant(value && typeof value === "object" && !Array.isArray(value), "E_OBJECT", `${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  invariant(actual.length === expected.length && actual.every((key, index) => key === expected[index]), "E_FIELDS", `${label} fields must be exactly ${keys.join(",")}`);
}

function normalizeCiphertext(raw, label) {
  invariant(raw && typeof raw === "object", "E_CIPHERTEXT", `${label} must be an object`);
  const R = raw.R;
  const S = raw.S;
  invariant(R && S && !Array.isArray(R) && !Array.isArray(S), "E_CIPHERTEXT", `${label} must contain affine R/S objects`);
  return {
    R: {
      x: canonicalField(R.x, `${label}.R.x`),
      y: canonicalField(R.y, `${label}.R.y`),
    },
    S: {
      x: canonicalField(S.x, `${label}.S.x`),
      y: canonicalField(S.y, `${label}.S.y`),
    },
  };
}

function boardHashPreimage(board) {
  const positions = board.ballots.map((ballot) => BigInt(ballot.position));
  const nullifiers = board.ballots.map((ballot) => BigInt(ballot.nullifier));
  const ciphertextWords = [];
  for (const ballot of board.ballots) {
    for (const ciphertext of ballot.ciphertexts) {
      ciphertextWords.push(BigInt(ciphertext.R.x));
      ciphertextWords.push(BigInt(ciphertext.R.y));
      ciphertextWords.push(BigInt(ciphertext.S.x));
      ciphertextWords.push(BigInt(ciphertext.S.y));
    }
  }
  return abi.encode(
    [
      "bytes32", "bytes32", "uint256", "address", "address", "uint256",
      "bytes32", "uint256", "uint256", "uint256", "bytes32", "bytes32",
      "uint256", "uint256[]", "uint256[]", "uint256[]",
    ],
    [
      keccak256(toUtf8Bytes(DOMAIN)),
      keccak256(toUtf8Bytes(VERSION)),
      BigInt(board.chainId),
      board.pollContract,
      board.ballotVerifier,
      BigInt(board.pollId),
      board.setupHash,
      BigInt(board.registryRoot),
      BigInt(board.committeePK.x),
      BigInt(board.committeePK.y),
      board.pollDomain,
      board.ballotSetCommitment,
      BigInt(board.ballots.length),
      positions,
      nullifiers,
      ciphertextWords,
    ]
  );
}

function computeSealedBoardHash(board) {
  return keccak256(boardHashPreimage(board)).toLowerCase();
}

function validateSealedBoard(raw) {
  exactKeys(raw, [
    "schema", "version", "chainId", "pollContract", "ballotVerifier", "pollId",
    "setupHash", "registryRoot", "committeePK", "pollDomain", "ballotSetCommitment",
    "ballots", "sealedBoardHash",
  ], "sealed board");
  invariant(raw.schema === SCHEMA, "E_BOARD_SCHEMA", `sealed board schema must be ${SCHEMA}`);
  invariant(raw.version === VERSION, "E_BOARD_VERSION", `sealed board version must be ${VERSION}`);

  const board = {
    schema: SCHEMA,
    version: VERSION,
    chainId: canonicalDecimal(raw.chainId, "chainId"),
    pollContract: canonicalAddress(raw.pollContract, "pollContract"),
    ballotVerifier: canonicalAddress(raw.ballotVerifier, "ballotVerifier"),
    pollId: canonicalDecimal(raw.pollId, "pollId"),
    setupHash: canonicalBytes32(raw.setupHash, "setupHash"),
    registryRoot: canonicalField(raw.registryRoot, "registryRoot"),
    committeePK: {
      x: canonicalField(raw.committeePK.x, "committeePK.x"),
      y: canonicalField(raw.committeePK.y, "committeePK.y"),
    },
    pollDomain: canonicalBytes32(raw.pollDomain, "pollDomain"),
    ballotSetCommitment: canonicalBytes32(raw.ballotSetCommitment, "ballotSetCommitment"),
    ballots: [],
    sealedBoardHash: canonicalBytes32(raw.sealedBoardHash, "sealedBoardHash"),
  };

  invariant(Array.isArray(raw.ballots) && raw.ballots.length > 0, "E_BALLOT_COUNT", "sealed board must contain accepted ballots");
  const nullifiers = new Set();
  for (let index = 0; index < raw.ballots.length; index++) {
    const rawBallot = raw.ballots[index];
    exactKeys(rawBallot, ["position", "nullifier", "ciphertexts"], `ballots[${index}]`);
    invariant(rawBallot.position === index, "E_BALLOT_ORDER", `ballot ${index} position must equal canonical index`);
    const nullifier = canonicalField(rawBallot.nullifier, `ballots[${index}].nullifier`);
    invariant(!nullifiers.has(nullifier), "E_NULLIFIER_DUPLICATE", `duplicate nullifier at ballot ${index}`);
    nullifiers.add(nullifier);
    invariant(Array.isArray(rawBallot.ciphertexts) && rawBallot.ciphertexts.length === 8, "E_CIPHERTEXT_COUNT", `ballot ${index} must contain eight ciphertexts`);
    board.ballots.push({
      position: index,
      nullifier,
      ciphertexts: rawBallot.ciphertexts.map((ciphertext, bit) => normalizeCiphertext(ciphertext, `ballots[${index}].ciphertexts[${bit}]`)),
    });
  }

  const recomputed = computeSealedBoardHash(board);
  invariant(recomputed === board.sealedBoardHash, "E_SEALED_BOARD_HASH", `sealed board hash mismatch: expected ${recomputed}`);
  return board;
}

function fromChainSnapshot(snapshot) {
  invariant(snapshot && typeof snapshot === "object", "E_SNAPSHOT", "chain snapshot must be an object");
  invariant(snapshot.contract && snapshot.verifier && snapshot.pollConfiguration && snapshot.backendBinding, "E_SNAPSHOT", "chain snapshot is missing required public context");
  invariant(Array.isArray(snapshot.ballots) && snapshot.ballots.length > 0, "E_SNAPSHOT", "chain snapshot has no accepted ballots");
  const board = {
    schema: SCHEMA,
    version: VERSION,
    chainId: canonicalDecimal(snapshot.chainId, "snapshot.chainId"),
    pollContract: canonicalAddress(snapshot.contract.address, "snapshot.contract.address"),
    ballotVerifier: canonicalAddress(snapshot.verifier.address, "snapshot.verifier.address"),
    pollId: canonicalDecimal(snapshot.pollConfiguration.pollId, "snapshot.pollId"),
    setupHash: canonicalBytes32(snapshot.backendBinding.setupHash, "snapshot.setupHash"),
    registryRoot: canonicalField(snapshot.pollConfiguration.registryRoot, "snapshot.registryRoot"),
    committeePK: {
      x: canonicalField(snapshot.backendBinding.committeePK.x, "snapshot.committeePK.x"),
      y: canonicalField(snapshot.backendBinding.committeePK.y, "snapshot.committeePK.y"),
    },
    pollDomain: canonicalBytes32(snapshot.pollDomain, "snapshot.pollDomain"),
    ballotSetCommitment: canonicalBytes32(snapshot.ballotSetCommitment, "snapshot.ballotSetCommitment"),
    ballots: snapshot.ballots.map((ballot, index) => ({
      ...(() => {
        invariant(ballot.position === index, "E_BALLOT_ORDER", `snapshot ballot ${index} position must equal canonical index`);
        return {};
      })(),
      position: index,
      nullifier: canonicalField(ballot.nullifier, `snapshot.ballots[${index}].nullifier`),
      ciphertexts: ballot.ciphertexts.map((ciphertext, bit) => normalizeCiphertext(ciphertext, `snapshot.ballots[${index}].ciphertexts[${bit}]`)),
    })),
    sealedBoardHash: "0x" + "00".repeat(32),
  };
  board.sealedBoardHash = computeSealedBoardHash(board);
  return validateSealedBoard(board);
}

function serializeSealedBoard(board) {
  const checked = validateSealedBoard(board);
  return Buffer.from(canonicalJson(checked), "utf8");
}

function deserializeSealedBoard(bytes) {
  let raw;
  try {
    raw = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch (error) {
    invariant(false, "E_BOARD_JSON", "sealed board is not valid UTF-8 JSON");
  }
  return validateSealedBoard(raw);
}

function backendInputsFromSealedBoard(board) {
  const checked = validateSealedBoard(board);
  return checked.ballots.map((ballot) => ballot.ciphertexts.map((ciphertext) => ({
    R: [BigInt(ciphertext.R.x), BigInt(ciphertext.R.y)],
    S: [BigInt(ciphertext.S.x), BigInt(ciphertext.S.y)],
  })));
}

module.exports = {
  SCHEMA,
  VERSION,
  DOMAIN,
  FIELD_MODULUS,
  boardHashPreimage,
  computeSealedBoardHash,
  validateSealedBoard,
  fromChainSnapshot,
  serializeSealedBoard,
  deserializeSealedBoard,
  backendInputsFromSealedBoard,
};
