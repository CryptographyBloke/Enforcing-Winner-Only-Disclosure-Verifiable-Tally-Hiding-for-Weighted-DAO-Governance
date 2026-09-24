"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {
  BASE8,
  IDENTITY,
  addPoints,
  negatePoint,
  scalarMultiply,
  pointEquals,
} = require("../src/group");
const { encryptScalar } = require("../src/elgamal");
const {
  provisionFreshTestOnly,
  verifySecretShare,
  interpolateScalarAtZero,
} = require("../src/threshold_setup");
const {
  addBits,
  subLTBits,
  decisionFromBorrow,
  createCiphertextOps,
} = require("../src/arithmetic");

function bits(value, width) {
  return Array.from({ length: width }, (_, index) => (value >> index) & 1);
}

test("isolated cleartext harness confirms encrypted affine arithmetic and orientation", () => {
  const setupBundle = provisionFreshTestOnly();
  const setup = setupBundle.publicSetup;
  const secret = interpolateScalarAtZero(setup, setupBundle.secretShares.slice(0, 3).map((share) => verifySecretShare(setup, share)));
  let randomness = 1000n;
  const encryptBit = (bit) => encryptScalar(setup.committeeKey, BigInt(bit), randomness++);
  const decryptBit = (value) => {
    const messagePoint = addPoints(value.S, negatePoint(scalarMultiply(value.R, secret)));
    if (pointEquals(messagePoint, IDENTITY)) return 0;
    if (pointEquals(messagePoint, BASE8)) return 1;
    throw new Error("test oracle decoded a non-bit");
  };
  const ops = createCiphertextOps((left, right) => encryptBit(decryptBit(left) * decryptBit(right)));

  for (let left = 0; left < 4; left += 1) {
    for (let right = 0; right < 4; right += 1) {
      const encryptedLeft = bits(left, 2).map(encryptBit);
      const encryptedRight = bits(right, 2).map(encryptBit);
      const sum = addBits(encryptedLeft, encryptedRight, ops).map(decryptBit);
      assert.equal(sum.reduce((value, bit, index) => value + bit * (2 ** index), 0), left + right);
    }
  }

  for (let left = 0; left < 8; left += 1) {
    for (let right = 0; right < 8; right += 1) {
      const encryptedLeft = bits(left, 3).map(encryptBit);
      const encryptedRight = bits(right, 3).map(encryptBit);
      const result = subLTBits(encryptedLeft, encryptedRight, ops);
      assert.equal(decryptBit(result.borrow), left < right ? 1 : 0);
      assert.equal(decryptBit(decisionFromBorrow(result.borrow, ops)), left >= right ? 1 : 0);
      assert.equal(decryptBit(result.terminal.Q), decryptBit(result.borrow));
    }
  }
});
