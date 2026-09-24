"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {
  addBits,
  balancedAggregate,
  subLTBits,
  decisionFromBorrow,
  createPlaintextTestOps,
} = require("../src/arithmetic");

const ops = createPlaintextTestOps();

function bits(value, width) {
  return Array.from({ length: width }, (_, index) => (value >> index) & 1);
}

function integer(bitVector) {
  return bitVector.reduce((sum, bit, index) => sum + bit * (2 ** index), 0);
}

test("carry-retaining AddBits is exhaustive for widths one through four", () => {
  for (let width = 1; width <= 4; width += 1) {
    const limit = 2 ** width;
    for (let left = 0; left < limit; left += 1) {
      for (let right = 0; right < limit; right += 1) {
        const output = addBits(bits(left, width), bits(right, width), ops);
        assert.equal(output.length, width + 1);
        assert.equal(integer(output), left + right, `width=${width} left=${left} right=${right}`);
        output.forEach((bit) => assert.ok(bit === 0 || bit === 1));
      }
    }
  }
});

test("balanced aggregation retains every carry", () => {
  for (const count of [2, 4]) {
    const width = 3;
    const limit = 2 ** width;
    const totalCases = limit ** count;
    for (let encoded = 0; encoded < totalCases; encoded += 1) {
      let cursor = encoded;
      const values = [];
      for (let index = 0; index < count; index += 1) {
        values.push(cursor % limit);
        cursor = Math.floor(cursor / limit);
      }
      const output = balancedAggregate(values.map((value) => bits(value, width)), ops);
      assert.equal(integer(output), values.reduce((sum, value) => sum + value, 0));
      assert.equal(output.length, width + Math.log2(count));
    }
  }
});

test("SubLTBits and terminal identity are exhaustive for widths one through four", () => {
  let cStarDiffersFromDecision = false;
  for (let width = 1; width <= 4; width += 1) {
    const limit = 2 ** width;
    for (let left = 0; left < limit; left += 1) {
      for (let right = 0; right < limit; right += 1) {
        const result = subLTBits(bits(left, width), bits(right, width), ops);
        const expectedBorrow = left < right ? 1 : 0;
        const decision = decisionFromBorrow(result.borrow, ops);
        assert.equal(integer(result.difference), (left - right + limit) % limit, `difference width=${width} left=${left} right=${right}`);
        assert.equal(result.borrow, expectedBorrow, `borrow width=${width} left=${left} right=${right}`);
        assert.equal(result.terminal.Q, result.terminal.D - result.terminal.CStar);
        assert.equal(result.terminal.Q, expectedBorrow);
        assert.equal(decision, left >= right ? 1 : 0);
        if (result.terminal.CStar !== decision) cStarDiffersFromDecision = true;
      }
    }
  }
  assert.equal(cStarDiffersFromDecision, true, "physical C_* must not be identified with the logical decision");
});

test("unsupported arithmetic shapes reject before gate execution", () => {
  assert.throws(() => addBits([], [], ops), (error) => error.code === "E_BITS_EMPTY");
  assert.throws(() => addBits([0], [0, 1], ops), (error) => error.code === "E_BITS_WIDTH");
  assert.throws(() => balancedAggregate([], ops), (error) => error.code === "E_AGGREGATE_EMPTY");
  assert.throws(() => balancedAggregate([[0], [0], [0]], ops), (error) => error.code === "E_AGGREGATE_POWER_OF_TWO");
});
