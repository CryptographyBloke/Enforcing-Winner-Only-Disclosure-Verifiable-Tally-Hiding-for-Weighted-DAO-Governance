"use strict";

const { requireCondition } = require("./errors");
const { SUBGROUP_ORDER, BASE8, IDENTITY } = require("./group");
const {
  ciphertext,
  addCiphertexts,
  scaleCiphertext,
} = require("./elgamal");

function ensureBitVector(value, label) {
  requireCondition(Array.isArray(value) && value.length > 0, "E_BITS_EMPTY", `${label} must be a nonempty bit vector`);
}

function affineSubtract(ops, left, right) {
  return ops.add(left, ops.scale(right, -1n));
}

function xorWithProduct(ops, left, right, product) {
  return ops.add(ops.add(left, right), ops.scale(product, -2n));
}

function addBits(left, right, ops, label = "ADD") {
  ensureBitVector(left, "left addend");
  ensureBitVector(right, "right addend");
  requireCondition(left.length === right.length, "E_BITS_WIDTH", "AddBits requires equal-width operands");
  const output = [];
  let carry = ops.gate(left[0], right[0], `${label}/BIT_0/CARRY`);
  output.push(xorWithProduct(ops, left[0], right[0], carry));
  for (let index = 1; index < left.length; index += 1) {
    const pairProduct = ops.gate(left[index], right[index], `${label}/BIT_${index}/PAIR_PRODUCT`);
    const pairXor = xorWithProduct(ops, left[index], right[index], pairProduct);
    const carryProduct = ops.gate(pairXor, carry, `${label}/BIT_${index}/CARRY_PRODUCT`);
    const sumBit = xorWithProduct(ops, pairXor, carry, carryProduct);
    carry = ops.scale(
      ops.add(ops.add(ops.add(left[index], right[index]), carry), ops.scale(sumBit, -1n)),
      (SUBGROUP_ORDER + 1n) / 2n,
    );
    output.push(sumBit);
  }
  output.push(carry);
  return Object.freeze(output);
}

function balancedAggregate(bitVectors, ops, label = "AGGREGATE") {
  requireCondition(Array.isArray(bitVectors) && bitVectors.length > 0, "E_AGGREGATE_EMPTY", "balanced aggregation requires at least one operand");
  requireCondition((bitVectors.length & (bitVectors.length - 1)) === 0, "E_AGGREGATE_POWER_OF_TWO", "application profile requires a power-of-two operand count");
  const initialWidth = bitVectors[0].length;
  ensureBitVector(bitVectors[0], "aggregate operand");
  bitVectors.forEach((operand) => {
    ensureBitVector(operand, "aggregate operand");
    requireCondition(operand.length === initialWidth, "E_BITS_WIDTH", "aggregate leaves must have equal width");
  });
  let level = bitVectors.map((operand) => Array.from(operand));
  let depth = 0;
  while (level.length > 1) {
    const next = [];
    for (let index = 0; index < level.length; index += 2) {
      next.push(addBits(level[index], level[index + 1], ops, `${label}/LEVEL_${depth}/PAIR_${index / 2}`));
    }
    level = next;
    depth += 1;
  }
  return Object.freeze(level[0]);
}

function subLTBits(left, right, ops, label = "SUB_LT") {
  ensureBitVector(left, "left subtraction operand");
  ensureBitVector(right, "right subtraction operand");
  requireCondition(left.length === right.length, "E_BITS_WIDTH", "SubLTBits requires equal-width operands");
  const difference = [];
  let physicalLastGate = ops.gate(left[0], right[0], `${label}/BIT_0/PRODUCT`);
  difference.push(xorWithProduct(ops, left[0], right[0], physicalLastGate));
  let affineTerm = right[0];
  let borrow = affineSubtract(ops, affineTerm, physicalLastGate);
  for (let index = 1; index < left.length; index += 1) {
    const yBorrow = ops.gate(right[index], borrow, `${label}/BIT_${index}/Y_BORROW`);
    const yXorBorrow = xorWithProduct(ops, right[index], borrow, yBorrow);
    const xProduct = ops.gate(left[index], yXorBorrow, `${label}/BIT_${index}/X_PRODUCT`);
    difference.push(xorWithProduct(ops, left[index], yXorBorrow, xProduct));
    affineTerm = affineSubtract(ops, ops.add(right[index], borrow), yBorrow);
    physicalLastGate = xProduct;
    borrow = affineSubtract(ops, affineTerm, physicalLastGate);
  }
  return Object.freeze({
    difference: Object.freeze(difference),
    borrow,
    terminal: Object.freeze({ D: affineTerm, CStar: physicalLastGate, Q: borrow }),
  });
}

function decisionFromBorrow(borrow, ops) {
  return affineSubtract(ops, ops.publicBit(1), borrow);
}

function createCiphertextOps(gateFunction) {
  requireCondition(typeof gateFunction === "function", "E_GATE_FUNCTION", "ciphertext arithmetic requires a conditional-gate function");
  return Object.freeze({
    add: addCiphertexts,
    scale: (value, factor) => scaleCiphertext(value, ((factor % SUBGROUP_ORDER) + SUBGROUP_ORDER) % SUBGROUP_ORDER),
    publicBit: (bit) => {
      requireCondition(bit === 0 || bit === 1, "E_PUBLIC_BIT", "public bit must be zero or one");
      return ciphertext(IDENTITY, bit === 0 ? IDENTITY : BASE8);
    },
    gate: gateFunction,
  });
}

function createPlaintextTestOps() {
  const inverseTwo = (SUBGROUP_ORDER + 1n) / 2n;
  return Object.freeze({
    add: (left, right) => left + right,
    scale: (value, factor) => {
      if (factor === inverseTwo) return value / 2;
      return value * Number(factor);
    },
    publicBit: (bit) => bit,
    gate: (left, right) => left * right,
  });
}

module.exports = Object.freeze({
  affineSubtract,
  xorWithProduct,
  addBits,
  balancedAggregate,
  subLTBits,
  decisionFromBorrow,
  createCiphertextOps,
  createPlaintextTestOps,
});
