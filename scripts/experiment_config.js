"use strict";

const EXPECTED_SHAPES = Object.freeze({
  8: Object.freeze({ gates: 134, depth: 72, maxReadyWidth: 4 }),
  64: Object.freeze({ gates: 1086, depth: 147, maxReadyWidth: 32 }),
  256: Object.freeze({ gates: 4350, depth: 207, maxReadyWidth: 128 }),
  1024: Object.freeze({ gates: 17406, depth: 275, maxReadyWidth: 512 }),
});

const SUPPORTED_COUNTS = Object.freeze(Object.keys(EXPECTED_SHAPES).map(Number));

function thresholdForCount(count) {
  if (!SUPPORTED_COUNTS.includes(count)) throw new RangeError(`unsupported local experiment size: ${count}`);
  return Math.floor(255 * count / 4);
}

function requiresStreaming(count) {
  if (!SUPPORTED_COUNTS.includes(count)) throw new RangeError(`unsupported local experiment size: ${count}`);
  return count >= 256;
}

function assertExpectedShape(manifest) {
  const expected = EXPECTED_SHAPES[manifest && manifest.count];
  if (!expected) throw new Error(`unsupported experiment size in manifest: ${manifest && manifest.count}`);
  if (manifest.gates !== expected.gates || manifest.derivedGates !== expected.gates
      || manifest.depth !== expected.depth || manifest.maxReadyWidth !== expected.maxReadyWidth) {
    throw new Error(`unexpected CGY structure for n=${manifest.count}; expected ${JSON.stringify(expected)}`);
  }
  if (manifest.tau !== thresholdForCount(manifest.count)) {
    throw new Error(`unexpected local threshold for n=${manifest.count}`);
  }
  return expected;
}

module.exports = { EXPECTED_SHAPES, SUPPORTED_COUNTS, thresholdForCount, requiresStreaming, assertExpectedShape };
