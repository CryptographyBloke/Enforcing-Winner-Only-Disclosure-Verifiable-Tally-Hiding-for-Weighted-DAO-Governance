"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { EXPECTED_SHAPES, SUPPORTED_COUNTS, thresholdForCount, requiresStreaming, assertExpectedShape } = require("./experiment_config");

test("all four local sizes retain the reported gate and scheduled-depth structure", () => {
  assert.deepEqual(SUPPORTED_COUNTS, [8, 64, 256, 1024]);
  assert.deepEqual(EXPECTED_SHAPES, {
    8: { gates: 134, depth: 72, maxReadyWidth: 4 },
    64: { gates: 1086, depth: 147, maxReadyWidth: 32 },
    256: { gates: 4350, depth: 207, maxReadyWidth: 128 },
    1024: { gates: 17406, depth: 275, maxReadyWidth: 512 },
  });
});

test("local thresholds use floor(255*n/4) and reject unsupported sizes", () => {
  assert.deepEqual(SUPPORTED_COUNTS.map(thresholdForCount), [510, 4080, 16320, 65280]);
  assert.throws(() => thresholdForCount(16), /unsupported local experiment size/);
});

test("n=256 and n=1024 use streamed transcript production and replay", () => {
  assert.deepEqual(SUPPORTED_COUNTS.map(requiresStreaming), [false, false, true, true]);
});

test("manifest shape validation rejects a changed gate count or threshold", () => {
  assert.equal(assertExpectedShape({ count: 256, gates: 4350, derivedGates: 4350, depth: 207, maxReadyWidth: 128, tau: 16320 }).depth, 207);
  assert.throws(() => assertExpectedShape({ count: 256, gates: 4351, derivedGates: 4350, depth: 207, maxReadyWidth: 128, tau: 16320 }), /unexpected CGY structure/);
  assert.throws(() => assertExpectedShape({ count: 256, gates: 4350, derivedGates: 4350, depth: 207, maxReadyWidth: 128, tau: 500 }), /unexpected local threshold/);
});
