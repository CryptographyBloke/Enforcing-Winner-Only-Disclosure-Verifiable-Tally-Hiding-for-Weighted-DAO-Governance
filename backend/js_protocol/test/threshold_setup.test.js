"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {
  BASE8,
  IDENTITY,
  pointEquals,
  scalarMultiply,
} = require("../src/group");
const {
  SETUP_KIND,
  evaluateCommitments,
  provisionFreshTestOnly,
  verifyPublicSetup,
  verifySecretShare,
  lagrangeCoefficientAtZero,
  interpolateScalarAtZero,
} = require("../src/threshold_setup");
const { scalarMod } = require("../src/scalars");

function expectCode(fn, code) {
  assert.throws(fn, (error) => error && error.code === code);
}

function combinations(values, size) {
  const output = [];
  function visit(start, selected) {
    if (selected.length === size) {
      output.push(selected.slice());
      return;
    }
    for (let index = start; index < values.length; index += 1) {
      selected.push(values[index]);
      visit(index + 1, selected);
      selected.pop();
    }
  }
  visit(0, []);
  return output;
}

test("fresh test-only setup is a consistent degree-2 3-of-5 profile", () => {
  const provisioned = provisionFreshTestOnly();
  const setup = verifyPublicSetup(provisioned.publicSetup);
  assert.equal(setup.kind, SETUP_KIND);
  assert.equal(setup.trustees, 5);
  assert.equal(setup.degree, 2);
  assert.equal(setup.threshold, 3);
  assert.equal(pointEquals(setup.generator, BASE8), true);
  assert.equal(pointEquals(setup.committeeKey, setup.coefficientCommitments[0]), true);
  for (const share of provisioned.secretShares) {
    const verified = verifySecretShare(setup, share);
    assert.equal(pointEquals(scalarMultiply(BASE8, verified.value), setup.verificationKeys[verified.trusteeId - 1].point), true);
    assert.equal(pointEquals(evaluateCommitments(setup.coefficientCommitments, verified.trusteeId), setup.verificationKeys[verified.trusteeId - 1].point), true);
  }
});

test("every one of the ten 3-of-5 quorums interpolates f(0)", () => {
  const provisioned = provisionFreshTestOnly();
  const setup = verifyPublicSetup(provisioned.publicSetup);
  const verified = provisioned.secretShares.map((share) => verifySecretShare(setup, share));
  for (const quorum of combinations(verified, 3)) {
    const recovered = interpolateScalarAtZero(setup, quorum);
    assert.equal(pointEquals(scalarMultiply(BASE8, recovered), setup.committeeKey), true);
    const ids = quorum.map((share) => share.trusteeId);
    const sum = ids.reduce((acc, id) => scalarMod(acc + lagrangeCoefficientAtZero(ids, id)), 0n);
    assert.equal(sum, 1n);
  }
});

test("fresh CSPRNG provisioning does not reuse setup", () => {
  const first = provisionFreshTestOnly();
  const second = provisionFreshTestOnly();
  assert.notEqual(first.publicSetup.setupHash, second.publicSetup.setupHash);
  assert.equal(pointEquals(first.publicSetup.committeeKey, second.publicSetup.committeeKey), false);
});

test("invalid, foreign, duplicate, and insufficient shares reject explicitly", () => {
  const first = provisionFreshTestOnly();
  const second = provisionFreshTestOnly();
  const setup = first.publicSetup;
  const verified = first.secretShares.map((share) => verifySecretShare(setup, share));
  expectCode(() => verifySecretShare(setup, { ...first.secretShares[0], value: first.secretShares[0].value + 1n }), "E_SECRET_SHARE_VALUE");
  expectCode(() => verifySecretShare(setup, second.secretShares[0]), "E_SHARE_SETUP");
  expectCode(() => interpolateScalarAtZero(setup, verified.slice(0, 2)), "E_THRESHOLD_INSUFFICIENT");
  expectCode(() => interpolateScalarAtZero(setup, [verified[0], verified[0], verified[1]]), "E_DUPLICATE_TRUSTEE");
  expectCode(() => interpolateScalarAtZero(setup, first.secretShares.slice(0, 3)), "E_SHARE_NOT_VERIFIED");
  expectCode(() => interpolateScalarAtZero(setup, verified.slice(0, 4)), "E_THRESHOLD_EXACT");
});

test("inconsistent public setup and degree downgrade reject", () => {
  const provisioned = provisionFreshTestOnly();
  const setup = provisioned.publicSetup;
  const inconsistentKeys = setup.verificationKeys.slice();
  inconsistentKeys[2] = Object.freeze({ trusteeId: 3, point: setup.verificationKeys[1].point });
  expectCode(() => verifyPublicSetup({ ...setup, verificationKeys: inconsistentKeys }), "E_SETUP_INCONSISTENT");
  const downgraded = setup.coefficientCommitments.slice();
  downgraded[2] = IDENTITY;
  expectCode(() => verifyPublicSetup({ ...setup, coefficientCommitments: downgraded }), "E_SETUP_LOWER_DEGREE");
  expectCode(() => verifyPublicSetup({ ...setup, setupHash: "00".repeat(32) }), "E_SETUP_HASH");
});
