"use strict";

const assert = require("node:assert/strict");
const {
  BASE8,
  PointRole,
  point,
  pointEquals,
  scalarMultiply,
  validatePoint,
} = require("../src/group");

const circomlibPath = process.env.CGY_CIRCOMLIBJS_PATH || require.resolve("circomlibjs");

function fromNative(babyjub, nativePoint) {
  return point(
    BigInt(babyjub.F.toObject(nativePoint[0]).toString()),
    BigInt(babyjub.F.toObject(nativePoint[1]).toString()),
  );
}

async function main() {
  const { buildBabyjub } = require(circomlibPath);
  const babyjub = await buildBabyjub();
  assert.equal(pointEquals(fromNative(babyjub, babyjub.Base8), BASE8), true);

  const scalars = [0n, 1n, 2n, 3n, 7n, 8n, 17n, 123456789n, 987654321n];
  for (const scalar of scalars) {
    const expected = fromNative(babyjub, babyjub.mulPointEscalar(babyjub.Base8, scalar));
    const actual = scalarMultiply(BASE8, scalar);
    validatePoint(actual, scalar === 0n ? PointRole.PROOF_ELEMENT : PointRole.MESSAGE_POINT);
    assert.equal(pointEquals(actual, expected), true, `Base8 scalar mismatch for ${scalar}`);
  }
  process.stdout.write(`CIRCOMLIB_REFERENCE_CROSSCHECK=PASS scalars=${scalars.length}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
