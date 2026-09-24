"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {
  FIELD_PRIME,
  SUBGROUP_ORDER,
  IDENTITY,
  BASE8,
  PointRole,
  point,
  pointEquals,
  isIdentity,
  isOnCurve,
  isInPrimeSubgroup,
  addPoints,
  scalarMultiply,
  validatePoint,
  bigintToLittleEndian,
  encodePoint,
  decodePoint,
  decodeAffineCoordinates,
  encodeAffineCoordinates,
} = require("../src/group");
const {
  PROTOCOL_VERSION,
  DOMAINS,
  encodeSourceSession,
  deriveAuxiliaryPoint,
} = require("../src/group_oracle");

const SESSION = Object.freeze({
  protocolVersion: PROTOCOL_VERSION,
  setupHash: "11".repeat(32),
  executionId: "22".repeat(32),
  gateId: 7n,
  invocation: 3n,
});
const COMMITTEE_KEY = scalarMultiply(BASE8, 123456789n);

function expectCode(fn, code) {
  assert.throws(fn, (error) => error && error.code === code);
}

test("fixed Base8 has the frozen coordinates and exact prime order", () => {
  assert.equal(BASE8.x, 5299619240641551281634865583518297030282874472190772894086521144482721001553n);
  assert.equal(BASE8.y, 16950150798460657717958625567821834550301663161624707787222815936182638968203n);
  assert.equal(isOnCurve(BASE8), true);
  assert.equal(isInPrimeSubgroup(BASE8), true);
  assert.equal(isIdentity(scalarMultiply(BASE8, SUBGROUP_ORDER)), true);
  assert.equal(isIdentity(BASE8), false);
});

test("canonical binary encoding is 32-byte little-endian x followed by y", () => {
  const encoded = encodePoint(BASE8, PointRole.GENERATOR);
  assert.equal(encoded.length, 64);
  assert.deepEqual(encoded.subarray(0, 32), bigintToLittleEndian(BASE8.x, 32));
  assert.deepEqual(encoded.subarray(32), bigintToLittleEndian(BASE8.y, 32));
  assert.equal(pointEquals(decodePoint(encoded, PointRole.GENERATOR), BASE8), true);
  expectCode(() => decodePoint(encoded.subarray(0, 63)), "E_POINT_ENCODING_LENGTH");
  const noncanonical = Buffer.from(encoded);
  bigintToLittleEndian(FIELD_PRIME, 32).copy(noncanonical, 0);
  expectCode(() => decodePoint(noncanonical), "E_POINT_ENCODING_NONCANONICAL");
});

test("canonical affine decimal encoding preserves accepted coordinate semantics", () => {
  const encoded = encodeAffineCoordinates(COMMITTEE_KEY, PointRole.COMMITTEE_KEY);
  assert.deepEqual(Object.keys(encoded), ["x", "y"]);
  assert.equal(pointEquals(decodeAffineCoordinates(encoded, PointRole.COMMITTEE_KEY), COMMITTEE_KEY), true);
  expectCode(() => decodeAffineCoordinates({ x: `0${encoded.x}`, y: encoded.y }), "E_DECIMAL_ENCODING");
  expectCode(() => decodeAffineCoordinates({ y: encoded.y, x: encoded.x }), "E_AFFINE_FIELDS");
});

test("curve, subgroup, and role-specific identity validation are explicit", () => {
  expectCode(() => validatePoint(point(1n, 1n), PointRole.PROOF_ELEMENT), "E_POINT_CURVE");
  const orderTwo = point(0n, FIELD_PRIME - 1n);
  assert.equal(isOnCurve(orderTwo), true);
  assert.equal(isInPrimeSubgroup(orderTwo), false);
  expectCode(() => validatePoint(orderTwo, PointRole.PROOF_ELEMENT), "E_POINT_SUBGROUP");
  expectCode(() => validatePoint(IDENTITY, PointRole.GENERATOR), "E_POINT_IDENTITY");
  expectCode(() => validatePoint(IDENTITY, PointRole.COMMITTEE_KEY), "E_POINT_IDENTITY");
  expectCode(() => validatePoint(IDENTITY, PointRole.TRUSTEE_VERIFICATION_KEY), "E_POINT_IDENTITY");
  expectCode(() => validatePoint(IDENTITY, PointRole.AUXILIARY), "E_POINT_IDENTITY");
  expectCode(() => validatePoint(IDENTITY, PointRole.CIPHERTEXT_R), "E_POINT_IDENTITY");
  assert.equal(pointEquals(validatePoint(IDENTITY, PointRole.CIPHERTEXT_S), IDENTITY), true);
  assert.equal(pointEquals(validatePoint(IDENTITY, PointRole.PROOF_ELEMENT), IDENTITY), true);
});

test("BabyJub group operations preserve the fixed subgroup", () => {
  const twoByAdd = addPoints(BASE8, BASE8);
  const twoByScalar = scalarMultiply(BASE8, 2n);
  assert.equal(pointEquals(twoByAdd, twoByScalar), true);
  assert.equal(isInPrimeSubgroup(scalarMultiply(BASE8, 987654321n)), true);
});

test("source-session encoding is injective and rejects noncanonical context", () => {
  const encoded = encodeSourceSession(SESSION);
  assert.ok(encoded.length > 64);
  expectCode(() => encodeSourceSession({ ...SESSION, protocolVersion: "wrong" }), "E_PROTOCOL_VERSION");
  expectCode(() => encodeSourceSession({ ...SESSION, setupHash: "AA".repeat(32) }), "E_HASH_ENCODING");
  expectCode(() => encodeSourceSession({ setupHash: SESSION.setupHash, protocolVersion: PROTOCOL_VERSION, executionId: SESSION.executionId, gateId: 7n, invocation: 3n }), "E_SOURCE_SESSION_FIELDS");
});

test("auxiliary oracle is deterministic, separated, nonidentity, and subgroup-valid", () => {
  const first = deriveAuxiliaryPoint(SESSION, COMMITTEE_KEY);
  const replay = deriveAuxiliaryPoint(SESSION, COMMITTEE_KEY);
  assert.deepEqual(first, replay);
  assert.equal(isOnCurve(first.point), true);
  assert.equal(isInPrimeSubgroup(first.point), true);
  assert.equal(isIdentity(first.point), false);

  const otherInvocation = deriveAuxiliaryPoint({ ...SESSION, invocation: 4n }, COMMITTEE_KEY);
  const otherKey = deriveAuxiliaryPoint(SESSION, scalarMultiply(BASE8, 123456790n));
  assert.equal(pointEquals(first.point, otherInvocation.point), false);
  assert.equal(pointEquals(first.point, otherKey.point), false);
  assert.match(DOMAINS.AUXILIARY_GROUP_ORACLE, /AUXILIARY\/V1$/);
});

test("auxiliary oracle frozen reference vector", () => {
  const result = deriveAuxiliaryPoint(SESSION, COMMITTEE_KEY);
  assert.deepEqual(
    { counter: result.counter, x: result.point.x.toString(), y: result.point.y.toString() },
    {
      counter: 33,
      x: "12573353409335610813024642004669906154802700419294641850973267748294489571726",
      y: "19346973127309075456033358936725831526269829943471175056245136984598697196272",
    },
  );
});
