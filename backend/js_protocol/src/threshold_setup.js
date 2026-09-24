"use strict";

const crypto = require("crypto");
const { requireCondition } = require("./errors");
const {
  SUBGROUP_ORDER,
  BASE8,
  IDENTITY,
  PointRole,
  pointEquals,
  isIdentity,
  addPoints,
  scalarMultiply,
  validatePoint,
  encodePoint,
} = require("./group");
const { PROTOCOL_VERSION } = require("./group_oracle");
const { randomScalar, scalarInverse, scalar, scalarMod } = require("./scalars");

const SETUP_DOMAIN = "-CGY-TOOLBOX-FULL-V1/THRESHOLD-SETUP/V1";
const SETUP_KIND = "TEST_ONLY_FRESH_CSPRNG_DEALER";
const VERIFIED_SHARE_TOKEN = Symbol("VerifiedSecretShare");

function u32be(value) {
  requireCondition(Number.isInteger(value) && value >= 0 && value <= 0xffffffff, "E_SETUP_INTEGER", "setup integer is outside uint32 range");
  const output = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return output;
}

function lp(value) {
  const bytes = Buffer.from(value);
  return Buffer.concat([u32be(bytes.length), bytes]);
}

function evaluatePolynomial(coefficients, x) {
  let result = 0n;
  let power = 1n;
  const input = BigInt(x);
  for (const coefficient of coefficients) {
    result = scalarMod(result + coefficient * power);
    power = scalarMod(power * input);
  }
  return result;
}

function evaluateCommitments(commitments, trusteeId) {
  let result = IDENTITY;
  let power = 1n;
  const input = BigInt(trusteeId);
  for (const commitment of commitments) {
    result = addPoints(result, scalarMultiply(commitment, power));
    power = scalarMod(power * input);
  }
  return result;
}

function serializePublicSetup(setup) {
  const pieces = [
    lp(Buffer.from(SETUP_DOMAIN, "utf8")),
    lp(Buffer.from(PROTOCOL_VERSION, "utf8")),
    u32be(setup.trustees),
    u32be(setup.degree),
    u32be(setup.threshold),
    encodePoint(BASE8, PointRole.GENERATOR),
    encodePoint(setup.committeeKey, PointRole.COMMITTEE_KEY),
    u32be(setup.coefficientCommitments.length),
  ];
  for (const commitment of setup.coefficientCommitments) {
    pieces.push(encodePoint(commitment, PointRole.PROOF_ELEMENT));
  }
  pieces.push(u32be(setup.verificationKeys.length));
  for (const entry of setup.verificationKeys) {
    pieces.push(u32be(entry.trusteeId));
    pieces.push(encodePoint(entry.point, PointRole.TRUSTEE_VERIFICATION_KEY));
  }
  return Buffer.concat(pieces);
}

function computeSetupHash(setup) {
  return crypto.createHash("sha256").update(serializePublicSetup(setup)).digest("hex");
}

function constructSetup(coefficients, trustees) {
  requireCondition(Number.isInteger(trustees) && trustees >= 2, "E_TRUSTEE_COUNT", "trustee count must be at least two");
  requireCondition(Array.isArray(coefficients) && coefficients.length >= 2, "E_SETUP_DEGREE", "at least a degree-one polynomial is required");
  coefficients.forEach(scalar);
  const degree = coefficients.length - 1;
  const threshold = degree + 1;
  requireCondition(threshold <= trustees, "E_THRESHOLD_RANGE", "threshold exceeds trustee count");
  requireCondition(coefficients[0] !== 0n, "E_SETUP_ZERO_SECRET", "committee secret must be nonzero");
  requireCondition(coefficients[degree] !== 0n, "E_SETUP_LOWER_DEGREE", "highest coefficient must be nonzero");

  const coefficientCommitments = Object.freeze(coefficients.map((coefficient) => scalarMultiply(BASE8, coefficient)));
  const secretShares = [];
  const verificationKeys = [];
  for (let trusteeId = 1; trusteeId <= trustees; trusteeId += 1) {
    const value = evaluatePolynomial(coefficients, BigInt(trusteeId));
    requireCondition(value !== 0n, "E_SETUP_ZERO_SHARE", `trustee ${trusteeId} received a zero share`);
    secretShares.push(Object.freeze({ trusteeId, value }));
    verificationKeys.push(Object.freeze({ trusteeId, point: scalarMultiply(BASE8, value) }));
  }

  const publicWithoutHash = {
    protocolVersion: PROTOCOL_VERSION,
    kind: SETUP_KIND,
    trustees,
    degree,
    threshold,
    generator: BASE8,
    committeeKey: coefficientCommitments[0],
    coefficientCommitments,
    verificationKeys: Object.freeze(verificationKeys),
  };
  const publicSetup = Object.freeze({ ...publicWithoutHash, setupHash: computeSetupHash(publicWithoutHash) });
  return Object.freeze({
    publicSetup,
    secretShares: Object.freeze(secretShares.map((share) => Object.freeze({ ...share, setupHash: publicSetup.setupHash }))),
  });
}

function provisionFreshTestOnly({ trustees = 5, degree = 2 } = {}) {
  requireCondition(Number.isInteger(degree) && degree >= 1, "E_SETUP_DEGREE", "degree must be a positive integer");
  for (;;) {
    const coefficients = [];
    for (let index = 0; index <= degree; index += 1) {
      coefficients.push(randomScalar({ nonzero: index === 0 || index === degree }));
    }
    try {
      return constructSetup(coefficients, trustees);
    } catch (error) {
      if (error.code === "E_SETUP_ZERO_SHARE") continue;
      throw error;
    }
  }
}

function verifyPublicSetup(setup) {
  requireCondition(setup && typeof setup === "object", "E_SETUP", "public setup is missing");
  requireCondition(setup.protocolVersion === PROTOCOL_VERSION, "E_SETUP_PROTOCOL", "public setup protocol version mismatch");
  requireCondition(setup.kind === SETUP_KIND, "E_SETUP_KIND", "unsupported setup provisioning kind");
  requireCondition(Number.isInteger(setup.trustees) && setup.trustees >= 2, "E_TRUSTEE_COUNT", "invalid trustee count");
  requireCondition(Number.isInteger(setup.degree) && setup.degree >= 1, "E_SETUP_DEGREE", "invalid polynomial degree");
  requireCondition(setup.threshold === setup.degree + 1 && setup.threshold <= setup.trustees, "E_THRESHOLD_PROFILE", "threshold must equal degree plus one");
  requireCondition(pointEquals(setup.generator, BASE8), "E_SETUP_GENERATOR", "setup generator is not fixed Base8");
  validatePoint(setup.committeeKey, PointRole.COMMITTEE_KEY);
  requireCondition(Array.isArray(setup.coefficientCommitments) && setup.coefficientCommitments.length === setup.degree + 1, "E_SETUP_COMMITMENTS", "wrong number of coefficient commitments");
  setup.coefficientCommitments.forEach((commitment, index) => {
    validatePoint(commitment, index === 0 ? PointRole.COMMITTEE_KEY : PointRole.PROOF_ELEMENT);
  });
  requireCondition(!isIdentity(setup.coefficientCommitments[setup.degree]), "E_SETUP_LOWER_DEGREE", "highest coefficient commitment is identity");
  requireCondition(pointEquals(setup.committeeKey, setup.coefficientCommitments[0]), "E_SETUP_COMMITTEE_KEY", "committee key differs from constant commitment");
  requireCondition(Array.isArray(setup.verificationKeys) && setup.verificationKeys.length === setup.trustees, "E_SETUP_VERIFICATION_KEYS", "wrong number of verification keys");
  for (let index = 0; index < setup.verificationKeys.length; index += 1) {
    const entry = setup.verificationKeys[index];
    requireCondition(entry.trusteeId === index + 1, "E_TRUSTEE_ID", "verification keys must be ordered by trustee identity");
    validatePoint(entry.point, PointRole.TRUSTEE_VERIFICATION_KEY);
    const expected = evaluateCommitments(setup.coefficientCommitments, entry.trusteeId);
    requireCondition(pointEquals(entry.point, expected), "E_SETUP_INCONSISTENT", `verification key ${entry.trusteeId} is inconsistent with polynomial commitments`);
  }
  requireCondition(typeof setup.setupHash === "string" && /^[0-9a-f]{64}$/.test(setup.setupHash), "E_SETUP_HASH_ENCODING", "setup hash is not canonical lowercase hexadecimal");
  requireCondition(computeSetupHash(setup) === setup.setupHash, "E_SETUP_HASH", "public setup hash mismatch");
  return setup;
}

class VerifiedSecretShare {
  constructor(token, setupHash, trusteeId, value) {
    requireCondition(token === VERIFIED_SHARE_TOKEN, "E_VERIFIED_SHARE_CONSTRUCTION", "verified shares can only be created by verification");
    this.setupHash = setupHash;
    this.trusteeId = trusteeId;
    this.value = value;
    Object.freeze(this);
  }
}

function verifySecretShare(setup, share) {
  verifyPublicSetup(setup);
  requireCondition(share && typeof share === "object", "E_SECRET_SHARE", "secret share is missing");
  requireCondition(share.setupHash === setup.setupHash, "E_SHARE_SETUP", "secret share belongs to another setup");
  requireCondition(Number.isInteger(share.trusteeId) && share.trusteeId >= 1 && share.trusteeId <= setup.trustees, "E_TRUSTEE_ID", "secret share trustee identity is invalid");
  scalar(share.value);
  const verificationKey = setup.verificationKeys[share.trusteeId - 1].point;
  requireCondition(pointEquals(scalarMultiply(BASE8, share.value), verificationKey), "E_SECRET_SHARE_VALUE", "[s_j]Base8 does not equal h_j");
  requireCondition(pointEquals(verificationKey, evaluateCommitments(setup.coefficientCommitments, share.trusteeId)), "E_SETUP_INCONSISTENT", "share verification key is inconsistent with commitments");
  return new VerifiedSecretShare(VERIFIED_SHARE_TOKEN, share.setupHash, share.trusteeId, share.value);
}

function lagrangeCoefficientAtZero(trusteeIds, targetId) {
  requireCondition(Array.isArray(trusteeIds) && trusteeIds.length > 0, "E_LAGRANGE_SET", "interpolation set is empty");
  const ids = trusteeIds.map((id) => {
    requireCondition(Number.isInteger(id) && id > 0, "E_TRUSTEE_ID", "interpolation identity must be positive");
    return BigInt(id);
  });
  requireCondition(new Set(trusteeIds).size === trusteeIds.length, "E_DUPLICATE_TRUSTEE", "duplicate trustee identity in interpolation set");
  const target = BigInt(targetId);
  requireCondition(ids.includes(target), "E_LAGRANGE_TARGET", "target trustee is not in interpolation set");
  let numerator = 1n;
  let denominator = 1n;
  for (const other of ids) {
    if (other === target) continue;
    numerator = scalarMod(numerator * -other);
    denominator = scalarMod(denominator * (target - other));
  }
  return scalarMod(numerator * scalarInverse(denominator));
}

function interpolateScalarAtZero(setup, verifiedShares) {
  verifyPublicSetup(setup);
  requireCondition(Array.isArray(verifiedShares), "E_SHARE_SET", "share set must be an array");
  requireCondition(verifiedShares.length >= setup.threshold, "E_THRESHOLD_INSUFFICIENT", `need ${setup.threshold} verified shares`);
  requireCondition(verifiedShares.length === setup.threshold, "E_THRESHOLD_EXACT", `source profile combines exactly ${setup.threshold} shares`);
  const ids = verifiedShares.map((share) => {
    requireCondition(share instanceof VerifiedSecretShare, "E_SHARE_NOT_VERIFIED", "unverified share supplied to interpolation");
    requireCondition(share.setupHash === setup.setupHash, "E_SHARE_SETUP", "verified share belongs to another setup");
    return share.trusteeId;
  });
  requireCondition(new Set(ids).size === ids.length, "E_DUPLICATE_TRUSTEE", "duplicate trustee identity in share set");
  let result = 0n;
  for (const share of verifiedShares) {
    result = scalarMod(result + lagrangeCoefficientAtZero(ids, share.trusteeId) * share.value);
  }
  requireCondition(pointEquals(scalarMultiply(BASE8, result), setup.committeeKey), "E_INTERPOLATION_SETUP", "interpolated secret is inconsistent with committee key");
  return result;
}

module.exports = Object.freeze({
  SETUP_DOMAIN,
  SETUP_KIND,
  evaluatePolynomial,
  evaluateCommitments,
  serializePublicSetup,
  computeSetupHash,
  provisionFreshTestOnly,
  verifyPublicSetup,
  verifySecretShare,
  lagrangeCoefficientAtZero,
  interpolateScalarAtZero,
  VerifiedSecretShare,
});
