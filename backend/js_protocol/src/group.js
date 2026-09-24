"use strict";

const { ProtocolError, requireCondition } = require("./errors");

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const SUBGROUP_ORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;
const CURVE_A = 168700n;
const CURVE_D = 168696n;
const FIELD_BYTES = 32;

function point(x, y) {
  return Object.freeze({ x, y });
}

const IDENTITY = point(0n, 1n);
const BASE8 = point(
  5299619240641551281634865583518297030282874472190772894086521144482721001553n,
  16950150798460657717958625567821834550301663161624707787222815936182638968203n,
);

const PointRole = Object.freeze({
  GENERATOR: "GENERATOR",
  COMMITTEE_KEY: "COMMITTEE_KEY",
  TRUSTEE_VERIFICATION_KEY: "TRUSTEE_VERIFICATION_KEY",
  AUXILIARY: "AUXILIARY",
  CIPHERTEXT_R: "CIPHERTEXT_R",
  CIPHERTEXT_S: "CIPHERTEXT_S",
  MESSAGE_POINT: "MESSAGE_POINT",
  PROOF_ELEMENT: "PROOF_ELEMENT",
  RERANDOMIZATION_ELEMENT: "RERANDOMIZATION_ELEMENT",
  PARTIAL_DECRYPTION: "PARTIAL_DECRYPTION",
});

const NONIDENTITY_ROLES = new Set([
  PointRole.GENERATOR,
  PointRole.COMMITTEE_KEY,
  PointRole.TRUSTEE_VERIFICATION_KEY,
  PointRole.AUXILIARY,
  PointRole.CIPHERTEXT_R,
]);

function mod(value, modulus = FIELD_PRIME) {
  const result = value % modulus;
  return result >= 0n ? result : result + modulus;
}

function modPow(base, exponent, modulus = FIELD_PRIME) {
  requireCondition(typeof exponent === "bigint" && exponent >= 0n, "E_EXPONENT", "exponent must be a nonnegative bigint");
  let x = mod(base, modulus);
  let n = exponent;
  let result = 1n;
  while (n > 0n) {
    if ((n & 1n) === 1n) result = (result * x) % modulus;
    x = (x * x) % modulus;
    n >>= 1n;
  }
  return result;
}

function modInverse(value, modulus = FIELD_PRIME) {
  const normalized = mod(value, modulus);
  requireCondition(normalized !== 0n, "E_INVERSE_ZERO", "zero has no multiplicative inverse");
  return modPow(normalized, modulus - 2n, modulus);
}

function pointEquals(left, right) {
  return left.x === right.x && left.y === right.y;
}

function isIdentity(value) {
  return pointEquals(value, IDENTITY);
}

function coordinatesInField(value) {
  return value && typeof value.x === "bigint" && typeof value.y === "bigint"
    && value.x >= 0n && value.x < FIELD_PRIME
    && value.y >= 0n && value.y < FIELD_PRIME;
}

function isOnCurve(value) {
  if (!coordinatesInField(value)) return false;
  const x2 = mod(value.x * value.x);
  const y2 = mod(value.y * value.y);
  return mod(CURVE_A * x2 + y2) === mod(1n + CURVE_D * x2 * y2);
}

function addPointsUnchecked(left, right) {
  const product = mod(left.x * right.x * left.y * right.y);
  const denominatorX = mod(1n + CURVE_D * product);
  const denominatorY = mod(1n - CURVE_D * product);
  requireCondition(denominatorX !== 0n && denominatorY !== 0n, "E_GROUP_DENOMINATOR", "exceptional Edwards addition denominator");
  return point(
    mod((left.x * right.y + left.y * right.x) * modInverse(denominatorX)),
    mod((left.y * right.y - CURVE_A * left.x * right.x) * modInverse(denominatorY)),
  );
}

function addPoints(left, right) {
  requireCondition(isOnCurve(left), "E_POINT_LEFT", "left operand is not a canonical BabyJub point");
  requireCondition(isOnCurve(right), "E_POINT_RIGHT", "right operand is not a canonical BabyJub point");
  const result = addPointsUnchecked(left, right);
  requireCondition(isOnCurve(result), "E_GROUP_RESULT", "BabyJub addition produced an invalid point");
  return result;
}

function negatePoint(value) {
  requireCondition(isOnCurve(value), "E_POINT_NEGATE", "operand is not a canonical BabyJub point");
  return point(mod(-value.x), value.y);
}

function toExtended(value) {
  return Object.freeze({ X: value.x, Y: value.y, Z: 1n, T: mod(value.x * value.y) });
}

const EXTENDED_IDENTITY = Object.freeze({ X: 0n, Y: 1n, Z: 1n, T: 0n });

function addExtended(left, right) {
  const aa = mod(left.X * right.X);
  const bb = mod(left.Y * right.Y);
  const cc = mod(CURVE_D * left.T * right.T);
  const dd = mod(left.Z * right.Z);
  const ee = mod((left.X + left.Y) * (right.X + right.Y) - aa - bb);
  const ff = mod(dd - cc);
  const gg = mod(dd + cc);
  const hh = mod(bb - CURVE_A * aa);
  return Object.freeze({
    X: mod(ee * ff),
    Y: mod(gg * hh),
    Z: mod(ff * gg),
    T: mod(ee * hh),
  });
}

function scalarMultiplyExtended(value, scalar) {
  let result = EXTENDED_IDENTITY;
  let addend = toExtended(value);
  let n = scalar;
  while (n > 0n) {
    if ((n & 1n) === 1n) result = addExtended(result, addend);
    addend = addExtended(addend, addend);
    n >>= 1n;
  }
  return result;
}

function extendedIsIdentity(value) {
  return value.X === 0n && value.Y === value.Z && value.Z !== 0n;
}

function fromExtended(value) {
  requireCondition(value.Z !== 0n, "E_PROJECTIVE_INFINITY", "invalid extended BabyJub point");
  const inverseZ = modInverse(value.Z);
  return point(mod(value.X * inverseZ), mod(value.Y * inverseZ));
}

function scalarMultiply(value, scalar) {
  requireCondition(isOnCurve(value), "E_POINT_SCALAR", "operand is not a canonical BabyJub point");
  requireCondition(typeof scalar === "bigint" && scalar >= 0n, "E_SCALAR", "scalar must be a nonnegative bigint");
  const result = fromExtended(scalarMultiplyExtended(value, scalar));
  requireCondition(isOnCurve(result), "E_GROUP_RESULT", "BabyJub scalar multiplication produced an invalid point");
  return result;
}

function isInPrimeSubgroup(value) {
  return isOnCurve(value) && extendedIsIdentity(scalarMultiplyExtended(value, SUBGROUP_ORDER));
}

function validatePoint(value, role) {
  requireCondition(Object.values(PointRole).includes(role), "E_POINT_ROLE", `unknown point role ${String(role)}`);
  requireCondition(coordinatesInField(value), "E_POINT_CANONICAL", "point coordinates are outside the canonical field range");
  requireCondition(isOnCurve(value), "E_POINT_CURVE", "point is not on BabyJub");
  requireCondition(isInPrimeSubgroup(value), "E_POINT_SUBGROUP", "point is not in the Base8 prime-order subgroup");
  if (NONIDENTITY_ROLES.has(role)) {
    requireCondition(!isIdentity(value), "E_POINT_IDENTITY", `identity is forbidden for role ${role}`);
  }
  return point(value.x, value.y);
}

function bigintToLittleEndian(value, length) {
  requireCondition(typeof value === "bigint" && value >= 0n, "E_INTEGER", "expected a nonnegative bigint");
  const output = Buffer.alloc(length);
  let remaining = value;
  for (let i = 0; i < length; i += 1) {
    output[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  requireCondition(remaining === 0n, "E_INTEGER_RANGE", `integer does not fit ${length} bytes`);
  return output;
}

function littleEndianToBigint(input) {
  const bytes = Buffer.from(input);
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) value = (value << 8n) + BigInt(bytes[i]);
  return value;
}

function encodePoint(value, role = PointRole.PROOF_ELEMENT) {
  const checked = validatePoint(value, role);
  return Buffer.concat([
    bigintToLittleEndian(checked.x, FIELD_BYTES),
    bigintToLittleEndian(checked.y, FIELD_BYTES),
  ]);
}

function decodePoint(input, role = PointRole.PROOF_ELEMENT) {
  const bytes = Buffer.from(input);
  requireCondition(bytes.length === FIELD_BYTES * 2, "E_POINT_ENCODING_LENGTH", "point encoding must be exactly 64 bytes");
  const x = littleEndianToBigint(bytes.subarray(0, FIELD_BYTES));
  const y = littleEndianToBigint(bytes.subarray(FIELD_BYTES));
  requireCondition(x < FIELD_PRIME && y < FIELD_PRIME, "E_POINT_ENCODING_NONCANONICAL", "encoded coordinate is not a canonical field element");
  return validatePoint(point(x, y), role);
}

function parseCanonicalDecimal(value, label) {
  requireCondition(typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value), "E_DECIMAL_ENCODING", `${label} is not canonical unsigned decimal`);
  const result = BigInt(value);
  requireCondition(result < FIELD_PRIME, "E_DECIMAL_RANGE", `${label} is outside the BabyJub base field`);
  return result;
}

function decodeAffineCoordinates(encoded, role = PointRole.PROOF_ELEMENT) {
  requireCondition(encoded && typeof encoded === "object", "E_AFFINE_ENCODING", "affine point must be an object");
  const keys = Object.keys(encoded);
  requireCondition(keys.length === 2 && keys[0] === "x" && keys[1] === "y", "E_AFFINE_FIELDS", "affine encoding must contain canonical ordered fields x,y only");
  return validatePoint(point(
    parseCanonicalDecimal(encoded.x, "x"),
    parseCanonicalDecimal(encoded.y, "y"),
  ), role);
}

function encodeAffineCoordinates(value, role = PointRole.PROOF_ELEMENT) {
  const checked = validatePoint(value, role);
  return Object.freeze({ x: checked.x.toString(10), y: checked.y.toString(10) });
}

function sqrtModPrime(value) {
  const n = mod(value);
  if (n === 0n) return 0n;
  if (modPow(n, (FIELD_PRIME - 1n) / 2n) !== 1n) return null;
  if ((FIELD_PRIME & 3n) === 3n) return modPow(n, (FIELD_PRIME + 1n) / 4n);

  let q = FIELD_PRIME - 1n;
  let s = 0n;
  while ((q & 1n) === 0n) {
    q >>= 1n;
    s += 1n;
  }
  let z = 2n;
  while (modPow(z, (FIELD_PRIME - 1n) / 2n) !== FIELD_PRIME - 1n) z += 1n;
  let c = modPow(z, q);
  let x = modPow(n, (q + 1n) / 2n);
  let t = modPow(n, q);
  let m = s;
  while (t !== 1n) {
    let i = 1n;
    let t2i = mod(t * t);
    while (i < m && t2i !== 1n) {
      t2i = mod(t2i * t2i);
      i += 1n;
    }
    if (i === m) return null;
    const b = modPow(c, 1n << (m - i - 1n));
    x = mod(x * b);
    t = mod(t * b * b);
    c = mod(b * b);
    m = i;
  }
  return x;
}

function recoverXFromY(y, sign) {
  requireCondition(typeof y === "bigint" && y >= 0n && y < FIELD_PRIME, "E_RECOVER_Y", "y is not a canonical field element");
  requireCondition(sign === 0 || sign === 1, "E_RECOVER_SIGN", "sign must be 0 or 1");
  const y2 = mod(y * y);
  const denominator = mod(CURVE_A - CURVE_D * y2);
  if (denominator === 0n) return null;
  const x2 = mod((1n - y2) * modInverse(denominator));
  let x = sqrtModPrime(x2);
  if (x === null) return null;
  if (x === 0n && sign === 1) return null;
  if (Number(x & 1n) !== sign) x = mod(-x);
  return x;
}

validatePoint(BASE8, PointRole.GENERATOR);

module.exports = Object.freeze({
  FIELD_PRIME,
  SUBGROUP_ORDER,
  CURVE_A,
  CURVE_D,
  FIELD_BYTES,
  IDENTITY,
  BASE8,
  PointRole,
  mod,
  modPow,
  modInverse,
  point,
  pointEquals,
  isIdentity,
  isOnCurve,
  isInPrimeSubgroup,
  addPoints,
  negatePoint,
  scalarMultiply,
  validatePoint,
  bigintToLittleEndian,
  littleEndianToBigint,
  encodePoint,
  decodePoint,
  parseCanonicalDecimal,
  decodeAffineCoordinates,
  encodeAffineCoordinates,
  sqrtModPrime,
  recoverXFromY,
  ProtocolError,
});
