"use strict";

const crypto = require("crypto");
const { requireCondition } = require("./errors");
const {
  SUBGROUP_ORDER,
  BASE8,
  PointRole,
  addPoints,
  negatePoint,
  scalarMultiply,
  validatePoint,
  encodePoint,
  pointEquals,
} = require("./group");
const { randomScalar, scalar, scalarMod } = require("./scalars");
const { encodeCiphertext } = require("./elgamal");
const { verifyPublicSetup, VerifiedSecretShare, lagrangeCoefficientAtZero } = require("./threshold_setup");
const {
  encodeExecutionContext,
  emitPartialShare,
  isAuthorizedForDecryption,
  isPartialShare,
} = require("./validation_state");

const PARTIAL_DECRYPTION_DOMAIN = "-CGY-TOOLBOX-FULL-V1/CGY/ALGORITHM-65/PARTIAL-DECRYPTION/V1";
const VERIFIED_PARTIAL_TOKEN = Symbol("VerifiedPartialDecryptionShare");

function u32be(value) {
  const output = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return output;
}

function lp(value) {
  const bytes = Buffer.from(value);
  return Buffer.concat([u32be(bytes.length), bytes]);
}

function challengePreimage(authorization, trusteeId, verificationKey, w, cG, cU, counter) {
  return Buffer.concat([
    lp(Buffer.from(PARTIAL_DECRYPTION_DOMAIN, "utf8")),
    encodeExecutionContext(authorization.context),
    Buffer.from(authorization.authorizationId, "hex"),
    encodePoint(BASE8, PointRole.GENERATOR),
    encodePoint(verificationKey, PointRole.TRUSTEE_VERIFICATION_KEY),
    encodeCiphertext(authorization.ciphertext),
    u32be(trusteeId),
    encodePoint(w, PointRole.PARTIAL_DECRYPTION),
    encodePoint(cG, PointRole.PROOF_ELEMENT),
    encodePoint(cU, PointRole.PROOF_ELEMENT),
    u32be(counter),
  ]);
}

function challengeScalar(authorization, trusteeId, verificationKey, w, cG, cU) {
  for (let counter = 0; counter <= 0xffffffff; counter += 1) {
    const bytes = crypto.createHash("shake256", { outputLength: 32 })
      .update(challengePreimage(authorization, trusteeId, verificationKey, w, cG, cU, counter))
      .digest();
    let candidate = 0n;
    for (let index = bytes.length - 1; index >= 0; index -= 1) candidate = (candidate << 8n) + BigInt(bytes[index]);
    if (candidate < SUBGROUP_ORDER) return candidate;
  }
  throw new Error("E_CHALLENGE_EXHAUSTED: scalar challenge rejection sampler exhausted");
}

function createPartialDecryptionShare(setup, authorization, verifiedSecretShare) {
  verifyPublicSetup(setup);
  requireCondition(isAuthorizedForDecryption(authorization), "E_STATE_PARTIAL_INPUT", "partial decryption requires AuthorizedForDecryption");
  requireCondition(authorization.context.setupHash === setup.setupHash, "E_SHARE_SETUP", "authorization belongs to another setup");
  requireCondition(verifiedSecretShare instanceof VerifiedSecretShare, "E_SHARE_NOT_VERIFIED", "secret share has not passed setup verification");
  requireCondition(verifiedSecretShare.setupHash === setup.setupHash, "E_SHARE_SETUP", "secret share belongs to another setup");
  const trusteeId = verifiedSecretShare.trusteeId;
  const verificationKey = setup.verificationKeys[trusteeId - 1].point;
  const u = authorization.ciphertext.R;
  const w = scalarMultiply(u, verifiedSecretShare.value);
  const alpha = randomScalar();
  const cG = scalarMultiply(BASE8, alpha);
  const cU = scalarMultiply(u, alpha);
  const d = challengeScalar(authorization, trusteeId, verificationKey, w, cG, cU);
  const a = scalarMod(alpha + d * verifiedSecretShare.value);
  return emitPartialShare(authorization, {
    trusteeId,
    setupHash: setup.setupHash,
    authorizationId: authorization.authorizationId,
    ciphertextHash: authorization.ciphertextHash,
    w,
    cG,
    cU,
    a,
  });
}

class VerifiedPartialDecryptionShare {
  constructor(token, authorizationId, setupHash, trusteeId, w) {
    requireCondition(token === VERIFIED_PARTIAL_TOKEN, "E_VERIFIED_PARTIAL_CONSTRUCTION", "verified partial shares are opaque");
    this.authorizationId = authorizationId;
    this.setupHash = setupHash;
    this.trusteeId = trusteeId;
    this.w = w;
    Object.freeze(this);
  }
}

function verifyPartialDecryptionShare(setup, authorization, partialShare) {
  verifyPublicSetup(setup);
  requireCondition(isAuthorizedForDecryption(authorization), "E_STATE_PARTIAL_INPUT", "partial-share verification requires AuthorizedForDecryption");
  requireCondition(isPartialShare(partialShare), "E_PARTIAL_NOT_TYPED", "partial share is not a typed protocol state");
  requireCondition(authorization.context.setupHash === setup.setupHash, "E_SHARE_SETUP", "authorization belongs to another setup");
  requireCondition(partialShare.authorizationId === authorization.authorizationId, "E_PARTIAL_SESSION", "partial share belongs to another authorization/session");
  requireCondition(partialShare.ciphertextHash === authorization.ciphertextHash, "E_PARTIAL_CIPHERTEXT", "partial share belongs to another ciphertext");
  const proof = partialShare.payload;
  requireCondition(proof.setupHash === setup.setupHash, "E_SHARE_SETUP", "partial share setup mismatch");
  requireCondition(proof.authorizationId === authorization.authorizationId, "E_PARTIAL_SESSION", "proof authorization mismatch");
  requireCondition(proof.ciphertextHash === authorization.ciphertextHash, "E_PARTIAL_CIPHERTEXT", "proof ciphertext mismatch");
  requireCondition(Number.isInteger(proof.trusteeId) && proof.trusteeId >= 1 && proof.trusteeId <= setup.trustees, "E_TRUSTEE_ID", "partial share trustee identity is invalid");
  const w = validatePoint(proof.w, PointRole.PARTIAL_DECRYPTION);
  const cG = validatePoint(proof.cG, PointRole.PROOF_ELEMENT);
  const cU = validatePoint(proof.cU, PointRole.PROOF_ELEMENT);
  scalar(proof.a);
  const verificationKey = setup.verificationKeys[proof.trusteeId - 1].point;
  const d = challengeScalar(authorization, proof.trusteeId, verificationKey, w, cG, cU);
  const expectedG = addPoints(scalarMultiply(BASE8, proof.a), negatePoint(scalarMultiply(verificationKey, d)));
  const expectedU = addPoints(scalarMultiply(authorization.ciphertext.R, proof.a), negatePoint(scalarMultiply(w, d)));
  requireCondition(pointEquals(cG, expectedG) && pointEquals(cU, expectedU), "E_PARTIAL_PROOF", "Algorithm 65 partial-decryption proof failed");
  return new VerifiedPartialDecryptionShare(VERIFIED_PARTIAL_TOKEN, authorization.authorizationId, setup.setupHash, proof.trusteeId, w);
}

function combineVerifiedPartialDecryptions(setup, authorization, verifiedShares) {
  verifyPublicSetup(setup);
  requireCondition(isAuthorizedForDecryption(authorization), "E_STATE_PARTIAL_INPUT", "threshold combination requires AuthorizedForDecryption");
  requireCondition(Array.isArray(verifiedShares), "E_SHARE_SET", "partial share set must be an array");
  requireCondition(verifiedShares.length >= setup.threshold, "E_THRESHOLD_INSUFFICIENT", `need ${setup.threshold} verified partial shares`);
  requireCondition(verifiedShares.length === setup.threshold, "E_THRESHOLD_EXACT", `source profile combines exactly ${setup.threshold} partial shares`);
  const ids = verifiedShares.map((share) => {
    requireCondition(share instanceof VerifiedPartialDecryptionShare, "E_PARTIAL_NOT_VERIFIED", "unverified partial share supplied to combination");
    requireCondition(share.setupHash === setup.setupHash, "E_SHARE_SETUP", "partial share belongs to another setup");
    requireCondition(share.authorizationId === authorization.authorizationId, "E_PARTIAL_SESSION", "partial share belongs to another ciphertext/session");
    return share.trusteeId;
  });
  requireCondition(new Set(ids).size === ids.length, "E_DUPLICATE_TRUSTEE", "duplicate trustee partial share");
  let decryptionFactor = { x: 0n, y: 1n };
  for (const share of verifiedShares) {
    const coefficient = lagrangeCoefficientAtZero(ids, share.trusteeId);
    decryptionFactor = addPoints(decryptionFactor, scalarMultiply(share.w, coefficient));
  }
  return addPoints(authorization.ciphertext.S, negatePoint(decryptionFactor));
}

module.exports = Object.freeze({
  PARTIAL_DECRYPTION_DOMAIN,
  challengeScalar,
  createPartialDecryptionShare,
  verifyPartialDecryptionShare,
  combineVerifiedPartialDecryptions,
  VerifiedPartialDecryptionShare,
});
