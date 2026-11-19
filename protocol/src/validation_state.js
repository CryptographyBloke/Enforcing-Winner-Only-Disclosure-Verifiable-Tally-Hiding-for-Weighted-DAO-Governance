"use strict";

const crypto = require("crypto");
const { requireCondition } = require("./errors");
const { PROTOCOL_VERSION } = require("./group_oracle");
const { validateCiphertext, encodeCiphertext, ciphertextHash } = require("./elgamal");

const AUTHORIZATION_DOMAIN = "-CGY-TOOLBOX-FULL-V1/DECRYPTION-AUTHORIZATION/V1";
const TOKEN = Symbol("validation-state-token");

function u32be(value) {
  const output = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return output;
}

function u64be(value, label) {
  const n = typeof value === "bigint" ? value : BigInt(value);
  requireCondition(n >= 0n && n <= 0xffffffffffffffffn, "E_CONTEXT_U64", `${label} is outside uint64 range`);
  const output = Buffer.alloc(8);
  output.writeBigUInt64BE(n);
  return output;
}

function lp(value) {
  const bytes = Buffer.from(value);
  return Buffer.concat([u32be(bytes.length), bytes]);
}

function validateHex32(value, label) {
  requireCondition(typeof value === "string" && /^[0-9a-f]{64}$/.test(value), "E_CONTEXT_HASH", `${label} must be lowercase 32-byte hexadecimal`);
  return value;
}

function validateExecutionContext(context) {
  requireCondition(context && typeof context === "object", "E_EXECUTION_CONTEXT", "execution context is missing");
  const expected = ["protocolVersion", "setupHash", "executionId", "gateId", "invocation", "phase", "purpose"];
  const keys = Object.keys(context);
  requireCondition(keys.length === expected.length && expected.every((key, index) => keys[index] === key), "E_EXECUTION_CONTEXT_FIELDS", "execution context fields or order are noncanonical");
  requireCondition(context.protocolVersion === PROTOCOL_VERSION, "E_PROTOCOL_VERSION", "execution context protocol mismatch");
  validateHex32(context.setupHash, "setupHash");
  validateHex32(context.executionId, "executionId");
  requireCondition(typeof context.phase === "string" && /^[A-Z][A-Z0-9_]*$/.test(context.phase), "E_CONTEXT_PHASE", "phase is noncanonical");
  requireCondition(["CGY_GATE_SELECTOR", "FINAL_DECISION"].includes(context.purpose), "E_CONTEXT_PURPOSE", "unauthorized decryption purpose");
  u64be(context.gateId, "gateId");
  u64be(context.invocation, "invocation");
  return Object.freeze({ ...context });
}

function encodeExecutionContext(context) {
  const checked = validateExecutionContext(context);
  return Buffer.concat([
    lp(Buffer.from(checked.protocolVersion, "utf8")),
    Buffer.from(checked.setupHash, "hex"),
    Buffer.from(checked.executionId, "hex"),
    u64be(checked.gateId, "gateId"),
    u64be(checked.invocation, "invocation"),
    lp(Buffer.from(checked.phase, "utf8")),
    lp(Buffer.from(checked.purpose, "utf8")),
  ]);
}

function authorizationId(context, value) {
  return crypto.createHash("sha256")
    .update(lp(Buffer.from(AUTHORIZATION_DOMAIN, "utf8")))
    .update(encodeExecutionContext(context))
    .update(encodeCiphertext(value))
    .digest("hex");
}

class Received {
  constructor(token, value, context, evidence) {
    requireCondition(token === TOKEN, "E_STATE_CONSTRUCTION", "Received is opaque");
    this.ciphertext = value;
    this.context = context;
    this.receiptEvidence = evidence;
    Object.freeze(this);
  }
}
class ProofValidated {
  constructor(token, prior, evidence) {
    requireCondition(token === TOKEN, "E_STATE_CONSTRUCTION", "ProofValidated is opaque");
    this.prior = prior;
    this.ciphertext = prior.ciphertext;
    this.context = prior.context;
    this.proofEvidence = evidence;
    Object.freeze(this);
  }
}
class BroadcastAgreed {
  constructor(token, prior, evidence) {
    requireCondition(token === TOKEN, "E_STATE_CONSTRUCTION", "BroadcastAgreed is opaque");
    this.prior = prior;
    this.ciphertext = prior.ciphertext;
    this.context = prior.context;
    this.broadcastEvidence = evidence;
    Object.freeze(this);
  }
}
class RerandomizationValidated {
  constructor(token, prior, rerandomized, evidence) {
    requireCondition(token === TOKEN, "E_STATE_CONSTRUCTION", "RerandomizationValidated is opaque");
    this.prior = prior;
    this.ciphertext = rerandomized;
    this.context = prior.context;
    this.rerandomizationEvidence = evidence;
    Object.freeze(this);
  }
}
class AuthorizedForDecryption {
  constructor(token, prior, policyEvidence) {
    requireCondition(token === TOKEN, "E_STATE_CONSTRUCTION", "AuthorizedForDecryption is opaque");
    this.prior = prior;
    this.ciphertext = prior.ciphertext;
    this.context = prior.context;
    this.policyEvidence = policyEvidence;
    this.authorizationId = authorizationId(this.context, this.ciphertext);
    this.ciphertextHash = ciphertextHash(this.ciphertext);
    Object.freeze(this);
  }
}
class PartialShare {
  constructor(token, authorization, payload) {
    requireCondition(token === TOKEN, "E_STATE_CONSTRUCTION", "PartialShare is opaque");
    this.authorizationId = authorization.authorizationId;
    this.context = authorization.context;
    this.ciphertextHash = authorization.ciphertextHash;
    this.payload = payload;
    Object.freeze(this);
  }
}

function receive(value, context, receiptEvidence) {
  requireCondition(receiptEvidence && typeof receiptEvidence === "object", "E_RECEIPT_EVIDENCE", "receipt evidence is required");
  return new Received(TOKEN, validateCiphertext(value), validateExecutionContext(context), Object.freeze({ ...receiptEvidence }));
}

function markProofValidated(received, proofEvidence) {
  requireCondition(received instanceof Received, "E_STATE_PROOF_INPUT", "proof validation requires Received");
  requireCondition(proofEvidence && proofEvidence.valid === true, "E_PROOF_INVALID", "proof validation failed");
  return new ProofValidated(TOKEN, received, Object.freeze({ ...proofEvidence }));
}

function markBroadcastAgreed(validated, broadcastEvidence) {
  requireCondition(validated instanceof ProofValidated, "E_STATE_BROADCAST_INPUT", "broadcast agreement requires ProofValidated");
  requireCondition(broadcastEvidence && broadcastEvidence.agreed === true, "E_BROADCAST_NOT_AGREED", "canonical broadcast view not agreed");
  return new BroadcastAgreed(TOKEN, validated, Object.freeze({ ...broadcastEvidence }));
}

function markRerandomizationValidated(agreed, rerandomized, rerandomizationEvidence) {
  requireCondition(agreed instanceof BroadcastAgreed, "E_STATE_RERANDOMIZATION_INPUT", "rerandomization validation requires BroadcastAgreed");
  requireCondition(rerandomizationEvidence && rerandomizationEvidence.valid === true, "E_RERANDOMIZATION_INVALID", "rerandomization proof failed");
  return new RerandomizationValidated(TOKEN, agreed, validateCiphertext(rerandomized), Object.freeze({ ...rerandomizationEvidence }));
}

function authorizeForDecryption(validated, policyEvidence) {
  requireCondition(validated instanceof RerandomizationValidated, "E_STATE_AUTHORIZATION_INPUT", "decryption authorization requires RerandomizationValidated");
  requireCondition(policyEvidence && policyEvidence.authorized === true, "E_DECRYPTION_POLICY", "decryption purpose is not authorized");
  return new AuthorizedForDecryption(TOKEN, validated, Object.freeze({ ...policyEvidence }));
}

function emitPartialShare(authorization, payload) {
  requireCondition(authorization instanceof AuthorizedForDecryption, "E_STATE_PARTIAL_INPUT", "partial share requires AuthorizedForDecryption");
  return new PartialShare(TOKEN, authorization, Object.freeze(payload));
}

function isAuthorizedForDecryption(value) {
  return value instanceof AuthorizedForDecryption;
}

function isPartialShare(value) {
  return value instanceof PartialShare;
}

module.exports = Object.freeze({
  AUTHORIZATION_DOMAIN,
  validateExecutionContext,
  encodeExecutionContext,
  authorizationId,
  receive,
  markProofValidated,
  markBroadcastAgreed,
  markRerandomizationValidated,
  authorizeForDecryption,
  emitPartialShare,
  isAuthorizedForDecryption,
  isPartialShare,
});
