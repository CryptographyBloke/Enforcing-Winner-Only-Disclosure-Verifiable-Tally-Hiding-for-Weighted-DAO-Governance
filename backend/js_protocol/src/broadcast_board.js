"use strict";

const crypto = require("crypto");
const { ProtocolError, requireCondition } = require("./errors");
const { PROTOCOL_VERSION } = require("./group_oracle");

const BOARD_DOMAIN = "-CGY-TOOLBOX-FULL-V1/CANONICAL-ATOMIC-BOARD/V1";
const SLOT_DOMAIN = "-CGY-TOOLBOX-FULL-V1/BROADCAST-SLOT/V1";

class BoardAbort extends ProtocolError {
  constructor(code, message) {
    super(code, message);
    this.name = "BoardAbort";
  }
}

function u32be(value) {
  requireCondition(Number.isInteger(value) && value >= 0 && value <= 0xffffffff, "E_BOARD_U32", "value is outside uint32 range");
  const output = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return output;
}

function u64be(value, label) {
  const n = typeof value === "bigint" ? value : BigInt(value);
  requireCondition(n >= 0n && n <= 0xffffffffffffffffn, "E_BOARD_U64", `${label} is outside uint64 range`);
  const output = Buffer.alloc(8);
  output.writeBigUInt64BE(n);
  return output;
}

function lp(value) {
  const bytes = Buffer.from(value);
  return Buffer.concat([u32be(bytes.length), bytes]);
}

function canonicalHex32(value, label) {
  requireCondition(typeof value === "string" && /^[0-9a-f]{64}$/.test(value), "E_BOARD_HASH", `${label} must be lowercase 32-byte hexadecimal`);
  return value;
}

function canonicalPhase(value) {
  requireCondition(typeof value === "string" && /^[A-Z][A-Z0-9_]*$/.test(value), "E_BOARD_PHASE", "phase is noncanonical");
  return value;
}

function canonicalSlot(slot) {
  requireCondition(slot && typeof slot === "object", "E_BOARD_SLOT", "slot is missing");
  const expected = ["protocolVersion", "setupHash", "executionId", "gateId", "invocation", "phase", "trusteeId"];
  const keys = Object.keys(slot);
  requireCondition(keys.length === expected.length && expected.every((key, index) => keys[index] === key), "E_BOARD_SLOT_FIELDS", "slot fields or order are noncanonical");
  requireCondition(slot.protocolVersion === PROTOCOL_VERSION, "E_BOARD_PROTOCOL", "slot protocol version mismatch");
  canonicalHex32(slot.setupHash, "setupHash");
  canonicalHex32(slot.executionId, "executionId");
  canonicalPhase(slot.phase);
  const gateId = typeof slot.gateId === "bigint" ? slot.gateId : BigInt(slot.gateId);
  const invocation = typeof slot.invocation === "bigint" ? slot.invocation : BigInt(slot.invocation);
  u64be(gateId, "gateId");
  u64be(invocation, "invocation");
  requireCondition(Number.isInteger(slot.trusteeId) && slot.trusteeId > 0, "E_TRUSTEE_ID", "trustee identity must be positive");
  return Object.freeze({
    protocolVersion: slot.protocolVersion,
    setupHash: slot.setupHash,
    executionId: slot.executionId,
    gateId,
    invocation,
    phase: slot.phase,
    trusteeId: slot.trusteeId,
  });
}

function encodeSlot(slot) {
  const checked = canonicalSlot(slot);
  return Buffer.concat([
    lp(Buffer.from(SLOT_DOMAIN, "utf8")),
    lp(Buffer.from(checked.protocolVersion, "utf8")),
    Buffer.from(checked.setupHash, "hex"),
    Buffer.from(checked.executionId, "hex"),
    u64be(checked.gateId, "gateId"),
    u64be(checked.invocation, "invocation"),
    lp(Buffer.from(checked.phase, "utf8")),
    u32be(checked.trusteeId),
  ]);
}

function payloadHash(payload) {
  return crypto.createHash("sha256").update(Buffer.from(payload)).digest("hex");
}

function signedMessage(slot, payload) {
  const bytes = Buffer.from(payload);
  return Buffer.concat([encodeSlot(slot), u32be(bytes.length), bytes]);
}

function createTrusteeAuthenticationRegistry(trustees) {
  requireCondition(Number.isInteger(trustees) && trustees >= 1, "E_TRUSTEE_COUNT", "trustee count must be positive");
  const publicKeys = [];
  const privateKeys = [];
  for (let trusteeId = 1; trusteeId <= trustees; trusteeId += 1) {
    const pair = crypto.generateKeyPairSync("ed25519");
    publicKeys.push(Object.freeze({ trusteeId, publicKey: pair.publicKey }));
    privateKeys.push(Object.freeze({ trusteeId, privateKey: pair.privateKey }));
  }
  return Object.freeze({ publicKeys: Object.freeze(publicKeys), privateKeys: Object.freeze(privateKeys) });
}

function signSubmission(privateKey, slot, payload) {
  return crypto.sign(null, signedMessage(slot, payload), privateKey);
}

function phaseKey(gateId, invocation, phase) {
  return `${BigInt(gateId).toString(10)}:${BigInt(invocation).toString(10)}:${phase}`;
}

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    requireCondition(Number.isSafeInteger(value), "E_CANONICAL_JSON_NUMBER", "canonical JSON number must be a safe integer");
    return JSON.stringify(value);
  }
  if (typeof value === "bigint") return JSON.stringify(value.toString(10));
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  requireCondition(value && typeof value === "object", "E_CANONICAL_JSON", "unsupported canonical JSON value");
  return `{${Object.keys(value).map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

class CanonicalAtomicBroadcastBoard {
  constructor({ setupHash, executionId, trusteePublicKeys }) {
    this.protocolVersion = PROTOCOL_VERSION;
    this.setupHash = canonicalHex32(setupHash, "setupHash");
    this.executionId = canonicalHex32(executionId, "executionId");
    requireCondition(Array.isArray(trusteePublicKeys) && trusteePublicKeys.length > 0, "E_BOARD_AUTH_REGISTRY", "trustee authentication registry is empty");
    this.trusteePublicKeys = new Map();
    for (let index = 0; index < trusteePublicKeys.length; index += 1) {
      const entry = trusteePublicKeys[index];
      requireCondition(entry.trusteeId === index + 1, "E_BOARD_AUTH_ORDER", "trustee authentication keys must be ordered 1..a");
      requireCondition(!this.trusteePublicKeys.has(entry.trusteeId), "E_DUPLICATE_TRUSTEE", "duplicate authentication identity");
      this.trusteePublicKeys.set(entry.trusteeId, entry.publicKey);
    }
    this.trustees = trusteePublicKeys.length;
    this.phases = new Map();
    this.status = "OPEN";
    this.abortRecord = null;
  }

  definePhase({ gateId, invocation, phase, dependsOnPhase = null, requiredTrusteeIds = null }) {
    requireCondition(this.status === "OPEN", "E_BOARD_ABORTED", "board is aborted");
    const normalizedPhase = canonicalPhase(phase);
    const gate = BigInt(gateId);
    const invoke = BigInt(invocation);
    u64be(gate, "gateId");
    u64be(invoke, "invocation");
    if (dependsOnPhase !== null) canonicalPhase(dependsOnPhase);
    const required = requiredTrusteeIds === null
      ? Array.from({ length: this.trustees }, (_, index) => index + 1)
      : Array.from(requiredTrusteeIds);
    requireCondition(required.length > 0, "E_PHASE_PARTICIPANTS", "phase requires at least one trustee");
    requireCondition(new Set(required).size === required.length, "E_DUPLICATE_TRUSTEE", "duplicate required trustee identity");
    required.forEach((trusteeId, index) => {
      requireCondition(Number.isInteger(trusteeId) && trusteeId >= 1 && trusteeId <= this.trustees, "E_TRUSTEE_ID", "required trustee is not registered");
      requireCondition(index === 0 || required[index - 1] < trusteeId, "E_PHASE_PARTICIPANT_ORDER", "required trustee identities must be strictly ordered");
    });
    const key = phaseKey(gate, invoke, normalizedPhase);
    requireCondition(!this.phases.has(key), "E_PHASE_DUPLICATE", "phase already defined");
    this.phases.set(key, {
      gateId: gate,
      invocation: invoke,
      phase: normalizedPhase,
      dependsOnPhase,
      requiredTrusteeIds: Object.freeze(required),
      status: "STAGING",
      submissions: new Map(),
      sealedVector: null,
    });
  }

  #checkBoardSlot(slot) {
    const checked = canonicalSlot(slot);
    requireCondition(checked.setupHash === this.setupHash && checked.executionId === this.executionId, "E_BOARD_CONTEXT", "slot belongs to a stale or different setup/execution");
    requireCondition(checked.trusteeId <= this.trustees && this.trusteePublicKeys.has(checked.trusteeId), "E_TRUSTEE_ID", "slot trustee is not registered");
    return checked;
  }

  #getPhase(slot) {
    const key = phaseKey(slot.gateId, slot.invocation, slot.phase);
    const phase = this.phases.get(key);
    requireCondition(phase, "E_PHASE_UNKNOWN", "broadcast phase is not defined");
    return phase;
  }

  #dependencyStatus(phase) {
    if (phase.dependsOnPhase === null) return "READY";
    const dependency = this.phases.get(phaseKey(phase.gateId, phase.invocation, phase.dependsOnPhase));
    requireCondition(dependency, "E_PHASE_DEPENDENCY", "phase dependency is not defined");
    return dependency.status === "SEALED" ? "READY" : "WAIT";
  }

  submit({ slot, payload, signature }) {
    if (this.status === "ABORTED") throw new BoardAbort("E_BOARD_ABORTED", this.abortRecord.code);
    const checkedSlot = this.#checkBoardSlot(slot);
    const phase = this.#getPhase(checkedSlot);
    requireCondition(phase.requiredTrusteeIds.includes(checkedSlot.trusteeId), "E_PHASE_TRUSTEE", "trustee has no slot in this phase");
    if (this.#dependencyStatus(phase) === "WAIT") {
      return Object.freeze({ status: "WAIT", code: "WAIT_COMMIT_BARRIER" });
    }
    requireCondition(phase.status === "STAGING", "E_PHASE_SEALED", "phase is already sealed");
    const bytes = Buffer.from(payload);
    requireCondition(bytes.length > 0, "E_PAYLOAD_EMPTY", "broadcast payload must be nonempty");
    const publicKey = this.trusteePublicKeys.get(checkedSlot.trusteeId);
    requireCondition(Buffer.isBuffer(signature) || signature instanceof Uint8Array, "E_SIGNATURE_ENCODING", "signature is missing");
    requireCondition(crypto.verify(null, signedMessage(checkedSlot, bytes), publicKey, Buffer.from(signature)), "E_TRUSTEE_AUTH", "trustee signature verification failed");

    const existing = phase.submissions.get(checkedSlot.trusteeId);
    if (existing) {
      if (existing.payload.equals(bytes)) return Object.freeze({ status: "STAGED", idempotent: true });
      this.status = "ABORTED";
      this.abortRecord = Object.freeze({
        code: "ABORT_EQUIVOCATION",
        gateId: checkedSlot.gateId,
        invocation: checkedSlot.invocation,
        phase: checkedSlot.phase,
        trusteeId: checkedSlot.trusteeId,
        firstPayloadHash: payloadHash(existing.payload),
        secondPayloadHash: payloadHash(bytes),
      });
      throw new BoardAbort("ABORT_EQUIVOCATION", `trustee ${checkedSlot.trusteeId} wrote a conflicting payload`);
    }

    phase.submissions.set(checkedSlot.trusteeId, Object.freeze({
      slot: checkedSlot,
      payload: Buffer.from(bytes),
      signature: Buffer.from(signature),
    }));
    if (phase.submissions.size === phase.requiredTrusteeIds.length) {
      phase.sealedVector = Object.freeze(phase.requiredTrusteeIds.map((trusteeId) => phase.submissions.get(trusteeId)));
      phase.status = "SEALED";
      return Object.freeze({ status: "SEALED", idempotent: false });
    }
    return Object.freeze({ status: "STAGED", idempotent: false });
  }

  readPhase({ gateId, invocation, phase }) {
    if (this.status === "ABORTED") return Object.freeze({ status: "ABORT", record: this.abortRecord });
    const record = this.phases.get(phaseKey(gateId, invocation, canonicalPhase(phase)));
    requireCondition(record, "E_PHASE_UNKNOWN", "broadcast phase is not defined");
    if (record.status !== "SEALED") {
      const missingTrustees = [];
      for (const trusteeId of record.requiredTrusteeIds) {
        if (!record.submissions.has(trusteeId)) missingTrustees.push(trusteeId);
      }
      return Object.freeze({ status: "WAIT", missingTrustees: Object.freeze(missingTrustees) });
    }
    return Object.freeze({
      status: "SEALED",
      vector: Object.freeze(record.sealedVector.map((entry) => Object.freeze({
        trusteeId: entry.slot.trusteeId,
        payload: Buffer.from(entry.payload),
      }))),
    });
  }

  exportTranscript() {
    const phases = Array.from(this.phases.values()).sort((left, right) => {
      if (left.gateId !== right.gateId) return left.gateId < right.gateId ? -1 : 1;
      if (left.invocation !== right.invocation) return left.invocation < right.invocation ? -1 : 1;
      return left.phase.localeCompare(right.phase);
    }).map((phase) => ({
      gateId: phase.gateId.toString(10),
      invocation: phase.invocation.toString(10),
      phase: phase.phase,
      dependsOnPhase: phase.dependsOnPhase,
      requiredTrusteeIds: phase.requiredTrusteeIds,
      status: phase.status,
      submissions: Array.from(phase.submissions.values()).sort((a, b) => a.slot.trusteeId - b.slot.trusteeId).map((entry) => ({
        trusteeId: entry.slot.trusteeId,
        payloadHex: entry.payload.toString("hex"),
        payloadHash: payloadHash(entry.payload),
        signatureBase64: entry.signature.toString("base64"),
      })),
    }));
    const transcript = {
      schema: BOARD_DOMAIN,
      protocolVersion: this.protocolVersion,
      setupHash: this.setupHash,
      executionId: this.executionId,
      trustees: this.trustees,
      trusteePublicKeys: Array.from(this.trusteePublicKeys.entries()).map(([trusteeId, key]) => ({
        trusteeId,
        publicKeyDerBase64: key.export({ type: "spki", format: "der" }).toString("base64"),
      })),
      status: this.status,
      abortRecord: this.abortRecord === null ? null : {
        ...this.abortRecord,
        gateId: this.abortRecord.gateId.toString(10),
        invocation: this.abortRecord.invocation.toString(10),
      },
      phases,
    };
    const canonical = canonicalJson(transcript);
    return Object.freeze({ transcript: Object.freeze(transcript), canonical, transcriptHash: crypto.createHash("sha256").update(canonical).digest("hex") });
  }
}

function verifyBroadcastTranscript(exported) {
  requireCondition(exported && typeof exported === "object", "E_TRANSCRIPT", "broadcast transcript is missing");
  const canonical = canonicalJson(exported.transcript);
  requireCondition(canonical === exported.canonical, "E_TRANSCRIPT_CANONICAL", "broadcast transcript canonical bytes mismatch");
  requireCondition(crypto.createHash("sha256").update(canonical).digest("hex") === exported.transcriptHash, "E_TRANSCRIPT_HASH", "broadcast transcript hash mismatch");
  const transcript = exported.transcript;
  requireCondition(transcript.schema === BOARD_DOMAIN && transcript.protocolVersion === PROTOCOL_VERSION, "E_TRANSCRIPT_SCHEMA", "broadcast transcript schema mismatch");
  canonicalHex32(transcript.setupHash, "setupHash");
  canonicalHex32(transcript.executionId, "executionId");
  requireCondition(Array.isArray(transcript.trusteePublicKeys) && transcript.trusteePublicKeys.length === transcript.trustees, "E_TRANSCRIPT_AUTH", "authentication registry mismatch");
  const keys = new Map();
  transcript.trusteePublicKeys.forEach((entry, index) => {
    requireCondition(entry.trusteeId === index + 1, "E_TRANSCRIPT_AUTH_ORDER", "authentication registry order mismatch");
    keys.set(entry.trusteeId, crypto.createPublicKey({ key: Buffer.from(entry.publicKeyDerBase64, "base64"), type: "spki", format: "der" }));
  });
  let priorPhaseSortKey = null;
  const phaseStatus = new Map();
  for (const phase of transcript.phases) {
    const sortKey = `${BigInt(phase.gateId).toString(16).padStart(16, "0")}:${BigInt(phase.invocation).toString(16).padStart(16, "0")}:${phase.phase}`;
    requireCondition(priorPhaseSortKey === null || priorPhaseSortKey < sortKey, "E_TRANSCRIPT_PHASE_ORDER", "phases are not canonically ordered");
    priorPhaseSortKey = sortKey;
    canonicalPhase(phase.phase);
    requireCondition(["STAGING", "SEALED"].includes(phase.status), "E_TRANSCRIPT_PHASE_STATUS", "invalid phase status");
    requireCondition(Array.isArray(phase.requiredTrusteeIds) && phase.requiredTrusteeIds.length > 0, "E_TRANSCRIPT_PARTICIPANTS", "phase participant set is missing");
    phase.requiredTrusteeIds.forEach((trusteeId, index) => {
      requireCondition(Number.isInteger(trusteeId) && trusteeId >= 1 && trusteeId <= transcript.trustees, "E_TRANSCRIPT_TRUSTEE", "phase requires an unregistered trustee");
      requireCondition(index === 0 || phase.requiredTrusteeIds[index - 1] < trusteeId, "E_TRANSCRIPT_PARTICIPANT_ORDER", "phase participant set is not canonical");
    });
    if (phase.status === "SEALED") requireCondition(phase.submissions.length === phase.requiredTrusteeIds.length, "E_TRANSCRIPT_BARRIER", "sealed phase is incomplete");
    if (phase.status === "STAGING") requireCondition(phase.submissions.length < phase.requiredTrusteeIds.length, "E_TRANSCRIPT_BARRIER", "complete phase was not sealed");
    let priorTrusteeId = 0;
    for (const submission of phase.submissions) {
      requireCondition(submission.trusteeId === priorTrusteeId + 1 || submission.trusteeId > priorTrusteeId, "E_TRANSCRIPT_TRUSTEE_ORDER", "submissions are not in trustee order");
      priorTrusteeId = submission.trusteeId;
      const payload = Buffer.from(submission.payloadHex, "hex");
      requireCondition(payload.toString("hex") === submission.payloadHex && payloadHash(payload) === submission.payloadHash, "E_TRANSCRIPT_PAYLOAD", "payload encoding or hash mismatch");
      const slot = {
        protocolVersion: transcript.protocolVersion,
        setupHash: transcript.setupHash,
        executionId: transcript.executionId,
        gateId: BigInt(phase.gateId),
        invocation: BigInt(phase.invocation),
        phase: phase.phase,
        trusteeId: submission.trusteeId,
      };
      requireCondition(keys.has(submission.trusteeId), "E_TRANSCRIPT_TRUSTEE", "submission trustee is unregistered");
      requireCondition(phase.requiredTrusteeIds.includes(submission.trusteeId), "E_TRANSCRIPT_PHASE_TRUSTEE", "submission trustee has no phase slot");
      requireCondition(crypto.verify(null, signedMessage(slot, payload), keys.get(submission.trusteeId), Buffer.from(submission.signatureBase64, "base64")), "E_TRANSCRIPT_SIGNATURE", "submission signature failed");
    }
    const submittedIds = phase.submissions.map((submission) => submission.trusteeId);
    const expectedSubmittedIds = phase.requiredTrusteeIds.filter((trusteeId) => submittedIds.includes(trusteeId));
    requireCondition(submittedIds.length === expectedSubmittedIds.length && submittedIds.every((trusteeId, index) => trusteeId === expectedSubmittedIds[index]), "E_TRANSCRIPT_TRUSTEE_ORDER", "submissions do not follow the required trustee subset");
    const key = phaseKey(BigInt(phase.gateId), BigInt(phase.invocation), phase.phase);
    phaseStatus.set(key, phase.status);
  }
  for (const phase of transcript.phases) {
    if (phase.dependsOnPhase !== null && phase.submissions.length > 0) {
      const dependencyKey = phaseKey(BigInt(phase.gateId), BigInt(phase.invocation), phase.dependsOnPhase);
      requireCondition(phaseStatus.get(dependencyKey) === "SEALED", "E_TRANSCRIPT_DEPENDENCY", "dependent phase contains submissions before sealed prerequisite");
    }
  }
  if (transcript.status === "ABORTED") requireCondition(transcript.abortRecord && transcript.abortRecord.code === "ABORT_EQUIVOCATION", "E_TRANSCRIPT_ABORT", "invalid abort record");
  else requireCondition(transcript.status === "OPEN" && transcript.abortRecord === null, "E_TRANSCRIPT_STATUS", "invalid board status");
  return Object.freeze({ valid: true, transcriptHash: exported.transcriptHash });
}

module.exports = Object.freeze({
  BOARD_DOMAIN,
  SLOT_DOMAIN,
  BoardAbort,
  canonicalSlot,
  encodeSlot,
  payloadHash,
  signedMessage,
  createTrusteeAuthenticationRegistry,
  signSubmission,
  CanonicalAtomicBroadcastBoard,
  verifyBroadcastTranscript,
  canonicalJson,
});
