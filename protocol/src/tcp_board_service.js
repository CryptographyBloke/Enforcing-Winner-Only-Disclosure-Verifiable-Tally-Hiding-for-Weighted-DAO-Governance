"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");
const {
  BoardAbort,
  CanonicalAtomicBroadcastBoard,
  canonicalJson,
  payloadHash,
  verifyBroadcastTranscript,
} = require("./broadcast_board");

const DEFAULT_MAX_FRAME_BYTES = 8 * 1024 * 1024;

function phaseKey(phase) {
  return `${BigInt(phase.gateId).toString(10)}/${BigInt(phase.invocation).toString(10)}/${phase.phase}`;
}

function sha256(text) {
  return crypto.createHash("sha256").update(text).digest("hex");
}

function delay(milliseconds) {
  return milliseconds <= 0 ? Promise.resolve() : new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function frame(value) {
  return Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
}

class TcpBoardService {
  constructor(config) {
    if (!config || typeof config !== "object") throw new TypeError("E_TCP_CONFIG: service config is required");
    this.config = config;
    this.setupHash = config.setupHash;
    this.executionId = config.executionId;
    this.trusteePublicKeys = config.trusteePublicKeys.map((entry) => ({
      trusteeId: entry.trusteeId,
      publicKey: crypto.createPublicKey({
        key: Buffer.from(entry.publicKeyDerBase64, "base64"),
        type: "spki",
        format: "der",
      }),
    }));
    this.phasePlan = config.phasePlan;
    this.expectedTrustees = Number(config.expectedTrustees || 5);
    this.oneWayDelayMs = Number(config.oneWayDelayMs || 0);
    this.phaseTimeoutMs = Number(config.phaseTimeoutMs || 120000);
    this.startupTimeoutMs = Number(config.startupTimeoutMs || 30000);
    this.maxFrameBytes = Number(config.maxFrameBytes || DEFAULT_MAX_FRAME_BYTES);
    this.eventLogPath = path.resolve(config.eventLogPath);
    this.exportPath = path.resolve(config.exportPath);
    this.summaryPath = path.resolve(config.summaryPath);
    this.connections = new Set();
    this.trusteeConnections = new Map();
    this.readyTrustees = new Set();
    this.finishedTrustees = new Set();
    this.server = null;
    this.board = null;
    this.phaseIndex = 0;
    this.phaseTimer = null;
    this.startupTimer = null;
    this.runStartedAt = null;
    this.lastPhaseSealAt = null;
    this.phaseTimings = [];
    this.phaseSubmissions = new Map();
    this.error = null;
    this.completed = false;
    this.finishWaiters = [];
    this.logFd = null;
    this.metrics = {
      tcpApplicationBytesIn: 0,
      tcpApplicationBytesOut: 0,
      applicationFramesIn: 0,
      applicationFramesOut: 0,
      submissionsReceived: 0,
      submissionsAccepted: 0,
      payloadBytes: 0,
      signatureBytes: 0,
      signatureVerificationMs: 0,
      durableLogBytes: 0,
      durableLogSyncMs: 0,
    };
    this.publicKeysById = new Map(this.trusteePublicKeys.map((entry) => [entry.trusteeId, entry.publicKey]));
  }

  _newBoard() {
    return new CanonicalAtomicBroadcastBoard({
      setupHash: this.setupHash,
      executionId: this.executionId,
      trusteePublicKeys: this.trusteePublicKeys,
    });
  }

  _appendLog(event) {
    const bytes = frame(event);
    fs.writeSync(this.logFd, bytes);
    const syncStarted = process.hrtime.bigint();
    fs.fsyncSync(this.logFd);
    this.metrics.durableLogSyncMs += Number(process.hrtime.bigint() - syncStarted) / 1e6;
    this.metrics.durableLogBytes += bytes.length;
  }

  _applySubmission(event, isAbort = false) {
    const payload = Buffer.from(event.payloadHex, "hex");
    const signature = Buffer.from(event.signatureBase64, "base64");
    try {
      const result = this.board.submit({ slot: event.slot, payload, signature });
      if (isAbort) throw new Error("E_TCP_LOG_ABORT: persisted abort did not abort the board");
      if (!result.idempotent) this._rememberSubmission(event, payload, signature);
      return result;
    } catch (error) {
      if (isAbort && error instanceof BoardAbort && error.code === "ABORT_EQUIVOCATION") return null;
      throw error;
    }
  }

  _rememberSubmission(event, payload, signature) {
    const key = phaseKey(event.slot);
    if (!this.phaseSubmissions.has(key)) this.phaseSubmissions.set(key, new Map());
    const entries = this.phaseSubmissions.get(key);
    if (!entries.has(event.slot.trusteeId)) entries.set(event.slot.trusteeId, {
      trusteeId: event.slot.trusteeId,
      payload,
      signature,
    });
  }

  _initializeLog() {
    fs.mkdirSync(path.dirname(this.eventLogPath), { recursive: true });
    this.board = this._newBoard();
    const configEvent = {
      type: "RUN_CONFIG",
      digest: sha256(canonicalJson({
        setupHash: this.setupHash,
        executionId: this.executionId,
        expectedTrustees: this.expectedTrustees,
        phasePlan: this.phasePlan,
      })),
    };
    if (!fs.existsSync(this.eventLogPath)) {
      this.logFd = fs.openSync(this.eventLogPath, "wx");
      const initialEvents = [configEvent];
      for (const phase of this.phasePlan) {
        this.board.definePhase(phase);
        initialEvents.push({ type: "DEFINE_PHASE", phase });
      }
      const initialBytes = Buffer.concat(initialEvents.map(frame));
      fs.writeSync(this.logFd, initialBytes);
      const syncStarted = process.hrtime.bigint();
      fs.fsyncSync(this.logFd);
      this.metrics.durableLogSyncMs += Number(process.hrtime.bigint() - syncStarted) / 1e6;
      this.metrics.durableLogBytes += initialBytes.length;
      return;
    }

    const raw = fs.readFileSync(this.eventLogPath, "utf8");
    if (raw.length !== 0 && !raw.endsWith("\n")) throw new Error("E_TCP_LOG_TRUNCATED: event log does not end on a frame boundary");
    const events = raw.split("\n").filter(Boolean).map((line) => JSON.parse(line));
    if (!events.length || canonicalJson(events[0]) !== canonicalJson(configEvent)) {
      throw new Error("E_TCP_LOG_CONFIG: event log belongs to another experiment configuration");
    }
    let phaseOffset = 0;
    for (const event of events.slice(1)) {
      if (event.type === "DEFINE_PHASE") {
        const expected = this.phasePlan[phaseOffset++];
        if (!expected || canonicalJson(expected) !== canonicalJson(event.phase)) throw new Error("E_TCP_LOG_PHASE: persisted phase plan differs from config");
        this.board.definePhase(event.phase);
      } else if (event.type === "SUBMIT") {
        this._applySubmission(event);
      } else if (event.type === "ABORT_EQUIVOCATION") {
        this._applySubmission(event, true);
      } else {
        throw new Error(`E_TCP_LOG_EVENT: unsupported event ${event.type}`);
      }
    }
    if (phaseOffset !== this.phasePlan.length) throw new Error("E_TCP_LOG_PHASE: persisted phase plan is incomplete");
    this.phaseIndex = this.phasePlan.findIndex((phase) => this.board.readPhase(phase).status !== "SEALED");
    if (this.phaseIndex < 0) this.phaseIndex = this.phasePlan.length;
    this.logFd = fs.openSync(this.eventLogPath, "a");
  }

  _send(connection, value) {
    const bytes = frame(value);
    return delay(this.oneWayDelayMs).then(() => new Promise((resolve, reject) => {
      if (connection.socket.destroyed) return reject(new Error("E_TCP_CLIENT_CLOSED: client socket is closed"));
      this.metrics.tcpApplicationBytesOut += bytes.length;
      this.metrics.applicationFramesOut += 1;
      connection.socket.write(bytes, (error) => error ? reject(error) : resolve());
    }));
  }

  async _reply(connection, id, result) {
    await this._send(connection, { type: "RES", id, ok: true, result });
  }

  async _replyError(connection, id, error) {
    await this._send(connection, {
      type: "RES",
      id,
      ok: false,
      error: { code: error.code || "E_TCP_BOARD", message: String(error.message || error) },
    });
  }

  async _broadcast(value) {
    await Promise.all(Array.from(this.connections, (connection) => this._send(connection, value).catch(() => {})));
  }

  _phaseExport(phase) {
    const submissions = this.phaseSubmissions.get(phaseKey(phase));
    if (!submissions || submissions.size !== phase.requiredTrusteeIds.length) throw new Error("E_TCP_PHASE_EXPORT: sealed phase submission vector is incomplete");
    const record = {
      gateId: BigInt(phase.gateId).toString(10),
      invocation: BigInt(phase.invocation).toString(10),
      phase: phase.phase,
      dependsOnPhase: phase.dependsOnPhase,
      requiredTrusteeIds: phase.requiredTrusteeIds,
      status: "SEALED",
      submissions: phase.requiredTrusteeIds.map((trusteeId) => {
        const submission = submissions.get(trusteeId);
        if (!submission) throw new Error("E_TCP_PHASE_EXPORT: required trustee submission is missing");
        return {
          trusteeId,
          payloadHex: submission.payload.toString("hex"),
          payloadHash: payloadHash(submission.payload),
          signatureBase64: submission.signature.toString("base64"),
        };
      }),
    };
    return {
      phaseKey: phaseKey(record),
      phase: record,
      phaseDigest: sha256(canonicalJson(record)),
    };
  }

  _armPhaseTimeout() {
    clearTimeout(this.phaseTimer);
    if (this.phaseIndex >= this.phasePlan.length) return;
    this.phaseTimer = setTimeout(() => {
      this._abortRun(Object.assign(new Error(`phase timeout: ${phaseKey(this.phasePlan[this.phaseIndex])}`), { code: "E_TCP_PHASE_TIMEOUT" }));
    }, this.phaseTimeoutMs);
  }

  async _abortRun(error) {
    if (this.error || this.completed) return;
    this.error = { code: error.code || "E_TCP_RUN_ABORT", message: String(error.message || error) };
    clearTimeout(this.phaseTimer);
    clearTimeout(this.startupTimer);
    await this._broadcast({ type: "EVENT", event: "ABORT", error: this.error });
    for (const waiter of this.finishWaiters.splice(0)) await this._replyError(waiter.connection, waiter.id, error).catch(() => {});
    if (this.server) this.server.close();
    for (const connection of this.connections) connection.socket.destroy();
    this._closeLog();
    process.stderr.write(`BOARD_ABORT=${this.error.code}:${this.error.message}\n`);
  }

  _closeLog() {
    if (this.logFd !== null) {
      fs.closeSync(this.logFd);
      this.logFd = null;
    }
  }

  async _finalize() {
    if (this.completed) return;
    if (this.phaseIndex !== this.phasePlan.length || this.finishedTrustees.size !== this.expectedTrustees) {
      throw new Error("E_TCP_FINISH_GATE: run cannot finish before all phases and clients finish");
    }
    const exported = this.board.exportTranscript();
    verifyBroadcastTranscript(exported);
    fs.mkdirSync(path.dirname(this.exportPath), { recursive: true });
    fs.writeFileSync(this.exportPath, `${JSON.stringify(exported, null, 2)}\n`, { flag: "wx", encoding: "utf8" });
    const summary = {
      schema: "winner-only-disclosure/tcp-board-summary/v1",
      setupHash: this.setupHash,
      executionId: this.executionId,
      phaseCount: this.phasePlan.length,
      sealedPhaseCount: this.phaseIndex,
      trusteeCount: this.expectedTrustees,
      boardTranscriptHash: exported.transcriptHash,
      oneWayApplicationDelayMs: this.oneWayDelayMs,
      targetApplicationRttMs: this.oneWayDelayMs * 2,
      phaseTimings: this.phaseTimings,
      metrics: this.metrics,
      elapsedMs: this.runStartedAt === null ? null : Number(process.hrtime.bigint() - this.runStartedAt) / 1e6,
    };
    fs.writeFileSync(this.summaryPath, `${JSON.stringify(summary, null, 2)}\n`, { flag: "wx", encoding: "utf8" });
    this.completed = true;
    clearTimeout(this.phaseTimer);
    clearTimeout(this.startupTimer);
    await this._broadcast({ type: "EVENT", event: "RUN_COMPLETE", result: { transcriptHash: exported.transcriptHash, phaseCount: this.phaseIndex } });
    for (const waiter of this.finishWaiters.splice(0)) await this._reply(waiter.connection, waiter.id, { status: "RUN_COMPLETE", transcriptHash: exported.transcriptHash });
    if (this.server) this.server.close();
    this._closeLog();
  }

  async _handle(connection, request) {
    if (!request || request.type !== "REQ" || !Number.isSafeInteger(request.id) || typeof request.method !== "string") {
      throw Object.assign(new Error("malformed request frame"), { code: "E_TCP_FRAME" });
    }
    const { id, method, args = {} } = request;
    if (this.error) throw Object.assign(new Error(this.error.message), { code: this.error.code });
    await delay(this.oneWayDelayMs);
    if (method === "HELLO") {
      const trusteeId = Number(args.trusteeId);
      if (!Number.isInteger(trusteeId) || trusteeId < 1 || trusteeId > this.expectedTrustees || !this.publicKeysById.has(trusteeId)) {
        throw Object.assign(new Error("unregistered trustee identity"), { code: "E_TCP_TRUSTEE_ID" });
      }
      const existing = this.trusteeConnections.get(trusteeId);
      if (existing && existing !== connection) throw Object.assign(new Error("trustee already connected"), { code: "E_TCP_DUPLICATE_CLIENT" });
      connection.trusteeId = trusteeId;
      this.trusteeConnections.set(trusteeId, connection);
      await this._reply(connection, id, { status: "CONNECTED", trusteeId });
      if (this.trusteeConnections.size === this.expectedTrustees) {
        clearTimeout(this.startupTimer);
        await this._broadcast({ type: "EVENT", event: "CLIENTS_READY", trusteeCount: this.expectedTrustees });
      }
      return;
    }
    if (!Number.isInteger(connection.trusteeId)) throw Object.assign(new Error("HELLO is required first"), { code: "E_TCP_HELLO_REQUIRED" });
    if (method === "PING") {
      await this._reply(connection, id, { status: "PONG", serverUnixMs: Date.now() });
      return;
    }
    if (method === "READY_TO_RUN") {
      this.readyTrustees.add(connection.trusteeId);
      await this._reply(connection, id, { status: "READY" });
      if (this.readyTrustees.size === this.expectedTrustees && this.runStartedAt === null) {
        this.runStartedAt = process.hrtime.bigint();
        this.lastPhaseSealAt = this.runStartedAt;
        this._armPhaseTimeout();
        await this._broadcast({ type: "EVENT", event: "START", phaseCount: this.phasePlan.length });
      }
      return;
    }
    if (method === "SUBMIT") {
      this.metrics.submissionsReceived += 1;
      if (this.runStartedAt === null) throw Object.assign(new Error("run has not started"), { code: "E_TCP_NOT_STARTED" });
      const slot = args.slot;
      const phase = this.phasePlan[this.phaseIndex];
      if (!phase) throw Object.assign(new Error("all phases are already sealed"), { code: "E_TCP_RUN_COMPLETE" });
      if (phaseKey(slot) !== phaseKey(phase)) throw Object.assign(new Error("submission arrived outside the current canonical phase"), { code: "E_TCP_PHASE_ORDER" });
      if (slot.trusteeId !== connection.trusteeId) throw Object.assign(new Error("authenticated connection identity differs from signed slot"), { code: "E_TCP_TRUSTEE_BINDING" });
      const payload = Buffer.from(args.payloadHex || "", "hex");
      const signature = Buffer.from(args.signatureBase64 || "", "base64");
      if (payload.length === 0 || signature.length === 0) throw Object.assign(new Error("payload or signature is empty"), { code: "E_TCP_MESSAGE_ENCODING" });
      const event = { type: "SUBMIT", slot, payloadHex: payload.toString("hex"), signatureBase64: signature.toString("base64") };
      const verifyStarted = process.hrtime.bigint();
      let result;
      try {
        result = this.board.submit({ slot, payload, signature });
      } catch (error) {
        this.metrics.signatureVerificationMs += Number(process.hrtime.bigint() - verifyStarted) / 1e6;
        if (error instanceof BoardAbort && error.code === "ABORT_EQUIVOCATION") {
          this._appendLog({ ...event, type: "ABORT_EQUIVOCATION" });
          await this._abortRun(error);
        }
        throw error;
      }
      this.metrics.signatureVerificationMs += Number(process.hrtime.bigint() - verifyStarted) / 1e6;
      if (!result.idempotent) this._rememberSubmission(event, payload, signature);
      this.metrics.payloadBytes += payload.length;
      this.metrics.signatureBytes += signature.length;
      this._appendLog(event);
      this.metrics.submissionsAccepted += 1;
      if (result.status === "SEALED") {
        const sealed = this._phaseExport(phase);
        const now = process.hrtime.bigint();
        this.phaseTimings.push({
          phaseIndex: this.phaseIndex,
          phaseKey: sealed.phaseKey,
          phaseName: phase.phase,
          wallMsSincePreviousSeal: Number(now - this.lastPhaseSealAt) / 1e6,
          submissionCount: sealed.phase.submissions.length,
          phaseDigest: sealed.phaseDigest,
        });
        this.lastPhaseSealAt = now;
        this.phaseIndex += 1;
        clearTimeout(this.phaseTimer);
        this._armPhaseTimeout();
        await Promise.all([
          this._reply(connection, id, { status: result.status, phaseDigest: sealed.phaseDigest }),
          this._broadcast({ type: "EVENT", event: "PHASE_SEALED", ...sealed }),
        ]);
        return;
      }
      await this._reply(connection, id, { status: result.status });
      return;
    }
    if (method === "FINISH") {
      if (this.phaseIndex !== this.phasePlan.length) throw Object.assign(new Error("client finished before all phases sealed"), { code: "E_TCP_FINISH_EARLY" });
      this.finishedTrustees.add(connection.trusteeId);
      this.finishWaiters.push({ connection, id });
      if (this.finishedTrustees.size === this.expectedTrustees) await this._finalize();
      return;
    }
    throw Object.assign(new Error(`unknown method ${method}`), { code: "E_TCP_METHOD" });
  }

  _accept(socket) {
    const connection = { socket, trusteeId: null, tail: Promise.resolve(), buffer: Buffer.alloc(0) };
    this.connections.add(connection);
    socket.on("data", (chunk) => {
      this.metrics.tcpApplicationBytesIn += chunk.length;
      connection.buffer = Buffer.concat([connection.buffer, chunk]);
      if (connection.buffer.length > this.maxFrameBytes && !connection.buffer.includes(0x0a)) {
        this._abortRun(Object.assign(new Error("frame exceeds configured limit"), { code: "E_TCP_FRAME_SIZE" }));
        return;
      }
      while (true) {
        const newline = connection.buffer.indexOf(0x0a);
        if (newline < 0) break;
        if (newline > this.maxFrameBytes) {
          this._abortRun(Object.assign(new Error("frame exceeds configured limit"), { code: "E_TCP_FRAME_SIZE" }));
          return;
        }
        const line = connection.buffer.subarray(0, newline).toString("utf8");
        connection.buffer = connection.buffer.subarray(newline + 1);
        if (line.length === 0) continue;
        this.metrics.applicationFramesIn += 1;
        let request;
        try { request = JSON.parse(line); }
        catch (error) { this._abortRun(Object.assign(new Error(`invalid JSON frame: ${error.message}`), { code: "E_TCP_JSON" })); return; }
        connection.tail = connection.tail.then(() => this._handle(connection, request)).catch((error) => this._replyError(connection, request.id, error).catch(() => {}));
      }
    });
    socket.on("error", (error) => {
      if (!this.completed && !this.error && Number.isInteger(connection.trusteeId)) this._abortRun(Object.assign(new Error(`trustee ${connection.trusteeId} socket error: ${error.message}`), { code: "E_TCP_SOCKET" }));
    });
    socket.on("close", () => {
      this.connections.delete(connection);
      if (Number.isInteger(connection.trusteeId) && !this.completed && !this.error && !this.finishedTrustees.has(connection.trusteeId)) {
        this._abortRun(Object.assign(new Error(`trustee ${connection.trusteeId} disconnected`), { code: "E_TCP_DISCONNECTED" }));
      }
    });
  }

  async listen({ host = "127.0.0.1", port = 0 } = {}) {
    this._initializeLog();
    this.server = net.createServer((socket) => this._accept(socket));
    await new Promise((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(port, host, () => {
        this.server.removeListener("error", reject);
        resolve();
      });
    });
    this.startupTimer = setTimeout(() => {
      this._abortRun(Object.assign(new Error(`only ${this.trusteeConnections.size}/${this.expectedTrustees} trustees connected`), { code: "E_TCP_STARTUP_TIMEOUT" }));
    }, this.startupTimeoutMs);
    const address = this.server.address();
    return { host: address.address, port: address.port };
  }
}

async function main(argv = process.argv.slice(2)) {
  const configIndex = argv.indexOf("--config");
  if (configIndex < 0 || !argv[configIndex + 1]) throw new Error("usage: tcp_board_service.js --config <json>");
  const config = JSON.parse(fs.readFileSync(path.resolve(argv[configIndex + 1]), "utf8"));
  const service = new TcpBoardService(config);
  const address = await service.listen({ host: config.host || "127.0.0.1", port: Number(config.port || 0) });
  process.stdout.write(`BOARD_READY=${address.host}:${address.port}\n`);
  const shutdown = () => {
    if (!service.completed && !service.error) service._abortRun(Object.assign(new Error("service interrupted"), { code: "E_TCP_INTERRUPTED" }));
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`BOARD_ERROR=${error.code || "E_TCP_BOARD"}:${error.stack || error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = Object.freeze({ TcpBoardService, phaseKey, sha256 });
