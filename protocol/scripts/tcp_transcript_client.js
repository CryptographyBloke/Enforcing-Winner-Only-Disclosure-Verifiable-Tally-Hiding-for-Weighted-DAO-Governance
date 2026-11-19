"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");

function frame(value) {
  return Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
}

function percentile(values, quantile) {
  if (!values.length) return null;
  const sorted = values.slice().sort((left, right) => left - right);
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(quantile * sorted.length) - 1))];
}

function sha256(text) {
  return crypto.createHash("sha256").update(text).digest("hex");
}

class JsonPeer {
  constructor(socket, timeoutMs) {
    this.socket = socket;
    this.timeoutMs = timeoutMs;
    this.nextId = 1;
    this.pending = new Map();
    this.events = [];
    this.eventWaiters = [];
    this.buffer = Buffer.alloc(0);
    this.error = null;
    this.metrics = { bytesSent: 0, bytesReceived: 0, framesSent: 0, framesReceived: 0, requestCounts: {} };
    socket.setNoDelay(true);
    socket.on("data", (chunk) => this._onData(chunk));
    socket.on("error", (error) => this._fail(error));
    socket.on("close", () => this._fail(new Error("board connection closed")));
  }

  _fail(error) {
    if (this.error) return;
    this.error = error;
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
    for (const waiter of this.eventWaiters.splice(0)) {
      clearTimeout(waiter.timer);
      waiter.reject(error);
    }
  }

  _onData(chunk) {
    this.metrics.bytesReceived += chunk.length;
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (true) {
      const newline = this.buffer.indexOf(0x0a);
      if (newline < 0) break;
      const line = this.buffer.subarray(0, newline).toString("utf8");
      this.buffer = this.buffer.subarray(newline + 1);
      if (!line) continue;
      this.metrics.framesReceived += 1;
      let message;
      try { message = JSON.parse(line); }
      catch (error) { this._fail(new Error(`invalid board frame: ${error.message}`)); return; }
      if (message.type === "RES") {
        const pending = this.pending.get(message.id);
        if (!pending) continue;
        this.pending.delete(message.id);
        clearTimeout(pending.timer);
        if (!message.ok) pending.reject(Object.assign(new Error(message.error.message), { code: message.error.code }));
        else pending.resolve(message.result);
      } else if (message.type === "EVENT") {
        const waiterIndex = this.eventWaiters.findIndex((waiter) => waiter.predicate(message));
        if (waiterIndex >= 0) {
          const waiter = this.eventWaiters.splice(waiterIndex, 1)[0];
          clearTimeout(waiter.timer);
          if (message.event === "ABORT") waiter.reject(Object.assign(new Error(message.error.message), { code: message.error.code }));
          else waiter.resolve(message);
        } else {
          this.events.push(message);
        }
      }
    }
  }

  request(method, args = {}) {
    if (this.error) return Promise.reject(this.error);
    const id = this.nextId++;
    const bytes = frame({ type: "REQ", id, method, args });
    this.metrics.bytesSent += bytes.length;
    this.metrics.framesSent += 1;
    this.metrics.requestCounts[method] = (this.metrics.requestCounts[method] || 0) + 1;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(Object.assign(new Error(`request timeout: ${method}`), { code: "E_TCP_CLIENT_TIMEOUT" }));
      }, this.timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.socket.write(bytes, (error) => {
        if (error) {
          const pending = this.pending.get(id);
          if (pending) {
            this.pending.delete(id);
            clearTimeout(pending.timer);
            reject(error);
          }
        }
      });
    });
  }

  waitEvent(event, predicate = () => true) {
    if (this.error) return Promise.reject(this.error);
    const queued = this.events.findIndex((candidate) => candidate.event === event && predicate(candidate));
    if (queued >= 0) return Promise.resolve(this.events.splice(queued, 1)[0]);
    return new Promise((resolve, reject) => {
      const waiter = {
        predicate: (candidate) => candidate.event === event && predicate(candidate),
        resolve,
        reject,
        timer: setTimeout(() => {
          const index = this.eventWaiters.indexOf(waiter);
          if (index >= 0) this.eventWaiters.splice(index, 1);
          reject(Object.assign(new Error(`event timeout: ${event}`), { code: "E_TCP_EVENT_TIMEOUT" }));
        }, this.timeoutMs),
      };
      this.eventWaiters.push(waiter);
    });
  }
}

async function run() {
  const args = process.argv.slice(2);
  const workloadIndex = args.indexOf("--workload");
  const hostIndex = args.indexOf("--host");
  const portIndex = args.indexOf("--port");
  if (workloadIndex < 0 || hostIndex < 0 || portIndex < 0) throw new Error("usage: tcp_transcript_client.js --workload <json> --host <host> --port <port>");
  const workload = JSON.parse(fs.readFileSync(path.resolve(args[workloadIndex + 1]), "utf8"));
  const host = args[hostIndex + 1];
  const port = Number(args[portIndex + 1]);
  const timeoutMs = Number(workload.timeoutMs || 120000);
  const socket = net.createConnection({ host, port });
  await new Promise((resolve, reject) => {
    socket.once("connect", resolve);
    socket.once("error", reject);
    const timer = setTimeout(() => reject(new Error("board connection timeout")), timeoutMs);
    socket.once("connect", () => clearTimeout(timer));
    socket.once("error", () => clearTimeout(timer));
  });
  const peer = new JsonPeer(socket, timeoutMs);
  await peer.request("HELLO", { trusteeId: workload.trusteeId });
  await peer.waitEvent("CLIENTS_READY");

  const rttMs = [];
  for (let index = 0; index < Number(workload.pingCount || 25); index += 1) {
    const started = process.hrtime.bigint();
    const response = await peer.request("PING", { sample: index });
    if (response.status !== "PONG") throw new Error("invalid PING response");
    rttMs.push(Number(process.hrtime.bigint() - started) / 1e6);
  }
  await peer.request("READY_TO_RUN");
  const startEvent = await peer.waitEvent("START");
  if (startEvent.phaseCount !== workload.phasePlan.length) throw new Error("server phase plan length mismatch");
  const runStarted = process.hrtime.bigint();
  const phaseTimings = [];
  const phaseViewDigests = [];

  for (let index = 0; index < workload.phasePlan.length; index += 1) {
    const phase = workload.phasePlan[index];
    const ownSubmission = phase.submission || null;
    const phaseStarted = process.hrtime.bigint();
    const sealed = peer.waitEvent("PHASE_SEALED", (event) => event.phaseKey === phase.phaseKey);
    if (ownSubmission) {
      const response = await peer.request("SUBMIT", ownSubmission);
      if (!(["STAGED", "SEALED"].includes(response.status))) throw new Error(`invalid submit status for ${phase.phaseKey}`);
    }
    const event = await sealed;
    if (event.phaseDigest !== phase.expectedPhaseDigest) throw new Error(`sealed phase digest mismatch: ${phase.phaseKey}`);
    if (event.phase.status !== "SEALED" || event.phase.submissions.length !== phase.requiredTrusteeIds.length) {
      throw new Error(`sealed vector is incomplete: ${phase.phaseKey}`);
    }
    if (ownSubmission) {
      const ownEntry = event.phase.submissions.find((entry) => entry.trusteeId === workload.trusteeId);
      if (!ownEntry || ownEntry.payloadHex !== ownSubmission.payloadHex || ownEntry.signatureBase64 !== ownSubmission.signatureBase64) {
        throw new Error(`board omitted this trustee's signed message: ${phase.phaseKey}`);
      }
    }
    phaseViewDigests.push(event.phaseDigest);
    phaseTimings.push({
      phaseIndex: index,
      phaseKey: phase.phaseKey,
      phaseName: phase.phase,
      wallMs: Number(process.hrtime.bigint() - phaseStarted) / 1e6,
      submissionCount: event.phase.submissions.length,
      phaseDigest: event.phaseDigest,
    });
  }

  const commonViewDigest = sha256(phaseViewDigests.join("\n"));
  const totalMs = Number(process.hrtime.bigint() - runStarted) / 1e6;
  const result = {
    schema: "winner-only-disclosure/tcp-trustee-client-result/v1",
    mode: "authenticated-transcript-transport-replay",
    trusteeId: workload.trusteeId,
    phaseCount: phaseTimings.length,
    submissionCount: workload.phasePlan.reduce((sum, phase) => sum + (phase.submission ? 1 : 0), 0),
    totalMs,
    commonViewDigest,
    rtt: {
      samples: rttMs.length,
      minMs: Math.min(...rttMs),
      medianMs: percentile(rttMs, 0.5),
      p95Ms: percentile(rttMs, 0.95),
      maxMs: Math.max(...rttMs),
    },
    rttValuesMs: rttMs,
    transport: peer.metrics,
    phaseTimings,
  };
  const finish = await peer.request("FINISH", { commonViewDigest });
  if (finish.status !== "RUN_COMPLETE") throw new Error("board did not complete the run");
  socket.end();
  const resultPath = path.resolve(workload.resultPath);
  fs.mkdirSync(path.dirname(resultPath), { recursive: true });
  fs.writeFileSync(resultPath, `${JSON.stringify(result, null, 2)}\n`, { flag: "wx", encoding: "utf8" });
  process.stdout.write(`CLIENT_RESULT=${JSON.stringify(result)}\n`);
}

run().catch((error) => {
  process.stderr.write(`CLIENT_ERROR=${error.code || "E_TCP_CLIENT"}:${error.stack || error.message}\n`);
  process.exitCode = 1;
});
