"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { PROTOCOL_VERSION } = require("../src/group_oracle");
const { createTrusteeAuthenticationRegistry, signSubmission, verifyBroadcastTranscript } = require("../src/broadcast_board");
const { TcpBoardService } = require("../src/tcp_board_service");

const SETUP_HASH = "ab".repeat(32);
const EXECUTION_ID = "cd".repeat(32);

class Peer {
  constructor(socket) {
    this.socket = socket;
    this.nextId = 1;
    this.pending = new Map();
    this.events = [];
    this.eventWaiters = [];
    this.buffer = "";
    socket.on("data", (chunk) => {
      this.buffer += chunk.toString("utf8");
      for (;;) {
        const newline = this.buffer.indexOf("\n");
        if (newline < 0) break;
        const line = this.buffer.slice(0, newline);
        this.buffer = this.buffer.slice(newline + 1);
        const frame = JSON.parse(line);
        if (frame.type === "RES") {
          const pending = this.pending.get(frame.id);
          if (!pending) continue;
          this.pending.delete(frame.id);
          if (frame.ok) pending.resolve(frame.result);
          else pending.reject(Object.assign(new Error(frame.error.message), { code: frame.error.code }));
        } else if (frame.type === "EVENT") {
          const waiterIndex = this.eventWaiters.findIndex((waiter) => waiter.name === frame.event);
          if (waiterIndex < 0) this.events.push(frame);
          else this.eventWaiters.splice(waiterIndex, 1)[0].resolve(frame);
        }
      }
    });
  }

  static connect(address) {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection(address);
      socket.once("connect", () => resolve(new Peer(socket)));
      socket.once("error", reject);
    });
  }

  request(method, args = {}) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.socket.write(`${JSON.stringify({ type: "REQ", id, method, args })}\n`, (error) => {
        if (error) {
          this.pending.delete(id);
          reject(error);
        }
      });
    });
  }

  waitEvent(name, timeoutMs = 5000) {
    const index = this.events.findIndex((event) => event.event === name);
    if (index >= 0) return Promise.resolve(this.events.splice(index, 1)[0]);
    return new Promise((resolve, reject) => {
      const waiter = { name, resolve, reject };
      const timer = setTimeout(() => {
        const position = this.eventWaiters.indexOf(waiter);
        if (position >= 0) this.eventWaiters.splice(position, 1);
        reject(new Error(`timed out waiting for ${name}`));
      }, timeoutMs);
      waiter.resolve = (event) => { clearTimeout(timer); resolve(event); };
      this.eventWaiters.push(waiter);
    });
  }

  close() { this.socket.destroy(); }
}

function phase(gateId, phaseName, dependsOnPhase = null) {
  return { gateId: String(gateId), invocation: "0", phase: phaseName, dependsOnPhase, requiredTrusteeIds: [1, 2, 3, 4, 5] };
}

function makeContext(t, { phases = [phase(1, "MASKING_1"), phase(1, "MASKING_2", "MASKING_1")], startupTimeoutMs = 5000 } = {}) {
  const auth = createTrusteeAuthenticationRegistry(5);
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "winner-only-tcp-board-test-"));
  t.after(() => {
    for (const peer of context.peers) peer.close();
    if (context.service.server?.listening) context.service.server.close();
    context.service._closeLog();
    const resolved = path.resolve(scratch);
    assert.equal(path.dirname(resolved), path.resolve(os.tmpdir()));
    assert.ok(path.basename(resolved).startsWith("winner-only-tcp-board-test-"));
    fs.rmSync(resolved, { recursive: true, force: true });
  });
  const service = new TcpBoardService({
    setupHash: SETUP_HASH,
    executionId: EXECUTION_ID,
    expectedTrustees: 5,
    trusteePublicKeys: auth.publicKeys.map(({ trusteeId, publicKey }) => ({ trusteeId, publicKeyDerBase64: publicKey.export({ type: "spki", format: "der" }).toString("base64") })),
    phasePlan: phases,
    oneWayDelayMs: 0,
    phaseTimeoutMs: 3000,
    startupTimeoutMs,
    eventLogPath: path.join(scratch, "events.jsonl"),
    exportPath: path.join(scratch, "board-export.json"),
    summaryPath: path.join(scratch, "summary.json"),
  });
  const context = { auth, scratch, service, peers: [], address: null };
  return context;
}

async function start(context, trusteeIds = [1, 2, 3, 4, 5]) {
  context.address = await context.service.listen();
  for (const trusteeId of trusteeIds) {
    const peer = await Peer.connect(context.address);
    context.peers[trusteeId - 1] = peer;
    await peer.request("HELLO", { trusteeId });
  }
  if (trusteeIds.length === 5) {
    await Promise.all(context.peers.map((peer) => peer.waitEvent("CLIENTS_READY")));
    await Promise.all(context.peers.map((peer) => peer.request("READY_TO_RUN")));
    await Promise.all(context.peers.map((peer) => peer.waitEvent("START")));
  }
}

function signedArgs(context, trusteeId, phaseName, payload, overrides = {}) {
  const slot = {
    protocolVersion: PROTOCOL_VERSION,
    setupHash: SETUP_HASH,
    executionId: EXECUTION_ID,
    gateId: "1",
    invocation: "0",
    phase: phaseName,
    trusteeId,
    ...overrides,
  };
  const bytes = Buffer.from(payload);
  return {
    slot,
    payloadHex: bytes.toString("hex"),
    signatureBase64: signSubmission(context.auth.privateKeys[trusteeId - 1].privateKey, slot, bytes).toString("base64"),
  };
}

async function expectRequestCode(promise, code) {
  await assert.rejects(promise, (error) => error.code === code);
}

test("TCP board enforces signed trustee binding, context, phase order, sealing and public verification", async (t) => {
  const context = makeContext(t);
  await start(context);
  await expectRequestCode(context.peers[0].request("SUBMIT", signedArgs(context, 2, "MASKING_1", "wrong identity")), "E_TCP_TRUSTEE_BINDING");
  await expectRequestCode(context.peers[0].request("SUBMIT", signedArgs(context, 1, "MASKING_2", "out of order")), "E_TCP_PHASE_ORDER");
  await expectRequestCode(context.peers[0].request("SUBMIT", signedArgs(context, 1, "MASKING_1", "stale", { executionId: "ef".repeat(32) })), "E_BOARD_CONTEXT");
  const invalid = signedArgs(context, 1, "MASKING_1", "invalid signature");
  invalid.signatureBase64 = Buffer.alloc(64).toString("base64");
  await expectRequestCode(context.peers[0].request("SUBMIT", invalid), "E_TRUSTEE_AUTH");

  const first = signedArgs(context, 1, "MASKING_1", "trustee-1");
  assert.equal((await context.peers[0].request("SUBMIT", first)).status, "STAGED");
  assert.deepEqual(await context.peers[0].request("SUBMIT", first), { status: "STAGED" });
  for (let trusteeId = 2; trusteeId <= 5; trusteeId += 1) {
    await context.peers[trusteeId - 1].request("SUBMIT", signedArgs(context, trusteeId, "MASKING_1", `trustee-${trusteeId}`));
  }
  const sealedFirst = await Promise.all(context.peers.map((peer) => peer.waitEvent("PHASE_SEALED")));
  assert.equal(new Set(sealedFirst.map((event) => event.phaseDigest)).size, 1);

  for (let trusteeId = 1; trusteeId <= 5; trusteeId += 1) {
    await context.peers[trusteeId - 1].request("SUBMIT", signedArgs(context, trusteeId, "MASKING_2", `next-${trusteeId}`));
  }
  const sealedSecond = await Promise.all(context.peers.map((peer) => peer.waitEvent("PHASE_SEALED")));
  assert.equal(new Set(sealedSecond.map((event) => event.phaseDigest)).size, 1);
  await Promise.all(context.peers.map((peer) => peer.request("FINISH")));
  const completed = await Promise.all(context.peers.map((peer) => peer.waitEvent("RUN_COMPLETE")));
  assert.equal(new Set(completed.map((event) => event.result.transcriptHash)).size, 1);
  const exported = JSON.parse(fs.readFileSync(path.join(context.scratch, "board-export.json"), "utf8"));
  assert.equal(verifyBroadcastTranscript(exported).valid, true);
  const tampered = structuredClone(exported);
  tampered.transcript.phases[0].submissions[0].payloadHex = Buffer.from("tampered").toString("hex");
  assert.throws(() => verifyBroadcastTranscript(tampered));
});

test("TCP board persists and aborts a conflicting signed duplicate", async (t) => {
  const context = makeContext(t, { phases: [phase(1, "MASKING_1")] });
  await start(context);
  await context.peers[0].request("SUBMIT", signedArgs(context, 1, "MASKING_1", "first"));
  void context.peers[0].request("SUBMIT", signedArgs(context, 1, "MASKING_1", "conflict")).catch(() => {});
  for (let attempt = 0; attempt < 50 && !context.service.error; attempt += 1) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(context.service.error.code, "ABORT_EQUIVOCATION");
  const events = fs.readFileSync(path.join(context.scratch, "events.jsonl"), "utf8").trimEnd().split("\n").map((line) => JSON.parse(line));
  assert.ok(events.some((event) => event.type === "ABORT_EQUIVOCATION"));
});

test("TCP board timeout fires when one trustee is missing at startup", async (t) => {
  const context = makeContext(t, { startupTimeoutMs: 100 });
  await start(context, [1, 2, 3, 4]);
  for (let attempt = 0; attempt < 50 && !context.service.error; attempt += 1) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(context.service.error.code, "E_TCP_STARTUP_TIMEOUT");
});

test("TCP board aborts an active run after a trustee disconnects", async (t) => {
  const context = makeContext(t);
  await start(context);
  context.peers[0].close();
  for (let attempt = 0; attempt < 50 && !context.service.error; attempt += 1) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(context.service.error.code, "E_TCP_DISCONNECTED");
});
