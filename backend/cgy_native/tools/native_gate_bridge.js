"use strict";

const childProcess = require("child_process");
const path = require("path");
const { randomScalar } = require("../../js_protocol/src/scalars");
const { publicSetupToJson, ciphertextToJson, ciphertextFromJson } = require("../../js_protocol/src/codec");

const backendRoot = path.resolve(__dirname, "..");
const defaultBinary = path.join(backendRoot, "target", "release", process.platform === "win32" ? "cgy-native.exe" : "cgy-native");
const dagMaxBuffer = Number(process.env.CGY_NATIVE_DAG_MAX_BUFFER || (4 * 1024 * 1024 * 1024));

function scalarText() {
  return randomScalar({ nonzero: true }).toString(10);
}

function gateRandomness(trustees = 5) {
  const maskRandomness = [];
  const xRandomness = [];
  const yRandomness = [];
  const partialRandomness = [];
  for (let index = 0; index < trustees; index += 1) {
    maskRandomness.push({
      sign: (randomScalar({ nonzero: true }) & 1n) === 0n ? 1 : -1,
      rX: scalarText(),
      rY: scalarText(),
      alpha: scalarText(),
      beta: scalarText(),
      fakeChallenge: scalarText(),
      fakeResponseX: scalarText(),
      fakeResponseY: scalarText(),
    });
    xRandomness.push({ randomness: scalarText(), alpha: scalarText() });
    yRandomness.push({ randomness: scalarText(), alpha: scalarText() });
    partialRandomness.push({ alpha: scalarText() });
  }
  return { maskRandomness, xRandomness, yRandomness, partialRandomness };
}

function gateRequest({ setupBundle, baseSession, inputX, inputY, randomness = gateRandomness() }) {
  return {
    setup: publicSetupToJson(setupBundle.publicSetup),
    secretShares: setupBundle.secretShares.map((share) => share.value.toString(10)),
    baseSession: {
      protocolVersion: baseSession.protocolVersion,
      setupHash: baseSession.setupHash,
      executionId: baseSession.executionId,
      gateId: baseSession.gateId.toString(10),
      invocation: baseSession.invocation.toString(10),
    },
    inputX: ciphertextToJson(inputX),
    inputY: ciphertextToJson(inputY),
    ...randomness,
  };
}

function parseGateRun(value) {
  if (!value.gate || value.gate.schema !== "-CGY-NATIVE/SINGLE-GATE/V1") throw new Error("native gate schema mismatch");
  return Object.freeze({
    gate: value.gate,
    output: ciphertextFromJson(value.gate.output),
    generationMs: Number(value.generationMs),
    verificationMs: Number(value.verificationMs),
  });
}

function runNativeGate({ setupBundle, baseSession, inputX, inputY, binaryPath = process.env.CGY_NATIVE_BIN || defaultBinary, randomness = gateRandomness() }) {
  const request = gateRequest({ setupBundle, baseSession, inputX, inputY, randomness });
  const child = childProcess.spawnSync(binaryPath, ["--gate-stdin"], {
    input: `${JSON.stringify(request)}\n`,
    encoding: "utf8",
    maxBuffer: 128 * 1024 * 1024,
    windowsHide: true,
  });
  if (child.error) throw child.error;
  if (child.status !== 0) throw new Error(`native gate failed (${child.status}): ${child.stderr || child.stdout}`);
  let value;
  try { value = JSON.parse(child.stdout); } catch (error) { throw new Error(`native gate returned invalid JSON: ${error.message}\n${child.stdout}`); }
  return parseGateRun(value);
}

function runNativeGateBatch({ gates, binaryPath = process.env.CGY_NATIVE_BIN || defaultBinary }) {
  if (!Array.isArray(gates) || gates.length === 0) throw new Error("native gate batch requires at least one gate");
  const requests = gates.map((gate) => gateRequest(gate));
  const child = childProcess.spawnSync(binaryPath, ["--gate-batch-stdin"], {
    input: `${JSON.stringify(requests)}\n`,
    encoding: "utf8",
    maxBuffer: 1024 * 1024 * 1024,
    windowsHide: true,
  });
  if (child.error) throw child.error;
  if (child.status !== 0) throw new Error(`native gate batch failed (${child.status}): ${child.stderr || child.stdout}`);
  let value;
  try { value = JSON.parse(child.stdout); } catch (error) { throw new Error(`native gate batch returned invalid JSON: ${error.message}\n${child.stdout}`); }
  if (!Array.isArray(value) || value.length !== gates.length) throw new Error("native gate batch result count mismatch");
  return Object.freeze(value.map(parseGateRun));
}

function dagRequest({ setupBundle, executionId, bitVectors, tau, labelPrefix = "N8" }) {
  return {
    setup: publicSetupToJson(setupBundle.publicSetup),
    secretShares: setupBundle.secretShares.map((share) => share.value.toString(10)),
    executionId,
    tau: Number(tau),
    labelPrefix,
    bitVectors: bitVectors.map((bits) => bits.map((value) => ({
      R: { x: value.R.x.toString(10), y: value.R.y.toString(10) },
      S: { x: value.S.x.toString(10), y: value.S.y.toString(10) },
    }))),
  };
}

function runNativeDag({ setupBundle, executionId, bitVectors, tau, labelPrefix = "N8", binaryPath = process.env.CGY_NATIVE_BIN || defaultBinary }) {
  const request = dagRequest({ setupBundle, executionId, bitVectors, tau, labelPrefix });
  const started = process.hrtime.bigint();
  const child = childProcess.spawnSync(binaryPath, ["--dag-stdin"], {
    input: `${JSON.stringify(request)}\n`,
    encoding: "utf8",
    maxBuffer: dagMaxBuffer,
    windowsHide: true,
  });
  if (child.error) throw child.error;
  if (child.status !== 0) throw new Error(`native weighted DAG failed (${child.status}): ${child.stderr || child.stdout}`);
  let value;
  try { value = JSON.parse(child.stdout); } catch (error) { throw new Error(`native weighted DAG returned invalid JSON: ${error.message}\n${child.stdout}`); }
  if (!value || value.schema !== "-CGY-NATIVE/WEIGHTED-DAG/V1") throw new Error("native weighted DAG schema mismatch");
  return Object.freeze({ ...value, __nativeProcessMs: Number(process.hrtime.bigint() - started) / 1e6 });
}

function runNativeDagStream({ setupBundle, executionId, bitVectors, tau, labelPrefix = "N8", transcriptPath, binaryPath = process.env.CGY_NATIVE_BIN || defaultBinary }) {
  if (!transcriptPath) throw new Error("native streamed DAG requires transcriptPath");
  const request = { ...dagRequest({ setupBundle, executionId, bitVectors, tau, labelPrefix }), transcriptPath: path.resolve(transcriptPath) };
  const started = process.hrtime.bigint();
  const child = childProcess.spawnSync(binaryPath, ["--dag-file-stdin"], {
    input: `${JSON.stringify(request)}\n`,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
    windowsHide: true,
  });
  if (child.error) throw child.error;
  if (child.status !== 0) throw new Error(`native streamed weighted DAG failed (${child.status}): ${child.stderr || child.stdout}`);
  let value;
  try { value = JSON.parse(child.stdout); } catch (error) { throw new Error(`native streamed weighted DAG returned invalid JSON: ${error.message}\n${child.stdout}`); }
  if (!value || value.schema !== "-CGY-NATIVE/WEIGHTED-DAG/V1") throw new Error("native streamed weighted DAG schema mismatch");
  return Object.freeze({ ...value, transcriptPath: path.resolve(transcriptPath), __nativeProcessMs: Number(process.hrtime.bigint() - started) / 1e6 });
}

function verifyNativeDag({ setup, executionId, bitVectors, tau, gates, labelPrefix = "N8", binaryPath = process.env.CGY_NATIVE_BIN || defaultBinary }) {
  const request = {
    setup: setup.protocolVersion ? publicSetupToJson(setup) : setup,
    executionId,
    tau: Number(tau),
    labelPrefix,
    bitVectors: bitVectors.map((bits) => bits.map((value) => ({
      R: { x: value.R.x.toString(10), y: value.R.y.toString(10) },
      S: { x: value.S.x.toString(10), y: value.S.y.toString(10) },
    }))),
    gates,
  };
  const started = process.hrtime.bigint();
  const child = childProcess.spawnSync(binaryPath, ["--verify-dag-stdin"], {
    input: `${JSON.stringify(request)}\n`,
    encoding: "utf8",
    maxBuffer: 1024 * 1024 * 1024,
    windowsHide: true,
  });
  if (child.error || child.status !== 0) throw new Error(`native public DAG verification failed (${child.status}): ${child.stderr || child.stdout || child.error}`);
  const result = JSON.parse(child.stdout);
  if (result.schema !== "-CGY-NATIVE/WEIGHTED-DAG-VERIFIED/V1" || result.gateCount !== gates.length) throw new Error("native public DAG verification result mismatch");
  return Object.freeze({ ...result, __nativeProcessMs: Number(process.hrtime.bigint() - started) / 1e6 });
}

function verifyNativeDagFile({ setup, executionId, bitVectors, tau, transcriptPath, labelPrefix = "N8", binaryPath = process.env.CGY_NATIVE_BIN || defaultBinary }) {
  const request = {
    setup: setup.protocolVersion ? publicSetupToJson(setup) : setup,
    executionId,
    tau: Number(tau),
    labelPrefix,
    transcriptPath: path.resolve(transcriptPath),
    bitVectors: bitVectors.map((bits) => bits.map((value) => ({
      R: { x: value.R.x.toString(10), y: value.R.y.toString(10) },
      S: { x: value.S.x.toString(10), y: value.S.y.toString(10) },
    }))),
  };
  const started = process.hrtime.bigint();
  const child = childProcess.spawnSync(binaryPath, ["--verify-dag-file-stdin"], {
    input: `${JSON.stringify(request)}\n`,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    windowsHide: true,
  });
  if (child.error || child.status !== 0) throw new Error(`native streamed DAG verification failed (${child.status}): ${child.stderr || child.stdout || child.error}`);
  const result = JSON.parse(child.stdout);
  if (result.schema !== "-CGY-NATIVE/WEIGHTED-DAG-VERIFIED/V1") throw new Error("native streamed DAG verification result mismatch");
  return Object.freeze({ ...result, __nativeProcessMs: Number(process.hrtime.bigint() - started) / 1e6 });
}

module.exports = Object.freeze({ gateRandomness, gateRequest, runNativeGate, runNativeGateBatch, dagRequest, runNativeDag, runNativeDagStream, verifyNativeDag, verifyNativeDagFile });
