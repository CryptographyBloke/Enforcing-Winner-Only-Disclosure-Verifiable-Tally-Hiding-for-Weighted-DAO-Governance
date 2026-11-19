"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const readline = require("node:readline");
const { spawn, spawnSync } = require("node:child_process");
const { assertExpectedShape } = require("../../scripts/experiment_config");
const {
  CanonicalAtomicBroadcastBoard,
  canonicalJson,
  verifyBroadcastTranscript,
} = require("../src/broadcast_board");

const repositoryRoot = path.resolve(__dirname, "../..");
const protocolScriptRoot = __dirname;
const defaultSourceRun = "runs/2026-11-19_local_n8_8665073c/public";

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function experimentSourceState() {
  const files = [
    "protocol/src/tcp_board_service.js",
    "protocol/scripts/tcp_transcript_client.js",
    "protocol/scripts/run_tcp_transcript_transport.js",
    "protocol/src/broadcast_board.js",
  ];
  const status = spawnSync("git", ["status", "--porcelain", "--", ...files], { cwd: repositoryRoot, encoding: "utf8" });
  const head = spawnSync("git", ["rev-parse", "HEAD"], { cwd: repositoryRoot, encoding: "utf8" });
  if (status.status !== 0 || head.status !== 0) throw new Error("E_GIT_SOURCE_STATE: cannot record source revision");
  return {
    experimentCodeCommit: head.stdout.trim(),
    experimentWorkingTreeDirty: status.stdout.trim().length > 0,
    experimentSourceFilesSha256: Object.fromEntries(files.map((file) => [file, sha256(fs.readFileSync(path.join(repositoryRoot, file)))])),
  };
}

function phaseKey(phase) {
  return `${BigInt(phase.gateId).toString(10)}/${BigInt(phase.invocation).toString(10)}/${phase.phase}`;
}

function phaseRank(phase, finalRelease = false) {
  if (finalRelease) {
    if (phase.phase === "FINAL_DECISION_RERANDOMIZATION") return 0;
    const partial = /^FINAL_DECISION_PARTIAL_DECRYPTION_(\d+)$/.exec(phase.phase);
    if (partial) return Number(partial[1]);
    throw new Error(`E_WORKLOAD_PHASE: unknown final-release phase ${phase.phase}`);
  }
  const masking = /^MASKING_(\d+)$/.exec(phase.phase);
  if (masking) return Number(masking[1]) - 1;
  if (phase.phase === "GATE_X_RERANDOMIZATION") return 5;
  if (phase.phase === "GATE_Y_DECRYPT_RERANDOMIZATION") return 6;
  const partial = /^GATE_Y_PARTIAL_DECRYPTION_(\d+)$/.exec(phase.phase);
  if (partial) return 6 + Number(partial[1]);
  throw new Error(`E_WORKLOAD_PHASE: unknown gate phase ${phase.phase}`);
}

function addPhaseRecords({ boardExport, phasePlan, submissionMaps, finalRelease = false }) {
  verifyBroadcastTranscript(boardExport);
  const transcript = boardExport.transcript;
  for (const phase of transcript.phases.slice().sort((left, right) => phaseRank(left, finalRelease) - phaseRank(right, finalRelease))) {
    if (phase.status !== "SEALED") throw new Error(`E_WORKLOAD_PHASE: source phase is not sealed: ${phaseKey(phase)}`);
    const key = phaseKey(phase);
    if (submissionMaps.has(key)) throw new Error(`E_WORKLOAD_PHASE: duplicate phase key ${key}`);
    const plan = {
      gateId: phase.gateId,
      invocation: phase.invocation,
      phase: phase.phase,
      dependsOnPhase: phase.dependsOnPhase,
      requiredTrusteeIds: phase.requiredTrusteeIds,
    };
    const submissions = new Map();
    for (const submission of phase.submissions) {
      const slot = {
        protocolVersion: transcript.protocolVersion,
        setupHash: transcript.setupHash,
        executionId: transcript.executionId,
        gateId: phase.gateId,
        invocation: phase.invocation,
        phase: phase.phase,
        trusteeId: submission.trusteeId,
      };
      submissions.set(submission.trusteeId, {
        slot,
        payloadHex: submission.payloadHex,
        signatureBase64: submission.signatureBase64,
      });
    }
    phasePlan.push(plan);
    submissionMaps.set(key, { plan, phase, submissions });
  }
}

async function readJsonl(filePath) {
  const rows = [];
  const input = fs.createReadStream(filePath, { encoding: "utf8" });
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  try {
    for await (const line of lines) if (line.length !== 0) rows.push(JSON.parse(line));
  } finally {
    lines.close();
    input.destroy();
  }
  return rows;
}

function writeNew(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content, { flag: "wx", encoding: "utf8" });
}

function scopeBoardExport(fullExport, gateId, invocation = null) {
  const transcript = {
    ...fullExport.transcript,
    phases: fullExport.transcript.phases.filter((phase) => phase.gateId === String(gateId)
      && (invocation === null || phase.invocation === String(invocation))),
  };
  const canonical = canonicalJson(transcript);
  return { transcript, canonical, transcriptHash: sha256(canonical) };
}

function summarize(values) {
  const sorted = values.slice().sort((left, right) => left - right);
  if (!sorted.length) return { samples: 0, min: null, median: null, p95: null, max: null };
  const at = (q) => sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(q * sorted.length) - 1))];
  return { samples: sorted.length, min: sorted[0], median: at(0.5), p95: at(0.95), max: sorted[sorted.length - 1] };
}

function measureInProcessBoardReplay({ phasePlan, submissionMaps, header }) {
  const trusteePublicKeys = header.trusteePublicKeys.map((entry) => ({
    trusteeId: entry.trusteeId,
    publicKey: crypto.createPublicKey({
      key: Buffer.from(entry.publicKeyDerBase64, "base64"),
      type: "spki",
      format: "der",
    }),
  }));
  const board = new CanonicalAtomicBroadcastBoard({ setupHash: header.setupHash, executionId: header.executionId, trusteePublicKeys });
  for (const phase of phasePlan) board.definePhase(phase);
  const started = process.hrtime.bigint();
  const phaseMs = [];
  let submissions = 0;
  for (const phase of phasePlan) {
    const phaseStarted = process.hrtime.bigint();
    const source = submissionMaps.get(phaseKey(phase));
    for (const trusteeId of phase.requiredTrusteeIds) {
      const submission = source.submissions.get(trusteeId);
      if (!submission) throw new Error(`E_LOCAL_CONTROL_SUBMISSION: missing trustee ${trusteeId} for ${phaseKey(phase)}`);
      const result = board.submit({
        slot: submission.slot,
        payload: Buffer.from(submission.payloadHex, "hex"),
        signature: Buffer.from(submission.signatureBase64, "base64"),
      });
      if (result.status === "WAIT") throw new Error(`E_LOCAL_CONTROL_BARRIER: dependency blocked ${phaseKey(phase)}`);
      submissions += 1;
    }
    const sealed = board.readPhase(phase);
    if (sealed.status !== "SEALED") throw new Error(`E_LOCAL_CONTROL_BARRIER: phase did not seal: ${phaseKey(phase)}`);
    phaseMs.push(Number(process.hrtime.bigint() - phaseStarted) / 1e6);
  }
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  const exported = board.exportTranscript();
  verifyBroadcastTranscript(exported);
  return { elapsedMs, phaseMs, phaseCount: phaseMs.length, submissions, transcriptHash: exported.transcriptHash };
}

function waitForBoard(child, stdoutPath, stderrPath, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    let stdoutBuffer = "";
    let settled = false;
    const stdout = fs.createWriteStream(stdoutPath, { flags: "wx" });
    const stderr = fs.createWriteStream(stderrPath, { flags: "wx" });
    const timer = setTimeout(() => finish(new Error("E_BOARD_START_TIMEOUT: TCP board did not start")), timeoutMs);
    const finish = (error, address) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      stdout.end();
      stderr.end();
      if (error) reject(error);
      else resolve(address);
    };
    child.stdout.on("data", (chunk) => {
      stdout.write(chunk);
      stdoutBuffer += chunk.toString("utf8");
      const match = /BOARD_READY=([^:\r\n]+):(\d+)/.exec(stdoutBuffer);
      if (match) finish(null, { host: match[1], port: Number(match[2]) });
    });
    child.stderr.on("data", (chunk) => stderr.write(chunk));
    child.once("error", (error) => finish(error));
    child.once("exit", (code) => {
      if (!settled) finish(new Error(`E_BOARD_START_EXIT: TCP board exited with ${code}`));
    });
  });
}

function waitForChild(child, stdoutPath, stderrPath, timeoutMs = 900000) {
  return new Promise((resolve, reject) => {
    const stdout = fs.createWriteStream(stdoutPath, { flags: "wx" });
    const stderr = fs.createWriteStream(stderrPath, { flags: "wx" });
    let settled = false;
    const timer = setTimeout(() => {
      child.kill();
      finish(new Error("E_CHILD_TIMEOUT: process exceeded its timeout"));
    }, timeoutMs);
    const finish = (error, code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      stdout.end();
      stderr.end();
      if (error) reject(error);
      else if (code !== 0) reject(new Error(`E_CHILD_EXIT: process exited with ${code}`));
      else resolve();
    };
    child.stdout.on("data", (chunk) => stdout.write(chunk));
    child.stderr.on("data", (chunk) => stderr.write(chunk));
    child.once("error", (error) => finish(error));
    child.once("exit", (code) => finish(null, code));
  });
}

function parseArgs(argv) {
  const result = { sourceRun: defaultSourceRun, outputRoot: "runs", oneWayDelayMs: 0 };
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    if (key === "--source-run") result.sourceRun = argv[++index];
    else if (key === "--output-root") result.outputRoot = argv[++index];
    else if (key === "--one-way-delay-ms") result.oneWayDelayMs = Number(argv[++index]);
    else throw new Error(`unknown argument ${key}`);
  }
  if (!Number.isFinite(result.oneWayDelayMs) || result.oneWayDelayMs < 0 || result.oneWayDelayMs > 1000) throw new Error("one-way application delay must be between 0 and 1000 ms");
  return result;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const sourceRun = path.resolve(repositoryRoot, options.sourceRun);
  const sourceManifest = JSON.parse(fs.readFileSync(path.join(sourceRun, "manifest.json"), "utf8"));
  if (![8, 64].includes(sourceManifest.count)) throw new Error("E_SOURCE_RUN_PROFILE: TCP transport replay supports the validated n=8 and n=64 profiles");
  assertExpectedShape(sourceManifest);
  const sourceReplay = JSON.parse(fs.readFileSync(path.join(sourceRun, "public_replay.json"), "utf8"));
  if (sourceReplay.status !== "PASS") throw new Error("E_SOURCE_REPLAY: source run has no passing public replay");
  const sourceJournalPath = path.join(sourceRun, "gate_transcript.jsonl");
  const sourceFinalPath = path.join(sourceRun, "final_release.json");
  const sourceJournalHash = sha256(fs.readFileSync(sourceJournalPath));
  if (sourceJournalHash !== sourceManifest.hashes.journalSha256) throw new Error("E_SOURCE_HASH: source journal hash differs from manifest");
  const sourceFinal = JSON.parse(fs.readFileSync(sourceFinalPath, "utf8"));
  const finalBoardExport = sourceFinal.boardExport;
  verifyBroadcastTranscript(finalBoardExport);

  const sourceEntries = await readJsonl(sourceJournalPath);
  if (sourceEntries.length !== sourceManifest.gates) throw new Error("E_SOURCE_GATE_COUNT: transcript gate count differs from manifest");
  const phasePlan = [];
  const submissionMaps = new Map();
  let commonHeader = null;
  for (const entry of sourceEntries) {
    const boardExport = entry.record.boardExport;
    verifyBroadcastTranscript(boardExport);
    const currentHeader = {
      protocolVersion: boardExport.transcript.protocolVersion,
      setupHash: boardExport.transcript.setupHash,
      executionId: boardExport.transcript.executionId,
      trustees: boardExport.transcript.trustees,
      trusteePublicKeys: boardExport.transcript.trusteePublicKeys,
    };
    if (commonHeader && canonicalJson(commonHeader) !== canonicalJson(currentHeader)) throw new Error("E_SOURCE_BOARD_HEADER: gate boards use different authentication registries");
    commonHeader = currentHeader;
    addPhaseRecords({ boardExport, phasePlan, submissionMaps });
  }
  if (canonicalJson(commonHeader.trusteePublicKeys) !== canonicalJson(finalBoardExport.transcript.trusteePublicKeys)) throw new Error("E_FINAL_BOARD_HEADER: final release uses a different trustee registry");
  if (finalBoardExport.transcript.setupHash !== commonHeader.setupHash || finalBoardExport.transcript.executionId !== commonHeader.executionId) throw new Error("E_FINAL_BOARD_CONTEXT: final release belongs to another session");
  addPhaseRecords({ boardExport: finalBoardExport, phasePlan, submissionMaps, finalRelease: true });
  const expectedPhaseCount = sourceManifest.gates * 12 + 6;
  if (phasePlan.length !== expectedPhaseCount) throw new Error(`E_WORKLOAD_PHASE_COUNT: expected ${expectedPhaseCount} phases, got ${phasePlan.length}`);

  const logicalSubmissionCount = Array.from(submissionMaps.values()).reduce((sum, entry) => sum + entry.submissions.size, 0);
  const expectedSubmissionCount = sourceManifest.gates * 20 + 10;
  if (logicalSubmissionCount !== expectedSubmissionCount) throw new Error(`E_WORKLOAD_SUBMISSION_COUNT: expected ${expectedSubmissionCount} submissions, got ${logicalSubmissionCount}`);
  const localBoardControl = measureInProcessBoardReplay({ phasePlan, submissionMaps, header: commonHeader });

  const now = new Date();
  const runId = `network-02_tcp_replay_n${sourceManifest.count}_${now.toISOString().replace(/[-:.TZ]/g, "").slice(0, 14)}_${crypto.randomBytes(3).toString("hex")}`;
  const outputRoot = path.resolve(repositoryRoot, options.outputRoot);
  const runRoot = path.join(outputRoot, runId);
  fs.mkdirSync(runRoot, { recursive: false });
  const transportRoot = path.join(runRoot, "transport");
  const inputRoot = path.join(transportRoot, "workload");
  const logRoot = path.join(runRoot, "logs");
  const replayRoot = path.join(runRoot, "replay", "public");
  for (const directory of [transportRoot, inputRoot, logRoot, replayRoot]) fs.mkdirSync(directory, { recursive: true });

  const sourceKeys = commonHeader.trusteePublicKeys;
  const servicePhasePlan = phasePlan.map(({ gateId, invocation, phase, dependsOnPhase, requiredTrusteeIds }) => ({ gateId, invocation, phase, dependsOnPhase, requiredTrusteeIds }));
  const workloadByTrustee = new Map();
  for (let trusteeId = 1; trusteeId <= 5; trusteeId += 1) {
    const clientPlan = phasePlan.map((plan) => {
      const source = submissionMaps.get(phaseKey(plan));
      const submission = source.submissions.get(trusteeId) || null;
      return {
        phaseKey: phaseKey(plan),
        gateId: plan.gateId,
        invocation: plan.invocation,
        phase: plan.phase,
        requiredTrusteeIds: plan.requiredTrusteeIds,
        expectedPhaseDigest: sha256(canonicalJson(source.phase)),
        submission,
      };
    });
    const resultPath = path.join(logRoot, `trustee-${trusteeId}.result.json`);
    const workloadPath = path.join(inputRoot, `trustee-${trusteeId}.json`);
    const workload = {
      schema: "winner-only-disclosure/tcp-transcript-client-workload/v1",
      runId,
      mode: "authenticated-transcript-transport-replay",
      trusteeId,
      timeoutMs: Math.max(120000, options.oneWayDelayMs * expectedPhaseCount * 3 + 30000),
      pingCount: 25,
      resultPath,
      phasePlan: clientPlan,
    };
    writeNew(workloadPath, `${JSON.stringify(workload)}\n`);
    workloadByTrustee.set(trusteeId, workloadPath);
  }

  const serviceConfig = {
    schema: "winner-only-disclosure/tcp-board-config/v1",
    mode: "authenticated-transcript-transport-replay",
    setupHash: commonHeader.setupHash,
    executionId: commonHeader.executionId,
    expectedTrustees: 5,
    trusteePublicKeys: sourceKeys,
    phasePlan: servicePhasePlan,
    oneWayDelayMs: options.oneWayDelayMs,
    phaseTimeoutMs: Math.max(30000, options.oneWayDelayMs * 20 + 15000),
    startupTimeoutMs: 30000,
    eventLogPath: path.join(transportRoot, "canonical-board-events.jsonl"),
    exportPath: path.join(transportRoot, "canonical-board-export.json"),
    summaryPath: path.join(transportRoot, "board-summary.json"),
  };
  const configPath = path.join(transportRoot, "service-config.json");
  writeNew(configPath, `${JSON.stringify(serviceConfig, null, 2)}\n`);

  const boardChild = spawn(process.execPath, [path.join(protocolScriptRoot, "..", "src", "tcp_board_service.js"), "--config", configPath], {
    cwd: repositoryRoot,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  let boardAddress;
  try {
    boardAddress = await waitForBoard(boardChild, path.join(logRoot, "board.stdout.log"), path.join(logRoot, "board.stderr.log"), Math.max(30000, expectedPhaseCount * 10));
  } catch (error) {
    if (boardChild.exitCode === null) boardChild.kill();
    throw error;
  }
  const clients = [];
  try {
    for (let trusteeId = 1; trusteeId <= 5; trusteeId += 1) {
      const child = spawn(process.execPath, [path.join(protocolScriptRoot, "tcp_transcript_client.js"), "--workload", workloadByTrustee.get(trusteeId), "--host", boardAddress.host, "--port", String(boardAddress.port)], {
        cwd: repositoryRoot,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      });
      clients.push({ trusteeId, child });
    }
    await Promise.all(clients.map(({ trusteeId, child }) => waitForChild(child,
      path.join(logRoot, `trustee-${trusteeId}.stdout.log`),
      path.join(logRoot, `trustee-${trusteeId}.stderr.log`),
      Math.max(300000, options.oneWayDelayMs * expectedPhaseCount * 4 + 120000))));
  } catch (error) {
    for (const { child } of clients) if (child.exitCode === null) child.kill();
    if (boardChild.exitCode === null) boardChild.kill();
    throw error;
  }
  await new Promise((resolve, reject) => {
    if (boardChild.exitCode !== null) return boardChild.exitCode === 0 ? resolve() : reject(new Error(`E_BOARD_EXIT: board exited ${boardChild.exitCode}`));
    boardChild.once("exit", (code) => code === 0 ? resolve() : reject(new Error(`E_BOARD_EXIT: board exited ${code}`)));
  });

  const fullBoardExport = JSON.parse(fs.readFileSync(serviceConfig.exportPath, "utf8"));
  verifyBroadcastTranscript(fullBoardExport);
  const reconstructedJournal = sourceEntries.map((entry) => {
    const clone = structuredClone(entry);
    const scoped = scopeBoardExport(fullBoardExport, entry.record.boardExport.transcript.phases[0].gateId);
    if (scoped.transcriptHash !== entry.record.boardExport.transcriptHash) throw new Error(`E_TCP_TRANSCRIPT_SCOPE: phase scope hash differs for gate ${entry.gateIndex}`);
    clone.record.boardExport = scoped;
    return canonicalJson(clone);
  }).join("\n") + "\n";
  if (sha256(reconstructedJournal) !== sourceManifest.hashes.journalSha256) throw new Error("E_TCP_CANONICAL_JOURNAL: TCP replay changed the canonical gate journal");

  const finalBoard = scopeBoardExport(fullBoardExport, sourceFinal.boardExport.transcript.phases[0].gateId);
  if (finalBoard.transcriptHash !== sourceFinal.boardExport.transcriptHash) throw new Error("E_TCP_FINAL_SCOPE: final release board transcript hash changed");
  const finalBytes = fs.readFileSync(sourceFinalPath);
  if (sha256(finalBytes) !== sourceManifest.hashes.finalSha256) throw new Error("E_SOURCE_FINAL_HASH: source final-release bytes differ from manifest");

  const publicFiles = ["ballot_public_context.json", "ballot_public_proofs.json", "local_admission_board.json", "manifest.json", "public_setup.json", "verification_key.json"];
  for (const name of publicFiles) {
    const sourcePath = name === "verification_key.json" && !fs.existsSync(path.join(sourceRun, name))
      ? path.join(repositoryRoot, "artifacts", "ballot", "groth16", "vote_bit_full_8", name)
      : path.join(sourceRun, name);
    fs.copyFileSync(sourcePath, path.join(replayRoot, name), fs.constants.COPYFILE_EXCL);
  }
  writeNew(path.join(replayRoot, "gate_transcript.jsonl"), reconstructedJournal);
  fs.writeFileSync(path.join(replayRoot, "final_release.json"), finalBytes, { flag: "wx" });

  const runDirectoryForReplay = path.relative(repositoryRoot, replayRoot).split(path.sep).join("/");
  const replayLog = path.join(logRoot, "public-replay.log");
  const replay = spawn(process.execPath, [path.join(protocolScriptRoot, "replay_local_run.js")], {
    cwd: repositoryRoot,
    env: { ...process.env, CGY_LOCAL_RUN_DIRECTORY: runDirectoryForReplay, CGY_BALLOT_ARTIFACT_ROOT: repositoryRoot },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  await waitForChild(replay, replayLog, path.join(logRoot, "public-replay.stderr.log"), 300000);
  const replayResult = JSON.parse(fs.readFileSync(path.join(replayRoot, "public_replay.json"), "utf8"));
  if (replayResult.status !== "PASS") throw new Error("E_TCP_PUBLIC_REPLAY: public replay did not pass");

  const oracleDirectory = path.resolve(path.dirname(sourceRun), "private", "oracle");
  if (!fs.existsSync(path.join(oracleDirectory, "cleartext_oracle_inputs.json"))) throw new Error("E_SOURCE_ORACLE: isolated source oracle input is unavailable");
  const oracleLog = path.join(logRoot, "oracle-comparison.log");
  const oracle = spawn(process.execPath, [path.join(protocolScriptRoot, "compare_replay_with_oracle.js")], {
    cwd: repositoryRoot,
    env: {
      ...process.env,
      CGY_LOCAL_RUN_DIRECTORY: path.relative(repositoryRoot, replayRoot).split(path.sep).join("/"),
      CGY_N8_ORACLE_DIRECTORY: oracleDirectory,
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  await waitForChild(oracle, oracleLog, path.join(logRoot, "oracle-comparison.stderr.log"), 300000);
  const replayManifest = JSON.parse(fs.readFileSync(path.join(replayRoot, "manifest.json"), "utf8"));
  if (replayManifest.validation?.oracleComparison?.status !== "PASS") throw new Error("E_TCP_ORACLE_COMPARISON: isolated oracle comparison did not pass");
  const replaySummary = JSON.parse(fs.readFileSync(path.join(replayRoot, "benchmark_summary.json"), "utf8"));
  const sourceState = experimentSourceState();

  const clientResults = Array.from({ length: 5 }, (_, index) => JSON.parse(fs.readFileSync(path.join(logRoot, `trustee-${index + 1}.result.json`), "utf8")));
  const rttValues = clientResults.flatMap((result) => result.rttValuesMs || []);
  if (new Set(clientResults.map((result) => result.commonViewDigest)).size !== 1) throw new Error("E_TCP_CLIENT_COMMON_VIEW: trustee clients observed different phase digests");
  const boardSummary = JSON.parse(fs.readFileSync(serviceConfig.summaryPath, "utf8"));
  const boardExportBytes = fs.readFileSync(serviceConfig.exportPath);
  const journalOutputBytes = fs.readFileSync(path.join(replayRoot, "gate_transcript.jsonl"));
  const networkManifest = {
    schema: "winner-only-disclosure/network-experiment-manifest/v1",
    runId,
    timestampUtc: new Date().toISOString(),
    sourceDataCommit: sourceManifest.gitCommit || sourceState.experimentCodeCommit,
    ...sourceState,
    sourceRunId: sourceManifest.runId,
    sourceRunPath: path.relative(repositoryRoot, sourceRun).split(path.sep).join("/"),
    sourceRunManifestSha256: sha256(fs.readFileSync(path.join(sourceRun, "manifest.json"))),
    mode: "authenticated-transcript-transport-replay",
    distributedCryptographicExecution: false,
    trusteeShareIsolation: false,
    topology: { boardService: "separate Node.js process", trusteeClients: 5, clientProcesses: 5, transport: "TCP over IPv4 loopback", os: `${os.type()} ${os.release()}` },
    configuredDelay: { mechanism: "application-level symmetric ingress/egress delay", oneWayDelayMs: options.oneWayDelayMs, nominalTargetRttMs: 2 * options.oneWayDelayMs },
    environment: { cpu: os.cpus()[0]?.model || "unknown", logicalCpuCount: os.cpus().length, totalMemoryBytes: os.totalmem(), node: process.version, platform: process.platform, architecture: process.arch },
    sourceRunPerformance: Object.fromEntries(["ballotProvingSeconds", "admissionSeconds", "backendSeconds", "finalReleaseSeconds", "replaySeconds", "totalSeconds"].map((field) => [field, sourceManifest.timing[field] ?? null])),
    experiment: { n: sourceManifest.count, gates: sourceManifest.gates, depth: sourceManifest.depth, phaseCount: boardSummary.phaseCount, observedBarriers: boardSummary.sealedPhaseCount, logicalSubmissions: boardSummary.metrics.submissionsAccepted },
    timing: {
      transportWallMs: boardSummary.elapsedMs,
      inProcessBoardControlMs: localBoardControl.elapsedMs,
      tcpMinusInProcessBoardMs: boardSummary.elapsedMs - localBoardControl.elapsedMs,
      localBoardControlPhaseMs: summarize(localBoardControl.phaseMs),
      phaseSealMs: summarize(boardSummary.phaseTimings.map((phase) => phase.wallMsSincePreviousSeal)),
      measuredRttMs: summarize(rttValues),
      boardSignatureVerificationMs: boardSummary.metrics.signatureVerificationMs,
      durableLogSyncMs: boardSummary.metrics.durableLogSyncMs,
      trusteeClients: clientResults.map((result) => ({ trusteeId: result.trusteeId, totalMs: result.totalMs, phaseViewDigest: result.commonViewDigest, rtt: result.rtt })),
      publicReplayStatus: replayResult.status,
      oracleComparisonStatus: replayManifest.validation.oracleComparison.status,
      independentPublicReplayMs: replayResult.timing?.replayTotalMs ?? (replayResult.timing?.replaySeconds || 0) * 1000,
      oracleComparisonMs: replaySummary.oracleComparisonSeconds * 1000,
    },
    communication: {
      applicationFramesReceivedByBoard: boardSummary.metrics.applicationFramesIn,
      applicationFramesSentByBoard: boardSummary.metrics.applicationFramesOut,
      applicationBytesReceivedByBoard: boardSummary.metrics.tcpApplicationBytesIn,
      applicationBytesSentByBoard: boardSummary.metrics.tcpApplicationBytesOut,
      trusteePayloadBytesAccepted: boardSummary.metrics.payloadBytes,
      signatureBytesAccepted: boardSummary.metrics.signatureBytes,
      durableEventLogBytes: boardSummary.metrics.durableLogBytes,
      canonicalBoardExportBytes: boardExportBytes.length,
      publicReplayJournalBytes: journalOutputBytes.length,
      byteLayer: "TCP application framing bytes; excludes IP/TCP/Ethernet headers and retransmission wire accounting",
    },
    verification: { sourcePublicReplay: sourceReplay.status, transportedTranscriptHash: fullBoardExport.transcriptHash, publicReplay: replayResult.status, oracleComparison: replayManifest.validation.oracleComparison.status, canonicalJournalPreserved: sha256(journalOutputBytes) === sourceManifest.hashes.journalSha256, finalReleaseHashPreserved: sha256(finalBytes) === sourceManifest.hashes.finalSha256 },
    hashes: {
      eventLogSha256: sha256(fs.readFileSync(serviceConfig.eventLogPath)),
      boardExportSha256: sha256(boardExportBytes),
      replayJournalSha256: sha256(journalOutputBytes),
      finalReleaseSha256: sha256(finalBytes),
      manifestSha256: sha256(fs.readFileSync(path.join(replayRoot, "manifest.json"))),
    },
    outputs: { transportRoot: path.relative(repositoryRoot, transportRoot), publicReplayRoot: runDirectoryForReplay, clientResults: clientResults.map((result) => ({ trusteeId: result.trusteeId, transport: result.transport })) },
  };
  writeNew(path.join(runRoot, "network_manifest.json"), `${JSON.stringify(networkManifest, null, 2)}\n`);
  process.stdout.write(`NETWORK_RUN=${runId}\nTRANSPORT_MODE=AUTHENTICATED_TRANSCRIPT_REPLAY\nTCP_BOARD=PASS\nTRUSTEE_CLIENTS=5\nLOGICAL_SUBMISSIONS=${boardSummary.metrics.submissionsAccepted}\nSEALED_PHASES=${boardSummary.sealedPhaseCount}\nPUBLIC_REPLAY=${replayResult.status}\nORACLE_COMPARISON=${replayManifest.validation.oracleComparison.status}\nTRANSPORT_WALL_SECONDS=${(boardSummary.elapsedMs / 1000).toFixed(3)}\nRUN=${path.relative(repositoryRoot, runRoot)}\n`);
}

main().catch((error) => {
  process.stderr.write(`TCP_TRANSPORT_ERROR=${error.code || "E_TCP_TRANSPORT"}:${error.stack || error.message}\n`);
  process.exitCode = 1;
});
