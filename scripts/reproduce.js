"use strict";

const crypto = require("node:crypto");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { SUPPORTED_COUNTS, assertExpectedShape } = require("./experiment_config");

const repositoryRoot = path.resolve(__dirname, "..");
const expectedParameters = {
  trustees: 5,
  shamirPolynomialDegree: 4,
  decryptionThreshold: 5,
  voteBits: 8,
};

function fail(message) { throw new Error(message); }

function parseArgs(argv) {
  const options = { sizes: [], buildArtifacts: false, outputRoot: path.join(repositoryRoot, "runs") };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--build-artifacts") options.buildArtifacts = true;
    else if (argument === "--sizes" || argument === "--output-root") {
      const value = argv[index + 1];
      if (!value) fail(`${argument} requires a value`);
      index += 1;
      if (argument === "--sizes") options.sizes = value.split(",").map((item) => Number(item.trim()));
      else options.outputRoot = path.resolve(repositoryRoot, value);
    } else if (argument === "--help" || argument === "-h") options.help = true;
    else fail(`unknown option: ${argument}`);
  }
  if (!options.help && options.sizes.length === 0) fail("provide at least one size with --sizes 8 or --sizes 8,64,256,1024");
  if (options.sizes.some((size) => !SUPPORTED_COUNTS.includes(size))) {
    fail(`supported sizes are ${SUPPORTED_COUNTS.join(", ")}`);
  }
  if (new Set(options.sizes).size !== options.sizes.length) fail("list each experiment size once");
  return options;
}

function commandResult(binary, args, options = {}) {
  const useShell = process.platform === "win32" && /\.cmd$/i.test(binary);
  return childProcess.spawnSync(binary, args, {
    cwd: options.cwd || repositoryRoot,
    encoding: "utf8",
    windowsHide: true,
    maxBuffer: 64 * 1024 * 1024,
    env: options.env || process.env,
    shell: useShell,
  });
}

function checkedOutput(binary, args, label) {
  const result = commandResult(binary, args);
  if (result.error || result.status !== 0) {
    fail(`${label} is unavailable. ${result.error ? result.error.message : result.stderr || result.stdout || "command failed"}`);
  }
  return (result.stdout || "").trim();
}

function fileSha256(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function readJson(filePath) { return JSON.parse(fs.readFileSync(filePath, "utf8")); }

function requiredFiles() {
  return {
    wasm: path.join(repositoryRoot, "artifacts", "ballot", "build", "matrix", "vote_bit_full_8", "O1", "vote_bit_full_8_js", "vote_bit_full_8.wasm"),
    zkey: path.join(repositoryRoot, "artifacts", "ballot", "groth16", "vote_bit_full_8", "vote_bit_full_8_final.zkey"),
    vkey: path.join(repositoryRoot, "artifacts", "ballot", "groth16", "vote_bit_full_8", "verification_key.json"),
    native: process.env.CGY_NATIVE_BIN || path.join(repositoryRoot, "native", "target", "release", process.platform === "win32" ? "cgy-native.exe" : "cgy-native"),
  };
}

function freeBytesAt(directory) {
  try {
    if (typeof fs.statfsSync === "function") {
      const stats = fs.statfsSync(directory);
      return Number(stats.bavail) * Number(stats.bsize);
    }
  } catch (_) { /* fall through to platform command */ }
  if (process.platform === "win32") {
    const drive = path.parse(directory).root.replace(/\\$/, "");
    const command = `(Get-PSDrive -Name '${drive.replace(":", "")}').Free`;
    const result = commandResult("powershell.exe", ["-NoProfile", "-Command", command]);
    if (!result.error && result.status === 0) return Number(String(result.stdout).trim());
    return null;
  }
  const result = commandResult("df", ["-Pk", directory]);
  if (result.error || result.status !== 0) return null;
  const fields = result.stdout.trim().split(/\s+/);
  return Number(fields[fields.length - 3]) * 1024;
}

function checkDiskSpace(sizes, outputRoot) {
  const requiredGiB = sizes.includes(1024) ? 10 : 2;
  const available = freeBytesAt(outputRoot);
  if (available === null) fail("could not determine free space; check it manually before starting (10 GiB recommended when n=1024 is selected)");
  if (available < requiredGiB * 1024 ** 3) {
    fail(`insufficient free disk space at ${outputRoot}: ${(available / 1024 ** 3).toFixed(1)} GiB available; ${requiredGiB} GiB required for this selection`);
  }
  return { availableBytes: available, requiredGiB };
}

function toolchainInfo() {
  const node = process.version;
  const nodeMajor = Number(node.slice(1).split(".")[0]);
  if (nodeMajor < 20) fail(`Node.js 20 or newer is required; found ${node}`);
  const npm = checkedOutput(process.platform === "win32" ? "npm.cmd" : "npm", ["--version"], "npm");
  const rustc = checkedOutput("rustc", ["--version"], "Rust compiler; install rustup and the pinned toolchain in rust-toolchain.toml");
  const cargo = checkedOutput("cargo", ["--version"], "Cargo; install rustup and the pinned toolchain in rust-toolchain.toml");
  const toolchainToml = fs.readFileSync(path.join(repositoryRoot, "rust-toolchain.toml"), "utf8");
  const pinnedRustMatch = toolchainToml.match(/^channel\s*=\s*["']([^"']+)["']/m);
  if (!pinnedRustMatch) fail("could not read the pinned Rust channel from rust-toolchain.toml");
  const rustVersion = pinnedRustMatch[1];
  if (!rustc.includes(rustVersion) || !cargo.includes(rustVersion)) {
    fail(`Rust ${rustVersion} is pinned; found '${rustc}' and '${cargo}'`);
  }
  const circomBinary = process.env.CIRCOM_BIN || "circom";
  const circom = checkedOutput(circomBinary, ["--version"], "Circom 2.1.6; install the pinned compiler or set CIRCOM_BIN");
  if (!/2\.1\.6(?:\D|$)/.test(circom)) fail(`Circom 2.1.6 is required; found '${circom}'`);
  return { node, npm, rustc, cargo, circom, circomBinary };
}

function runStage(name, binary, args, env, logDirectory) {
  process.stdout.write(`\n[${name}] ${path.basename(binary)} ${args.join(" ")}\n`);
  const result = commandResult(binary, args, { env });
  const stdout = result.stdout || "";
  const stderr = result.stderr || "";
  fs.writeFileSync(path.join(logDirectory, `${name}.log`), `${stdout}${stderr ? `\n--- stderr ---\n${stderr}` : ""}`, { flag: "wx" });
  if (stdout) process.stdout.write(stdout);
  if (stderr) process.stderr.write(stderr);
  if (result.error || result.status !== 0) {
    fail(`${name} failed (exit ${result.status ?? "unknown"}); see ${path.join(logDirectory, `${name}.log`)}`);
  }
  return { exitCode: result.status, stdout, stderr };
}

function ensureReferenceConfig() {
  const config = readJson(path.join(repositoryRoot, "configs", "reference", "five_of_five_n8.json"));
  if (config.trustees !== expectedParameters.trustees
      || config.shamirDegree !== expectedParameters.shamirPolynomialDegree
      || config.decryptionThreshold !== expectedParameters.decryptionThreshold
      || config.voteBits !== expectedParameters.voteBits
      || JSON.stringify(config.localScaleBallotCounts) !== JSON.stringify(SUPPORTED_COUNTS)) {
    fail("reference configuration differs from the four-size five-of-five profile");
  }
  return config;
}

function uniqueRunId(count) {
  const date = new Date().toISOString().slice(0, 10);
  return `${date}_local_n${count}_${crypto.randomBytes(4).toString("hex")}`;
}

function gitMetadata() {
  const commit = checkedOutput("git", ["rev-parse", "HEAD"], "Git");
  const status = commandResult("git", ["status", "--porcelain"]);
  return { commit, workingTreeDirty: Boolean(status.stdout && status.stdout.trim()) };
}

function updateRun(publicDirectory, runId, count, config, environment, git, timing) {
  const manifestPath = path.join(publicDirectory, "manifest.json");
  const manifest = readJson(manifestPath);
  assertExpectedShape(manifest);
  if (manifest.tau !== Math.floor(255 * count / 4)) fail("runner threshold differs from floor(255*n/4)");

  const proofContext = readJson(path.join(publicDirectory, "ballot_public_context.json"));
  const replay = readJson(path.join(publicDirectory, "public_replay.json"));
  const oracle = readJson(path.join(publicDirectory, "benchmark_summary.json"));
  if (oracle.oracleMatchesProtocol !== true) fail("isolated oracle comparison did not pass");
  Object.assign(manifest, {
    runId,
    timestampUtc: new Date().toISOString(),
    gitCommit: git.commit,
    workingTreeDirty: git.workingTreeDirty,
    execution: "local",
    environment: {
      operatingSystem: `${os.type()} ${os.release()}`,
      platform: process.platform,
      architecture: process.arch,
      cpu: os.cpus()[0] ? os.cpus()[0].model : "unknown",
      logicalCpuCount: os.cpus().length,
      node: environment.node,
      npm: environment.npm,
      rustc: environment.rustc,
      cargo: environment.cargo,
      circom: environment.circom,
    },
    parameters: {
      trustees: config.trustees,
      shamirPolynomialDegree: config.shamirDegree,
      decryptionThreshold: config.decryptionThreshold,
      voteBits: config.voteBits,
      weightRange: "0..255",
      weightedDecision: "sum(vote_i * weight_i) >= tau",
      localTauRule: config.localScaleTauRule,
      localTau: manifest.tau,
      publicChainReferenceTau: config.referenceThresholdTau,
      publicChainReferenceBallotCount: config.referenceBallotCount,
    },
    results: { ballotProofs: "PASS", admission: "PASS", boardBinding: "PASS", publicReplay: "PASS", oracleComparison: "PASS" },
    fullPipelineSeconds: timing.fullPipelineSeconds,
  });
  manifest.hashes = manifest.hashes || {};
  manifest.hashes.verificationKeySha256 = fileSha256(path.join(publicDirectory, "verification_key.json"));
  manifest.hashes.ballotWasmSha256 = proofContext.artifactHashes.wasmSha256;
  manifest.hashes.ballotZkeySha256 = proofContext.artifactHashes.zkeySha256;
  manifest.hashes.verificationKeyContextSha256 = proofContext.artifactHashes.vkeySha256;
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

  const performance = {
    schema: "winner-only-disclosure/experiment-performance/v1",
    runId,
    n: count,
    gates: manifest.gates,
    scheduledDepth: manifest.depth,
    provingSeconds: manifest.timing.ballotProvingSeconds,
    admissionSeconds: manifest.timing.admissionSeconds,
    backendSeconds: manifest.timing.backendSeconds,
    releaseSeconds: manifest.timing.finalReleaseSeconds,
    producerReplaySeconds: manifest.timing.replaySeconds,
    independentReplaySeconds: replay.timing.replaySeconds,
    totalPipelineSeconds: timing.fullPipelineSeconds,
    verification: "PASS",
    publicReplay: "PASS",
    oracleComparison: "PASS",
  };
  const verification = {
    schema: "winner-only-disclosure/experiment-verification/v1",
    status: "PASS",
    ballotProofs: "PASS",
    localAdmission: "PASS",
    exactAcceptedBoardBinding: "PASS",
    cgyTranscriptReplay: "PASS",
    fiveOfFiveFinalRelease: "PASS",
    publicReplay: replay,
    oracleComparison: {
      status: "PASS",
      matchesReleasedBit: oracle.oracleMatchesProtocol,
      resultBit: oracle.oracleResultBit,
    },
  };
  fs.writeFileSync(path.join(publicDirectory, "performance.json"), `${JSON.stringify(performance, null, 2)}\n`, { flag: "wx" });
  fs.writeFileSync(path.join(publicDirectory, "verification.json"), `${JSON.stringify(verification, null, 2)}\n`, { flag: "wx" });
  return { manifest, performance, verification };
}

function summarize(results, outputFile) {
  const header = "| n | gates | depth | proving | admission | backend | release | replay | total | verification |\n|---:|---:|---:|---:|---:|---:|---:|---:|---:|:---:|";
  const rows = results.map(({ performance }) => `| ${performance.n} | ${performance.gates} | ${performance.scheduledDepth} | ${performance.provingSeconds.toFixed(3)}s | ${performance.admissionSeconds.toFixed(3)}s | ${performance.backendSeconds.toFixed(3)}s | ${performance.releaseSeconds.toFixed(3)}s | ${performance.independentReplaySeconds.toFixed(3)}s | ${performance.totalPipelineSeconds.toFixed(3)}s | ${performance.verification} |`);
  const markdown = `# Fresh local experiment results\n\nGenerated from newly completed runs at ${new Date().toISOString()}. Runtime values are machine-dependent.\n\n${header}\n${rows.join("\n")}\n`;
  fs.writeFileSync(outputFile, markdown, { flag: "wx" });
  process.stdout.write(`\nSUMMARY=${path.relative(repositoryRoot, outputFile)}\n${markdown}`);
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    process.stdout.write("Usage: node scripts/reproduce.js --sizes 8[,64,256,1024] [--build-artifacts] [--output-root runs]\n");
    return;
  }
  const environment = toolchainInfo();
  const config = ensureReferenceConfig();
  const resolvedOutput = path.resolve(options.outputRoot);
  const relativeOutput = path.relative(repositoryRoot, resolvedOutput);
  const relativeRunsOutput = path.relative(path.join(repositoryRoot, "runs"), resolvedOutput);
  if (relativeOutput.startsWith("..") || path.isAbsolute(relativeOutput)
      || relativeRunsOutput.startsWith("..") || path.isAbsolute(relativeRunsOutput)) {
    fail("output root must be inside the repository's runs/ directory");
  }
  fs.mkdirSync(resolvedOutput, { recursive: true });
  const disk = checkDiskSpace(options.sizes, resolvedOutput);
  const git = gitMetadata();

  if (options.buildArtifacts) {
    const setupDirectory = path.join(resolvedOutput, `setup_${new Date().toISOString().replace(/[:.]/g, "-")}_${crypto.randomBytes(3).toString("hex")}`);
    const setupLogs = path.join(setupDirectory, "logs");
    fs.mkdirSync(setupLogs, { recursive: true });
    runStage("00-npm-circuits-ci", process.platform === "win32" ? "npm.cmd" : "npm", ["ci", "--prefix", "circuits"], process.env, setupLogs);
    runStage("00-npm-protocol-ci", process.platform === "win32" ? "npm.cmd" : "npm", ["ci", "--prefix", "protocol"], process.env, setupLogs);
    runStage("00-rust-build", "cargo", ["build", "--release", "--locked", "--manifest-path", "native/Cargo.toml"], process.env, setupLogs);
    runStage("00-ballot-setup", process.platform === "win32" ? "npm.cmd" : "npm", ["--prefix", "protocol", "run", "build:ballot"], process.env, setupLogs);
  }
  const missing = Object.entries(requiredFiles()).filter(([, filePath]) => !fs.existsSync(filePath));
  if (missing.length > 0) {
    fail(`required executable or proving artifact is missing: ${missing.map(([name, filePath]) => `${name}: ${path.relative(repositoryRoot, filePath)}`).join("; ")}`);
  }
  if (!fs.existsSync(path.join(repositoryRoot, "protocol", "node_modules", "snarkjs", "build", "cli.cjs"))) {
    fail("protocol dependencies are missing; run npm ci --prefix protocol");
  }
  if (options.buildArtifacts && !fs.existsSync(path.join(repositoryRoot, "circuits", "node_modules", "circomlib"))) {
    fail("circuits dependency is missing; run npm ci --prefix circuits");
  }

  const results = [];
  for (const count of options.sizes) {
    const runId = uniqueRunId(count);
    const runRoot = path.join(resolvedOutput, runId);
    const publicDirectory = path.join(runRoot, "public");
    const privateParent = path.join(runRoot, "private");
    const oracleDirectory = path.join(privateParent, "oracle");
    const logDirectory = path.join(runRoot, "logs");
    fs.mkdirSync(runRoot, { recursive: false });
    fs.mkdirSync(logDirectory);
    fs.mkdirSync(privateParent);
    const started = process.hrtime.bigint();
    const localDirectory = path.relative(repositoryRoot, publicDirectory);
    const runEnv = {
      ...process.env,
      CGY_LOCAL_N: String(count),
      CGY_LOCAL_RUN_DIRECTORY: localDirectory,
      CGY_N8_ORACLE_DIRECTORY: oracleDirectory,
      CGY_BALLOT_ARTIFACT_ROOT: repositoryRoot,
    };
    process.stdout.write(`\nRUN_ID=${runId}\nPUBLIC=${path.relative(repositoryRoot, publicDirectory)}\nPRIVATE_ORACLE=separate\n`);
    runStage("01-local-pipeline", process.execPath, [path.join(repositoryRoot, "protocol", "scripts", "run_local_scale.js")], runEnv, logDirectory);
    fs.copyFileSync(requiredFiles().vkey, path.join(publicDirectory, "verification_key.json"), fs.constants.COPYFILE_EXCL);
    runStage("02-public-replay", process.execPath, [path.join(repositoryRoot, "protocol", "scripts", "replay_local_run.js")], runEnv, logDirectory);
    runStage("03-verify-results", process.execPath, [path.join(repositoryRoot, "scripts", "verify-results.js"), "--run", publicDirectory], runEnv, logDirectory);
    runStage("04-oracle-comparison", process.execPath, [path.join(repositoryRoot, "protocol", "scripts", "compare_replay_with_oracle.js")], runEnv, logDirectory);
    const elapsed = Number(process.hrtime.bigint() - started) / 1e9;
    const enriched = updateRun(publicDirectory, runId, count, config, environment, git, { fullPipelineSeconds: elapsed });
    enriched.performance.diskSpaceAtStart = { availableBytes: disk.availableBytes, minimumGiB: disk.requiredGiB };
    fs.writeFileSync(path.join(publicDirectory, "performance.json"), `${JSON.stringify(enriched.performance, null, 2)}\n`);
    results.push({ runRoot, publicDirectory, performance: enriched.performance });
    process.stdout.write(`EXPERIMENT=PASS\nN=${count}\nRUN=${path.relative(repositoryRoot, runRoot)}\n`);
  }
  const reportId = `${new Date().toISOString().replace(/[:.]/g, "-")}_${crypto.randomBytes(3).toString("hex")}`;
  summarize(results, path.join(resolvedOutput, `summary_${reportId}.md`));
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`REPRODUCTION_FAILED: ${error.stack || error.message}\n`);
    process.exit(1);
  });
}

module.exports = { parseArgs, freeBytesAt, checkDiskSpace, requiredFiles, updateRun };
