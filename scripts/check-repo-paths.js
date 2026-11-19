"use strict";

const fs = require("node:fs");
const path = require("node:path");

const repositoryRoot = path.resolve(__dirname, "..");
const requiredPaths = [
  "protocol/package.json", "protocol/package-lock.json", "protocol/src/accepted_board.js",
  "native/Cargo.toml", "native/Cargo.lock", "contracts/arbitrum/package.json",
  "circuits/package-lock.json", "configs/reference/five_of_five_n8.json",
  "scripts/reproduce.ps1", "scripts/reproduce.sh", "scripts/reproduce.js",
  "scripts/verify-results.js", "scripts/summarize_runs.js", "scripts/export_public_run.js",
  "docs/architecture.md", "docs/protocol.md", "docs/security-model.md", "docs/quickstart.md",
  "docs/experiments.md", "docs/paper-to-code.md", "docs/provenance.md", "docs/troubleshooting.md",
];

function checkLinks(markdownPath) {
  const text = fs.readFileSync(markdownPath, "utf8");
  const links = [...text.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)].map((match) => match[1].split("#")[0]);
  for (const target of links) {
    if (!target || /^[a-z][a-z0-9+.-]*:/i.test(target)) continue;
    const decoded = decodeURIComponent(target);
    const localPath = path.resolve(path.dirname(markdownPath), decoded);
    if (!fs.existsSync(localPath)) throw new Error(`${path.relative(repositoryRoot, markdownPath)} links to missing path ${target}`);
  }
}

function main() {
  const missing = requiredPaths.filter((relativePath) => !fs.existsSync(path.join(repositoryRoot, relativePath)));
  if (missing.length) throw new Error(`missing repository paths:\n${missing.map((item) => `- ${item}`).join("\n")}`);
  for (const relativePath of ["README.md", "README.zh-CN.md", ...requiredPaths.filter((item) => item.startsWith("docs/"))]) {
    checkLinks(path.join(repositoryRoot, relativePath));
  }
  process.stdout.write(`REPOSITORY_PATHS=PASS\nCHECKED_FILES=${requiredPaths.length}\n`);
}

try { main(); }
catch (error) { process.stderr.write(`REPOSITORY_PATHS=FAIL\n${error.message}\n`); process.exit(1); }
