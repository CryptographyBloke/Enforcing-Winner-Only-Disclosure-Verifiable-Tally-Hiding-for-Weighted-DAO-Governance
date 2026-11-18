# Repository Cleanup Report

## 1. Executive Result

已完成维护版目录迁移、四种本地规模配置、PowerShell/Bash 复现入口、逐次运行清单与验证、公共结果导出/汇总工具、双语首页、技术文档和 GitHub Actions 更新。密码学关系、BabyJub/Base8、CGY gate 语义、transcript 哈希、已接受 board 绑定和五取五 release 未作算法修改。

代码已提交到专用分支并打开 PR。清理前 tag 已推送。当前环境没有 Rust/Cargo 1.98.1、Circom 2.1.6 或生成的 Groth16 产物，因此没有声称完成端到端的新实验；具体阻塞和作者命令见下文。最终状态：**READY_WITH_LIMITATIONS**。

## 2. Repository Before and After

| 清理前 | 清理后 | 内容 |
|---|---|---|
| `backend/js_protocol/` | `protocol/` | JavaScript 协议、runner、replay、测试 |
| `backend/cgy_native/` | `native/` | Rust CGY backend 与 transcript 工具 |
| `implementation/arbitrum/` | `contracts/arbitrum/` | Hardhat、Solidity、board binding、fixtures |
| `implementation/logs/bit_ballot/` | `artifacts/ballot/`（忽略） | 本地生成的电路和 Groth16 产物 |
| `scripts/setup/` | 保留 | 测试专用 ballot artifact 构建 |
| — | `docs/`、`runs/README.md` | 技术说明与运行目录说明 |

`circuits/`、`configs/`、`evidence/` 保留在根目录。`evidence/` 下的历史 run、数据、冻结源码和哈希记录均保留。

## 3. Version Preservation

- 清理前 `main`：`d193adb05424c31280bb7e1c9a0f4eb85294e40f`。
- 已创建并推送 annotated tag：[`archive/pre-cleanup-2026-11`](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/tree/archive/pre-cleanup-2026-11)，指向上述清理前 commit。
- 已有 [`blocksys2027-evidence-v1`](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/releases/tag/blocksys2027-evidence-v1) release 未改动。下载的 `blocksys2027_evidence_package.zip` SHA-256 为 `7169b79aa099fa42de3c37cadcdd6c21125b7ca4ac63e6a7419e9475cc776a84`，包内 81 项；该哈希与发布资产核对一致。
- 新维护版基于上述 `main`，其首个提交为 `a547202f7f7c7e268d963e8ee0ee32fd27003eff`。历史测量仍对应 `evidence/frozen_source_q5/`，不是清理后的源码。
- 版本关系、归档范围和历史结果不得重新标注为新复现实验，详见 [`docs/provenance.md`](docs/provenance.md)。

清理只改了 `evidence/README.md` 中当前包管理器路径的说明。`evidence/data/`、`evidence/runs/`、`evidence/frozen_source_q5/` 的 Git diff 为空；历史测量、transcript 哈希、合约地址和冻结源码记录没有被改写。

## 4. Source and Configuration Changes

- 所有受迁移影响的 JS import、仓库根路径、Rust manifest、artifact 路径、Hardhat 目录、replay 和包脚本已更新；仓库路径 smoke check 通过。
- runner 接受 `n = 8, 64, 256, 1024`。期望门数/深度由共享配置验证：`134/72`、`1086/147`、`4350/207`、`17406/275`。
- `n >= 256` 使用文件流式 transcript 生产与公共 replay，以控制内存使用；其目标是保持 transcript 字节、哈希和 release 语义不变。此改动已通过结构与 streaming 选择单测；由于本机缺少原生工具链，未完成 n=256 实际 CGY transcript 的端到端回归。
- 五取五参数保持 `a=5`、Shamir 次数 `t=4`、`q_dec=5`、8-bit 权重。local `tau=floor(255*n/4)`；Sepolia 参考运行 n=8 使用 `tau=500`，local n=8 使用 `tau=510`。
- 新 runner 生成唯一 `runs/<id>/`，将公开文件与 `private/oracle/` 分开；只有在 replay 和 oracle 比对均成功后才写成功状态。结果汇总只读取新运行产物，公开导出按文件白名单复制。
- oracle 输入哈希不再写入公开 benchmark summary，避免泄露私有输入的可关联指纹；这不改变 oracle 比对或密码学行为。
- push/PR CI 运行 Rust build/test、JS suite、跨语言兼容、合同编译/测试、board-binding、路径检查与 Bash 语法检查；手动触发流程可运行带新 test-only setup 的 n=8。

## 5. Experiment Support

| n | gates | depth | runner 参数/结构测试 | 完整新 pipeline |
|---:|---:|---:|---|---|
| 8 | 134 | 72 | 通过 | 未运行 |
| 64 | 1,086 | 147 | 通过 | 未运行 |
| 256 | 4,350 | 207 | 通过；streaming 选择通过 | 未运行 |
| 1,024 | 17,406 | 275 | 通过；streaming 选择通过 | 未运行 |

端到端阻塞是环境缺少 `rustc`/`cargo`（复现入口实际报 `spawnSync rustc ENOENT`）、Circom 2.1.6 和新生成的 WASM/zkey/vkey；cross-language 命令也因 `native/target/release/cgy-native.exe` 不存在而退出。所有尺寸的代码入口和结构参数已校验，但没有声称这些完整 pipeline 已经被 fresh run 验证。历史 n=1024 JSONL transcript 约 3.55 GB；脚本对 n=1024 要求至少 10 GiB 可用空间。

## 6. Verification

以下命令均在本次清理后的 checkout 执行；退出码是实际观察值。

| 命令 | 结果 |
|---|---|
| `npm --prefix protocol test` | exit 0；49 passed，0 failed |
| `npm --prefix contracts/arbitrum run compile` | exit 0；编译 3 个 Solidity 文件 |
| `npm --prefix contracts/arbitrum test` | exit 0；51 passed |
| `npm --prefix contracts/arbitrum run test:board-binding` | exit 0；3 passed |
| `npm --prefix protocol run replay:single-gate` | exit 0；`SINGLE_GATE_INDEPENDENT_REPLAY=PASS` |
| `npm --prefix protocol run test:group:reference` | exit 0；`CIRCOMLIB_REFERENCE_CROSSCHECK=PASS scalars=9` |
| `node --test scripts/experiment_config.test.js scripts/reproducibility.test.js` | exit 0；8 passed |
| `node scripts/check-repo-paths.js` | exit 0；22 files checked |
| 维护版 JS 文件 `node --check` | exit 0；64 files通过；本次改动的 reproduction/test 文件也单独通过 |
| `git diff --check` | exit 0；仅 Git 的 LF/CRLF 提示 |
| `.gitignore` 探针 | exit 0；运行 manifest、oracle 输入、artifact、node_modules、Rust target 被忽略，`runs/README.md` 未被忽略 |
| `.\scripts\reproduce.ps1 -Sizes 8` | exit 1；PowerShell 参数正确进入 runner，因缺 Rust `rustc` 退出 |
| `npm --prefix protocol run test:cross-language` | exit 1；原生二进制不存在，Rust/Cargo 未安装 |

本机没有可用的 Bash shell（系统 `bash.exe` 是无法启动的 WSL stub），因此没有声称本机 `bash -n` 通过；Ubuntu CI 已加入该检查。完整本地 n=8/n=256 pipeline、Rust build/test 和 Groth16 setup 仍需在具备工具链的环境执行。

## 7. README and Documentation

英文与简体中文 README 已重写为简洁研究主页，包括论文与作者、总票数泄露示例、贡献、架构图、研究安全范围、已实现/拟议组件、历史 Q5 表格、Sepolia 与 local 阈值差异、许可证和 BibTeX。细节拆到 `docs/architecture.md`、`protocol.md`、`security-model.md`、`quickstart.md`、`experiments.md`、`paper-to-code.md`、`provenance.md`、`troubleshooting.md`。

## 8. Security and Artifact Hygiene

- `.gitignore` 排除新运行目录、私有 oracle 输入、witness、zkey、seed、secret、Rust target、npm dependencies 和编译产物；已实际检查典型运行文件被忽略。
- 私有 oracle 目录位于每次运行的 `private/oracle/`，与 `public/` 分开。公开导出拒绝没有通过 public replay 与 oracle 比对的目录，且不复制 oracle、witness、secret shares 或 proving keys。
- 对维护代码、文档和配置进行了私钥/凭据模式扫描，没有发现匹配的候选文件。该扫描不替代专用 secret-scanning 服务。
- 新本地实验不执行 RPC；Sepolia 新 run 仅提供 read-only preflight 与由作者显式发起的单独 transaction pipeline。此任务没有花费 testnet funds，也未提交交易。

## 9. GitHub Publication

- Feature branch：`cleanup/reproducibility-2026-11`。
- 首个源代码提交：`a547202f7f7c7e268d963e8ee0ee32fd27003eff`。
- PR：[#4 — Clean up repository and add reproducible experiments](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/pull/4)。分支已推送；PR 当前为开放状态，GitHub Actions 检查状态以链接中的最新提交为准。
- 仓库描述与八个研究相关 topic 已配置。没有修改默认分支、重写历史或覆盖已有 evidence release；没有发布新测量 release。
- `main` 尚未合并。完整新 n=256 pipeline 尚待带有 Rust/Circom/Groth16 工具链的作者环境验证，因此此 PR 保持可审阅状态。

## 10. Author Reproduction Guide

以下在 Windows PowerShell 中从干净 clone 运行。需要预先安装 Node.js 20+ 和 Visual Studio C++ build tools；Rustup/Circom 可按下面命令安装。命令会将 n=8 新 run 写入 `runs/`，再允许作者选择运行四种尺寸：

```powershell
git clone --branch cleanup/reproducibility-2026-11 https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance.git
Set-Location Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance

$rustupInstaller = Join-Path $env:TEMP "rustup-init.exe"
Invoke-WebRequest "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe" -OutFile $rustupInstaller
& $rustupInstaller -y --default-toolchain none --profile minimal
$env:Path += ";$env:USERPROFILE\.cargo\bin"
rustup toolchain install 1.98.1 --profile minimal

$toolDirectory = Join-Path $env:LOCALAPPDATA "winner-only-disclosure\tools"
New-Item -ItemType Directory -Force $toolDirectory | Out-Null
$env:CIRCOM_BIN = Join-Path $toolDirectory "circom-2.1.6.exe"
Invoke-WebRequest "https://github.com/iden3/circom/releases/download/v2.1.6/circom-windows-amd64.exe" -OutFile $env:CIRCOM_BIN
& $env:CIRCOM_BIN --version

# 首次运行：安装锁定依赖、构建 Rust backend，并创建新的 test-only ballot setup。
.\scripts\reproduce.ps1 -Sizes 8 -BuildArtifacts

# 所有四种 local size；每次都会创建新的唯一 runs/<id>/，不覆盖先前结果。
.\scripts\reproduce.ps1 -Sizes 8,64,256,1024

# 从实际成功 run 产物生成汇总。
node scripts/summarize_runs.js --format markdown
node scripts/summarize_runs.js --format csv
```

若 Node.js 不存在，请先从官方 Node.js 下载页安装 20 或更高版本。使用 Visual Studio MSVC Rust toolchain 时需要 C++ build tools。可按单个规模运行并检查 `runs/<id>/public/manifest.json`、`performance.json`、`verification.json` 与 `logs/`。不要分享整个 run 父目录；其中 `private/oracle/` 是私有输入。历史 Q5 数字仅在 evidence 页面展示，不会进入新 run 汇总。

### 可选：新的 Arbitrum Sepolia 实验

不执行下面的交易步骤，除非作者已决定使用新 poll ID、已确认测试币余额并准备接受部署/交易。复现脚本不会自动执行该 pipeline。

```powershell
$runId = "sepolia_n8_" + (Get-Date -Format "yyyyMMdd_HHmmss")
$env:ARBITRUM_SEPOLIA_RPC_URL = Read-Host "Arbitrum Sepolia RPC URL"
$secureKey = Read-Host "Funded testnet private key" -AsSecureString
$keyPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
try { $env:ARBITRUM_SEPOLIA_PRIVATE_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($keyPointer) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($keyPointer) }
$env:CGY_SEPOLIA_POLL_ID = Read-Host "Fresh unused decimal poll ID"
$env:CGY_N8_RUN_DIRECTORY = "runs\$runId\public"
$env:CGY_N8_ORACLE_DIRECTORY = "runs\$runId\private\oracle"
$env:CGY_BALLOT_ARTIFACT_ROOT = (Get-Location).Path

# 只做 read-only RPC preflight；不部署、不发送交易。
node protocol/scripts/sepolia_preflight.js

# 只有作者审阅 preflight 并决定执行后，才运行以下交易 pipeline。
npm ci --prefix contracts/arbitrum
npm --prefix contracts/arbitrum run compile
npm --prefix protocol run run:sepolia
```

## 11. Final Status

**READY_WITH_LIMITATIONS** — repository cleanup、README/docs、run tooling、source commit、历史 tag、release preservation 和 PR 已完成。fresh Groth16 pipeline 与 n=256 端到端验证尚未执行，原因是本机缺 Rust/Cargo、Circom 和新生成 proving artifacts；作者可按第 10 节在工具链齐全的环境运行后，再决定合并及是否发布新 evidence release。
