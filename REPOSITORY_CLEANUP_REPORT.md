# Repository Cleanup and Reproducibility Report

## 1. Executive Result

仓库已迁移到清晰的维护版目录，完成中英文主页、技术文档、四规模复现入口、运行清单、公共结果导出、汇总工具和 GitHub Actions 更新。`n=8/64/256/1024` 的新鲜本地实验均完成全流程并通过验证，公共安全导出及 59 项 SHA-256 清单均已校验。五取五配置和密码学协议语义未作修改。

实验使用清理版 commit `c60db5d7cb006c07db68743751a100e5c8e4260e`、Rust release 后端和新生成的 test-only Groth16 setup。门数和调度深度与论文一致，但 `n=256/1024` 用时明显高于历史 Q5；性能差异原因仍未定位。因此 fresh 结果如实发布为新观察，不声称复现历史性能。最终状态为 **READY_WITH_LIMITATIONS**。

## 2. Repository Before and After

| 清理前 | 清理后 | 内容/处理 |
|---|---|---|
| `backend/js_protocol/` | `protocol/` | 协议编排、runner、公共重放、JS 测试 |
| `backend/cgy_native/` | `native/` | Rust CGY 后端、调度和 transcript 工具 |
| `implementation/arbitrum/` | `contracts/arbitrum/` | Solidity、Hardhat、board binding 与 fixtures |
| `implementation/logs/bit_ballot/` | `artifacts/ballot/`（Git 忽略） | 本机生成的 Circom/Groth16 构建产物 |
| 分散的说明和实验文档 | `docs/` | 架构、协议、安全、复现、实验、映射、来源、排错 |
| 根目录实验脚本 | `scripts/` | setup、PowerShell/Bash 一键复现、校验、汇总、导出 |
| 历史 `evidence/` | `evidence/` 保留 | 原记录、冻结 Q5 源码和 hash 未搬移或改写 |
| 新实验输出 | `runs/`（除 README 外忽略） | 每次唯一目录，公开材料和私有 oracle 分开 |

`circuits/`、`configs/` 和 `evidence/` 留在根目录。主要文档入口为 `README.md`、`README.zh-CN.md`；具体迁移、运行边界和协议路径见 `docs/`。

## 3. Version Preservation

- 清理前默认分支 commit：`d193adb05424c31280bb7e1c9a0f4eb85294e40f`。
- 已推送 annotated tag [`archive/pre-cleanup-2026-11`](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/tree/archive/pre-cleanup-2026-11)，指向该清理前 commit；没有改写历史或 force-push。
- 原有 [`blocksys2027-evidence-v1`](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/releases/tag/blocksys2027-evidence-v1) 未修改。下载归档 SHA-256：`7169b79aa099fa42de3c37cadcdd6c21125b7ca4ac63e6a7419e9475cc776a84`，包内 81 项。
- 维护版从上述 `main` 清理而来。新实验使用的源 commit 为 `c60db5d7cb006c07db68743751a100e5c8e4260e`，实验时工作树干净。
- 版本关系与证据范围见 [`docs/provenance.md`](docs/provenance.md)：FC 2027 原始研究实现 → 冻结 Q5 测量源码 → 现有 evidence v1 → 清理维护版 → 本次新实验。历史 manifests、时间、transcript hashes、合约地址及冻结源码记录均未修改。

## 4. Source and Configuration Changes

- 迁移后修正了 JS 相对 import、文件路径、Rust Cargo 调用、Circom 构建路径、Hardhat 配置、包脚本、workflow、配置和文档链接。
- local runner 接受 `n=8,64,256,1024`；预期 `(gates, depth)` 依次为 `(134,72)`、`(1086,147)`、`(4350,207)`、`(17406,275)`。
- `n>=256` 的 transcript 写入、Rust gate producer 和公共 replay 使用文件流，减小内存峰值。本次 `n=256/1024` 的实际 transcript、hash 和 replay 均通过；没有改 ballot relation、BabyJub/Base8、CGY gate、threshold、accepted-board binding 或 release 逻辑。
- 每次实验使用 `a=5`、Shamir degree `t=4`、`q_dec=5`、8-bit 权重和已建立的加权阈值关系。local `tau=floor(255*n/4)`；Sepolia 的 n=8 参考实验为 `tau=500`，与 local n=8 的 `510` 不同。
- Groth16 产物由本次新生成的 test-only setup 创建：58,140 constraints、PTAU power 17；setup 用时约 14 分钟，未计入各规模运行时间。未复用历史 zkey、witness 或二进制。
- 新运行写入独一无二的 `runs/<id>/`。`public/` 与 `private/oracle/` 分开；结果汇总从新产物读取；白名单导出只在 replay 和 oracle 比对通过后执行。
- CI 的 push/PR 检查覆盖 Rust build/test、JS suite、跨语言兼容、合同编译/测试、board binding、路径与 Bash 语法。手动工作流可运行带 fresh test-only setup 的本地 n=8；大规模 Groth16 proving 不进入每次 push。

## 5. Experiment Support

以下为 2026-11-19 在清理维护版上的新鲜 local run。主表测量来自每次 `public/performance.json` 和 `public/manifest.json`，不是历史 CSV。

| n | 门数 | 深度 | 证明 (s) | admission (s) | Rust backend 阶段 (s) | release (s) | producer replay (s) | independent replay (s) | 完整每规模 pipeline (s) | 结果 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:---:|
| 8 | 134 | 72 | 17.947 | 0.620 | 5.302 | 8.031 | 1.282 | 2.900 | 38.645 | PASS |
| 64 | 1,086 | 147 | 150.325 | 2.566 | 24.397 | 4.583 | 13.050 | 14.982 | 226.338 | PASS |
| 256 | 4,350 | 207 | 592.009 | 9.414 | 83.640 | 8.873 | 59.714 | 70.161 | 886.193 | PASS |
| 1,024 | 17,406 | 275 | 2,363.563 | 34.649 | 322.893 | 6.960 | 246.083 | 281.850 | 3,507.043 | PASS |

四组均通过选票证明、admission、精确 board sealing、Rust CGY、五取五最终 release、独立 public replay、结果检查和隔离 oracle 比对。完整每规模时间还包括 compact encoding、独立 replay 和后置结果检查/oracle comparison；共享一次性的 setup 时间不包括在内。

这次确定使用 `native/target/release/cgy-native.exe`，通过 `cargo build --release --locked` 构建，不是旧版 JS 计票执行路径。`backend` 阶段包含 native 进程和 transcript journal 写入；n=1,024 的 Rust 内部 `backendMs=208.750s`，native 子进程 `216.218s`，journal 写入约 `106.348s`，外围总 backend 阶段 `322.893s`。这说明本次较长时间不是改走旧 JS 计票器造成的；但内部 Rust 时间本身也高于历史整段 backend 的 `156.715s`。历史 CSV 没有对应内部拆分数据，差异原因尚未查明，不能声称达到历史性能。

本次 n=1,024 JSONL 为 `3,539,239,193` bytes，compact transcript 为 `956,381,856` bytes；n=256 JSONL 为 `884,274,559` bytes。新结果与历史 Q5 的具体口径不同，尤其完整 pipeline 多含独立 replay、compact encoding、oracle comparison；不能直接比较总时间。

新运行原始目录在本机 `runs/`（Git 忽略）；白名单公开文件已单独打包成 `blocksys2027-evidence-v2-cleaned-local-2026-11` release，各包均低于 2 GB。该 release 的资产 SHA-256 清单随发布资产附上。四份 public export 的逐文件清单共 59 项，均与 `runs/public_exports/SHA256SUMS.txt` 匹配。

## 6. Verification

以下命令已实际执行，退出码为实测值：

| 命令/检查 | 结果 |
|---|---|
| `npm --prefix protocol test` | exit 0；49 passed |
| `npm --prefix contracts/arbitrum run compile` | exit 0；3 Solidity files 编译 |
| `npm --prefix contracts/arbitrum test` | exit 0；51 passed |
| `npm --prefix contracts/arbitrum run test:board-binding` | exit 0；3 passed |
| `npm --prefix protocol run replay:single-gate` | exit 0；`SINGLE_GATE_INDEPENDENT_REPLAY=PASS` |
| `npm --prefix protocol run test:group:reference` | exit 0；`CIRCOMLIB_REFERENCE_CROSSCHECK=PASS scalars=9` |
| `node --test scripts/experiment_config.test.js scripts/reproducibility.test.js` | exit 0；8 passed |
| `node scripts/check-repo-paths.js` | exit 0；22 files checked |
| 维护版 JavaScript `node --check` | exit 0；64 files checked |
| `.gitignore` 探针 | exit 0；runs/oracle/artifact/node_modules/target 均忽略，`runs/README.md` 保留跟踪 |
| `.\scripts\reproduce.ps1 -Sizes 8,64,256,1024 -BuildArtifacts` | exit 0；四个规模 `EXPERIMENT=PASS` |
| public run 导出器 | 每规模 13 个白名单文件 + `EXPORT_README.md`；全部 PASS |
| public export SHA-256 | exit 0；59 项 PASS |
| release `.tar.gz` 完整性/目录检查 | 全部 7 个 archive 可完整读取，全部小于 2 GB |
| `git diff --check` | exit 0；仅 Git 换行提示 |
| PR workflow `fast-validation` | GitHub Actions pass；PR #4 对应提交检查记录见 [PR Checks](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/pull/4) |

首次缺工具链时的 `-Sizes 8` 和 cross-language 尝试曾因 rustc/binary 缺失失败；随后已装上锁定 toolchain 并重新执行上述完整四规模流程。那次失败不作为最终 run。Arbitrum Sepolia 只准备了说明；未执行 RPC preflight 或链上交易。

## 7. README and Documentation

英文与简体中文 README 包含研究问题示例、贡献、架构、可信范围、历史与新 fresh 结果、quick start、Sepolia 边界、仓库地图、GPLv3 和 BibTeX。详细材料位于 `docs/architecture.md`、`protocol.md`、`security-model.md`、`quickstart.md`、`experiments.md`、`paper-to-code.md`、`provenance.md` 和 `troubleshooting.md`。

README 和实验文档将历史 Q5 表标为历史，将本次清理版 run 单列，并把 producer replay 和 independent replay 分开。当前新数据的真实性与验证状态明确记录；性能差距没有被重新包装成复现成功。

## 8. Security and Artifact Hygiene

- `.gitignore` 排除所有新 run、oracle 私有数据、witness、zkey、Rust target、npm 依赖和编译产物；public exports 不包含 private oracle。
- n=1024 单个 transcript 大于 3.5 GB；已拆成单独的压缩 JSONL 与 compact transcript。所有 GitHub release 附件小于 2 GB。
- 公共导出通过白名单生成。59 项 public export SHA-256 均通过；压缩包逐个通过 tar/gzip 完整性读取检查。压缩资产 SHA-256 列于 evidence v2 的独立 checksums 附件。
- 秘钥/凭据模式扫描没有发现维护代码、配置或文档中的候选；该检查不等同于专用 secret scanning。私有 oracle 文件没有打包或公开。
- 所有四个新实验均为 local/off-chain。未使用 RPC、未部署合约、未发起 Sepolia 交易、未花费测试币。

## 9. GitHub Publication

- 功能分支：`cleanup/reproducibility-2026-11`。
- 当前清理和复现 PR：[#4](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/pull/4)。分支提交及最新 checks 以 GitHub 页面为准。
- 预期新证据 release/tag：[`blocksys2027-evidence-v2-cleaned-local-2026-11`](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/releases/tag/blocksys2027-evidence-v2-cleaned-local-2026-11)，目标只包含本次四规模新运行的 public-safe 文件和摘要。历史 v1 不变。
- `main` 合并和新 evidence release 的最终 GitHub 状态应以 PR/release 页面及本报告最后更新的提交状态为准。不得覆盖/删除 v1，不要把私有 `runs/<id>/private/` 上传。

## 10. Author Reproduction Guide

以下顺序适用于全新 Windows PowerShell checkout。先安装 Node.js 20+、Git 和 Visual Studio C++ Build Tools；再执行锁定 Rust/Circom setup。Circom 使用官方 2.1.6 Windows release。作者当前机器已经完成过这套 setup；Groth16 setup 约 14 分钟，首次产生的 test-only artifacts 不可用于真实投票。

```powershell
git clone --branch main https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance.git
Set-Location Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance

$rustupInstaller = Join-Path $env:TEMP 'rustup-init.exe'
Invoke-WebRequest 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe' -OutFile $rustupInstaller
& $rustupInstaller -y --default-toolchain none --profile minimal
$env:Path += ";$env:USERPROFILE\.cargo\bin"
rustup toolchain install 1.98.1 --profile minimal

$toolDirectory = Join-Path $env:LOCALAPPDATA 'winner-only-disclosure\tools'
New-Item -ItemType Directory -Force $toolDirectory | Out-Null
$env:CIRCOM_BIN = Join-Path $toolDirectory 'circom-2.1.6.exe'
Invoke-WebRequest 'https://github.com/iden3/circom/releases/download/v2.1.6/circom-windows-amd64.exe' -OutFile $env:CIRCOM_BIN
& $env:CIRCOM_BIN --version
node --version
rustc --version
cargo --version

# 首次运行：安装锁定依赖、release 构建 Rust backend、新建 test-only Groth16 setup，并完成全流程 n=8。
.\scripts\reproduce.ps1 -Sizes 8 -BuildArtifacts

# 同一 setup 完成后，需要四个 fresh local 尺寸时执行：
.\scripts\reproduce.ps1 -Sizes 8,64,256,1024

# 只根据成功生成的新 manifests 汇总：
node scripts/summarize_runs.js --format markdown
node scripts/summarize_runs.js --format csv
```

验证标记应包含 `LOCAL_NATIVE_EXECUTION=PASS`、`LOCAL_PUBLIC_REPLAY=PASS`、`ORACLE_COMPARISON=PASS` 和 `EXPERIMENT=PASS`。本次首次新 n=8 的精确命令是：

```powershell
$env:CIRCOM_BIN = "$env:LOCALAPPDATA\winner-only-disclosure\tools\circom-2.1.6.exe"
.\scripts\reproduce.ps1 -Sizes 8 -BuildArtifacts
```

可选 Sepolia 步骤：只在作者决定开展新 on-chain 运行后，提供 RPC endpoint、未用 poll ID、测试网有余额的 deployer 和独立 fresh output/private oracle 路径。先运行 `node protocol/scripts/sepolia_preflight.js` 做只读检查。随后是否运行 `npm --prefix contracts/arbitrum run compile` 和 `npm --prefix protocol run run:sepolia` 由作者自行决定；后一条会部署并提交交易。本任务没有执行它。

## 11. Final Status

**READY_WITH_LIMITATIONS** — 四种规模均已在清理版 Rust release 后端上新鲜完成并通过验证，结构值正确，公共安全证据包已拆分并校验。历史性能比当前 fresh 大规模测量更快，差异原因未定位；因此不能称为历史 timing replication，也不应替换论文中的 Q5 数值。PR、主分支合并和新证据 release 以 GitHub 最终状态为准；没有运行链上实验。
