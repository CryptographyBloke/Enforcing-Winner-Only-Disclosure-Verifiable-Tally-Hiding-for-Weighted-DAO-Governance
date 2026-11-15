# 强制仅披露获胜结果

[《Enforcing Winner-Only Disclosure: Verifiable Tally Hiding for Weighted DAO Governance》](https://eprint.iacr.org/2026/1773) 的研究代码与复现说明。

**语言：** [English](README.md) | 简体中文

本仓库包含构建参考实现、运行测试以及开展全新本地实验所需的源代码和脚本，也包含论文两张结果表背后的原始运行记录（目录 [`evidence/`](evidence/README.md)，说明为英文）。这是研究原型，不是可直接用于生产环境的治理投票软件。测试通过或实验成功本身并不能证明论文中的定理及其假设成立。

## 选择要复现的内容

| 目标 | 从这里开始 | 是否需要钱包或公共 RPC？ |
|---|---|---:|
| **一步一步复现 n=8 结果（Rust 后端）** | [分步指南](#分步指南用-rust-后端复现-n8-结果) | 否 |
| 核对论文记录的 Sepolia 运行与表格数据 | [`evidence/README.md`](evidence/README.md)（英文） | 只需要只读 RPC |
| 检查协议、原生后端和合约测试 | [验证](#验证) | 否 |
| 运行更大规模的本地实验 | [本地规模实验](#本地规模实验) | 否 |
| 在 Arbitrum Sepolia 上运行全新 n=8 实验 | [公共测试网实验](#在-arbitrum-sepolia-上运行全新的-n8-实验) | 是 |
| 重放已有的公共实验 | [公共重放](#重放已有公共运行) | 只需要只读 RPC |

首次复现建议从本地 n=8 开始（见下面的分步指南）。它会依次执行选票关系检查、全新的测试用密钥设置、精确的已接受选票板 admission、原生 CGY tally、五份 trustee share 的结果释放、独立重放和隔离的 oracle 比较，不需要消耗测试网资金。

## 参考配置与范围

最终参考配置为 `winner-only-disclosure/five-of-five/v1`：

- 五名 trustee；Shamir 多项式次数为 4；最终解密必须使用全部五份 share。
- 链上合约是固定为八张选票的 `StrongN8Poll` 参考实现。
- 当前本地规模 runner 支持 **n = 8、64 和 1024**。其他规模尚未开放。论文中 n = 256 一行由冻结的发布前 runner 产生，它与当前 runner 只差三处已记录的比较条件（见 [`evidence/README.md`](evidence/README.md)）；当前 runner 不接受 n = 256。
- 本地实验的阈值为 `floor(255*n/4)`；n=8 合约参考配置使用 `tau = 500`。
- 本地 setup 由单进程的**测试专用 dealer**生成，不是生产级 DKG 或可信 setup 仪式。
- common-view board 是本地参考服务，不是拜占庭共识协议。

本地规模实验与公共链传输实验是两类不同的实验。公共合约仍固定为 n=8；不要把本地 n=64 或 n=1024 结果描述为公共链部署。

## 环境依赖

| 工具 | 版本 / 用途 |
|---|---|
| Node.js 与 npm | Node.js 20 或更高版本。各 package 均包含 npm lockfile。 |
| Rust 与 Cargo | `rust-toolchain.toml` 固定 Rust 1.98.1；`backend/cgy_native/Cargo.lock` 固定 Cargo 依赖。请通过 [rustup](https://rust-lang.org/tools/install) 安装 Rust。Windows 需安装 MSVC 目标所需的 Visual Studio C++ Build Tools。 |
| Circom 编译器 | 只有构建本地选票电路产物时才需要 Circom 2.1.6。请参考 [Circom 官方安装指南](https://docs.circom.io/getting-started/installation/)。 |
| Arbitrum Sepolia RPC | 只有运行全新的公共测试网实验或公共重放时才需要。新部署还需要有测试网余额的 deployer 密钥。 |

电路使用的 circomlib 2.0.5 固定在 `circuits/package-lock.json` 中；后端 package 固定使用 snarkjs 0.7.6。无需全局安装 snarkjs。

Windows 安装 Rust 后，请重新打开一个 **PowerShell** 窗口，确保 rustup 的 `%USERPROFILE%\.cargo\bin` 已加入 `PATH`。如果 Circom 不在 `PATH` 中，可在当前 PowerShell 会话中将 `CIRCOM_BIN` 设置为其完整路径；构建脚本会检查编译器版本是否为 2.1.6。

<a id="clean-checkout"></a>
## 1. 获取干净的仓库副本

以下命令均从仓库根目录运行：

```powershell
git clone https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance.git
Set-Location Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance
```

安装依赖前先检查工具版本：

```powershell
node --version
npm --version
rustc --version
cargo --version
circom --version
```

在此 checkout 中首次运行 Cargo 命令时，会根据 `rust-toolchain.toml` 使用固定的 Rust 工具链。如果使用其他 shell，请按该 shell 的语法设置下文列出的相同环境变量。

## 2. 安装依赖并构建

在每个 package 中使用锁定的 manifest 安装依赖：

```powershell
npm ci --prefix circuits
npm ci --prefix backend/js_protocol
npm ci --prefix implementation/arbitrum
cargo build --release --locked --manifest-path backend/cgy_native/Cargo.toml
npm --prefix implementation/arbitrum run compile
```

只有 Solidity 编译/测试及公共链实验需要合约 package。运行全新的本地选票/tally 实验则需要 circuits、JS backend package 和 Rust。

### 构建本地选票证明产物

仓库不会存放生成的 proving key 或 WASM 文件。请在本机生成：

```powershell
npm --prefix backend/js_protocol run build:ballot
```

该命令会编译 `circuits/prototypes/strong_bit/vote_bit_full_8.circom`，并在 `implementation/logs/bit_ballot/` 下生成本地 WASM、R1CS、verification key 和一套**全新、临时使用的 Groth16 key**。setup 脚本使用临时测试用 powers-of-tau，并拒绝覆盖已命名的输出。生成产物已被 Git 忽略。这些产物仅用于功能实验；不得将这套测试 setup 用于真实投票，也不得称其为可信仪式。

如果此步骤失败，请先确认 `circom --version` 显示 2.1.6，并确认 `npm ci --prefix circuits` 和 `npm ci --prefix backend/js_protocol` 均成功完成。

<a id="validation"></a>
## 验证

### 快速协议与跨语言检查

```powershell
cargo test --locked --manifest-path backend/cgy_native/Cargo.toml
npm --prefix backend/js_protocol test
npm --prefix backend/js_protocol run test:group:reference
npm --prefix backend/js_protocol run test:cross-language
npm --prefix backend/js_protocol run test:threshold-release
```

JS 测试覆盖群与点验证、证明/挑战绑定、masking、rerandomization、threshold decryption、验证状态转换、broadcast board 一致性、已接受选票板绑定、最终释放及 transcript 篡改。Rust 测试覆盖原生群与 gate 路径。跨语言测试会比较确定性的 JS/Rust gate 记录。

部分 JS 测试会有意调用默认值为历史 3-of-5 配置的通用参考 helper。当前五 trustee 的端到端 runner 和 `five_of_five_*` 测试使用最终 5-of-5 配置。

### 合约检查

```powershell
npm --prefix implementation/arbitrum run compile
npm --prefix implementation/arbitrum test -- --grep StrongN8Poll
npm --prefix implementation/arbitrum run test:board-binding
```

合约测试使用仓库内的公开选票 fixture 和本地 EVM，不会向 Arbitrum Sepolia 发送交易。

GitHub Actions 会运行快速 Rust、JS、跨语言和合约检查；它**不会**生成本地 Groth16 setup，也不会运行耗时较长的端到端规模实验。后续章节介绍这些步骤。

<a id="complete-local-n8-run"></a>
## 分步指南：用 Rust 后端复现 n=8 结果

这一节带你从一台空机器走到一次通过验证的本地 n=8 实验。不需要钱包，不需要测试网资金，装好依赖后也不需要联网。所有命令都在**仓库根目录**执行。下面每一条"预期输出"都是在本仓库的干净克隆上实际观察到的（Windows 11、Node.js 24.15、Rust 1.98.1、Circom 2.1.6、Intel Core i7-14650HX）。耗时只是示例，取决于你的机器。

做完之后你验证了什么：选票关系的 Groth16 证明通过；加密 tally 由 Rust 后端在精确的已接受 ciphertext 上计算；五份 trustee share 只打开最终的决策比特；一个独立的重放进程在不接触秘密 share 的情况下重新验证了整个 transcript；与隔离的明文 oracle 比较，结果一致。

### 第 0 步：准备环境

| 工具 | 版本 | 检查命令 |
|---|---|---|
| Git | 较新版本即可 | `git --version` |
| Node.js 与 npm | 20 或更高 | `node --version` |
| Rust 与 Cargo | 1.98.1（rustup 会按 `rust-toolchain.toml` 自动安装） | `cargo --version` |
| Circom | 必须是 2.1.6 | `circom --version` 应输出 `circom compiler 2.1.6` |
| 磁盘 | 约 1 GB 空闲（见第 7 步的表） | |
| 时间 | 总共约 20 分钟，其中第 3 步一次性生成密钥约 11 分钟 | |

Circom 2.1.6 的可执行文件在 [release 页面](https://github.com/iden3/circom/releases/tag/v2.1.6)（`circom-linux-amd64`、`circom-macos-amd64`、`circom-windows-amd64.exe`）。下载对应系统的文件，改名为 `circom`（Windows 为 `circom.exe`），赋予可执行权限并放到 `PATH` 中；也可以放在任意位置，然后在执行第 3 步的 shell 里把 `CIRCOM_BIN` 设为它的完整路径。不要用其他版本：构建脚本会报错并停止。

### 第 1 步：克隆并安装依赖

```bash
git clone https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance.git
cd Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance
npm ci --prefix circuits
npm ci --prefix backend/js_protocol
```

预期：两条 `npm ci` 都以 `found 0 vulnerabilities` 结束。

### 第 2 步：构建原生 Rust 后端

```bash
cargo build --release --locked --manifest-path backend/cgy_native/Cargo.toml
```

预期：命令以 `Finished` 结束，首次构建约 40 秒。它会生成 `backend/cgy_native/target/release/cgy-native`（Windows 上是 `cgy-native.exe`）。JavaScript runner 会自动找到这个文件；只有挪动过它时才需要设置 `CGY_NATIVE_BIN`。

### 第 3 步：生成选票证明密钥（一次性，约 11 分钟）

```bash
npm --prefix backend/js_protocol run build:ballot
```

脚本先编译 `circuits/prototypes/strong_bit/vote_bit_full_8.circom`，再生成一把**一次性的测试专用** Groth16 密钥。这是最慢的一步。它会为每个阶段打印一行（`Compiling the ballot circuit ...`、`Creating temporary test powers-of-tau ...`、`Preparing phase two test parameters ...`），而最后两个阶段会有很长一段时间没有任何输出。请不要中断。

预期最后两行：

```text
ZKEY=implementation/logs/bit_ballot/groth16/vote_bit_full_8/vote_bit_full_8_final.zkey
VKEY=implementation/logs/bit_ballot/groth16/vote_bit_full_8/verification_key.json
```

脚本不会覆盖已有输出。要重新构建，先删除 `implementation/logs/bit_ballot/`。这把密钥只用于功能实验，不是可信 setup 仪式，绝不能用于真实投票。

### 第 4 步：运行快速检查（几分钟）

```bash
cargo test --locked --manifest-path backend/cgy_native/Cargo.toml
npm --prefix backend/js_protocol test
npm --prefix backend/js_protocol run test:group:reference
npm --prefix backend/js_protocol run test:cross-language
npm --prefix backend/js_protocol run test:threshold-release
```

预期：

| 命令 | 实际观察到的结果 |
|---|---|
| `cargo test` | `test result: ok. 2 passed`（`lib` 与 `babyjub_compat` 各一次） |
| `test` | `ℹ tests 49`、`ℹ pass 49`、`ℹ fail 0` |
| `test:group:reference` | `CIRCOMLIB_REFERENCE_CROSSCHECK=PASS scalars=9` |
| `test:cross-language` | `JS_GATE_VERIFIED_BY_RUST=PASS` 和 `RUST_GATE_VERIFIED_BY_JS=PASS` |
| `test:threshold-release` | `ℹ tests 7`、`ℹ pass 7`、`ℹ fail 0` |

`test:cross-language` 检查 JavaScript 参考 gate 与 Rust gate 能否互相验证对方的 transcript。这说明快速的 Rust 后端计算的就是参考实现所计算的关系。

### 第 5 步：运行 n=8 流程

每次都要选择**全新的**运行目录名。runner 会拒绝覆盖已有目录。

macOS 与 Linux（bash 或 zsh）：

```bash
export CGY_LOCAL_N=8
export CGY_LOCAL_RUN_DIRECTORY=artifacts/local_five_trustee_n8_run_001
export CGY_N8_ORACLE_DIRECTORY=artifacts/local_five_trustee_n8_run_001_oracle
export CGY_BALLOT_ARTIFACT_ROOT="$(pwd)"
```

Windows PowerShell：

```powershell
$env:CGY_LOCAL_N = "8"
$env:CGY_LOCAL_RUN_DIRECTORY = "artifacts/local_five_trustee_n8_run_001"
$env:CGY_N8_ORACLE_DIRECTORY = "artifacts/local_five_trustee_n8_run_001_oracle"
$env:CGY_BALLOT_ARTIFACT_ROOT = (Get-Location).Path
```

然后**按这个顺序**运行三个阶段：

```bash
npm --prefix backend/js_protocol run run:local-scale
npm --prefix backend/js_protocol run replay:local
npm --prefix backend/js_protocol run compare:oracle
```

| 阶段 | 做什么 | 预期输出（实测） | 实测耗时 |
|---|---|---|---|
| `run:local-scale` | 全新的测试用五 trustee setup、八张证明有效的选票、admission、sealed board、Rust 计算 134 个 gate、五份 share 释放 | `LOCAL_NATIVE_EXECUTION=PASS`、`N=8`、`GATES=134`、`FINAL_THRESHOLD=5_OF_5`、`ORACLE_INPUTS_ISOLATED=YES` | 约 30 到 40 秒，见下面的说明 |
| `replay:local` | 独立进程重新验证 setup、证明、board、每个 gate、release 和各哈希，**不读取** oracle | `LOCAL_PUBLIC_REPLAY=PASS`、`SOURCE_GATES_VERIFIED=134`、`ORACLE_READ=NO` | 约 6 秒 |
| `compare:oracle` | 仅在重放通过后：把释放出的比特与明文 oracle 比较 | `ORACLE_COMPARISON=PASS`，且 `RESULT_BIT` 等于 `ORACLE_RESULT_BIT` | 不到 1 秒 |

**耗时与并行证明。** 八张选票的证明彼此独立，所以 `run:local-scale` 最多同时证明 3 张，每张在自己的进程里（`CGY_BALLOT_PROOF_CONCURRENCY`，默认 3）。在 24 线程的机器上，单个 snarkjs 证明已经用了约 11 个线程，所以同时超过 3 张没有帮助。在上述机器上交替运行同一份代码的实测：`CGY_BALLOT_PROOF_CONCURRENCY=1` 时证明阶段约 18 秒，默认值时约 10 秒。其余阶段每次运行都有波动（我们的运行里，五份 share 的 release 阶段在 7 秒到 15 秒之间），所以尝试别的取值时请对比 `manifest.json` 里的**证明**一项，而不是总耗时。证明本身和 board 的顺序不受影响：第 `i` 张选票始终是 `publicProofs[i]`。

本地实验的选票权重与选择是固定的（`weights[i] = (37 i + 11) mod 256`，`votes[i] = (7 i + 1) mod 2`），密钥、随机数和证明则每次全新生成。所以**结果比特和各项计数每次都相同**（`n = 8`、`tau = 510`、134 个 gate、深度 72、结果比特 `0`），而哈希、证明和耗时每次不同。与论文本地规模表对照时，只比较结构性的列（gate 数与深度）。论文 `n = 8` 的耗时是在一台指定工作站上记录的，见 [`evidence/`](evidence/README.md)。

### 第 6 步：查看产出

```bash
ls artifacts/local_five_trustee_n8_run_001
```

| 文件 | 含义 | 是否可公开 |
|---|---|---|
| `manifest.json` | 参数、gate 数、深度、各阶段耗时、所有哈希 | 是 |
| `benchmark_summary.json` | 同样的耗时（扁平汇总）以及 `oracleMatchesProtocol` | 是 |
| `public_setup.json`、`ballot_public_proofs.json`、`local_admission_board.json` | 公开输入 | 是 |
| `gate_transcript.jsonl`（约 27 MB）与 `gate_transcript.compact.bin`（约 7 MB） | 规范 transcript 及其无损压缩形式 | 是 |
| `final_release.json` | 五份 share 的 release 记录 | 是 |
| `public_replay.json` | 独立重放的结果 | 是 |
| `artifacts/..._oracle/` | 明文 oracle 输入 | **否，请保密** |

读取各阶段耗时：

```bash
node -e "const t=require('./artifacts/local_five_trustee_n8_run_001/manifest.json').timing; console.log(t)"
```

论文的本地规模表报告的是同样几个阶段：证明、admission、后端、release、重放。

### 第 7 步：清理（可选）

| 目录 | 实测大小 | 用完可删除 |
|---|---|---|
| `backend/cgy_native/target/` | 534 MB | 可以，用第 2 步重建 |
| `backend/js_protocol/node_modules/` | 118 MB | 可以，用 `npm ci` 重装 |
| `implementation/logs/bit_ballot/` | 51 MB | 可以，但第 3 步要再花 11 分钟 |
| `artifacts/local_five_trustee_n8_run_001/` | 34 MB | 可以 |

它们都已被 git 忽略。

### 本分步指南的常见问题

| 现象 | 原因与处理 |
|---|---|
| 第 5 步很慢，或选票证明阶段内存不足 | 八个 Groth16 证明在各自的进程里并行，默认同时 3 个。在 `run:local-scale` 之前把 `CGY_BALLOT_PROOF_CONCURRENCY` 设为更小的正整数（例如 `1`，表示像以前一样在当前进程里一次证明一个）。 |
| 第 3 步报 `Circom 2.1.6 is required` | `circom --version` 输出了其他版本，或 Circom 不在 `PATH`。安装 2.1.6，或设置 `CIRCOM_BIN`（PowerShell：`$env:CIRCOM_BIN = "C:\tools\circom.exe"`）。 |
| 第 3 步看起来卡住了 | 没有卡住。最后两个阶段（powers-of-tau 与 Groth16 密钥）约需 11 分钟且没有输出。 |
| 第 5 步报 `E_LOCAL_RUN_EXISTS` 或 `E_LOCAL_ORACLE_EXISTS` | 该目录是上次运行留下的。两个变量都换成新的 `_002` 名字。 |
| 第 5 步因缺少选票产物而停止 | 先完成第 3 步，并保持 `CGY_BALLOT_ARTIFACT_ROOT` 等于仓库根目录。 |
| 找不到 `native` 二进制 | 先做第 2 步。若构建在别处，把 `CGY_NATIVE_BIN` 设为 `cgy-native` 的完整路径。 |
| 在 Windows 上，`python` 或 `node` 不认从 Git Bash 里复制的 `/tmp/...` 路径 | 原生 Windows 程序需要 Windows 路径。在 Git Bash 里用 `cygpath -m /tmp/x` 转换；在 PowerShell 里用普通的 `C:\...` 路径。 |

## 完整本地 n=8 实验

上面的分步指南是推荐路线。下面的内容用 PowerShell 语法更详细地描述同一条流水线。

运行前，请先构建依赖、Rust release binary 和本地选票产物。每次实验都要选择全新的输出目录名：runner 会拒绝覆盖已有实验目录或 oracle 目录。

```powershell
$env:CGY_LOCAL_N = "8"
$env:CGY_LOCAL_RUN_DIRECTORY = "artifacts/local_five_trustee_n8_run_001"
$env:CGY_N8_ORACLE_DIRECTORY = "artifacts/local_five_trustee_n8_run_001_oracle"
$env:CGY_BALLOT_ARTIFACT_ROOT = (Get-Location).Path

npm --prefix backend/js_protocol run run:local-scale
npm --prefix backend/js_protocol run replay:local
npm --prefix backend/js_protocol run compare:oracle
```

oracle 目录必须与协议实验目录分开。不要将 oracle 输入复制到协议进程，也不要作为公共证据发布。

执行顺序有意安排如下：

1. `run:local-scale` 生成全新的五 trustee 测试 setup 和 proof-valid 选票，执行本地 admission 检查并封存 board，将精确获批的 ciphertext 交给 Rust DAG evaluator，然后写入五份 share 的最终 release 和 transcript。
2. `replay:local` 独立检查公开 setup、选票证明、获批 board 及 ciphertext 顺序、broadcast 记录、原生 gate DAG、最终 release 和 transcript hash。它不会读取明文 oracle。
3. `compare:oracle` 是隔离的测试 harness 步骤。**只有 public replay 成功后才能运行**；它会比较释放的结果位与 oracle 结果，但不会发布加权总和。

n=8 实验成功时，终端会包含 `LOCAL_NATIVE_EXECUTION=PASS`、`LOCAL_PUBLIC_REPLAY=PASS` 和 `ORACLE_COMPARISON=PASS`，且结果位一致。gate 数量和耗时由本次运行实际计算；不要把历史实验数字直接当作本次结果。

<a id="local-scale-runs"></a>
## 本地规模实验

同一个本地 runner 仅接受 **8、64 或 1024**。先完成 n=8，再尝试更大规模。n=64 或 n=1024 时，请设置新的唯一实验目录和对应的 oracle 目录，然后运行上一节中的三条命令。例如：

```powershell
$env:CGY_LOCAL_N = "64"
$env:CGY_LOCAL_RUN_DIRECTORY = "artifacts/local_five_trustee_n64_run_001"
$env:CGY_N8_ORACLE_DIRECTORY = "artifacts/local_five_trustee_n64_run_001_oracle"
$env:CGY_BALLOT_ARTIFACT_ROOT = (Get-Location).Path
```

n=1024 时，将数量和两个目录名中的 `64` 替换为 `1024`。runner 会推导 arithmetic DAG 和 `tau = floor(255*n/4)`，并在运行 manifest/summary 中记录实际 gate 数量、depth、ready width、耗时、transcript 大小和输出。大规模实验会产生大量证明计算和 transcript 文件，运行前请检查磁盘和内存余量；不要让多个大任务写入同一目录。

这些本地实验使用相同的选票关系和 Q5 密码学配置，但 admission 使用本地 sealed-board harness，而非公共链传输。它们是规模实验，不是公共部署。

<a id="fresh-arbitrum-sepolia-n8-run"></a>
## 在 Arbitrum Sepolia 上运行全新的 n=8 实验

此步骤可选，会消耗 Arbitrum Sepolia 测试 ETH。它会部署现有 n=8 verifier/poll、提交八张选票、运行 Q5 tally、发布现有结果 claim，并生成公共运行证据包。无需修改合约。

发送交易前：

1. 为本次运行设置**全新的唯一** run 目录、oracle 目录和十进制 `CGY_SEPOLIA_POLL_ID`。
2. 设置 `ARBITRUM_SEPOLIA_RPC_URL`，并通过安全的钱包/secret manager 将 `ARBITRUM_SEPOLIA_PRIVATE_KEY` 加载到当前 shell。切勿将真实密钥粘贴到 README、脚本、已提交的 `.env` 或 transcript 中。
3. 设置 `CGY_NATIVE_BACKEND=1`，确保公共运行使用 Rust tally backend。若未设置，runner 会使用 JS reference gate 路径。
4. 运行 preflight，并检查链 ID 是否为 `421614`、RPC 是否可响应，以及测试网 deployer 余额是否足够支付部署、八笔提交和最终 claim。preflight 会报告地址与余额，但不能保证余额足以覆盖服务商当前 gas 价格。

PowerShell 配置与执行示例：

```powershell
$env:ARBITRUM_SEPOLIA_RPC_URL = "https://sepolia-rollup.arbitrum.io/rpc"
# 在当前 shell 中通过安全方式加载 ARBITRUM_SEPOLIA_PRIVATE_KEY；不要将其保存到仓库。
# 这里只是示例，请为每次运行选择全新且未使用的十进制 poll ID。
$env:CGY_SEPOLIA_POLL_ID = "202610110001"
$env:CGY_NATIVE_BACKEND = "1"
$env:CGY_N8_RUN_DIRECTORY = "artifacts/public_sepolia_n8_run_001"
$env:CGY_N8_ORACLE_DIRECTORY = "artifacts/public_sepolia_n8_run_001_oracle"
$env:CGY_BALLOT_ARTIFACT_ROOT = (Get-Location).Path

node backend/js_protocol/scripts/sepolia_preflight.js
npm --prefix backend/js_protocol run run:sepolia
```

公共运行会生成全新的测试用委员会 setup 和选票证明，通过未修改的 n=8 合约提交选票，将 backend 输入绑定到链上接受的 ciphertext 坐标，运行 134 个 source gate，使用五份经过验证的 share 释放结果，并提交最终结果 claim。它还会在检查 verification-key SHA-256 与选票生成 manifest 一致后，将完全相同的 verification-key 字节复制到运行证据包，供独立 public replayer 使用。run 目录可作为公共证据；同级 oracle 目录必须保持私密。

### 重放公共运行

重放只需公开产物和**只读** Arbitrum Sepolia RPC，不需要 deployer 密钥。运行重放前先从 shell 移除签名密钥：

```powershell
Remove-Item Env:ARBITRUM_SEPOLIA_PRIVATE_KEY -ErrorAction SilentlyContinue
npm --prefix backend/js_protocol run replay:sepolia
npm --prefix backend/js_protocol run compare:oracle
```

重放成功标记为 `PUBLIC_REPLAY=PASS`。只有出现此标记后才能进行 oracle 比较。公共 RPC 可能会对历史 receipt/block 查询限流；如果重放中断，请换用具备历史读取能力的可靠只读 endpoint，并对同一个保留的 run 目录重新运行重放。

<a id="replay-a-public-run"></a>
## 重放已有公共运行

本仓库**不包含**论文所记录的那次历史 Sepolia 运行的大体积 gate transcript；那份保存的运行包只能用 [`evidence/frozen_source_q5/`](evidence/README.md) 里冻结的发布前源码验证，不能用本目录的代码验证。运行记录、哈希和无需密钥的检查脚本在 [`evidence/`](evidence/README.md)。要重放一次**新的**运行，请向运行者获取其 public run 目录，并确认其中包含 manifest、公开 setup、公开选票证明、链快照、sealed board、gate transcript（JSONL 或受支持的 compact 格式）、最终 release 记录、verification key 和所需合约产物。不要向运行者索取私钥、选票 witness 或明文 oracle 输入。

在仓库根目录构建合约产物并设置：

```powershell
$env:ARBITRUM_SEPOLIA_RPC_URL = "https://sepolia-rollup.arbitrum.io/rpc"
$env:CGY_N8_RUN_DIRECTORY = "D:/path/to/the/public/run-bundle"
$env:CGY_BALLOT_ARTIFACT_ROOT = (Get-Location).Path
npm --prefix backend/js_protocol run replay:sepolia
```

重放会验证链 ID、部署及 runtime code、选票 receipt 和 event、精确 ciphertext 坐标、证明有效性、sealed board、CGY transcript、最终 release 以及公共结果 claim。oracle 比较是重放后的独立评估步骤，需要本地单独保存的 oracle 目录；它不属于 public replay。

## 生成文件与来源记录

| 输出 | 内容 | 是否公开分享？ |
|---|---|---|
| `implementation/logs/bit_ballot/` | 生成的电路及本地测试 proving 产物 | 通常无需分享；检查源代码或通过 `build:ballot` 重新生成并不需要这些文件。 |
| `artifacts/local_five_trustee_*/` | 本地运行 manifest、公开输入、transcript、重放结果和 summary | 其中的公开部分可以分享；发布前请逐项检查。 |
| `artifacts/*_oracle/` | 明文测试 oracle 输入 | **不要公开**；分开保存并保持私密。 |
| `artifacts/public_sepolia_*/` | 公共链运行证据和 transcript | 确认不包含凭据或私有 oracle 数据后可以分享。 |

运行目录按约定视为不可变：脚本会在所选输出目录已存在时失败。请使用新的 run ID，不要覆盖以往实验。`.gitignore` 会排除生成的 proving key、本地日志、oracle 目录和大型 transcript；提交前仍需检查具体文件。

若要形成可复现报告，请保留 source commit、runtime/toolchain 版本、run manifest、public setup hash、accepted-board hash、transcript hash 和 replay 结果。耗时受硬件影响，应记录实际运行值，而不是将其视为固定保证。

## 仓库结构

| 路径 | 用途 |
|---|---|
| `backend/cgy_native` | 原生 BabyJubjub 运算、CGY gate 证明的生成/验证、DAG 调度、transcript codec 和流式 public replay |
| `backend/js_protocol` | threshold 测试 setup、选票 witness/证明编排、Groth16 验证、admission/binding、board 逻辑、最终 release adapter、runner 和 JS reference implementation |
| `circuits/prototypes/strong_bit` | 当前 8 位加权选票 Circom 关系及包含的 BabyJubjub/ElGamal 电路库 |
| `implementation/arbitrum` | `StrongN8Poll`、Groth16 verifier、Hardhat 配置、选票 fixture、合约测试和链上 board-binding 代码 |
| `configs/reference/five_of_five_n8.json` | 机器可读的最终参考配置 |
| `scripts/setup` | 生成全新的本地测试选票产物 |
| `evidence` | 论文表格背后的原始运行记录、哈希、产生这些记录的冻结源码，以及无需密钥的复核脚本。见 [`evidence/README.md`](evidence/README.md)（英文） |

Rust 不负责验证选票 Groth16 证明，也不负责部署或交互 Solidity。上述工作由 JavaScript 处理，再将 admission 通过的 ciphertext 交给 Rust。JS gate 实现保留为 reference/test oracle；本地规模实验总是使用 Rust DAG evaluator，Sepolia runner 则需设置 `CGY_NATIVE_BACKEND=1` 才会使用 Rust。

## 论文内容与代码位置

| 论文组件 | 主要源码位置 |
|---|---|
| 规范化 BabyJubjub 点和辅助 oracle | `backend/js_protocol/src/group.js`、`group_oracle.js`；`backend/cgy_native/src/lib.rs`、`gate.rs` |
| Setup、masking、zero encryption、rerandomization、threshold share/proof | `backend/js_protocol/src/threshold_setup.js`、`proofs.js`、`rerandomization.js`、`threshold_decryption.js`；`backend/cgy_native/src/gate.rs` |
| 状态机与 common-view board | `backend/js_protocol/src/validation_state.js`、`broadcast_board.js`、`conditional_gate.js` |
| Gate 及 Algorithms 7–10、21、23、40、63–67 | `backend/js_protocol/src/conditional_gate.js`；`backend/cgy_native/src/gate.rs` |
| 加权聚合与阈值比较 | `backend/js_protocol/src/arithmetic.js`；`backend/cgy_native/src/gate.rs` 中的 native DAG |
| 链上 admission 与精确 board binding | `implementation/arbitrum/contracts/StrongN8Poll.sol`、`implementation/arbitrum/board_binding/lib/sealed_board.js`、`backend/js_protocol/src/accepted_board.js` |
| 最终 rerandomize-then-decrypt 与结果 claim | `backend/js_protocol/src/final_release.js`；Sepolia runner 和 `replay_sepolia_public.js` |
| 规范 transcript、流式重放和 compact codec | `backend/cgy_native/src/gate.rs`、`backend/cgy_native/tools/compact_transcript.js`、replay scripts |

上表中的算法编号用于标识本 artifact 的源码映射；正式假设和安全声明请查阅论文及相应 verifier 路径。

## 常见问题排查

| 现象 | 检查方法 |
|---|---|
| 系统找不到 `cargo` 或 `rustc` | 安装 rustup；如使用 Windows，再安装 MSVC C++ Build Tools；打开新 shell 后重新运行 `rustc --version`。 |
| 跨语言测试提示缺少 native binary | 在仓库根目录运行 `cargo build --release --locked --manifest-path backend/cgy_native/Cargo.toml`。 |
| 选票构建提示缺少 Circom 或版本错误 | 安装 Circom 2.1.6 并运行 `circom --version`；若不在 `PATH`，为当前 shell 设置 `CIRCOM_BIN`。 |
| 缺少选票产物 | 运行 `npm ci --prefix circuits`、`npm ci --prefix backend/js_protocol`，再运行 `npm --prefix backend/js_protocol run build:ballot`。 |
| Runner 报告输出目录已存在 | 选择新的唯一 `CGY_LOCAL_RUN_DIRECTORY`/`CGY_N8_RUN_DIRECTORY` 以及匹配的 oracle 目录。脚本有意拒绝覆盖既有实验。 |
| Sepolia preflight 报告链错误或 RPC 错误 | 确认 endpoint 是 Arbitrum Sepolia（chain ID 421614），并使用可响应的 provider；部署前检查测试网余额。 |
| Public replay 被限流 | 更换具备足够历史 block/receipt 读取能力的只读 RPC provider；不要重新发送或替换已接受的选票交易。 |

## 范围与安全提示

- 这是可审计的研究 artifact，不是生产投票软件。
- 本地 setup 使用单进程测试 dealer，不是 DKG。
- 本地 common-view board 是参考服务，不是拜占庭 broadcast 共识。
- 五取五 release 意味着任意一名 trustee 不可用都可能阻止结果输出；不声称系统级 liveness 保证。
- artifact 和测试本身不能证明论文定理。
- 选票 witness 仅在证明生成子进程中使用；tally 路径和 public replay 不会接收明文 oracle 或加权总和。
- 论文记录的 Sepolia 运行以数据形式放在 `evidence/`，其 transcript 在 GitHub release 附件中；全新的测试网实验需要有余额的测试网密钥，并会生成新的链上数据。

## 许可证与上游依赖

本 artifact 按 [GNU GPL v3](LICENSE) 发行。依赖版本和许可证元数据记录在 npm lockfile 与 Cargo lockfile 中。主要上游组件包括 [Circomlib](https://github.com/iden3/circomlib)、[circomlibjs](https://github.com/iden3/circomlibjs)、[snarkjs](https://github.com/iden3/snarkjs)、[ethers](https://github.com/ethers-io/ethers.js) 和 [Hardhat](https://github.com/NomicFoundation/hardhat)。论文与 artifact 仅供研究评估，不适用于实际选举。

