# RUST-01 — Rust 原生迁移与分布式执行

日期：2026-11-20
迁移分支：`refactor/rust-native-distributed`
迁移基线：NETWORK-02 `6ceb21109b33e5898b282a08921189a07fcdbc90`
论文主分支基线：`main` `2d76ba053ed8f21d23996180f1a6baf168edbd0c`

## 1. 前后架构

迁移前，Rust CGY gate 代码位于单个 `native/src/gate.rs`，同一请求可携带五份 Shamir share；JavaScript 负责 Circom/snarkjs ballot、admission、算术 DAG、实验运行、public replay 和 oracle comparison。NETWORK-02 的 TCP board 使用 JavaScript 服务。

本分支把原 Rust 密码学和 gate 实现拆入 Rust workspace，增加 trustee、coordinator、board、verifier、runner 二进制和 read-only chain crate。Rust trustee 可独立从自己的配置加载一份 share 与一个 Ed25519 seed，Rust board 可验证签名及 CGY phase proof、顺序封存并持久化 event log。coordinator 根据公开 phase plan 启动 trustee 子进程。

目前 coordinator 仍是静态 phase-plan 执行器；它还没有从 ballot/admission 生成完整的 weighted arithmetic DAG，也没有依赖已 seal 输出动态生成后续 gate context。因此，本分支**尚未完成纯 Rust 单 gate 网络执行或纯 Rust n=8 election**。

## 2. Rust workspace 与变更文件

`native/Cargo.toml` 成为 pinned Rust 1.98.1 workspace，分成六个 crate：

| Crate | 已迁入功能 |
|---|---|
| `cgy-crypto` | BabyJub/Base8 常量、canonical 点与标量检查、仿射编码、群运算 |
| `cgy-protocol` | 现有 CGY gate、证明验证、DAG 验证及单 share trustee worker |
| `cgy-network` | Ed25519 签名、phase 状态机、TCP board、持久 event log、Rust board replay |
| `cgy-ballot` | 原 Circom 37 个 public signal 的结构解码和密文点检查 |
| `cgy-chain` | 只读 Ethereum JSON-RPC：chain ID、receipt、logs 等 |
| `cgy-evidence` | public artifact SHA-256 manifest 及私密路径过滤 |

新增二进制：`board`、`coordinator`、`runner`、`trustee`、`verifier`。根 package 的 `cgy-native` 和 `native/src/lib.rs` 保留兼容入口。旧 `native/src/gate.rs` 已由 `git rm` 移除，内容迁至 `native/crates/protocol/src/gate.rs`。

本次精确变更：

- `.github/workflows/ci.yml`：Cargo build/test 改为覆盖整个 workspace。
- `.gitignore`：排除 `runs-private/`、trustee 配置、share、auth seed 等运行时私密文件。
- `README.md`、`README.zh-CN.md`：说明迁移分支与当前边界。
- `docs/rust-migration.md`、`docs/paper-to-code.md`：Rust CLI、迁移覆盖范围及源码映射。
- `native/Cargo.toml`、`native/Cargo.lock`：workspace crate 和锁定依赖。
- `native/crates/{crypto,protocol,network,ballot,chain,evidence}/`：六个 crate 源码及清单。
- `native/src/bin/{board,coordinator,runner,trustee,verifier}.rs`：五个 CLI。
- `native/src/lib.rs`、`native/src/main.rs`：兼容 facade 和 worker 命令入口。
- `native/crates/network/testdata/js_signed_slot.json`：冻结 JavaScript slot 编码/Ed25519 签名向量。
- `native/tests/{babyjub_compat.rs,rust_board_tcp.rs}`：跨语言点运算及 Rust TCP board 检查。

## 3. 已迁移与待迁移的功能

现有 Rust BabyJub/Base8 代码已拆入 crate；固定 Base8、子群检查、canonical affine 编码和现有 gate fixture 可运行。Rust per-trustee worker API 支持单 trustee masking、rerandomization、partial decryption 的证明生成接口；board 端有对应 public proof verifier。Rust test-only dealer 生成五份 degree-4 Shamir shares、公开验证点和 setup，并把每份 share 与各自 Ed25519 seed 写入 trustee 私有目录。

仍由 JavaScript 承担的功能：Circom witness 生成、snarkjs Groth16 proving/verification、ballot admission、accepted-board 构造、完整 weighted DAG builder、异步 DAG scheduler、local-scale runner、已有 transcript schema 的 replay/oracle 工具。`cgy-ballot` 只解码并检查 37 个 public signal，**不能验证 Groth16 proof**。`cgy-chain` 只读 RPC，尚无完整 Solidity ABI 解码、链上 admission/accepted-board 重建或交易流程。

因此 JavaScript reference 保留为当前完整 protocol/evidence 路径；尚未移除任何未由 Rust 验证替代的 JS 功能，也未改变 Circom 电路、Solidity 合约或论文。

## 4. Trustee 状态与隔离检查

Rust test dealer 执行命令：

```powershell
native\target\release\runner.exe test-dealer --output runs-private\rust-dealer-smoke-20261120
```

结果：`RUST_TEST_DEALER=READY trustees=5 degree=4 threshold=5`。输出的五个 `trustee-config.json` 各含一份 share、一个 auth seed 和公共 setup；公开目录只有 `public_setup.json` 与 dealer manifest。公开文件扫描未发现 `secretShare`、`authSeedHex`、witness、private key 或 oracle 输入。`git check-ignore -q runs-private/.../trustee-config.json` 成功。

`coordinator.exe --plan <private-startup-plan>` 用上述配置启动五个独立 trustee 子进程并正常关闭，输出 `RUST_COORDINATOR_PHASES=PASS count=0`。这是**进程启动/配置隔离 smoke test**，该计划执行零个密码学 phase，不能算作 gate 运行。代码中 coordinator 只接收 config 路径，由子进程读取对应文件；board 配置类型只包含公开 setup、trustee public keys 和 phase plan。

另一个 NETWORK-03 n=8 实验的 manifest 记录了五个 trustee PID、各自只读自己的 share/authentication key、coordinator 和 board 各读取零份 share 文件；该实验用的是 NETWORK-03 当时的 dirty source tree，详见第 7、9 节。

## 5. 密码学兼容测试

固定 fixture 和跨语言检查通过：

- `node protocol/scripts/test_native_gate_compatibility.js`：`JS_GATE_VERIFIED_BY_RUST=PASS`、`RUST_GATE_VERIFIED_BY_JS=PASS`。
- `native\target\release\verifier.exe gate native\testdata\rust_single_gate.json`：`RUST_GATE_REPLAY=PASS`。
- `native/crates/network/testdata/js_signed_slot.json`：Rust 复算的 slot 编码及 Ed25519 签名与冻结 JavaScript 字节完全一致。
- Rust BabyJub 测试检查 Base8 常量、模数、点往返、projective/affine 结果及非法点拒绝。

这些是 fixture、编码和 verifier 兼容结果；不是 Rust 进程通过 TCP 完成的新 gate。Groth16/Solidity 证明兼容性没有迁移，也没有声称已测试。

## 6. 单 gate 分布式验证

状态：**未通过验收，尚未执行**。本分支验证了 Rust gate fixture、Rust board 的 TCP health/status 和 event-log 配置恢复，也启动过五个 trustee 子进程，但没有让该 Rust coordinator 经 TCP 完成一个由五 trustee 实时生成贡献的 gate。

主要缺口是 coordinator 尚不能构建/推进 gate 的依赖 DAG，也不能在每个 board seal 后根据新公开输出计算下一 phase context。静态 phase plan 二进制因此还没有可由现有 ballot 自动生成的 end-to-end 输入。

## 7. 完整 n=8 分布式结果

此 Rust 迁移分支没有完成纯 Rust n=8。当前可用的相关实测来自先前 NETWORK-03 run：

| 字段 | 观测值 |
|---|---|
| Run ID | `network-03_true-distributed_n8_rtt0_20261120033956_c596d0` |
| Source commit / tree | `6ceb21109b33e5898b282a08921189a07fcdbc90` / dirty |
| 后端与组件 | 五个独立 Rust native crypto workers；Node coordinator、DAG scheduler、board framing 和 replay orchestration |
| 输入/门/深度 | n=8；134 gates；depth 72 |
| 协议量 | 1,614 phase barriers；2,690 trustee submissions；five-of-five final release |
| 测量结果 | decision bit 1；Rust native distributed computation 1,201.354 s；full producer 1,221.858 s |
| 网络 | loopback；无 delay injection；TCP application bytes 83,008,842；trustee ping RTT mean 0.2351 ms，p95 0.5312 ms |
| Public replay | PASS；replay artifact SHA-256 `05b5c7d4fe3e772db25b4716f8f5b1cfbea760f002f0f3dc4e4a0b7045360ec0` |
| Oracle comparison | 查询该报告快照时仍为 PENDING；不计为通过 |

该 run 证明 Rust native trustee worker 在独立进程中实时生成 CGY contributions 的可行性，也包含 board proof/signature 验证和 public replay。它不是本分支的纯 Rust orchestrated run；source tree dirty，且 oracle 尚未通过。因此不能作为 RUST-01 的 Rust 端到端验收结果。

## 8. n=64 状态

没有执行 Rust-native n=64。本分支的 DAG builder 和 n=8 Rust TCP gate 仍未通过，故 n=64 gate 未达到。NETWORK-02 的 n=64 数据属于 transcript transport-only；NETWORK-03 的相关 Rust run也不是本分支完整 Rust 路径。

## 9. 网络结果与论文模型对照

| 结果来源 | n=8 模式 | 时间 | 用途/限制 |
|---|---|---:|---|
| 历史 local control | 中央 Rust backend + JS pipeline | full 46.989 s；backend 6.271 s | NETWORK-01 报告所列控制值 |
| NETWORK-02 | 已生成签名 transcript 的 TCP replay | loopback 8.269 s；20 ms target 57.431 s；100 ms target 195.861 s | 只测认证 transport、board persistence/replay |
| NETWORK-03 run | Rust trustee crypto workers + Node 编排 | computation 1,201.354 s；full 1,221.858 s | 活跃分布式密码学，但非本分支纯 Rust，oracle pending |

三行测量范围不同，不能做受控倍率比较。NETWORK-03 的长耗时包含真实 per-trustee proof generation 和 phase scheduling，说明中央 Rust backend 的速度不能直接外推到分布式证明路径。

论文的七层模型在 n=8、scheduled depth 72 时对应 `7 × 72 = 504` 个关键路径 RTT 层；十二 phase reference schedule 有 `12 × 134 = 1,608` 个 gate phase，再加 final release 的六个逻辑 phase，共 1,614 个观测 seal。phase 数量不是 RTT 数量；NETWORK-03 的本地测量也不是 WAN 结果。当前没有基于本 Rust branch 的匹配网络 profile，无法判断七层模型在 Rust distributed DAG 下的拟合程度，也未测试 20 ms / 100 ms 或 batching/concurrency。

## 10. 安全、对抗测试与产物卫生

当前本分支测试覆盖：错误/未知 trustee 身份、无效签名、out-of-order phase、冲突重试、相同重试、TCP board health/status 和事件配置重启恢复、错误/短 ballot signal 和无效点、RPC transaction method 拒绝、证据路径敏感文件过滤、test dealer 五份独立 share 校验。

仍未完成 Rust 网络层的 proof tamper、错误 share、缺席 trustee/timeout、断线、变更 accepted-ballot 顺序、错误 terminal ciphertext 等系统级 adversarial 测试。现有 JavaScript 参考套件包含相应协议负例，但不能代替 Rust 实现的覆盖。

Rust TCP board 是单一 trusted sequencer。它用 Ed25519 签名认证 trustee message，并严格顺序 seal；这不构成 Byzantine reliable broadcast。当前通信为 TCP 实验，不代表生产 trustee 部署。

私有 test dealer 目录位于 ignored `runs-private/`，没有加入 Git。NETWORK-03 public run 的 manifest 也记录 plaintext votes、witnesses、trustee shares、oracle inputs 和 deployer keys 均未发布。该 run 尚无 public-safe release；不发布其未完成 oracle 产物。

## 11. 验证命令与结果

| 命令 | 退出码/结果 |
|---|---|
| `& "$env:USERPROFILE\.cargo\bin\cargo.exe" build --workspace --release --locked --manifest-path native\Cargo.toml` | 0；Windows x64 release build 成功 |
| `& "$env:USERPROFILE\.cargo\bin\cargo.exe" test --workspace --locked --manifest-path native\Cargo.toml` | 0；14 passed，0 failed |
| `node protocol/scripts/test_native_gate_compatibility.js` | 0；JS/Rust 双向 fixture 验证 PASS |
| `native\target\release\verifier.exe gate native\testdata\rust_single_gate.json` | 0；Rust fixture replay PASS |
| `npm --prefix protocol test` | 0；57 passed，0 failed |
| `npm --prefix contracts/arbitrum run compile` | 0；3 Solidity files 编译成功 |
| `npm --prefix contracts/arbitrum test` | 0；51 passing |
| `npm --prefix contracts/arbitrum run test:board-binding` | 0；3 passed，0 failed |
| `node scripts/check-repo-paths.js` | 0；22 files checked，`REPOSITORY_PATHS=PASS` |
| `rustfmt --check`（新 binaries/crate files）及 `git diff --check` | 0 |
| `runner.exe test-dealer ...` + public/private 文件检查 | 0；5 私有配置、public secret scan 和 gitignore 检查 PASS |
| `coordinator.exe --plan <startup-plan>` | 0；五个 trustee 启停通过，`count=0`，未执行 phase |

测试主机为 Windows 11 x64，Rust/Cargo 1.98.1、Node v24.15.0。工作流面向 Ubuntu 24.04，但本次没有执行 GitHub Actions/Linux 构建。`npm ci --prefix contracts/arbitrum` 安装成功；npm audit 报告 56 项依赖告警（20 low、15 moderate、20 high、1 critical）。为保持 lockfile 与研究基线，本次未升级依赖。

## 12. 原始结果路径、哈希与来源

NETWORK-03 公共目录仍在作者原工作区 `D:\31831\Desktop\BlockSys2027-submission-clean\runs\network-03_true-distributed_n8_rtt0_20261120033956_c596d0\public\`。该目录不属于当前 Rust branch，也没有复制进 Git：

- transcript commitment：`ff97f3a953a746d8c9fcbdef7c0b401a48ea2da25ae3b7bac766c207e2731239`
- accepted/sealed board hash：`be741643b0d4c1993444ddc5a0ff1b5e842c08cc7eccec112907fbaf8b1661d0`
- `gate_transcript.jsonl` SHA-256：`b37379dc5229048ff18cb257178bbb6b705ecf453a9ceb75da6e641d95860c07`
- `final_release.json` SHA-256：`6612ee365809488e70e122a981a19801e4614d3263c06cd0c560d0cdcf555ee0`
- `public_setup.json` SHA-256：`8bc764ff5e0de961e79788ec240f1c80dc576a4d3479a64af53a1860c060f21b`
- public replay artifact SHA-256：`05b5c7d4fe3e772db25b4716f8f5b1cfbea760f002f0f3dc4e4a0b7045360ec0`

迁移 branch 的稳定兼容 fixtures 为 `native/testdata/javascript_single_gate.json`、`native/testdata/rust_single_gate.json` 和 `native/crates/network/testdata/js_signed_slot.json`；它们由测试验证，随本分支提交。Rust dealer smoke 的随机输出在 ignored `runs-private/rust-dealer-smoke-20261120/`，仅是私有 provisioning 检查，不是实验结果或发布证据。

Fixture SHA-256：

- `javascript_single_gate.json`: `7a2ac8753f36f96977956a47ac08dad94c59e5f54c7db3269960e6d2dbe89afe`
- `rust_single_gate.json`: `c4d852d42fb6e3a1105c6269ff3836f87fdea76acdbaf2151d2140edf0709076`
- `js_signed_slot.json`: `604aacc880ae13e4e19fbcf0a0e6c0332db3d48ba46685e70896454598099c13`
- 当前本地 dealer smoke 的公开 setup: `eae450f36385423969a3489b99d0d589a1def35718b8471e57e34d6bc96466d3`；它是一次随机 test setup，不随代码发布。

## 13. GitHub 与历史版本

- 独立分支：[`refactor/rust-native-distributed`](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/tree/refactor/rust-native-distributed)
- Rust workspace 实现提交：`202d44b8f83e38ec42b30c61b4f192c941fc6a01` (`Start Rust-native protocol migration`)
- `main` 未修改；不合并未完成的 Rust 实验路径。
- 保留历史 tag `archive/pre-cleanup-2026-11`、`blocksys2027-evidence-v1` 及 `network-02-tcp-transport-v1`。
- NETWORK-02 release 仍在[原有 GitHub release](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/releases/tag/network-02-tcp-transport-v1)；本次未改写 release 或 tag，也未创建新的证据 release。
- 本报告作为独立文档提交；branch 最终 head 包含上述实现提交和本报告。

## 14. 复现命令与剩余工作

Windows PowerShell 当前分支的构建与兼容检查：

```powershell
Set-Location D:\31831\Desktop\winner-only-rust-native
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
cargo build --workspace --release --locked --manifest-path native\Cargo.toml
cargo test --workspace --locked --manifest-path native\Cargo.toml
node protocol\scripts\test_native_gate_compatibility.js
native\target\release\verifier.exe gate native\testdata\rust_single_gate.json
```

生成 test-only setup：

```powershell
native\target\release\runner.exe test-dealer --output runs-private\rust-dealer-$(Get-Date -Format yyyyMMdd-HHmmss)
```

`runner distributed --plan` 还需要公开 board phase plan、已启动的 board，以及引用上述独立 trustee 配置的五个 trustee 路径。当前仓库没有从 ballot 生成这份完整 plan 的 Rust 命令；空 phase plan 只验证进程启动，不能替代 n=8 reproduction。

达到 Rust n=8 验收前还需：实现 ballot admission 和 weighted DAG 构建；接通动态 phase/依赖结果；实现 coordinator 的公开 affine gate 输出与 terminal adapter；让 Rust verifier 兼容既有 public transcript/export；补全 Rust proof tamper、timeout、disconnect、terminal ciphertext 和 accepted-board binding 系统测试；执行 Rust board + 五 trustee 的 live single gate 和完整 n=8；验证 public replay 与独立 oracle；之后再测 n=64 和 0/20/100 ms 网络 profile。Groth16 prover compatibility 与链上 EVM binding 的 Rust path 仍需独立迁移。

本次没有修改 BlockSys manuscript/PDF，也不建议据此新增论文性能主张。NETWORK-03 n=8 的速度包含 Rust native 分布式 proof generation，但仍由 Node 编排，且 oracle 比较在报告快照时为 PENDING；它不能替代纯 Rust 复现或写成已验证的新论文数据。

## 15. 最终状态

`RUST_MIGRATION_PARTIAL`
