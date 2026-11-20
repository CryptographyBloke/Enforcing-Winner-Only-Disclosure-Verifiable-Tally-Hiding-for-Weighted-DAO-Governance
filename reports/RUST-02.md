# RUST-02 — Rust 端迁移与实测进展

日期：2026-11-20
分支：[`refactor/rust-native-distributed`](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/tree/refactor/rust-native-distributed)
RUST-01 基线：`db9c9a8c603dcc501b7005bd8f211001e5fa90b6`
本次 ballot 实现提交：`75349fd8c7c0987e7ce01582b433bb42353d75a6`

## 1. Rust 实现覆盖范围

本次完成了 Rust 原生 ballot proving/verification 子流程：Rust 生成测试身份、Poseidon 注册树和 witness；通过 `ark-circom` 执行既有 Circom WASM witness；从原 SnarkJS `.zkey` 读取 Groth16 proving key；在 Rust 中生成并验证 proof；解析 SnarkJS proof/VK JSON；检查 37 个公开信号；用未修改的 Solidity verifier 对新 proof 做 EVM 兼容验证。

Rust 命令 `ballot prove` 与 `ballot verify` 在该实验阶段没有启动 Node.js。Node/Hardhat 只用于随后独立调用 Solidity verifier 的兼容测试。其余 RUST-02 目标尚未完成，结论为部分迁移。

## 2. 架构、变更文件与仍待迁移功能

新增或修改：

- `native/crates/ballot/src/proving.rs`：SnarkJS `.zkey` 读取、Circom WASM witness、Groth16 prove/verify、公开信号检查、SnarkJS JSON 编码/解析、fresh ballot profile。
- `native/crates/ballot/src/poseidon.rs` 与 `native/crates/ballot/data/poseidon_t2_t3.json`：Circomlib 兼容的一输入/二输入 BN254 Poseidon，用于 identity commitment、注册树和 nullifier 所需输入。
- `native/src/bin/ballot.rs`：`prove`、`verify` 和 `check-vkey` CLI。新输出使用 `create_new`，不会覆盖旧 bundle。
- `native/crates/ballot/Cargo.toml`、`native/Cargo.toml`、`native/Cargo.lock`：Arkworks/ark-circom 依赖及锁文件。
- `contracts/arbitrum/test/RustBallotVerifier.test.js`：可选 EVM 回归测试，通过环境变量加载 Rust bundle。
- `README.md`、`README.zh-CN.md`、`docs/rust-migration.md`：更新实际实现边界和 proving 命令。
- `evidence/rust02-ballot-proving/`：三次 ballot 子实验的公开 proof bundle、manifest 和路径已清理日志。
- `evidence/README.md`：说明此子实验的范围与复现条件。

没有修改 Circom 源、Solidity 合约、CGY 原语、历史 Q5 数据、NETWORK-02 release 或 BlockSys 稿件。

Rust 当前还没有接通完整 admission/accepted-board 构造、加权 tally DAG、live five-trustee gate、终局 release、全协议 Rust public replay、隔离 oracle comparison、链上 ABI/事件到 board 绑定、Rust distributed runner 或 Rust 结果汇总 CLI。现有 `runner`/`coordinator` 不能执行完整加权 election。

## 3. Groth16 与 Solidity 兼容性

本次使用的 `.zkey` verification key 与仓库现有 `Groth16Verifier` 一致。Rust 新生成的三组 n=8 bundle 共 24 张 ballot，分别通过 Rust Groth16 verification、Rust public bundle replay 和未修改 Solidity verifier。另将已有的八张 SnarkJS ballot fixture 交给 Rust verifier，八张均通过。proof 保持 BN254 Groth16，Circom relation、公信号顺序与 proof statement 未改。

本机曾生成的 test-only setup key 与 Solidity verifier 不匹配，故没有用于此兼容结果。正确匹配的旧 proving artifact 只在本机历史 `THproto-master` 归档中找到；它不在当前 checkout，也不在 `blocksys2027-evidence-v1` zip。新 proof 可以由现有 verifier 验证，但从全新 clone 重新生成 proof 仍需要作者提供哈希匹配的 WASM/R1CS/`.zkey`/verification key 文件集。

## 4. 单 gate 与完整 n=8 分布式执行

单 gate 验收：**未完成**。RUST-01 的 coordinator 子进程 smoke test 运行的是零 phase plan；本次没有把 Rust trustee 贡献通过 TCP board 执行成 gate。

完整 Rust n=8 验收：**未完成**。本次生成并验证了 8 张 proof-valid ballots，但没有执行 admission、134 个 CGY conditional gates、五份独立 trustee contribution、terminal adapter、five-of-five release、全 transcript public replay 或隔离 oracle comparison。因此这三次 run 是 ballot proving microbenchmark，不能称为完整 n=8 election，也不替代论文计票数据。

## 5. n=64 与更大规模

n=64 全协议没有运行。n=256 和 n=1024 全协议没有运行。本次的 ballot 生成代码保留了 1–1024 注册树容量，但这不代表大规模 proof/tally pipeline 已通过验证。

## 6. ballot 阶段的实测结果

环境：Windows 11 专业版，Intel Core i7-14650HX（16 核/24 逻辑线程），rustc/cargo 1.98.1。release Rust 命令生成 8 张新 ballot；三次使用相同程序、匹配的原 key、weight `[3,5,7,9,11,13,15,17]` 和交替 vote 输入，凭据、poll ID 与 proof 随机数每次新生成。

时间为每次 n=8 批次总计，单位秒：

| 阶段 | 三次结果范围 | 中位数 |
|---|---:|---:|
| Witness 生成 | 2.726–2.974 | 2.872 |
| Groth16 proving | 2.023–2.064 | 2.048 |
| Rust Groth16 verification | 0.042–0.043 | 0.042 |
| Ballot pipeline（以上每票处理阶段合计） | 4.880–5.102 | 5.043 |
| `ballot prove` 命令墙钟时间 | 10.901–11.102 | 11.005 |

命令墙钟包含程序启动、Circom WASM/R1CS 与 `.zkey` 初始化、注册树生成、witness、证明和 Rust 验证；不含 Cargo 编译、之后单独运行的 Solidity 测试，也不含 admission/tally/release。中位 Groth16 proving 时间约为每票 0.256 秒。Rust 在这部分确实很快；完整分布式 tally 时间仍不能据这组 ballot 阶段数据推断。论文 Q5 的历史 n=8 `proving=10.04 s` 使用了不同版本和计时边界，本报告不把两者当作受控对比，也不据此改论文数据。

## 7. 网络测量与模型对照

本次没有执行 Rust 分布式 CGY 计算，也没有设置 0/20/100 ms 网络 profile，因此没有新的 RTT、trustee 证明计算时间、board 等待、阶段数或应用层消息/字节测量。

NETWORK-02 是中央生成 transcript 后的传输重放；NETWORK-03 是 Rust trustee workers 与 Node 编排的混合执行；历史 Q5 是原集中式实验。三者与当前 Rust ballot-only run 测量范围不同。本报告不将它们拼接，也不据此估算七层或十二 phase 模型的经验拟合。

## 8. 回归、安全与隔离检查

- Rust workspace 单元/集成测试：20 passed，0 failed。
- `protocol` JavaScript 回归：57 passed，0 failed。
- Hardhat 全套：51 passed，1 pending。pending 项是需显式设置 `CGY_RUST_BALLOT_BUNDLE` 的可选 Rust proof 测试。
- 对三次 bundle 分别运行可选 Hardhat 测试：每次 1 passed；每组八张 proof 均被本地 EVM 的原 `Groth16Verifier` 接受。
- 篡改第一张 ballot 的 nullifier 后，Rust verifier 返回非零状态并输出 `Groth16 proof rejected`。
- Rust 单元测试拒绝错误 proof system、截断 proof 坐标、非 canonical public scalar、超范围 uint8 weight 和错误公开信号布局。
- `git check-ignore` 确认 `runs/` 与 `runs-private/` 被忽略。公开 bundle 的字段仅含 registry/poll/committee context、proof、37 个公开信号及阶段耗时；没有 vote 数组、identity secret、witness、share、auth key 或 oracle 输入。每份公开日志已移除本机绝对路径。

本次没有 trustee、share provisioning、coordinator 或 board 参与；所以不报告本次 run 的 share isolation 状态。旧 test dealer 仍为 test-only provisioning，不是 DKG。

## 9. 公共证据、哈希与复现命令

三组可公开验证产物位于 `evidence/rust02-ballot-proving/`。对应 Rust source commit 为 `75349fd8c7c0987e7ce01582b433bb42353d75a6`，每个 manifest 均记录该 SHA 和 `source_tree_clean=true`。

| Run | Ballot bundle SHA-256 | Manifest SHA-256 |
|---|---|---|
| `rust02_ballot_release_n8_r1_1cbdc4c8` | `D8D9C21E9A4CA641EFEFCFF6E20C5B74D7C2B521122A4EAB53B7ED6883F0E313` | `1F299687CA2FA6658D1816FD86A3ABA022130775839A6B477296D18F07D62971` |
| `rust02_ballot_release_n8_r2_5cca7a54` | `B3F7F53FA12B812026EB66C63E4FB891F755627D60D91AD71AD5B06703121B3F` | `077F93E7F7720671AA6680CE958DF6A9984DA61F3897B212FF194280A601973B` |
| `rust02_ballot_release_n8_r3_a9ffd487` | `328D95B81E1EA19876C101A800876B6334C4739621E4024989E8EB5B09508CD5` | `7E76F1A862C8E67AF7B3923CDA60E21E2294260044E9B0AF8C830E3B5094A605` |

输入 artifact 哈希：`.zkey` `6D80E0822F72C3F5613D02E9BD907DE33CF50C4BD21C3470139C31DA6AE28E4C`；verification key `548D5FF2673E10CCE2029F3CA6D4FD90BF325A0A605384C877691828602063BF`；R1CS `ED87C61814D64020CADC29B0DD7BEFDABD735DD163FB1D676C93051FBC342727`；WASM `44C8ACFC902A6A89A1EB44D17D5660FB365D2B296009842B5186E907C444D838`。Poseidon 常量文件 `native/crates/ballot/data/poseidon_t2_t3.json` SHA-256 为 `A68B352737646F641533D6BA6CFA160724AB28918743198A87A17AD41D357C34`。

在具备匹配 artifact 文件的 PowerShell 环境中，ballot 子流程命令如下：

```powershell
cargo test --workspace --locked --manifest-path native/Cargo.toml
cargo build --workspace --release --locked --manifest-path native/Cargo.toml
native\target\release\ballot.exe prove --config runs-private\ballot-prove-config.json
native\target\release\ballot.exe verify --bundle runs\<run-id>\public\ballots.json --vkey $VerificationKey
```

用 EVM 验证已导出的 proof bundle：

```powershell
$env:CGY_RUST_BALLOT_BUNDLE = (Resolve-Path "evidence\rust02-ballot-proving\rust02_ballot_release_n8_r1_1cbdc4c8\public\ballots.json").Path
npm --prefix contracts/arbitrum test -- --no-compile test/RustBallotVerifier.test.js
Remove-Item Env:CGY_RUST_BALLOT_BUNDLE
```

## 10. 论文整合

没有修改论文源码或 PDF。当前数据只覆盖 ballot proving/verification，没有新的分布式 tally 数据，不能支持把 NETWORK-02 transport 或 NETWORK-03 mixed run 改写成 Rust-only protocol 结果。保持 BlockSys 提交稿中的 Q5 历史表、Arbitrum 证据和安全定理原样。

## 11. GitHub 分支与历史版本

工作分支为 `refactor/rust-native-distributed`，ballot implementation commit 为 `75349fd8c7c0987e7ce01582b433bb42353d75a6`。报告提交后会将该分支推送到原仓库；没有修改 `main`，也没有覆盖或删除 `blocksys2027-evidence-v1`、`network-02-tcp-transport-v1` 或历史 Q5 数据。

## 12. 仍待完成的主要工作

1. 在 Rust 中实现 ballot admission、nullifier uniqueness、exact accepted-board order/commitment 和 chain receipt/event binding。
2. 构建完整的 Rust 加权 threshold DAG 与异步依赖 scheduler。
3. 动态连接 coordinator、Rust TCP board 与五个 trustee 进程；每个 CGY gate 都由五个进程实时生成 proof/contribution。
4. 执行 terminal adapter、five-of-five final release、独立 Rust public replay 和 replay 之后才运行的隔离 oracle。
5. 完成 Gate A 之外的单 gate 和完整 n=8 验收，再测 n=64 与更大规模。
6. 完成 0/20/100 ms 分布式网络测量、运行汇总 CLI 和 Windows/Linux fresh-clone 复现脚本。
7. 将匹配的旧 proving artifact 以可获取方式提供，或由作者决定兼容原 verifier 的 artifact 分发方案。
8. 只有完整分布式运行通过后，才评估 manuscript 是否需要新的、明确界定计时范围的实验段落。

## 13. 完成状态

已验证 Rust 原生 Groth16 ballot proving、Rust 验证、旧 SnarkJS fixture 验证、原 Solidity verifier 兼容和三个 release 计时批次。没有完成完整 Rust-only experiment path，尚不能满足 RUST-02 最终目标。

## 14. 最终状态

`RUST_MIGRATION_PARTIAL`
