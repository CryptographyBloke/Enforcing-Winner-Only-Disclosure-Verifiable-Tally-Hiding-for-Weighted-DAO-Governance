# 强制仅披露获胜结果：面向加权链上治理的可验证计票隐藏

作者：Jiayu Li、Gongli Li · 单位：河南师范大学 · [IACR Cryptology ePrint 2026/1773](https://eprint.iacr.org/2026/1773) · BlockSys 2027 · [提交版 PDF](paper/BlockSys2027_submission.pdf)

本仓库提供加密加权投票的参考实现与可复现实验材料，目标是在不公开精确加权总票数的情况下验证治理结果。这是研究原型，不是可直接用于生产 DAO 的投票系统。

## 为什么要隐藏总票数？

当选民权重公开或可关联时，精确加权总票数可能泄露个人选择。例如三位选民权重为 `7、4、1`，若公开“赞成票数为 `8`”，就能识别出权重为 `7` 和 `1` 的选民投了赞成票。只公布阈值结果可以避免泄露精确总和。

协议让每位选民的加权贡献在求和和阈值比较期间保持加密。公共验证者会检查计算确实使用了合约接受并封存的选票；受托方最后只开放结果位。

## 主要贡献

- **注册权重认证选票：** 零知识选票将加密二元投票与注册权重绑定。
- **加密加权阈值计算：** 计票和比较使用 Cortier–Gaudry–Yang（CGY）可验证计票隐藏工具箱。
- **精确绑定已接受选票：** 后端计算绑定到合约接受并封存的密文坐标。
- **独立公共重放：** 任何人都可以使用公开运行产物验证选票证明、board 绑定、CGY transcript 和最终 release。
- **仅 release 决策位：** 参考运行需要全部五个受托方份额，只开放结果位。

## 架构

```mermaid
flowchart LR
  R[注册权重快照] --> B[加密选票与证明]
  B --> C[Arbitrum Sepolia 选票合约]
  C --> S[封存的已接受选票 board]
  S --> T[五个受托方角色]
  T --> E[加密加权计票与阈值比较]
  E --> V[独立公共验证者]
  S --> V
  V --> O[结果声明：仅决策位]
  O -. 提议的集成 .-> X[治理执行器]
```

合约、本地 CGY 后端、公共重放和结果声明均已实现。参考代码把五个受托方角色模拟在一个进程中，并未提供生产级受托方隔离。治理执行器只是建议的集成边界，不属于当前实现。

## 快速开始

请先安装 Node.js 20 或更高版本、Rust/Cargo 1.98.1 和 Circom 2.1.6。在全新的 Windows PowerShell checkout 中运行以下命令：它会安装锁定依赖、构建原生后端、生成全新的**测试专用** Groth16 产物，并执行验证过的本地 `n=8` 实验。

```powershell
.\scripts\reproduce.ps1 -Sizes 8 -BuildArtifacts
```

完成一次性 setup 后，可运行更多规模：

```powershell
.\scripts\reproduce.ps1 -Sizes 8,64,256,1024
```

Bash 入口：`bash scripts/reproduce.sh 8,64,256,1024`。这些命令会生成新的验证运行，不会重现随附论文中的历史计时。详细安装、输出目录、资源估计和链上说明见[快速指南](docs/quickstart.md)和[实验指南](docs/experiments.md)。

## 提交论文中的实验结果

随仓库提供的 BlockSys 2027 PDF 报告的是历史五取五 Q5 实验。下表对应论文表 1，数据来自带清单校验的 [evidence v1 归档](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/releases/tag/blocksys2027-evidence-v1)。

| n | 门数 | 深度 | 证明（秒） | admission（秒） | Rust 后端（秒） | release（秒） | replay（秒） | 总计（秒） |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 8 | 134 | 72 | 10.04 | 0.15 | 4.05 | 6.93 | 0.92 | 22.12 |
| 64 | 1,086 | 147 | 146.51 | 1.28 | 15.98 | 8.93 | 11.68 | 184.41 |
| 256 | 4,350 | 207 | 368.45 | 5.22 | 47.13 | 8.40 | 32.91 | 462.13 |
| 1,024 | 17,406 | 275 | 1,414.93 | 19.16 | 156.72 | 4.57 | 114.54 | 1,709.95 |

源码、机器和运行 ID 均属于历史记录。总计列采用 Q5 manifest 的 `totalSeconds`，其中包含一小段未单独列出的 setup 时间。此表不代表维护版 checkout 在新机器或新运行上的性能。当前维护版的新实验用于验证实现，和论文历史数据分开保存。详见[实验指南](docs/experiments.md)及[版本来源说明](docs/provenance.md)。

## TCP transcript 传输实验

NETWORK-02 将已有受托方签名消息通过五个 TCP 客户端进程发送至独立持久化 board 服务。本实验测量传输、board 持久化和公共重放；客户端传输的是本地 CGY 源运行生成的公开记录。

| n | 目标 RTT | 实测 RTT 中位数（p95） | TCP 耗时中位数（范围） | 封存阶段 | TCP 应用层字节数 |
|---:|---:|---:|---:|---:|---:|
| 8 | 0 ms | 0.194（0.495）ms | 8.269（8.136–9.180）s | 1,614 | 67,767,585 |
| 8 | 20 ms | 31.227（39.989）ms | 57.431（57.418–57.891）s | 1,614 | 67,768,165 |
| 8 | 100 ms | 116.213（126.381）ms | 195.861（194.678–196.362）s | 1,614 | 67,768,745 |
| 64 | 0 ms | 0.199（0.332）ms | 74.509 s | 13,038 | 548,458,033 |
| 64 | 20 ms | 31.091（39.614）ms | 469.832 s | 13,038 | 548,458,613 |

每个 n=8 网络档位运行三次并通过验证；n=64 每档一次，n=64、100 ms 档尚未测量。字节数统计 TCP 应用帧并包含 board 广播，不包含网络包头。客户端重放的是集中生成的签名记录，因此这些数据描述认证 transcript 的 TCP 传输与重放。详见[完整报告](reports/NETWORK-02.md)和[论文插入片段](paper/network_results.tex)。

下载[NETWORK-02 公共证据包](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/releases/tag/network-02-tcp-transport-v1)。包内索引记录了每个导出文件的 SHA-256。

## Rust 原生迁移分支

[`refactor/rust-native-distributed` 分支](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/tree/refactor/rust-native-distributed)开始把 CGY 密码学、认证 TCP board、trustee worker、公开回放、选票信号解码、只读链访问和证据哈希迁入 Rust workspace。Windows 上可执行：

```powershell
cargo test --workspace --locked --manifest-path native/Cargo.toml
cargo build --workspace --release --locked --manifest-path native/Cargo.toml
```

这是实验性迁移。Rust `ballot` 程序现在使用 `ark-circom` 执行原 Circom WASM witness，读取原 SnarkJS `.zkey`，并在 Rust 中生成 Groth16 证明、检查全部 37 个公开信号。一次 release 模式 n=8 新鲜证明运行中，8 张 ballot 均通过未修改的 Solidity verifier。这是选票证明层的兼容性结果；admission、加权 DAG、完整分布式 gate、replay 和 oracle 比较仍在现有 JavaScript 流程中，Rust-only 端到端投票尚未完成。Rust prover 需要匹配的 WASM、R1CS、`.zkey` 和 verification key；这些 setup 产物没有提交到仓库。命令和迁移边界见 [Rust 迁移说明](docs/rust-migration.md)。

## 安全范围

论文证明了即使受托方恶意也不会接受错误结果，并证明少于五个解密份额的静态主动攻击者集合无法获知 tally；winner-only disclosure 推论针对实际封存的 board。实现中的五个受托方角色位于同一进程，使用测试专用 setup；这不是分布式密钥生成仪式，也不是生产部署。详见[安全模型](docs/security-model.md)。

## Arbitrum Sepolia 参考运行

归档的 `n=8` 测试网实验使用 chain ID `421614`，接受八张选票，并保存公共重放及结果声明。这是测试网参考实验，不代表生产 Arbitrum DAO 治理。链上参考阈值为 `tau=500`；本地规模实验使用 `floor(255*n/4)`，因此本地 `n=8` 的 `tau=510`。本地复现命令不会提交新的链上交易，详见[链上实验说明](docs/experiments.md#fresh-arbitrum-sepolia-experiment)。

## 仓库目录

| 路径 | 内容 |
|---|---|
| [`protocol/`](protocol/package.json) | JavaScript 协议、选票编排、公共重放与测试 |
| [`native/`](native/Cargo.toml) | Rust workspace：CGY 密码学/协议、trustee、board、coordinator、verifier 和 runner |
| [`circuits/`](circuits/package.json) | Circom 选票关系和锁定的 circuit 依赖 |
| [`contracts/arbitrum/`](contracts/arbitrum/package.json) | Arbitrum 选票合约、board 绑定、fixtures 和 Hardhat 测试 |
| [`configs/reference/`](configs/reference/five_of_five_n8.json) | 五取五参数和本地实验规模 |
| [`scripts/`](scripts/reproduce.ps1) | setup、一键复现、结果核验、汇总与安全导出 |
| [`docs/`](docs/architecture.md) | 架构、协议、安全、复现、映射和来源说明 |
| [`evidence/`](evidence/README.md) | 历史论文证据归档链接与哈希 |
| `runs/` | 新实验的忽略输出，仅跟踪 `runs/README.md` |

## 许可证与引用

代码采用 [GPL-3.0](LICENSE)。CGY 工具箱归功于 Véronique Cortier、Pierrick Gaudry 和 Quentin Yang，见其 [IACR ePrint 2021/491](https://eprint.iacr.org/2021/491)。

```bibtex
@misc{li2026enforcing,
  author       = {Jiayu Li and Gongli Li},
  title        = {Enforced Winner-Only Disclosure: Verifiable Tally Hiding for Weighted On-Chain Governance},
  howpublished = {Cryptology ePrint Archive, Paper 2026/1773},
  year         = {2026},
  url          = {https://eprint.iacr.org/2026/1773}
}
```

历史运行与源码版本的关系见[来源说明](docs/provenance.md)；论文到代码的映射见[paper-to-code](docs/paper-to-code.md)。
