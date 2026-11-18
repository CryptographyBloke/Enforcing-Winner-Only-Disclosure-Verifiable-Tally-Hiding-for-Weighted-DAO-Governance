# 强制仅披露获胜结果

**面向加权 DAO 治理的可验证计票隐藏**

作者：Jiayu Li、Gongli Li · 单位：河南师范大学 · [IACR Cryptology ePrint 2026/1773](https://eprint.iacr.org/2026/1773) · BlockSys 2027

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

Bash 入口：`bash scripts/reproduce.sh 8,64,256,1024`。详细安装、输出目录、资源估计和链上说明见[快速指南](docs/quickstart.md)和[实验指南](docs/experiments.md)。

## 历史 Q5 测量

下列数值来自历史冻结版 Q5 源码和原测试工作站，不是清理后 checkout 产生的结果。运行时间随机器变化。

| n | 门数 | 深度 | 选票证明 | 后端 | 独立重放 | 总计 |
|---:|---:|---:|---:|---:|---:|---:|
| 8 | 134 | 72 | 10.044 秒 | 4.055 秒 | 0.919 秒 | 22.123 秒 |
| 64 | 1,086 | 147 | 146.507 秒 | 15.981 秒 | 11.684 秒 | 184.408 秒 |
| 256 | 4,350 | 207 | 368.449 秒 | 47.129 秒 | 32.910 秒 | 462.134 秒 |
| 1,024 | 17,406 | 275 | 1,414.928 秒 | 156.715 秒 | 114.540 秒 | 1,709.946 秒 |

各阶段数据见[`evidence/data/performance_local.csv`](evidence/data/performance_local.csv)。原始证据归档及其哈希保存在 [blocksys2027-evidence-v1 release](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/releases/tag/blocksys2027-evidence-v1)。新实验写入 Git 忽略的 `runs/`，并从实际生成的产物中汇总，不会预填这些历史数字。

## 安全范围

论文证明了即使受托方恶意也不会接受错误结果，并证明少于五个解密份额的静态主动攻击者集合无法获知 tally；winner-only disclosure 推论针对实际封存的 board。实现中的五个受托方角色位于同一进程，使用测试专用 setup；这不是分布式密钥生成仪式，也不是生产部署。详见[安全模型](docs/security-model.md)。

## Arbitrum Sepolia 参考运行

归档的 `n=8` 测试网实验使用 chain ID `421614`，接受八张选票，并保存公共重放及结果声明。这是测试网参考实验，不代表生产 Arbitrum DAO 治理。链上参考阈值为 `tau=500`；本地规模实验使用 `floor(255*n/4)`，因此本地 `n=8` 的 `tau=510`。本地复现命令不会提交新的链上交易，详见[链上实验说明](docs/experiments.md#fresh-arbitrum-sepolia-experiment)。

## 仓库目录

| 路径 | 内容 |
|---|---|
| [`protocol/`](protocol/package.json) | JavaScript 协议、选票编排、公共重放与测试 |
| [`native/`](native/Cargo.toml) | Rust CGY gate 引擎、调度器和 transcript 工具 |
| [`circuits/`](circuits/package.json) | Circom 选票关系和锁定的 circuit 依赖 |
| [`contracts/arbitrum/`](contracts/arbitrum/package.json) | Arbitrum 选票合约、board 绑定、fixtures 和 Hardhat 测试 |
| [`configs/reference/`](configs/reference/five_of_five_n8.json) | 五取五参数和本地实验规模 |
| [`scripts/`](scripts/reproduce.ps1) | setup、一键复现、结果核验、汇总与安全导出 |
| [`docs/`](docs/architecture.md) | 架构、协议、安全、复现、映射和来源说明 |
| [`evidence/`](evidence/README.md) | 历史 Q5 记录、冻结源码和核验说明 |
| `runs/` | 新实验的忽略输出，仅跟踪 `runs/README.md` |

## 许可证与引用

代码采用 [GPL-3.0](LICENSE)。CGY 工具箱归功于 Véronique Cortier、Pierrick Gaudry 和 Quentin Yang，见其 [IACR ePrint 2021/491](https://eprint.iacr.org/2021/491)。

```bibtex
@misc{li2026enforcing,
  author       = {Jiayu Li and Gongli Li},
  title        = {Enforcing Winner-Only Disclosure: Verifiable Tally Hiding for Weighted {DAO} Governance},
  howpublished = {Cryptology ePrint Archive, Paper 2026/1773},
  year         = {2026},
  url          = {https://eprint.iacr.org/2026/1773}
}
```

历史运行与源码版本的关系见[来源说明](docs/provenance.md)；论文到代码的映射见[paper-to-code](docs/paper-to-code.md)。
