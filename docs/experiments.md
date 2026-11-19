# Experiments and result handling

## Local size sweep

The maintained five-of-five local runner supports all four paper sizes. Expected gate structure is fixed and checked against each new run's actual manifest:

| n | Gates | Scheduled depth | Max ready width | Local threshold `floor(255*n/4)` |
|---:|---:|---:|---:|---:|
| 8 | 134 | 72 | 4 | 510 |
| 64 | 1,086 | 147 | 32 | 4,080 |
| 256 | 4,350 | 207 | 128 | 16,320 |
| 1,024 | 17,406 | 275 | 512 | 65,280 |

The local pipeline uses `a=5`, Shamir degree `t=4`, `q_dec=5`, eight-bit weights, and the established weighted threshold construction. At `n>=256`, journal writing, native gate production, and public replay stream through files to bound memory use. This changes I/O and buffering, not the ballot relation, gate records, transcript hash, or release semantics.

Local runs use `tau=floor(255*n/4)`. The Arbitrum Sepolia reference uses `tau=500` at `n=8`; the corresponding local value is `510`. Do not compare those two thresholds as if they were the same experiment.

The GitHub Actions `workflow_dispatch` reproduction job defaults to `n=8`. Its `sizes` input accepts a comma-separated local selection such as `256` or `8,64`; the same disk-space and verification gates apply as for a PowerShell or Bash run.

## Historical Q5 timings

The following phase timings are from the manifests behind the rounded historical Q5 values in the PDF. The manifests and source records are preserved in the [evidence-v1 release](../evidence/README.md), not duplicated in the main source tree. The source, machine, and run IDs are historical; timings are not promises for a new host.

| n | proving (s) | admission (s) | backend (s) | release (s) | producer replay (s) | total (s) | JSONL transcript |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 8 | 10.044 | 0.153 | 4.055 | 6.926 | 0.919 | 22.123 | 27 MB |
| 64 | 146.507 | 1.282 | 15.981 | 8.927 | 11.684 | 184.408 | 221 MB |
| 256 | 368.449 | 5.216 | 47.129 | 8.403 | 32.910 | 462.134 | 886 MB |
| 1,024 | 1,414.928 | 19.164 | 156.715 | 4.568 | 114.540 | 1,709.946 | 3.55 GB |

The original measurement host was Windows 11 with an Intel Core i7-14650HX, Node.js 24.15, and Rust 1.98.1. The total column uses the manifest `totalSeconds` field, which includes a small setup interval not shown as a separate Table 1 column. Fresh results belong under `runs/` and are summarized with `node scripts/summarize_runs.js`. Runtime comparisons should include host and toolchain details.

## Fresh local reproduction

The PowerShell and Bash entry points generate new run IDs, verify each phase, and summarize only the artifacts produced by that invocation. Their measurements are new observations for the maintained checkout; they do not regenerate the historical values in the submission PDF.

A separate cleaned-workspace validation archive exists as evidence v2. It is an engineering record outside the submission results. The paper tables and their source manifests remain in evidence v1.

## Public-safe results

The run's `public/` folder contains only public inputs and verification outputs. `private/oracle/` holds the test votes and weights used by the isolated comparison. The comparator is called only after the independent replay succeeds. The public export tool copies a reviewed allowlist and requires both replay and oracle comparison to pass.

Avoid sharing the entire run parent directory: it contains the private oracle subdirectory. A valid export can be created with:

```powershell
node scripts/export_public_run.js --run runs\<run-id>\public --out runs\exports\<run-id>
```

New run artifacts are separate from the paper's historical evidence. The validated 2026-11-19 public-safe outputs have been packaged as a separate evidence-v2 release; the existing Q5 archive remains unchanged. Fresh measurements may be cited as new cleaned-workspace observations, but not as a replication of historical timings.

## Fresh Arbitrum Sepolia experiment

The existing `n=8` contract, poll parameters, and protocol are unchanged. A future public-chain experiment is a separate author-controlled action and is not started by `scripts/reproduce.ps1`.

Prepare the environment only when the author is ready. It requires:

- a read RPC endpoint for Arbitrum Sepolia;
- a fresh, unused decimal poll ID;
- a testnet-funded deployer;
- fresh public output and separate private oracle directories;
- the test-only ballot artifacts and the pinned toolchain.

Set credentials in the current PowerShell session without printing them or saving them in the repository, then run the read-only preflight:

```powershell
$env:ARBITRUM_SEPOLIA_RPC_URL = '<RPC endpoint>'
$env:ARBITRUM_SEPOLIA_PRIVATE_KEY = '<funded testnet key>'
node protocol/scripts/sepolia_preflight.js
```

The preflight queries chain ID, block height, deployer address, and balance. It submits no transaction and does not write credentials. The current implementation does not log the private key or RPC URL. After reviewing the preflight, the author may choose to execute the existing `run:sepolia` pipeline with a new poll ID and fresh paths. That pipeline deploys and submits transactions; do not run it as part of routine local reproduction. Keep its oracle directory private and outside the public run directory.

The archived Sepolia reference used chain ID `421614`, poll ID `910004`, eight accepted ballots, 134 gates, and `tau=500`. It is testnet evidence, not a production Arbitrum DAO deployment. The public archive and its limitations are described in [provenance.md](provenance.md) and [`evidence/README.md`](../evidence/README.md).
