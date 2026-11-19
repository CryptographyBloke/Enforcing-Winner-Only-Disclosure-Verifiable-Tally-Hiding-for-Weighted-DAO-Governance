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

The following values are read from the retained `evidence/data/performance_local.csv`. The source, machine, and run IDs are historical; timings are not promises for a new host.

| n | proving (s) | admission (s) | backend (s) | release (s) | producer replay (s) | total (s) | JSONL transcript |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 8 | 10.044 | 0.153 | 4.055 | 6.926 | 0.919 | 22.123 | 27 MB |
| 64 | 146.507 | 1.282 | 15.981 | 8.927 | 11.684 | 184.408 | 221 MB |
| 256 | 368.449 | 5.216 | 47.129 | 8.403 | 32.910 | 462.134 | 886 MB |
| 1,024 | 1,414.928 | 19.164 | 156.715 | 4.568 | 114.540 | 1,709.946 | 3.55 GB |

The original measurement host was Windows 11 with an Intel Core i7-14650HX, Node.js 24.15, and Rust 1.98.1. Fresh results belong under `runs/` and are summarized with `node scripts/summarize_runs.js`. Runtime comparisons should include host and toolchain details.

## Fresh cleaned-workspace runs (2026-11-19)

These four runs were generated from cleaned source commit `c60db5d7cb006c07db68743751a100e5c8e4260e` on Windows 11 (build 10.0.26200), Intel Core i7-14650HX (16 physical / 24 logical cores), Node.js 24.15.0, Rust 1.98.1, and Circom 2.1.6. One fresh test-only Groth16 setup took about 14 minutes and is excluded from the per-size pipeline totals. Each run passed ballot proof verification, local admission, exact accepted-board binding, five-of-five final release, producer replay, independent public replay, result checks, and isolated oracle comparison.

| n | gates | depth | proving (s) | admission (s) | Rust backend (s) | release (s) | producer replay (s) | independent replay (s) | complete per-size pipeline (s) |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 8 | 134 | 72 | 17.947 | 0.620 | 5.302 | 8.031 | 1.282 | 2.900 | 38.645 |
| 64 | 1,086 | 147 | 150.325 | 2.566 | 24.397 | 4.583 | 13.050 | 14.982 | 226.338 |
| 256 | 4,350 | 207 | 592.009 | 9.414 | 83.640 | 8.873 | 59.714 | 70.161 | 886.193 |
| 1,024 | 17,406 | 275 | 2,363.563 | 34.649 | 322.893 | 6.960 | 246.083 | 281.850 | 3,507.043 |

The table is parsed from the four new run artifacts; it is not filled from the historical CSV. The new per-size total includes the current pipeline's producer replay, compact transcript encoding, independent public replay, result checks, and oracle comparison. Historical totals have a different scope, so compare phase timings rather than totals. The four manifest files are in the public evidence release linked from [`provenance.md`](provenance.md); machine-readable data are also in `runs/public_exports/fresh_results.csv` in the local workspace.

The fresh gate counts and depths match all four expected structures. Runtime is materially slower than the historical Q5 measurements at `n=256` and `n=1,024`, including for the Rust backend. The cause has not been isolated; these valid fresh observations do not establish a performance reproduction and must not replace the historical paper results. A controlled repeat/profile is needed before making a timing claim. For `n=1,024`, the canonical JSONL transcript is 3,539,239,193 bytes and compact encoding is 956,381,856 bytes.

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
