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

The preflight queries chain ID, block height, deployer address, and balance. It submits no transaction. Its output excludes the RPC URL and private key; error output redacts both values. The ballot-generation child process does not receive either credential.

After reviewing the preflight, the author may choose to run a new testnet experiment. The poll ID must be a fresh unused decimal value, and the directories below are unique for each invocation. The deployment command submits transactions and spends testnet funds. Do not run it as part of routine local reproduction.

```powershell
# Replace both prompts with your private endpoint and funded testnet key.
$env:ARBITRUM_SEPOLIA_RPC_URL = '<read-only Arbitrum Sepolia RPC endpoint>'
$env:ARBITRUM_SEPOLIA_PRIVATE_KEY = '<funded testnet deployer key>'
npm ci --prefix protocol
node protocol/scripts/sepolia_preflight.js
```

Stop after the preflight and review the chain ID and balance. Only if you choose to continue, keep the same PowerShell session and run:

```powershell
$repoRoot = (Get-Location).Path
$env:CGY_SEPOLIA_POLL_ID = '<fresh unused decimal poll ID>'
$env:HARDHAT_NETWORK = 'arbitrumSepolia'
$env:CGY_NATIVE_BACKEND = '1'
$env:CGY_BALLOT_ARTIFACT_ROOT = $repoRoot
$runId = 'sepolia_' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmss') + '_' + [guid]::NewGuid().ToString('N')
$env:CGY_N8_RUN_DIRECTORY = Join-Path $repoRoot "runs\$runId\public"
$env:CGY_N8_ORACLE_DIRECTORY = Join-Path $repoRoot "runs\$runId-private-oracle"

npm ci --prefix circuits
npm ci --prefix contracts/arbitrum
cargo build --release --locked --manifest-path native/Cargo.toml
npm --prefix protocol run build:ballot
npm --prefix contracts/arbitrum run compile
node protocol/scripts/run_sepolia_pipeline.js
node protocol/scripts/replay_sepolia_public.js
node protocol/scripts/compare_replay_with_oracle.js
```

`HARDHAT_NETWORK=arbitrumSepolia` is required for the deployment to target the testnet. The pipeline writes public verification files under `runs/<run-id>/public` and cleartext oracle inputs to a sibling private directory. The oracle comparison refuses to open those inputs until independent replay passes; it then records only the comparison result and timings in the public summary and manifest. Never print or commit the two credential variables. The build creates local test-only proving artifacts and must not be treated as a trusted setup.

The archived Sepolia reference used chain ID `421614`, poll ID `910004`, eight accepted ballots, 134 gates, and `tau=500`. It is testnet evidence, not a production Arbitrum DAO deployment. The public archive and its limitations are described in [provenance.md](provenance.md) and [`evidence/README.md`](../evidence/README.md).

## Authenticated TCP transcript transport (NETWORK-02)

This experiment replays the signed public trustee messages from a validated local run through a separate TCP board and five client processes. Each client receives the public records assigned to one trustee ID. The board persists each event and seals the existing phase vectors. Public replay and the isolated oracle comparison run after transport completes.

Run a fresh local experiment first and set `$sourceRun` to its public output directory. Replace the example path below with that run's path when reproducing with fresh inputs. For the n=8 source run used in NETWORK-02:

```powershell
$sourceRun = 'runs/2026-11-19_local_n8_8665073c/public'
node protocol/scripts/run_tcp_transcript_transport.js --source-run $sourceRun --one-way-delay-ms 0
node protocol/scripts/run_tcp_transcript_transport.js --source-run $sourceRun --one-way-delay-ms 10
node protocol/scripts/run_tcp_transcript_transport.js --source-run $sourceRun --one-way-delay-ms 50
```

The delay value is applied in each direction by the application. Values `10` and `50` model nominal 20 ms and 100 ms RTT; the manifests record the measured PING distribution. This Windows run uses IPv4 loopback and application-level delay. It records JSON framing bytes at the TCP application layer, board fsync time, signature verification, phase-seal timings, client RTT samples, independent replay time, oracle result, and source artifact hashes.

For n=64, first create a fresh local n=64 run and pass its public directory with `--source-run`. NETWORK-02 completed the 0 ms and 20 ms profiles for n=64. The 100 ms n=64 profile is not included. Each n=8 profile has three successful repetitions; the n=64 profiles have one run each.

Summarize generated network manifests and create a public-safe local bundle with:

```powershell
node scripts/summarize-network-runs.js
node scripts/export-network-evidence.js
```

Both tools write under ignored `runs/`. The exporter copies public replay artifacts, the signed canonical board log, manifests, result logs, CSV, and replay commands. It excludes the private oracle directory and workload input files. The TCP experiment replays existing signatures; the Rust CGY backend measurement is recorded separately in the source run manifest. See [the NETWORK-02 report](../reports/NETWORK-02.md) for results and the [manuscript insertion fragment](../paper/network_results.tex).
