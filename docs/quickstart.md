# Quick start

This guide runs a fresh local `n=8` experiment from a clean Windows PowerShell checkout. It does not submit blockchain transactions.

## Requirements

| Tool | Required version | Notes |
|---|---|---|
| Git | recent | Clone the public repository |
| Node.js | 20 or later | npm comes with Node.js |
| Rust/Cargo | 1.98.1 | Pinned in `rust-toolchain.toml`; install with rustup |
| Circom | 2.1.6 | Set `CIRCOM_BIN` if it is not on `PATH` |
| Disk | 2 GiB free for `n=8`; 10 GiB recommended for `n=1024` | Large transcripts remain in each run directory |

## One-command `n=8`

```powershell
git clone https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance.git
Set-Location Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance
.\scripts\reproduce.ps1 -Sizes 8 -BuildArtifacts
```

`-BuildArtifacts` installs locked npm dependencies, builds the Rust binary, and creates a fresh local test-only Groth16 setup before the run. The setup is for experiments only; it is not a trusted ceremony and must not be used for a real poll. The artifact builder refuses to overwrite prior proving artifacts. If those artifacts already exist, omit `-BuildArtifacts`.

After the first setup, run:

```powershell
.\scripts\reproduce.ps1 -Sizes 8
```

The accepted multi-size syntax is:

```powershell
.\scripts\reproduce.ps1 -Sizes 8,64,256,1024
```

Bash equivalent:

```bash
bash scripts/reproduce.sh 8,64,256,1024
```

## Success markers and output

The script exits nonzero when setup, proving, admission, sealing, Rust evaluation, five-of-five release, public replay, oracle comparison, or structure checks fail. A successful run prints `LOCAL_NATIVE_EXECUTION=PASS`, `LOCAL_PUBLIC_REPLAY=PASS`, `ORACLE_COMPARISON=PASS`, and `EXPERIMENT=PASS`.

Every run gets a unique directory such as `runs/2026-11-18_local_n8_<id>/`:

```text
public/                 public setup, proofs, accepted board, transcript,
                        final release, verification key, manifest and timings
private/oracle/         cleartext comparison inputs; never include in an export
logs/                   per-stage command output
```

The public manifest records the run ID, UTC timestamp, commit, OS/CPU, tool versions, cryptographic parameters, threshold, gate shape, phase runtimes, replay and oracle status, and public artifact hashes. The private oracle directory is outside `public/`. All run outputs are ignored by Git.

To create a public-only copy after every verification stage passes, replace the example ID with the run ID printed by the script:

```powershell
$runId = "2026-11-18_local_n8_ab12cd34"
node scripts/export_public_run.js --run "runs\$runId\public" --out "runs\exports\$runId"
```

To summarize all newly completed local runs:

```powershell
node scripts/summarize_runs.js --format markdown
node scripts/summarize_runs.js --format csv
```

The summarizer reads fresh run manifests and timing files. It does not import historical Q5 timings. For resource details and expected structural values, see [experiments.md](experiments.md).
