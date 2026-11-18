# Troubleshooting

| Symptom | Resolution |
|---|---|
| `Circom 2.1.6 is required` | Install Circom 2.1.6 and confirm `circom --version`. Set `$env:CIRCOM_BIN` to its executable if needed. |
| `Rust 1.98.1 is pinned` or `cargo` is unavailable | Install rustup and the pinned toolchain from `rust-toolchain.toml`; reopen the shell and check `rustc --version` and `cargo --version`. |
| Missing `native/target/release/cgy-native` | Run `cargo build --release --locked --manifest-path native/Cargo.toml`, or use `-BuildArtifacts` on a fresh checkout. |
| Missing ballot WASM, zkey, or verification key | Install Circom 2.1.6, then run `npm ci --prefix circuits`, `npm ci --prefix protocol`, and `npm --prefix protocol run build:ballot`. The builder refuses to overwrite existing artifacts. |
| `E_LOCAL_SCALE_N` | Accepted sizes are exactly `8`, `64`, `256`, and `1024`. |
| Disk-space check stops an `n=1024` run | Keep at least 10 GiB free on the volume containing `runs/`. The historical JSONL transcript alone was about 3.55 GB. |
| A run fails after creating its directory | Keep the failed directory for diagnosis; the logs show each completed stage. Start a new command to get a new unique run ID. The tool never resumes or overwrites a run. |
| Public replay fails | Do not run the oracle comparator. Check the recorded public files, Rust executable, verification key, transcript, and source commit first. |
| Oracle comparison refuses to run | It requires a passing independent public replay and matching transcript hash and result bit. Keep the oracle private. |
| Hardhat requests RPC credentials during contract tests | The local contract tests use Hardhat's in-process EVM. Do not set or print real wallet credentials for those tests. |
| PowerShell rejects a Git Bash `/tmp/...` path | Use native PowerShell paths. For a path copied from Git Bash, convert it with `cygpath -m` inside Git Bash. |

The local reproduction script performs no RPC call. The optional Sepolia preflight is read-only, but the separate Sepolia pipeline deploys contracts and sends transactions. Run that pipeline only when the author has selected a fresh poll ID, funded testnet account, and separate public/private directories.
