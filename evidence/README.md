# Historical paper evidence

The main branch keeps the submission PDF and its maintained implementation easy to find. Detailed historical run files and the frozen Q5 source are preserved in the existing [`blocksys2027-evidence-v1 release`](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/releases/tag/blocksys2027-evidence-v1), rather than duplicated throughout this source tree.

The release asset `blocksys2027_evidence_package.zip` contains the Q5 run manifests, source and artifact hash records, public-chain records, replay materials, and frozen source snapshot. Its published SHA-256 is:

```text
7169b79aa099fa42de3c37cadcdd6c21125b7ca4ac63e6a7419e9475cc776a84
```

The release and its asset are historical records and remain unchanged. To download and verify the archive in PowerShell:

```powershell
$evidenceDir = Join-Path $env:TEMP ("blocksys2027-evidence-v1-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $evidenceDir | Out-Null
gh release download blocksys2027-evidence-v1 --repo CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance --pattern blocksys2027_evidence_package.zip --dir $evidenceDir
Get-FileHash (Join-Path $evidenceDir "blocksys2027_evidence_package.zip") -Algorithm SHA256
```

The post-cleanup engineering runs are in the separate [`evidence-v2 release`](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/releases/tag/blocksys2027-evidence-v2-cleaned-local-2026-11). They are not the measurements reported by the submission PDF. New runs from this checkout are written under the ignored `runs/` directory.

## Rust ballot-proving subexperiment

Three fresh release-mode n=8 ballot-proving runs from RUST-02 are exported under [`rust02-ballot-proving/`](rust02-ballot-proving/). Each includes the public proof bundle, a provenance manifest, and sanitized logs. The Rust binary generated and verified the Groth16 proofs; the unchanged Solidity verifier accepted all eight ballots in each run. This measures the ballot-proof stage. It does not measure admission, encrypted tally gates, trustee communication, final release, public tally replay, or oracle comparison. The full Rust protocol remains incomplete; see [`reports/RUST-02.md`](../reports/RUST-02.md).

The runs used the original `.zkey` whose SHA-256 is `6D80E0822F72C3F5613D02E9BD907DE33CF50C4BD21C3470139C31DA6AE28E4C`. The matching WASM/R1CS and verification key are identified by hashes in each manifest. Those proving artifacts are not part of this repository or the historical evidence release, so reproducing proof generation from a fresh checkout requires the author to provide that matched artifact set.

To verify an exported Rust-generated bundle against the unchanged Solidity verifier in the local Hardhat EVM:

```powershell
$env:CGY_RUST_BALLOT_BUNDLE = (Resolve-Path "evidence\rust02-ballot-proving\rust02_ballot_release_n8_r1_1cbdc4c8\public\ballots.json").Path
npm --prefix contracts/arbitrum test -- --no-compile test/RustBallotVerifier.test.js
Remove-Item Env:CGY_RUST_BALLOT_BUNDLE
```
