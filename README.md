# Enforcing Winner-Only Disclosure

Research artifact for [Enforcing Winner-Only Disclosure: Verifiable Tally Hiding for Weighted DAO Governance](https://eprint.iacr.org/2026/1773). The system keeps weighted ballot values encrypted through aggregation and comparison, then opens a rerandomized ciphertext for the final decision bit. A policy that merely says “publish only the winner” is a declared disclosure rule; this implementation adds proof-checked protocol steps that restrict decryption to authorized gate outputs and the final decision. The artifact documents and tests that code path; it does not by itself establish the paper’s theorem or its assumptions.

## Repository architecture

| Component | Responsibility |
|---|---|
| `backend/cgy_native` | Authoritative five-trustee-profile gate execution and DAG evaluation; BabyJubjub arithmetic, canonical point validation and subgroup checks, auxiliary-point derivation, Fiat–Shamir proof checks, masking, rerandomization, partial-decryption proofs, and streaming DAG replay are native Rust. Rayon evaluates independent ready-frontier nodes in parallel. |
| `backend/js_protocol` | JavaScript protocol and integration layer: test-only threshold setup, ballot witness/proof orchestration, Groth16 verification, local and chain admission, exact accepted-board binding, trustee board envelopes, final-release adapter, public replay, and the cleartext oracle comparator. It also contains the JavaScript gate implementation used as a reference/test oracle. The reference runners select the Rust DAG backend. |
| `circuits/prototypes/strong_bit` | The current 8-bit weighted-ballot Circom relation and its included BabyJubjub/ElGamal circuit library. |
| `implementation/arbitrum` | `StrongN8Poll`, the Groth16 verifier, Hardhat configuration, current public ballot fixtures, and the contract admission tests. |
| `backend/cgy_native/tools/compact_transcript.js` | Lossless, framed compression of canonical gate JSONL. Canonical JSONL remains the hash and proof input. |
| `scripts/setup` | Local test-only ballot circuit and Groth16 artifact generation. |

Rust does not verify ballot Groth16 proofs or deploy/interact with Solidity. JavaScript handles those tasks and passes the admitted ciphertexts to Rust. JavaScript gate/proof modules remain as a reference implementation and test oracle; the local and Sepolia pipelines call the Rust DAG evaluator. The common-view board and test dealer are reference components, not Byzantine-consensus infrastructure or a production DKG.

## Reference configuration

`configs/reference/five_of_five_n8.json` records the current profile: five trustees, degree-four Shamir polynomial, 5-of-5 release, eight admitted ballots, 8 vote bits, 11 aggregate bits, and `tau = 500`. The contract supports `tau` through 2040. Local scale runs support `n = 8, 64, 1024` with `tau = floor(255*n/4)`.

## Prerequisites

- Node.js 20 or later and npm; package lock files pin JavaScript dependencies. CI uses Node 20.
- Rust 1.98.1, pinned in `rust-toolchain.toml`; `Cargo.lock` pins crate versions.
- Circom 2.1.6 for ballot circuit compilation. The circuit dependency `circomlib` 2.0.5 is pinned separately under `circuits/`.
- snarkjs 0.7.6 is installed by the backend package. Hardhat and contract dependencies are pinned by `implementation/arbitrum/package-lock.json`.
- A read-only Arbitrum Sepolia RPC endpoint when replaying a public run. The public endpoint used in the example is listed in the [Arbitrum documentation](https://docs.arbitrum.io/arbitrum-bridge/quickstart).

The local setup script creates a fresh, throwaway Groth16 setup for functional tests. It is not a secure ceremony and its generated proving artifacts are ignored by Git.

## Build

From the repository root:

```powershell
npm ci --prefix circuits
npm ci --prefix backend/js_protocol
npm ci --prefix implementation/arbitrum
cargo build --release --locked --manifest-path backend/cgy_native/Cargo.toml
npm --prefix implementation/arbitrum run compile
npm --prefix backend/js_protocol run build:ballot
```

`build:ballot` compiles the circuit and creates ignored local WASM, proving key, and verification key files under `implementation/logs/bit_ballot/`. It refuses to overwrite existing outputs. Do not use its test setup for live governance.

## Quick test

After the Rust build and the two npm installs for `circuits/` and the backend:

```powershell
cargo test --locked --manifest-path backend/cgy_native/Cargo.toml
npm --prefix backend/js_protocol run test:threshold-release
npm --prefix backend/js_protocol run test:cross-language
```

## Full local protocol run

First build the local ballot artifacts as described above. This run uses the current ballot relation and proofs, application-level local admission, the Rust weighted DAG, 5-of-5 final release, and a separately launched ballot child that writes oracle inputs outside the protocol directory.

```powershell
$env:CGY_LOCAL_N = "8"
$env:CGY_LOCAL_RUN_DIRECTORY = "artifacts/local_five_trustee_n8"
$env:CGY_N8_ORACLE_DIRECTORY = "artifacts/local_five_trustee_n8_oracle"
$env:CGY_BALLOT_ARTIFACT_ROOT = (Get-Location).Path
npm --prefix backend/js_protocol run run:local-scale
npm --prefix backend/js_protocol run replay:local
npm --prefix backend/js_protocol run compare:oracle
```

The independent replay verifies public proofs, the sealed accepted board, every broadcast transcript, the Rust gate DAG, the final release, and the complete transcript hash. Only after that replay passes does the comparator open the separate cleartext oracle input file. The comparator writes result bits and a match field to `benchmark_summary.json`; it does not write the weighted sum.

## Scale benchmark

Use the same build and command sequence, changing `CGY_LOCAL_N` and the run/oracle directory names:

```powershell
$env:CGY_LOCAL_N = "64"
$env:CGY_LOCAL_RUN_DIRECTORY = "artifacts/local_five_trustee_n64"
$env:CGY_N8_ORACLE_DIRECTORY = "artifacts/local_five_trustee_n64_oracle"
```

Then run the three commands from the local protocol section. `1024` is also supported by the streaming runner; change the values to `1024`, `artifacts/local_five_trustee_n1024`, and `artifacts/local_five_trustee_n1024_oracle`. The runner emits machine-readable run manifests and summaries with gate count, DAG measurements, stage timings, transcript sizes, result bit, oracle result bit, and agreement. Timings are generated at runtime, not copied from the paper.

## Independent public replay

No public-run bundle is included in this revision. To replay a public run generated with the current source, set `CGY_N8_RUN_DIRECTORY` to its public artifact directory and run:

```powershell
$env:ARBITRUM_SEPOLIA_RPC_URL = "https://sepolia-rollup.arbitrum.io/rpc"
$env:CGY_N8_RUN_DIRECTORY = "<directory containing the public run bundle>"
$env:CGY_BALLOT_ARTIFACT_ROOT = (Get-Location).Path
npm --prefix backend/js_protocol run replay:sepolia
```

The replay command reads public artifacts and uses a read-only RPC endpoint; it does not require a private key. RPC providers may impose rate limits.

## Test suites

- JavaScript protocol tests: `npm --prefix backend/js_protocol test`. These cover point/group validation, challenge binding, masking, rerandomization, threshold decryption, state transitions, board consistency, accepted-board binding, terminal release, and transcript tampering. `test/five_of_five_threshold.test.js` and `test/five_of_five_final_release.test.js` exercise the current 5-of-5 profile, including 3- and 4-share rejection, invalid or duplicate shares, wrong-session/ciphertext shares, altered trustee verification keys, and final-release authorization.
- Native Rust tests: `cargo test --locked --manifest-path backend/cgy_native/Cargo.toml`, including BabyJubjub compatibility and gate-proof validation.
- Cross-language checks: `npm --prefix backend/js_protocol run test:cross-language` checks deterministic JavaScript/Rust gate transcripts; `test:group:reference` cross-checks group arithmetic against circomlibjs. `test/compact_transcript.test.js` checks byte-for-byte JSONL round-trip and rejection of a malformed compact header.
- Solidity tests: `npm --prefix implementation/arbitrum test -- --grep StrongN8Poll`.
- Circuit generation and ballot proving are exercised by `build:ballot` followed by the local `n=8` run. CI does not run the costly proving setup or large scale benchmarks.

Some JavaScript unit tests exercise the generic reference helper’s older 3-of-5 default. The current end-to-end runners explicitly provision the five-trustee, 5-of-5 reference profile.

## Public-chain execution record

This repository does not ship a public-chain execution bundle. The sealed-board schema and hash domain use the descriptive v1 identifiers in the current source, so any earlier bundle must be regenerated before replay. Generate a fresh public run with `run:sepolia` before attempting independent replay.

## Security and artifact scope

The artifact supplies executable code and adversarial tests; it does not include a public-chain execution bundle. Tests do not prove the manuscript’s security theorem. The protocol argument depends on its stated cryptographic assumptions, correct implementations and proof systems, trusted public parameters, and the specified trustee behavior. The setup used by local runs is a single-process test-only dealer, not DKG. The common-view board is a local reference service. Requiring all five trustees creates an availability dependency: one unavailable trustee prevents release. The contracts and tooling are research artifacts and are not presented as production-ready governance software.

Normal tally execution is not given the cleartext weighted tally or oracle inputs. Ballot witnesses exist only in the child proof-generation process; oracle inputs are written to a sibling directory and are read only by the post-replay evaluation comparator.

## Paper mapping

| Paper component | Source |
|---|---|
| Canonical BabyJubjub points and hash-to-subgroup | `backend/js_protocol/src/group.js`, `group_oracle.js`; `backend/cgy_native/src/lib.rs`, `gate.rs` |
| Setup, masking, zero encryption, rerandomization, threshold shares and proofs | `backend/js_protocol/src/threshold_setup.js`, `proofs.js`, `rerandomization.js`, `threshold_decryption.js`; `backend/cgy_native/src/gate.rs` |
| Validation state machine and common-view board | `backend/js_protocol/src/validation_state.js`, `broadcast_board.js`, `conditional_gate.js` |
| Conditional gate and Algorithms 7–10, 21, 23, 40, 63–67 | `backend/js_protocol/src/conditional_gate.js`; `backend/cgy_native/src/gate.rs` |
| Weighted aggregation and threshold comparison | `backend/js_protocol/src/arithmetic.js`; Rust DAG in `backend/cgy_native/src/gate.rs` |
| Chain admission and exact accepted-board binding | `implementation/arbitrum/contracts/StrongN8Poll.sol`, `implementation/arbitrum/board_binding/lib/sealed_board.js`, `backend/js_protocol/src/accepted_board.js` |
| Terminal adapter, final rerandomize-then-decrypt and result claim | `backend/js_protocol/src/final_release.js`; reference runners and `replay_sepolia_public.js` |
| Canonical transcript, streaming replay and compact codec | `backend/cgy_native/src/gate.rs`; `backend/cgy_native/tools/compact_transcript.js`; replay scripts |

The manuscript algorithm numbers correspond to the current source comments and protocol code; consult the cited function implementations for precise steps and assumptions.

## License and acknowledgements

This artifact is distributed under GNU GPL version 3; see [`LICENSE`](LICENSE). Dependency versions and license metadata are recorded in the npm lock files; notable upstream components include [Circomlib](https://github.com/iden3/circomlib) (LGPL-3.0), [circomlibjs](https://github.com/iden3/circomlibjs), [snarkjs](https://github.com/iden3/snarkjs), [ethers](https://github.com/ethers-io/ethers.js), and [Hardhat](https://github.com/NomicFoundation/hardhat). The paper and artifact are provided for research evaluation, not deployment in a live election.
