# Evidence for the paper's measurements

This directory holds the recorded runs behind the two result tables of the paper (local scale, and the Arbitrum Sepolia run), the hashes that pin them, and checks that need **no wallet, no private key and no account**. It adds no new measurement. For running the code itself, use the [repository README](../README.md).

## What the numbers are, and what they are not

| Item | Value |
|---|---|
| Profile | `winner-only-disclosure/five-of-five/v1` (internal name `FC2027-CGY-TOOLBOX-FULL-V1-Q5`) |
| Parameters | 5 trustees, Shamir degree 4, five-of-five opening, 8-bit weights (`L_vote = 8`) |
| Local runs | `n` = 8, 64, 256, 1,024 on one workstation. One native Rust process holds all five trustee shares |
| Public-chain run | Arbitrum Sepolia (chain ID 421614), poll 910004, `n` = 8, 134 gates |
| Setup | test-only key dealer and test-only Groth16 reference string. It is not a distributed key generation and not a trusted-setup ceremony |
| Timing scope | local and co-located. Network latency between trustees is **not** measured |
| Original hardware | Intel Core i7-14650HX (16 cores, 24 threads), Windows 11, Node.js 24.15, `rustc` 1.98.1 |

Older three-of-five runs of the same workspace are not evidence for this profile and are not included.

## Layout

| Path | Content |
|---|---|
| `runs/q5_local_n{8,64,256,1024}_*/manifest.json` | run manifest of each local run: parameters, gate count, depth, per-phase timings, setup, board, journal and release hashes |
| `runs/q5_sepolia_n8_20260923_02/` | the public-chain run: manifest, public setup, ballot proofs, chain snapshot, sealed board, final release, public replay record, oracle comparison, verification key |
| `data/performance_local.csv` | the numbers of the local-scale table, one row per run |
| `data/sepolia_identifiers.json` | every address, block, gas value and hash of the public-chain run, including the 11 transaction hashes |
| `data/onchain_receipt_check.json` | result of re-reading those 11 transactions from a public RPC on 2026-11-14 |
| `data/large_transcripts.csv` | size, SHA-256 and original location of every gate transcript |
| `data/frozen_source_check.csv` | the 41-entry production source manifest checked against `frozen_source_q5/` |
| `docs/` | the original evidence reports of the Q5 series and its 49-line SHA-256 manifest |
| `frozen_source_q5/` | the source snapshot that produced the recorded runs (see the next section) |
| `tools/` | scripts that re-check the recorded runs |

The gate transcripts are **not** in the git tree (27 MB for `n` = 8 up to 3.55 GB for `n` = 1,024). The compact `n` = 8 Sepolia transcript (7.4 MB) is an asset of the GitHub release [`blocksys2027-evidence-v1`](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/releases/tag/blocksys2027-evidence-v1), which holds the complete evidence archive (81 files, SHA-256 `7169b79aa099fa42de3c37cadcdd6c21125b7ca4ac63e6a7419e9475cc776a84`) with its own `MANIFEST.sha256`. This directory is a subset of that archive; the one data column that differs is described in Step 5.

## Which source produced the recorded runs

The recorded runs were produced by the pre-release workspace, **not** by the repository head. The repository is a renamed release:

* The prefix `FC2027` was removed from protocol and domain-separation strings and from the Rust crate name. The recorded transcript hash recomputes with the old string (`FC2027-CGY-TOOLBOX-FULL-V1/N8-COMPLETE-TRANSCRIPT/V1`) and not with the new one.
* The sealed-board library and its domain strings were renamed. The repository head's library gives a different sealed-board hash for the retained chain snapshot than the recorded value. The frozen library reproduces the recorded value.
* Two JavaScript files differ in content (`accepted_board.js`, `n8_ballots.js`). The five Rust files differ only by the removed prefix and the crate name.

So the retained run bundles verify against `frozen_source_q5/`, not against the repository head. Do not expect a recorded bundle to pass the head's replay. The head is tested on its own and reproduces the protocol with fresh runs (see the repository README).

`frozen_source_q5/` holds 38 of the 41 files of the production source manifest, byte-identical to the recorded hashes, plus the two board libraries. `run_q5_local_scale.js` differs from its manifest hash by a documented change for `n` = 256 (three comparisons `count >= 1024` changed to `count >= 256`, see `docs/CGY_Q5_N256_AND_PARALLEL_EVIDENCE.md`, section 1). The 2.3 MB circuit `.wasm` and the 29.8 MB proving key `.zkey` are not copied; their hashes and original locations are in `data/frozen_source_check.csv`.

## Checks that need no key

Run these from the **repository root**. They need Python 3 and Node.js 20 or later. Step 3 also needs the `ethers` package, which `npm ci --prefix backend/js_protocol` installs.

### Step 1. Check a frozen source file against its recorded hash

`data/frozen_source_check.csv` lists the recorded SHA-256 of each frozen source file. Check the frozen Rust lock file as an example:

```bash
sha256sum evidence/frozen_source_q5/backend/cgy_native/Cargo.lock
grep Cargo.lock evidence/data/frozen_source_check.csv
```

Expected: both print `87e5ec008934ae9c3396cffcb133564c24d9a9699827babcc55a0ad454c33b86`.

Line endings matter for these hashes. `.gitattributes` marks `evidence/**` as `-text` so that git does not rewrite them. Do not run an editor or a formatter over this directory.

### Step 2. Re-read the Sepolia run from the public chain

```bash
python evidence/tools/check_onchain.py
```

This reads the 11 transactions and the outcome-claim event from `https://sepolia-rollup.arbitrum.io/rpc` (pass another RPC URL as the first argument if this one rate-limits). It compares status, block, gas, accepted-ballot commitment, transcript hash and result bit with the recorded run. Expected: eleven `OK` lines, the line `OK   claim event: commitment 0x7744133e30fb..., H(T) 0c48bb7062a4..., b=1`, and exit code 0.

### Step 3. Recompute the backend sealed-board hash

```bash
npm ci --prefix backend/js_protocol
NODE_PATH=backend/js_protocol/node_modules node evidence/tools/verify_board_hash.js
```

On Windows PowerShell set the variable first: `$env:NODE_PATH = "backend/js_protocol/node_modules"`. Expected last line: `MATCH` (recomputed `0x64876090cba05fdd26b631ac3a23078d11e5f42cc516c854478c52c05610a172`, equal to the recorded value).

### Step 4. Recompute the transcript hash H(T) from the retained transcript

Download the evidence zip from the release, unpack it, and point the tool at the compact transcript:

```bash
curl -L -o evidence.zip https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/releases/download/blocksys2027-evidence-v1/blocksys2027_evidence_package.zip
python -m zipfile -e evidence.zip evidence-zip
node evidence/tools/verify_transcript_hash.js evidence-zip/blocksys2027-evidence-package/runs/q5_sepolia_n8_20260923_02/gate_transcript.compact.bin
```

The archive's SHA-256 is `7169b79aa099fa42de3c37cadcdd6c21125b7ca4ac63e6a7419e9475cc776a84` (`sha256sum evidence.zip`). Expected last line: `TRANSCRIPT_HASH=MATCH`. The tool unpacks the lossless compact encoding in memory and checks four things: the gate-journal hash, the final-release hash, the recomputed H(T), and that H(T) equals the value the contract recorded in its outcome claim. This tool needs only Node.js.

### Step 5. Regenerate the data tables from the run manifests

```bash
python evidence/tools/make_package_data.py
git diff --stat evidence/data
```

The script copies every value from a recorded manifest and asserts that gate counts, result bits and timing sums agree. Expected: it prints one `wrote ...` line and `git diff` prints nothing. The script writes the line endings of the host system, so on Linux or macOS use `git diff --ignore-cr-at-eol --stat evidence/data` instead, which must also print nothing. If you first unpack a transcript into `evidence/runs/...`, the column `in_this_archive` of `large_transcripts.csv` changes to `yes` for it. That is the only expected difference.

## The three hashes of the Sepolia run

They are different values and are not interchangeable.

| Name | Meaning | Value |
|---|---|---|
| accepted-ballot commitment | the contract's Keccak accumulator after the eighth ballot, checked by the claim | `0x7744133e30fb60af210302967a37324db2bf3acc7dbb7631f7cdaf6dae2706da` |
| sealed-board hash | hash of the canonical board object that contains the commitment, bound into the transcript hash | `0x64876090cba05fdd26b631ac3a23078d11e5f42cc516c854478c52c05610a172` |
| transcript hash H(T) | hash over setup, sealed board, gate journal and final release, recorded by the claim | `0c48bb7062a4be1c599bebaad90557753338cd6764673207a26584419aa8d064` |

The claim contract compares only the commitment and requires a nonzero transcript hash. It does **not** verify the transcript. That check is the public replay, so a recorded claim alone is not a verified result.

## What was and was not re-run

| Check | Status |
|---|---|
| 11 Sepolia transactions and the claim event re-read from a public RPC | re-run (Step 2) |
| sealed-board hash recomputed with the frozen library | re-run (Step 3) |
| H(T) recomputed from the retained transcript | re-run (Step 4) |
| data tables regenerated from the manifests | re-run (Step 5) |
| local scale runs `n` = 64, 256, 1,024 | **not re-run**. Timings are those recorded on the workstation above |
| full public replay of the retained Sepolia bundle with the frozen source | **not completed** in this revision |

To reproduce a **fresh** local run instead of auditing the recorded one, follow the repository README. Its timings will differ from the recorded ones because they depend on the host.

## License

The code under `frozen_source_q5/` is distributed under the GNU GPL v3 as in the repository ([LICENSE](../LICENSE)). The run records are data of the same project.
