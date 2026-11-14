STATUS=PARTIAL
PROTOCOL_PROFILE=FC2027-CGY-TOOLBOX-FULL-V1-Q5
N256_FRESH_Q5_RUN=PASS
Q5_PARALLEL_MICROBENCHMARK=PASS
Q5_FRONTIER_SWEEP=PASS
Q5_MEMORY_MICROBENCHMARK=FAIL_INCOMPLETE_PRODUCER_COVERAGE
PRODUCTION_CRYPTO_SOURCE_CHANGED=NO
MANUSCRIPT_EDITED=NO

# 1. Source identity

- Q5 source commit: `6708c956d794f7da04a7902d7eea932b9fe283ca`; production source parent: `0d49fed671ce33037a1b2d0a5b6007c3a5d17b97`.
- Frozen production-manifest file SHA-256: `68bb0d3cf2fbd9cee2981857989979455416160d3eeb8a079df01469c6458a84` (same recorded value as the final Q5 n=1024 evidence).
- `backend/cgy_native/Cargo.lock` SHA-256: `87e5ec008934ae9c3396cffcb133564c24d9a9699827babcc55a0ad454c33b86`.
- `backend/cgy_native/src/gate.rs` SHA-256 remains `865bf75097deaeae3c2840d237c75f195e370b7fa42b7b1bee5529bbeeb859c0`.
- Runtime: Node `v24.15.0`; `rustc 1.98.1 (48a229cea 2026-09-01)`; Intel Core i7-14650HX, 16 physical cores / 24 logical processors.
- The Q5 source manifest has 41 entries. Forty matched exact SHA-256/length after mapping its five `external/07_implementation/...` paths to the existing `THproto-master/07_implementation/...` artifact root; the ballot WASM, zkey, verification key, and two contract artifacts all matched their frozen hashes. The sole mismatch is the evaluation runner described below.
- To handle the 886 MB n=256 JSONL without a single oversized Node string, the evaluation runner temporarily routed `count >= 256` through its already-existing n=1024 streaming generation/journal/replay path. Exact diff: three comparisons changed from `count >= 1024` to `count >= 256`, plus a comment. This did not change gate inputs, messages, canonical JSONL, transcript codec, cryptographic source, or verifier. Frozen runner SHA `a24acd774258f950d68b4159c8f02c3c9c609d311f4658c73a0bcf4dafddd3ce`; run-time evaluation runner SHA `ef64becc4d25b844b8a42aa33ec6b2b52cae251953111742edba05da9fe1cff2`. Classified `EVALUATION_HARNESS_ONLY_CHANGE=YES`.
- The prior n=1024 report did not record Rust or CPU versions, so exact environment identity to that historical run cannot be established. The source parent, source-manifest artifact, Cargo.lock, native gate source, ballot artifacts, and Q5 profile are matched as above.

# 2. n=256 graph

Derived independently from the existing AddBits/SubLTBits graph generator before the successful run. For `L_vote=8`, the balanced 256-input aggregation has eight levels and aggregate bit-width `L_agg=L_vote+log2(n)=16`. The AddBits cost at widths 8 through 15 is `2m-1` gates per pair, giving `128·15 + 64·17 + 32·19 + 16·21 + 8·23 + 4·25 + 2·27 + 1·29 = 4,319` aggregation gates; 16-bit SubLTBits contributes 31 comparison gates.

| n | L_vote | L_agg | total gates | aggregation gates | comparison gates | depth | max ready width |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 256 | 8 | 16 | 4,350 | 4,319 | 31 | 207 | 128 |

The successful run manifest reports exactly the derived graph values; no dimension was forced. It also matches `C_total=(2L_vote+1)n-2=4,350`.

# 3. n=256 full execution

| n | gates | proving (s) | admission (s) | backend (s) | release (s) | replay (s) | total (s) | JSONL bytes | compact bytes | result/oracle |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:---:|
| 256 | 4,350 | 368.448950 | 5.215520 | 47.128688 | 8.402803 | 32.910089 | 462.133677 | 886,045,853 | 239,114,329 | 1 / 1 |

Additional transcript facts: compact/JSONL ratio `0.269867` (3.7055x); lossless compact round-trip output length was 886,045,853 bytes and round-trip SHA-256 exactly equaled the canonical JSONL SHA-256 `9de97c74426cb8f1b5f1b53021d5e245ba712002a79402b9ca25a8291ab48589`. Compact SHA-256: `ff735eb2b1333d692f731447b1f65e47394546376777f76fa7de5c53299c2b22`.

Accepted ballots: 256; rejected: 0; protocol retries: 0. Three fresh application attempts were made: attempts 01 and 02 failed only in Node transcript materialization (`Array.join` string limit, then `Buffer.toString` string limit); both directories are preserved. Attempt 03 used a fresh setup, ballots, execution ID, and board, then completed. These were two application-run restarts, not protocol retries; no failed run was silently counted as a pass or overwritten.

Final threshold was 5-of-5; final share IDs were `{1,2,3,4,5}`. Result bit and isolated oracle bit were both 1. The run recorded `PUBLIC_REPLAY=PASS` and `ORACLE_MATCH=YES`.

# 4. n=256 validation

| Check | Status | Evidence |
|---|---|---|
| Fresh Q5 setup | PASS | New test-only degree-4 setup in attempt 03; profile says 5 trustees / threshold 5. |
| Proof-valid ballots | PASS | Admission verified all 256 unchanged Groth16 proofs and registry/nullifier/public-key fields. |
| Exact accepted-input binding | PASS | Rechecked all 256×8 coordinates: each accepted `(R.x,R.y,S.x,S.y)` equals the corresponding proof public-signal coordinates position by position; board seal recomputed to `1c3b6bbed394a4a6607c3c1699fff70343b063e581558961b8faa8bc818465a3`. |
| Q5 profile | PASS | `FC2027-CGY-TOOLBOX-FULL-V1-Q5`, degree 4, threshold 5. |
| Five-share final release | PASS | Independently reverified persisted release; all IDs 1–5 and all five share proofs accepted. |
| Independent public replay | PASS | Native public verifier replayed the complete 4,350-gate transcript without secret shares. |
| Oracle match | PASS | `1 == 1`; oracle remained outside producer/replay. |
| Compact round-trip | PASS | Byte count and SHA-256 equal canonical JSONL. |
| No historical artifact reuse | PASS | Successful attempt 03 contains fresh setup, board, ballots, randomness, and execution ID. |

Key SHA-256 values: setup `3a10ef084e9e54aa314e711653c0f004c258421495193400cc79cb79f04f9344`; proofs `d6a465c3d21415a4562fd87a75624c9c584a0aae515f2a503754dab63794a1b2`; admission board `2de4bf9e3bcabab45dca0b81a6640f8cec20abe0e55ae349e3d548d23fda8c3a`; final release `4bfd3fa7903586d925a9754da1bf7e1516c9a10c750f20bb6bfd8e98c4f8c94d`; run manifest `1cbc2612fce92c468a3c022b628376839557db49782ba56fba0d3f1f877d8a12`.

# 5. Q5 parallel microbenchmark

The 32-gate Task B measurement used one fresh Q5 setup (`setupHash=1ec839c5f6b8d70e4947b7d1070c6b29bf26d7fae3641ba94c97f1d575c4831f`), degree 4 / threshold 5, and ten fresh gate batches. Each serial/parallel pair received the identical requests, setup, and gate IDs. Timed region was the native `run_gate_request` loop only; setup, process startup, JSON parsing, transcript adaptation, and public verification were excluded from both modes. Every repetition's records were checked by the same native public gate verifier; the serial and parallel canonical transcripts were byte-identical. All adapted broadcast records also passed the frozen broadcast verifier.

| rep | serial (s) | parallel (s) | speedup |
|---:|---:|---:|---:|
| 1 | 1.461173 | 0.217076 | 6.731154x |
| 2 | 1.430693 | 0.193761 | 7.383788x |
| 3 | 1.434314 | 0.204137 | 7.026226x |
| 4 | 1.440076 | 0.210564 | 6.839136x |
| 5 | 1.428458 | 0.195274 | 7.315128x |
| 6 | 1.436565 | 0.212644 | 6.755727x |
| 7 | 1.437604 | 0.213773 | 6.724895x |
| 8 | 1.434616 | 0.223373 | 6.422509x |
| 9 | 1.426351 | 0.209476 | 6.809140x |
| 10 | 1.428364 | 0.214419 | 6.661560x |

32-gate summary: median serial `1.434465 s`; median parallel `0.211604 s`; median speedup `6.779008x`; mean serial `1.435821 s` (population SD `0.009455`); mean parallel `0.209450 s` (population SD `0.008844`). Both modes passed the same public verifier.

## Task D — ready-frontier width sweep

Five repetitions per mode for widths 1, 2, 4, 8, and 16; ten per mode for width 32. All 475 gate outputs per mode were individually accepted by the same final-Q5 public verifier. Paired transcripts were byte-identical, canonical gate order was retained, and broadcast exports verified. This measures a scheduler microbenchmark only; it is not an end-to-end scalability claim.

| ready gates | reps/mode | serial median (s) | parallel median (s) | serial gates/s | parallel gates/s | speedup |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 5 | 0.046337 | 0.046977 | 21.581 | 21.287 | 0.986387x |
| 2 | 5 | 0.090841 | 0.047196 | 22.016 | 42.377 | 1.924767x |
| 4 | 5 | 0.182189 | 0.050191 | 21.955 | 79.696 | 3.629939x |
| 8 | 5 | 0.366741 | 0.082459 | 21.814 | 97.018 | 4.447557x |
| 16 | 5 | 0.729228 | 0.105502 | 21.941 | 151.655 | 6.911960x |
| 32 | 10 | 1.434465 | 0.211604 | 22.308 | 151.226 | 6.779008x |

Raw 32-gate and all-width observations are in `backend/cgy_toolbox_full_v1/evidence/q5_frontier_sweep_20260925_01/raw_timings.json` (SHA-256 `468df1968f85b9bc64c471b1221305253c7caddb8599697174a3f58fb01caac4`). Q5 profile is recorded in that file; no degree-2/3-of-5 fixture was used.

# 6. Comparability with the existing final data

The n=256 execution used the same Q5 profile, unchanged ballot relation and CRS/zkey, exact proof-signal-to-accepted-board coordinates, native Rust CGY gate library, source gate equations, Q5 final release, public verifier, and canonical JSONL/compact codec as the final Q5 n=8/64/1024 series. Its large journal used the same streaming implementation already used for n=1024. The only source-tree delta was the evaluation-runner routing change documented in §1; no production cryptographic source, protocol messages, verifier semantics, ballot circuit/CRS, threshold, or transcript format changed. No historical Q3 result is included.

## Task C — retained-artifact memory microbenchmark

The OS-native measurement was Windows `PeakWorkingSet64`, sampled separately for the Node replay wrapper and the native verifier process. Replays used only retained public setup, accepted board, and transcript; each of n=8/64/256/1024 was independently replayed three times. The “process wall” column includes Node launch, board/transcript checks, and child verifier; native wall is the verifier-reported process interval. These retained-artifact replays are not new end-to-end scale executions.

| n | rep | process wall (s) | native verifier wall (s) | Node peak WS (bytes) | native verifier peak WS (bytes) |
|---:|---:|---:|---:|---:|---:|
| 8 | 1 | 1.689616 | 0.744756 | 257,290,240 | 96,989,184 |
| 8 | 2 | 1.832625 | 0.755116 | 256,143,360 | 97,517,568 |
| 8 | 3 | 1.605116 | 0.743177 | 257,478,656 | 97,095,680 |
| 64 | 1 | 10.643284 | 5.811462 | 1,540,497,408 | 715,870,208 |
| 64 | 2 | 10.329911 | 5.796839 | 1,539,796,992 | 715,862,016 |
| 64 | 3 | 10.381764 | 5.813549 | 1,538,174,976 | 715,640,832 |
| 256 | 1 | 72.821624 | 47.212227 | 238,608,384 | 130,580,480 |
| 256 | 2 | 49.999224 | 23.237373 | 238,399,488 | 130,748,416 |
| 256 | 3 | 42.949007 | 22.866874 | 237,305,856 | 133,672,960 |
| 1024 | 1 | 169.283126 | 91.508825 | 254,210,048 | 153,899,008 |
| 1024 | 2 | 166.810940 | 89.457452 | 256,413,696 | 155,189,248 |
| 1024 | 3 | 263.267627 | 186.459791 | 245,440,512 | 149,266,432 |

| n | median process wall (s) | median native verifier wall (s) | median Node peak WS (bytes) | median native verifier peak WS (bytes) |
|---:|---:|---:|---:|---:|
| 8 | 1.689616 | 0.744756 | 257,290,240 | 97,095,680 |
| 64 | 10.381764 | 5.811462 | 1,539,796,992 | 715,862,016 |
| 256 | 49.999224 | 23.237373 | 238,399,488 | 130,748,416 |
| 1024 | 169.283126 | 91.508825 | 254,210,048 | 153,899,008 |

One OS-sampled producer observation is available from the successful fresh n=256 run: native `--dag-file-stdin` peak working set `1,386,561,536` bytes; native process interval `30.185474 s` (full backend phase `47.128688 s`). Producer measurements for retained n=8/64/1024 cannot be obtained from the saved public artifacts: they contain no threshold secret shares, and the frozen producer cannot regenerate those gate proofs from public transcripts alone. No n=1024 ballots were regenerated. Therefore the requested producer/replay matrix is incomplete and this memory benchmark is not paper-ready. The n=256 producer value is one run, not a three-repetition median.

Raw per-repetition OS samples are under `backend/cgy_toolbox_full_v1/evidence/q5_memory_replay_20260925_01/` and `.../q5_memory_replay_n256_20260925_01/`. Corrected aggregate SHA-256: `60472e570362128cab9ea6137edfbf15ac159928056bdc7a164ad17d85745c88`; n=256 aggregate SHA-256: `3d5bdb7d04644948b35a132b674c0807ce790b4cd5c7b08b9640246eee174e8e`; producer OS sample SHA-256: `2b57f06a4492969a0d21853d1f9617d152543cee819291af71027e0cd057aa82`.

# 7. Paper-ready values

```ini
N256_GATES=4350
N256_DEPTH=207
N256_WIDTH=128
N256_PROVING_S=368.4489502
N256_ADMISSION_S=5.2155201
N256_BACKEND_S=47.1286881
N256_RELEASE_S=8.4028034
N256_REPLAY_S=32.9100891
N256_TOTAL_S=462.1336772
N256_JSONL_BYTES=886045853
N256_COMPACT_BYTES=239114329
N256_RESULT=1
N256_ORACLE=1
N256_REPLAY_PASS=PASS
N256_EXACT_BINDING_PASS=PASS

Q5_PARALLEL_REPETITIONS=10
Q5_SERIAL_MEDIAN_S=1.434465
Q5_PARALLEL_MEDIAN_S=0.211604
Q5_PARALLEL_SPEEDUP=6.779008
Q5_PARALLEL_VERIFIER_PASS=PASS
```

# 8. Final flags

N256_FRESH_Q5_RUN:
PASS

N256_SOURCE_CONFORMING:
YES

N256_INDEPENDENT_REPLAY:
PASS

N256_ORACLE_MATCH:
YES

N256_EXACT_BINDING:
PASS

N256_FINAL_THRESHOLD:
5_OF_5

N256_SAFE_TO_ADD_TO_PAPER:
YES

Q5_PARALLEL_MICROBENCHMARK:
PASS

Q5_PARALLEL_USES_FINAL_PROFILE:
YES

Q5_PARALLEL_VERIFIER:
PASS

Q5_PARALLEL_SAFE_TO_ADD_TO_PAPER:
YES

Q5_MEMORY_MICROBENCHMARK:
FAIL

Q5_MEMORY_USES_FINAL_ARTIFACTS:
YES

Q5_MEMORY_SAFE_TO_ADD_TO_PAPER:
NO

Q5_FRONTIER_SWEEP:
PASS

Q5_FRONTIER_SWEEP_EVALUATION_ONLY:
YES

Q5_FRONTIER_SWEEP_SAFE_TO_ADD_TO_PAPER:
YES

PRODUCTION_CRYPTO_SOURCE_CHANGED:
NO

EVALUATION_HARNESS_ONLY_CHANGE:
YES

MANUSCRIPT_EDITED:
NO

REMAINING_BLOCKER:
Producer peak-memory repetitions for retained n=8, n=64, and n=1024 cannot be measured because the final public artifacts do not retain the secret shares needed to rerun producer-side gates.
