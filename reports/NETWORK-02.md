# NETWORK-02 — TCP Transcript Transport Measurements

**Branch:** `network-02-tcp-distributed-experiment`

**Main baseline:** `2d76ba053ed8f21d23996180f1a6baf168edbd0c`

**Experiment source base:** `3b4c7472bc2721b66099e36b668f80159a588a77`
**Conclusion:** `TRANSPORT_MEASUREMENTS_ONLY`

## 1. Implementation status

Implemented and ran a real TCP transport experiment in [`tcp_board_service.js`](../protocol/src/tcp_board_service.js), [`tcp_transcript_client.js`](../protocol/scripts/tcp_transcript_client.js), and [`run_tcp_transcript_transport.js`](../protocol/scripts/run_tcp_transcript_transport.js).

The separate board service accepts five persistent TCP client connections, verifies the existing Ed25519 signed slots, enforces session and phase order/dependencies, handles identical retries, aborts conflicting submissions, times out missing work, appends a durable canonical event log, seals canonical phase vectors, and exports a transcript for public verification. Five separate Node processes sent one trustee's signed public records each. The board and clients recorded actual TCP application frames and bytes, PING RTT samples, per-phase seal times, signature-verification time, durable-log sync time, and a local in-process board control.

The clients replay the source run's already-generated public messages. The existing Rust CGY source runs generated the cryptographic contributions centrally. This experiment measures authenticated transcript transport, board persistence, and replay.

## 2. Network architecture and trustee-share isolation

```text
Validated public source run
        │ split signed public messages by trustee ID
        ├── trustee client 1 ──┐
        ├── trustee client 2 ──┤
        ├── trustee client 3 ──┼── TCP/IPv4 loopback ── separate board service
        ├── trustee client 4 ──┤                         ├── durable JSONL event log
        └── trustee client 5 ──┘                         ├── canonical board export
                                                         └── independent public replay
                                                                  └── isolated oracle comparison
```

The five clients held public signed records for their respective trustee IDs. The coordinator and board received no Shamir shares or trustee authentication private keys. The clients did not hold Shamir shares either, so `trusteeShareIsolation=false` and `distributedCryptographicExecution=false` are recorded in every network manifest. The board is a trusted sequencer for this testbed; signed messages authenticate trustee slots, while this experiment makes no Byzantine reliable-broadcast claim.

Windows host: `Windows_NT 10.0.26200`, Intel Core i7-14650HX, 24 logical CPUs, 31.8 GiB RAM, Node v24.15.0. Controlled latency used symmetric application-level delay before request handling and response delivery. Target 20 ms and 100 ms RTT used 10 ms and 50 ms each way. The TCP PING RTT measured the loopback socket plus process scheduling. Traffic totals below are application framing bytes, not packet-wire bytes.

## 3. Test commands and outcomes

| Command | Result |
|---|---|
| `node --test protocol/test/tcp_board_service.test.js` | Exit 0; 4 passed. Wrong signed identity, invalid signature, stale execution ID, out-of-order phase, duplicate retry, conflicting retry, missing-trustee timeout, disconnect, sealed phase view, and tampered transcript checks passed. |
| `npm --prefix protocol test` | Exit 0; 57 passed, 0 failed. Includes accepted-board order, transcript integrity, invalid proof, five-of-five release, and replay tests. |
| `& 'C:\Users\31831\.cargo\bin\cargo.exe' test --locked --manifest-path native\Cargo.toml` | Exit 0; 4 Rust tests passed, 0 failed. |
| `$env:PATH='C:\Users\31831\.cargo\bin;' + $env:PATH; node protocol\scripts\test_native_gate_compatibility.js` | Exit 0; `JS_GATE_VERIFIED_BY_RUST=PASS`, `RUST_GATE_VERIFIED_BY_JS=PASS`. |

For n=8, the validated source run `runs/2026-11-19_local_n8_8665073c/public` had 134 gates, depth 72, a passing public replay, and a passing isolated oracle comparison. Its local control output reported 46.989 s for the full pipeline and 6.271 s for the Rust backend. Each TCP run then passed board verification, independent public replay, and oracle comparison.

After final metadata changes, `node protocol/scripts/run_tcp_transcript_transport.js --source-run runs/2026-11-19_local_n8_8665073c/public --one-way-delay-ms 0` also passed end to end as run `network-02_tcp_replay_n8_20261119150517_14d6e3` in 9.079 s. The protocol suite was rerun on the final code: 57 passed, 0 failed.

For n=64, a fresh local five-of-five run was generated at `runs/2026-11-19_local_n64_network02b/public`. It produced 1,086 gates at depth 147; the Rust backend took 24.833 s and local replay took 13.587 s. `replay_local_run.js`, `verify-results.js`, and `compare_replay_with_oracle.js` each passed. The network replay also passed public replay and oracle comparison.

The n=64 local runner required its private oracle parent directory to exist. The successful run used a new run ID and created that private directory before proving. The first TCP n=64 startup reached the 15-second startup limit while individually syncing 13,038 phase definitions. The service now writes the initial phase table as one durable prefix before accepting clients; both n=64 transport profiles then started and completed.

## 4. Measured results

RTT median and p95 aggregate the PING samples across successful runs: 375 samples for each n=8 profile and 125 for each n=64 profile. Wall time is the median of runs. `TCP - in-process control` subtracts the measured signed-board replay performed in one process; it still includes TCP framing, fan-out, service scheduling, signature checks, and durable sync.

| n | Target RTT | Measured RTT median / p95 | Runs | TCP wall median (range) | In-process control | TCP minus control | Seals / submissions | TCP app frames / bytes | Replay / oracle |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|:---:|
| 8 | 0 ms | 0.194 / 0.495 ms | 3 | 8.269 s (8.136–9.180) | 0.238 s | 8.030 s | 1,614 / 2,690 | 13,735 / 67,767,585 | PASS / PASS |
| 8 | 20 ms | 31.227 / 39.989 ms | 3 | 57.431 s (57.418–57.891) | 0.246 s | 57.190 s | 1,614 / 2,690 | 13,745 / 67,768,165 | PASS / PASS |
| 8 | 100 ms | 116.213 / 126.381 ms | 3 | 195.861 s (194.678–196.362) | 0.235 s | 195.629 s | 1,614 / 2,690 | 13,755 / 67,768,745 | PASS / PASS |
| 64 | 0 ms | 0.199 / 0.332 ms | 1 | 74.509 s | 2.929 s | 71.579 s | 13,038 / 21,730 | 108,935 / 548,458,033 | PASS / PASS |
| 64 | 20 ms | 31.091 / 39.614 ms | 1 | 469.832 s | 2.959 s | 466.873 s | 13,038 / 21,730 | 108,945 / 548,458,613 | PASS / PASS |

The n=64, 100 ms profile was not run. The n=64, 20 ms profile took 469.832 s with the current sequential phase schedule.

The n=8 board sealed a median 3.04 ms per phase at zero delay, 32.15 ms at 20 ms target RTT, and 120.07 ms at 100 ms target RTT. The corresponding phase-seal p95 values were 14.90, 48.69, and 134.82 ms. For n=64, the measured phase-seal median/p95 was 3.33/15.95 ms at zero delay and 32.95/48.76 ms at 20 ms target RTT.

The n=8 service accepted 5,053,848 trustee payload bytes and 172,160 signature bytes. The full application exchange totals about 67.8 MB because the board sends sealed vectors to all clients. Its durable event log was 11,507,082 bytes, canonical export 22,372,427 bytes, and replay journal 27,205,672 bytes. At n=64, application traffic was about 548.5 MB, the event log 93,150,962 bytes, board export 181,071,855 bytes, and replay journal 220,658,275 bytes. These file sizes are separate artifacts and are not counted as network traffic.

Across n=8 profiles, board signature verification took approximately 0.35–0.57 s and durable sync approximately 6.4–8.2 s. At n=64 those sums were 3.47–4.37 s and 55.33–60.59 s. The event log synchronizes each accepted signed submission. A process-memory snapshot during an n=8 delayed run showed 80.9 MiB for the coordinator, 93.8 MiB for the board, and 49.4–49.9 MiB per client.

## 5. Comparison with the 7-layer and 12-phase models

The paper model `T(RTT) ≈ T_local + 7 × d × RTT` predicts 504 critical-path layer round trips at n=8 (`7 × 72`) and 1,029 at n=64 (`7 × 147`). For a matched delay comparison, subtracting the loopback RTT from the measured RTT gives predicted added communication terms of 15.64 s at n=8/20 ms, 58.47 s at n=8/100 ms, and 31.79 s at n=64/20 ms. The observed increases over each size's loopback TCP wall time were 49.16 s, 187.59 s, and 395.32 s.

The twelve-phase implementation schedule has 12 phase instances per gate plus six final-release phases: 1,614 observed seals at n=8 and 13,038 at n=64. The transport replay processes gate phases sequentially, so it does not batch independent ready gates. Its observed seals exceed the seven-layer counts by factors of 3.20 and 12.67. These measurements include board persistence and fan-out, while the seven-layer expression models latency under batching and negligible bandwidth assumptions. The figures therefore characterize this sequential TCP board workload; they do not calibrate the paper model for a fully distributed cryptographic run.

No batched/concurrent gate schedule was measured. The present board order is the replay workload's deterministic gate/phase order. A subsequent experiment would need to schedule concurrently ready DAG gates while preserving each gate's dependencies and canonical transcript bytes before comparing wall time with the idealized model.

## 6. Raw evidence paths, hashes, and source revision

Selected run directories and all raw signed event logs remain under ignored `runs/`:

- n=8 loopback: `network-02_tcp_replay_n8_20261119144304_bcf67b`, `...145222_15ec1d`, `...145248_00fb89`.
- n=8 20 ms: `...143627_6d3f09`, `...143815_1234f5`, `...145111_58ab89`.
- n=8 100 ms: `...143230_08e6fd`, `...143928_155744`, `...144739_d71e41`.
- n=64 loopback: `network-02_tcp_replay_n64_20261119142045_b54205`.
- n=64 20 ms: `...142344_1d67cd`.

Each directory contains `network_manifest.json`, a persistent `transport/canonical-board-events.jsonl`, `transport/canonical-board-export.json`, five client result files, independent public replay artifacts, logs, and hashes. The n=8 canonical transported transcript hash is `3a05901c4232688b4f6cb5cc90650f5837bc89f0c00d0d0170c98a16c82049e2`; its replay-journal SHA-256 is `1e81afe6cbace5875c0a8c6b61a4bab7e58a2a88a1bc24d4d2c488036c9d8881`, and final-release SHA-256 is `3d9a420175b7ede849da56853c70b24991f185ede9767a7f1851644776860061`. The n=64 canonical transcript hash is `df2d9e3740f9e1e4af14c9bc21d1c4ec8e8f7a7251edbf7e586a36ab90de7b36`; replay-journal SHA-256 is `ab40a11f58fed454b351ff955f7e683a5691ec09844992068f6a49d068b02166`, and final-release SHA-256 is `c645d89a0a38dde6a3a59dd5025ff7f2632b4b50503adf871f56b78b32c3e05b`.

Every selected run preserves the source gate-journal and final-release hashes. The network manifests record the code commit at run time and SHA-256 values for the board, client, coordinator, and canonical board source files. The n=8 source-data commit was `2d76ba053ed8f21d23996180f1a6baf168edbd0c`; the fresh n=64 source run was generated from this branch's `3b4c7472bc2721b66099e36b668f80159a588a77` base. The later branch commits package the same measured transport implementation and this report.

The safe export `runs/network-02_public_export_20261119150701_80cab9` contains the selected 11 verified runs. Its index covers 385 files; all indexed SHA-256 values verified, and the archive scan found no private/oracle directories, shares, witnesses, environment files, or workload inputs. The ZIP is 402,637,754 bytes with SHA-256 `6693266817aa9512be26fd2afa0bcaafb59cd7fcedc2384a02bc4fedd327f7de`; it is published in the [NETWORK-02 evidence release](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/releases/tag/network-02-tcp-transport-v1). [`scripts/summarize-network-runs.js`](../scripts/summarize-network-runs.js) writes the fresh-run CSV under ignored `runs/`. The source n=8 and n=64 outputs remain separate from historical Q5 evidence.

## 7. Discovered limitations

- The injected latency is application-level Windows loopback delay, not `tc netem` or physical network latency.
- The payload values are existing signed public messages; no fresh per-trustee cryptographic masking, rerandomization, or partial decryption ran in these client processes.
- The board is one trusted sequencer. This test evaluates signed message acceptance and common-view replay; the trust model does not include Byzantine board behavior.
- Wire-header bytes, retransmissions, packet loss, multi-host CPU contention, and wide-area network effects were not measured.
- The n=64 100 ms profile remains outstanding. n=64 profiles have one successful run each.
- A ready-gate concurrent scheduler was not measured; current results follow a sequential replay schedule.

## 8. Distributed execution classification

This work is an **authenticated transcript transport/replay microbenchmark**. It uses five separate client processes and a separate board process. It is not five-process distributed cryptographic execution: the local CGY backend and JS adapter still centrally handle all five shares and authentication private keys in the source run. The precise restructuring boundary is `Setup.shares: Vec<Fr>` plus `setup_with_secret_shares()` in `native/src/gate.rs`, and the all-trustee `trusteePrivateKeys` interfaces in `native/tools/native_gate_adapter.js`, `protocol/src/conditional_gate.js`, and `protocol/src/final_release.js`. A true split requires per-trustee Rust/JS state machines and proof-producing APIs that accept one share per process while preserving the existing canonical phase transcript.

## 9. Manuscript changes and PDF status

No editable `main.tex` or `references.bib` is available in the checkout. `pdfinfo` reports the unchanged submission PDF at 14 pages. [`paper/network_results.tex`](../paper/network_results.tex) contains insertion-ready measured text and a compact table. [`paper/NETWORK-02_INTEGRATION.md`](../paper/NETWORK-02_INTEGRATION.md) gives its exact insertion point and page-limit edit. The PDF was not rebuilt. The abstract, theorem statements, assumptions, historical Q5 tables, Arbitrum evidence, AI-use declaration, and references were left untouched.

The manuscript can include these numbers only as an authenticated TCP transcript transport microbenchmark, with the centralized source and sequential schedule stated in the text. They do not substantiate a performance claim for five share-isolated trustees.

## 10. GitHub branch and publication

The verified main baseline remains `2d76ba053ed8f21d23996180f1a6baf168edbd0c`. Work is on `network-02-tcp-distributed-experiment`. The implementation commit is `34b9a7d31c7c5b0ec5255b3e266b2b5e41c1cc9e`, pushed to GitHub. The existing `blocksys2027-evidence-v1` release remains unchanged. The public-safe archive is published as [`network-02-tcp-transport-v1`](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/releases/tag/network-02-tcp-transport-v1).

**Implementation commit:** `34b9a7d31c7c5b0ec5255b3e266b2b5e41c1cc9e`

**Branch:** `https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/tree/network-02-tcp-distributed-experiment`

**Pull request:** Not opened.

## 11. Remaining author-side submission actions

1. Review the published NETWORK-02 evidence release and decide whether to cite its transport results.
2. Decide whether the transport-only table fits Section 8; use the insertion note to replace a modeled example and keep the paper at 14 pages.
3. Apply the fragment to the editable manuscript, compile, visually inspect all pages, and confirm the final page count.
4. Treat a five-process cryptographic split and n=64 100 ms profile as separate follow-up experiments before describing distributed trustee execution.
5. Submit through EasyChair only after the author verifies the final PDF and records the actual submission receipt.

## Final status

`TRANSPORT_MEASUREMENTS_ONLY`
