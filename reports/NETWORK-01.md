# NETWORK-01 — Real Distributed Communication Experiment

**Status:** feasibility audit complete; true distributed run stopped before implementation.
**Branch:** `network-01-real-distributed-communication`
**Base commit:** `2d76ba053ed8f21d23996180f1a6baf168edbd0c` (`main`, clean working tree)
**Date:** 2026-11-19

## Decision

A five-process experiment is feasible as a separate research implementation, but it is not a transport-only change to the current runner. The current Rust and JavaScript paths centralize all five secret shares, trustee authentication keys, gate contribution generation, and board state. Wrapping those centrally generated records in TCP would measure transport of a centralized simulation, not execution by five trustees that each hold only their own share.

Following the NETWORK-01 safety gate, this branch stops before changing the cryptographic execution path. It contains this audit report only. No TCP experiment, latency injection, or n=64 run was performed. No network message count, wire bytes, barrier time, RTT, or network overhead is claimed.

## Current architecture and blockers

1. **Setup centralizes the shares.** `run_local_scale.js` creates one `setupBundle` for all five trustees. The Rust bridge serializes `setupBundle.secretShares` as a five-element array in each native request (`native/tools/native_gate_bridge.js`, [single-gate request](../native/tools/native_gate_bridge.js#L39-L43), [DAG request](../native/tools/native_gate_bridge.js#L98-L103)). Rust parses this into `Setup.shares: Vec<Fr>` (`native/src/gate.rs`, [setup type](../native/src/gate.rs#L31), [share parser](../native/src/gate.rs#L433-L450)).

2. **Rust generates a complete gate centrally.** `run_gate_core` loops over all trustees to produce the masking chain, both rerandomization vectors, and all partial decryptions (`native/src/gate.rs`, [gate core](../native/src/gate.rs#L512-L574)). The DAG scheduler calls that full-share interface for each gate. A coordinator can therefore see every share and trustee contribution today.

3. **The JavaScript adapter impersonates all five authenticated identities.** `native/tools/native_gate_adapter.js` takes the already-generated native gate record and signs submissions using `trusteePrivateKeys[trusteeId - 1]` for every trustee ([message adaptation](../native/tools/native_gate_adapter.js#L98-L164), [submission signing](../native/tools/native_gate_adapter.js#L179-L184)). The local runner creates and retains the complete authentication registry.

4. **The canonical board is an in-process object.** `CanonicalAtomicBroadcastBoard` verifies signed slots, enforces phase dependencies and trustee order, detects conflicting retries, seals a common vector, and exports the transcript ([board implementation](../protocol/src/broadcast_board.js#L127-L278)). `submit` and `readPhase` are synchronous method calls. There is no socket transport, remote wait, persistent network log, or protection against a remote service presenting different views to different clients.

5. **Gate and release APIs require co-located roles.** `runConditionalGate` requires all five setup shares and all trustee authentication keys ([gate path](../protocol/src/conditional_gate.js#L251-L344)); `runRerandomization` loops over all five trustees in one call ([rerandomization path](../protocol/src/rerandomization.js#L73-L89)); `runFinalRelease` similarly accepts the complete setup bundle and authentication-key set ([release path](../protocol/src/final_release.js#L114-L170)).

These are substantive API and state-machine boundaries. A TCP wrapper around `runNativeDag` would still send every secret share to one Rust process and would still create trustee messages centrally. It would be a transport simulation, which is explicitly not presented as the requested distributed experiment.

## Paper communication model

The paper's Section 8, pages 11–12, describes a conditional gate as twelve logical phases: five sequential masking steps, two rerandomizations, and five partial decryptions. If the two rerandomization groups and the five partial decryptions run in parallel, it gives seven critical-path layers, `R = 5 + 1 + 1 = 7`. It also describes twelve serial board operations per gate in the reference implementation. These are different counts: a phase can contain multiple trustee submissions.

The paper's idealized model is `T(RTT) ≈ T_local + R · d · RTT`, under its stated batching and negligible-bandwidth assumptions. For the paper's n=8 depth `d=72`, this implies **504 modeled layer round trips**; at a hypothetical 100 ms RTT, the modeled network addition is **50.4 s**. This is an arithmetic consequence of the model, not an experiment result. The paper's n=1024 example is 1,925 modeled round trips at depth 275.

For the twelve-phase reference path, n=8 has 134 gates and therefore **1,608 logical gate-phase instances** (`12 × 134`) before final release. This count is not a physical RTT count: actual round trips depend on whether phases and independent gates are batched, board fan-out, and scheduling. No measured network value is available to compare with either model. We do not add the model estimate to the existing local runtime because the local manifest's scope and the paper model's `T_local` are not a controlled, like-for-like measurement.

The current adapter also yields a source-derived workload count: 20 signed trustee submissions per gate (five masking, five in each of two rerandomization vectors, and five partial decryptions), plus ten submissions for final release. For n=8 this is 2,690 logical application submissions (20 × 134 + 10). It is not a measured socket-packet or broadcast-fan-out count.

## Existing n=8 local control (not a network run)

The existing run `2026-11-19_local_n8_8665073c` records commit `2d76ba053ed8f21d23996180f1a6baf168edbd0c`, a clean working tree, and `execution: local`. Its manifest records 134 gates, depth 72, five-of-five release, public replay `PASS`, oracle comparison `PASS`, full local pipeline 46.989 s, backend 6.271 s, and 27,258,421 bytes of canonical transcript plus final-release artifact (7,355,879 bytes in compact transcript form).

These are local baseline observations. The transcript file size is not TCP wire traffic; it excludes framing, acknowledgments, retransmission, and board fan-out. The run does not report network RTT, physical message counts, or communication barriers. It cannot establish a network overhead or validate the latency model.

## Validation performed

The following existing in-process checks were run on this branch. They validate the code paths audited above; they are not network tests.

| Command | Result |
|---|---|
| `& (Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe') test --locked --manifest-path native\Cargo.toml` | Exit 0; 4 Rust tests passed, 0 failed |
| `node --test protocol\test\broadcast_board.test.js protocol\test\conditional_gate.test.js protocol\test\rerandomization.test.js protocol\test\threshold_setup.test.js protocol\test\threshold_decryption.test.js protocol\test\final_release.test.js protocol\test\five_of_five_final_release.test.js protocol\test\five_of_five_threshold.test.js protocol\test\compact_transcript.test.js` | Exit 0; 26 passed, 0 failed |
| `node protocol\scripts\test_native_gate_compatibility.js` | Exit 0; `JS_GATE_VERIFIED_BY_RUST=PASS`, `RUST_GATE_VERIFIED_BY_JS=PASS` |

No n=8 network test was run because there is no distributed implementation to test. Therefore the gate for starting n=64 was not reached, and n=64 was not run.

## Safe implementation plan

1. **Define the experiment trust boundary.** Keep the existing five-of-five profile (`a=5`, `t=4`, `q_dec=5`) and test-only setup warning. A test-only dealer may create the lab shares before launch, but each trustee process must load only its own share. Store each share only in a private, ignored runtime directory; never serialize the five-share array into the coordinator's Rust request. This is process-level experimental isolation, not DKG or production key custody.

2. **Split the Rust gate API.** Separate public DAG scheduling and proof verification from trustee-local contribution generation. Each trustee endpoint must receive only public setup, the session/gate context, and the public ciphertext inputs; it must generate its own fresh randomness and produce only its own masking, rerandomization, or partial-decryption message. The coordinator must not receive or reconstruct the secret shares.

3. **Add an asynchronous board transport.** Implement a separate TCP board service that accepts signed trustee submissions, persists a canonical ordered log, enforces the existing slot, dependency, duplicate, equivocation, and seal rules, and lets clients wait for sealed phase vectors. The service is a trusted sequencer for this experiment. TCP, TLS, signatures, and a single sequencer do not provide Byzantine reliable broadcast; the experiment must not claim that they do. Clients should verify signed checkpoints and the complete canonical transcript hash during replay.

4. **Preserve the phase and DAG semantics.** Keep the five-step masking chain, both five-contributor rerandomization vectors, the five partial-decryption proofs, the exact accepted-board binding, gate IDs, phase IDs, trustee order, and canonical transcript bytes/hash rules. Use an asynchronous scheduler to batch only gates whose DAG dependencies permit it. Apply the same per-share process boundary to the final release.

5. **Gate validation on n=8.** First compare one deterministic fixture gate's public output and replay against the existing implementation. Then run a fresh local n=8 experiment with five trustee processes and the board service at zero injected delay. Require ballot proof verification, admission, sealed-board hash, all gate proofs, five-of-five release, exact canonical replay, oracle comparison after replay, and a matching public result before measuring latency. Repeat with declared RTT profiles using Linux network namespaces/veth plus `tc netem` (or a documented equivalent). Record application submissions and wire sends separately, payload and wire bytes separately, phase/barrier counts, measured RTT distribution, per-phase wall time, and end-to-end wall time. Only after all n=8 checks pass should n=64 be attempted.

6. **Exercise failure and replay boundaries.** Test wrong trustee identity, invalid signature, stale session, duplicate identical submission, conflicting submission/equivocation, out-of-order phase, timeout/disconnect, service restart, corrupted checkpoint, altered transcript bytes, and replay against changed board order. Keep the board's trusted-sequencer assumption explicit in every report.

## Provenance and artifact hygiene

This report is based on the cleaned source at commit `2d76ba053ed8f21d23996180f1a6baf168edbd0c` and its existing local n=8 manifest. The paper PDF was inspected for its communication model. No paper, historical Q5 manifest, frozen-source record, evidence archive, or release was modified. The existing [`blocksys2027-evidence-v1` release](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/releases/tag/blocksys2027-evidence-v1) remains the historical evidence source. No test-only share, oracle input, witness, or generated run artifact is added to this branch.

## Recommendation for the manuscript

The manuscript already labels the RTT figures as model-based estimates and states that the five roles are co-located in the reported runs. Keep that wording. NETWORK-01 produced **no measured network result**, so there is no new communication-performance claim strong enough to add to the BlockSys manuscript. A later five-process run may support a separately labeled experimental result after it passes the n=8 correctness and public-replay gates above; it must not be described as Byzantine-broadcast security or substituted for the historical Q5 measurements.
