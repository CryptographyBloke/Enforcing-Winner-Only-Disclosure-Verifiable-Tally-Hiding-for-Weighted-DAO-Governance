# Version and evidence provenance

This repository separates the maintained source from the source snapshot that produced the published Q5 measurements.

## Version relationships

1. **Original FC 2027 research implementation.** The early research workspace is part of the project's historical development. Its measurements and provenance are not inferred from the current checkout.
2. **Frozen Q5 source.** The published local and Sepolia measurements were produced by the Q5 source snapshot preserved under [`evidence/frozen_source_q5/`](../evidence/frozen_source_q5/) and included in the evidence archive. The evidence README lists the byte-level differences from the renamed public source and the files that were omitted from the Git snapshot.
3. **Existing evidence release.** [`blocksys2027-evidence-v1`](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/releases/tag/blocksys2027-evidence-v1) remains the immutable public archive. Its `blocksys2027_evidence_package.zip` has SHA-256 `7169b79aa099fa42de3c37cadcdd6c21125b7ca4ac63e6a7419e9475cc776a84` and contains 81 entries. The archive hash was verified against the downloaded release asset during cleanup. It includes run manifests, source records, public-chain records, checks, and a compact Sepolia transcript; the multi-gigabyte local JSONL transcripts are identified by hash, not bundled.
4. **Cleaned maintained implementation.** It is based on the pre-cleanup `main` commit `d193adb05424c31280bb7e1c9a0f4eb85294e40f`, preserved by the annotated tag [`archive/pre-cleanup-2026-11`](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/tree/archive/pre-cleanup-2026-11). Directory paths, scripts, documentation, and CI were reorganized. The local runner now accepts `n=256` and uses file streaming from that size; the ballot relation, BabyJub/Base8 configuration, CGY gate semantics, transcript binding, accepted-board binding, and five-of-five release were not changed.
5. **New experiments.** New runs created after cleanup receive a unique ID, source commit, environment, parameters, measured phase timings, verification results, and hashes under ignored `runs/`. They are new observations from the maintained implementation. They must not be relabeled as reruns of the published Q5 measurements.

## What remains authoritative

The historical run manifests, timing rows, transcript hashes, contract addresses, and frozen-source records remain unchanged. `evidence/` in the repository is a readable subset of the release archive; the release and its archive hash are the permanent public evidence reference. The annotated cleanup tag preserves the exact pre-cleanup repository tree. No history rewrite or force push is used.

The cleaned source is prepared for new experiments, but the evidence release will only be supplemented by a separate future release after the author completes and validates fresh reruns.
