# Paper version and evidence provenance

The submission PDF is [`paper/BlockSys2027_submission.pdf`](../paper/BlockSys2027_submission.pdf), SHA-256 `3c881f7d73fa97601fdc09afe2e63eba510448b04ceee43c4d5d35cd2c3012c3`.

## Data reported in the paper

Tables 1 and 2 use the recorded five-of-five Q5 local runs and the Arbitrum Sepolia n=8 run. Their manifests, source records, hashes, and public-chain artifacts are preserved in the immutable [blocksys2027-evidence-v1 release](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/releases/tag/blocksys2027-evidence-v1). The archive SHA-256 is `7169b79aa099fa42de3c37cadcdd6c21125b7ca4ac63e6a7419e9475cc776a84`.

The Q5 source snapshot used for those measurements, its source-hash records, run manifests, and public-chain artifacts are preserved in the evidence-v1 archive. The main branch links to that immutable archive and records its checksum in [`evidence/README.md`](../evidence/README.md), avoiding a second copy of the historical source and data in the maintained tree.

## Version relationship

1. **Original FC 2027 research implementation.** This was the earlier research workspace; it remains part of the project's history, not a second current implementation.
2. **Frozen Q5 source.** The source snapshot used for the measurements in the PDF and its source-hash records are preserved in the evidence-v1 archive. The archive documents the `n=256` runner adjustment and omitted generated proving artifacts by hash.
3. **Existing evidence release.** The immutable [`blocksys2027-evidence-v1` release](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/releases/tag/blocksys2027-evidence-v1) preserves the historical Q5 manifests, chain evidence, hashes, and frozen source. Its archive checksum is recorded in [`evidence/README.md`](../evidence/README.md).
4. **Cleaned maintained implementation.** The current source tree keeps the protocol and five-of-five semantics while organizing code and reproduction paths. The exact pre-cleanup tree remains available under [`archive/pre-cleanup-2026-11`](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/tree/archive/pre-cleanup-2026-11).
5. **Experiments after cleanup.** These are new observations from the maintained implementation. The separate [evidence-v2 release](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/releases/tag/blocksys2027-evidence-v2-cleaned-local-2026-11) is not cited by the PDF and must not be presented as a reproduction of the historical timings.

## Maintained code and later runs

The current `main` tree is the maintained implementation: source paths and reproducibility scripts were cleaned up while the ballot relation, BabyJub/Base8 configuration, CGY gate semantics, accepted-board binding, transcript hashing, and five-of-five release were preserved. New runs from this checkout are new observations and are not the measurements in the PDF.

The annotated pre-cleanup tag and both evidence releases remain unchanged. No Git history was rewritten.
