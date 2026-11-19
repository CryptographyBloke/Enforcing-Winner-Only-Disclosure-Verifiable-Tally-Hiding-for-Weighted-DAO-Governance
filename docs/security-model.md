# Security model and limits

This summary follows the public paper at [IACR ePrint 2026/1773](https://eprint.iacr.org/2026/1773) and the Q5 parameter authority retained in [`evidence/docs/CGY_Q5_PARAMETER_AUTHORITY.md`](../evidence/docs/CGY_Q5_PARAMETER_AUTHORITY.md). It does not extend the paper's claims.

## The two theorems and the corollary

1. **Accepted-result correctness.** Even if all trustees behave maliciously, any result accepted by the protocol is correct for the exact board accepted by the contract. Trustees may still abort or stall; correctness does not promise liveness.
2. **Restricted-I/O tally privacy.** In the paper's SUC model, a static active coalition smaller than the decryption threshold cannot learn the tally from the encrypted computation transcript. With `q_dec=5`, the concrete Q5 instance covers up to four corrupted trustee roles.
3. **Winner-only disclosure corollary.** Relative to the actual sealed accepted board and the decision bit, the tally computation discloses no additional plaintext tally value under the theorem's assumptions.

The paper's result is about the defined protocol and its cryptographic model. The local program does not instantiate five isolated machines: one process holds and simulates all five trustee roles. The release uses a test-only dealer and a test-only Groth16 reference string.

## Main assumptions

The Q5 argument relies on the frozen BabyJub/Base8 configuration, fixed-base DDH, a programmable group-valued oracle, ordinary auxiliary-input Groth16 computational knowledge soundness together with the paper's finite-board ballot-admission lemma, and the approved canonical broadcast model. The exact parameter and lemma mapping is retained in the [Q5 paper handoff](../evidence/docs/CGY_Q5_PAPER_HANDOFF.md).

## Explicit boundaries

The implementation is not a production DKG or trusted setup. It does not claim whole-voting SUC security, blockchain UC security, adaptive corruption security, receipt freeness, coercion resistance, protection when all five trustee roles are corrupted, or production consensus for the trustee broadcast board. The Sepolia contract is a testnet reference, not production Arbitrum DAO governance.

Five-of-five is the final opening threshold in the maintained profile. Older three-of-five material is not the final reference and must not be mixed with Q5 results. See [provenance.md](provenance.md).
