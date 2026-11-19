# Protocol overview

The reference profile is `winner-only-disclosure/five-of-five/v1` with `a=5` trustee roles, Shamir degree `t=4`, decryption threshold `q_dec=5`, and eight-bit ballot weights.

## Ballots and accepted board

Each voter has a registered weight and submits an encrypted binary contribution. The ballot relation proves in zero knowledge that the contribution is consistent with the registered weight and the vote bit. The Arbitrum reference contract verifies the ballot proof, the poll and registry context, and the nullifier before accepting the ciphertext coordinates.

When the ballot set is sealed, its canonical representation is hashed. Backend admission checks the public ballot proofs again and binds the computation to the exact accepted ciphertext list. A reordered, replaced, or modified ciphertext board fails this check.

## Encrypted tally and threshold

The backend aggregates the accepted ciphertexts and compares the encrypted weighted sum against a public threshold using the Cortier–Gaudry–Yang (CGY) conditional-gate toolbox. The Rust scheduler evaluates the weighted arithmetic DAG. Trustee messages and gate records are committed to an authenticated canonical broadcast transcript.

For local runs, the threshold is

```text
tau_local = floor(255 * n / 4)
```

This gives `tau=510` at local `n=8`. The Arbitrum Sepolia reference uses `tau=500`. These are distinct experimental configurations; see [experiments.md](experiments.md).

## Decision-bit release

The protocol forms a logical ciphertext for the comparison result, rerandomizes it for the final session, and verifies five partial decryption shares and their proofs. A valid release opens only the decision bit `b`. The exact weighted tally is not released by this protocol path.

## Public replay

The independent replay reads public setup, ballot proofs, the accepted board, the gate transcript, and the final release. It verifies ballot admission and the sealed-board hash, checks transcript integrity and the native DAG result, then verifies the final release. It does not open the isolated plaintext oracle. `compare_replay_with_oracle.js` is a separate evaluation step and refuses to read oracle inputs until public replay has passed.

The JS reference implementation, native backend, board-binding library, and tests are mapped in [paper-to-code.md](paper-to-code.md).
