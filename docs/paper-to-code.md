# Paper-to-code map

| Paper or protocol element | Maintained implementation |
|---|---|
| BabyJubjub Base8 group and canonical points | [`protocol/src/group.js`](../protocol/src/group.js), [`native/src/lib.rs`](../native/src/lib.rs) |
| Ballot relation, proof generation, and proof checks | [`circuits/prototypes/strong_bit/`](../circuits/prototypes/strong_bit), [`protocol/src/n8_ballots.js`](../protocol/src/n8_ballots.js), [`protocol/src/proofs.js`](../protocol/src/proofs.js) |
| Registered-root, nullifier, and board admission | [`contracts/arbitrum/contracts/StrongN8Poll.sol`](../contracts/arbitrum/contracts/StrongN8Poll.sol), [`protocol/src/accepted_board.js`](../protocol/src/accepted_board.js) |
| Canonical accepted-board encoding | [`contracts/arbitrum/board_binding/lib/`](../contracts/arbitrum/board_binding/lib), [`protocol/src/broadcast_board.js`](../protocol/src/broadcast_board.js) |
| Threshold setup and partial decryption checks | [`protocol/src/threshold_setup.js`](../protocol/src/threshold_setup.js), [`protocol/src/threshold_decryption.js`](../protocol/src/threshold_decryption.js) |
| CGY conditional gate and transcript | [`protocol/src/conditional_gate.js`](../protocol/src/conditional_gate.js), [`native/src/gate.rs`](../native/src/gate.rs) |
| Weighted aggregation and threshold comparison DAG | [`protocol/src/arithmetic.js`](../protocol/src/arithmetic.js), [`native/tools/native_arithmetic_scheduler.js`](../native/tools/native_arithmetic_scheduler.js) |
| Five-of-five result-only release | [`protocol/src/final_release.js`](../protocol/src/final_release.js) |
| Local full-scale runner and public replay | [`protocol/scripts/run_local_scale.js`](../protocol/scripts/run_local_scale.js), [`protocol/scripts/replay_local_run.js`](../protocol/scripts/replay_local_run.js) |
| One-command setup, run verification, and export | [`scripts/reproduce.ps1`](../scripts/reproduce.ps1), [`scripts/verify-results.js`](../scripts/verify-results.js), [`scripts/export_public_run.js`](../scripts/export_public_run.js) |

The CGY toolbox is due to Véronique Cortier, Pierrick Gaudry, and Quentin Yang, [“A toolbox for verifiable tally-hiding e-voting systems,” IACR ePrint 2021/491](https://eprint.iacr.org/2021/491), published at ESORICS 2022. This project builds a weighted DAO-governance protocol using that toolbox; it does not claim authorship of the toolbox.
