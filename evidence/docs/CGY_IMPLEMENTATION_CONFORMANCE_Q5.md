# CGY implementation conformance — Q5 reference instance

```ini
PROFILE=FC2027-CGY-TOOLBOX-FULL-V1-Q5
SOURCE_PROTOCOL_CHANGED=NO
THRESHOLD_PARAMETER_CHANGED=YES
PREVIOUS_REFERENCE_THRESHOLD=3_OF_5
FINAL_REFERENCE_THRESHOLD=5_OF_5
```

This is a mechanical parameter update of the closed Q3 implementation. The
source protocol, equations, encodings, domains, board resource, arithmetic DAG,
and public-verifier semantics are unchanged. The source theorem permits
degree `t` and combines exactly `t+1` verified shares; the Q5 specialization is
`a=5`, `t=4`, `q_dec=5`, with `f<5`.

| executed code path | CGY algorithm / result | Q5 parameter and assumptions | transcript / verifier path | deviation |
| --- | --- | --- | --- | --- |
| `src/group.js`, `backend/cgy_native/src/group.rs` | common group operations; Algorithms 9/10, 63–67 | BabyJub Base8; Lemma FG; fixed-base DDH | exact affine points, curve/subgroup/role checks | none |
| `src/group_oracle.js`, native `derive_htilde` | auxiliary programmable group oracle | frozen domain-separated group-valued output; no public dlog | session/key/counter and re-derived `htilde` | none |
| `src/hash_to_scalar.js`, native challenge functions | Algorithms 9, 63, 65 | unchanged RO domains and full context | challenge recomputation | none |
| `src/threshold_setup.js:constructSetup/provisionFreshTestOnly` | Shamir setup for Algorithms 65–67 | trustees `a=5`; polynomial degree `4`; `q_dec=5`; fresh test-only dealer | `h`, five commitments, ordered `h_j`, setup hash | parameter only: degree 2→4 |
| `src/threshold_setup.js:verifyPublicSetup/verifySecretShare` | trustee verification values | `[s_j]g=h_j`; all five IDs | setup/share checks | none |
| `src/threshold_setup.js:interpolateScalarAtZero` | Algorithm 66 interpolation | exactly five distinct verified shares; any four insufficient | duplicate/foreign/invalid/short rejection | parameter only: threshold 3→5 |
| `src/broadcast_board.js`, native board transcript | CGY common-view broadcast resource | all five trustee identities and barriers | canonical ordered immutable slots | none |
| `src/proofs.js`, native gate proof code | Algorithms 7, 9, 10, 63, 64 | unchanged equations, `e_j`, rerandomization, zero proofs | full source records and challenge recomputation | none |
| `src/threshold_decryption.js`, native verified shares | Algorithms 65–66 | authorized ciphertext; exactly five verified shares at every opening | share/session/ciphertext/proof checks and Lagrange at zero | parameter only: required shares 3→5 |
| `src/validation_state.js` | Algorithm 67 prerequisites | `Received→ProofValidated→BroadcastAgreed→RerandomizationValidated→AuthorizedForDecryption→PartialShare` | typed state and explicit failures | none |
| `src/conditional_gate.js`, native `run_gate_core` | Algorithm 67 and source conditional gate | all five masking/rerandomization contributions; five-share selector opening | independent Q5 fixture and public replay | none |
| `src/arithmetic.js` and native DAG scheduler | Algorithms 21, 23, 40 | same 134/1086/17406 application graphs | exact gate IDs, terminal `Q=D-C_*`, `C_b` | none |
| `src/final_release.js:runFinalRelease` | Algorithms 63–66 final release | five rerandomization trustees and five final shares | five share IDs `[1,2,3,4,5]`; public verification | parameter only |
| `src/accepted_board.js`, ballot prover/verifier, unchanged contract | Lemma BA finite-board adapter | unchanged complete ballot relation, ordinary auxiliary-input CKS | exact accepted ciphertext coordinates | none |
| `scripts/run_q5_local_scale.js` | restricted-I/O CGY composition | Q5 setup and five-share release | fresh local n=8/64/1024 manifests | application profile identifier only |
| `scripts/run_q5_sepolia_pipeline.js` | same composition on public chain | fresh Q5 setup, unchanged N=8 contract | public event board, native transcript, claim | transport orchestration only |
| `scripts/replay_q5_sepolia_public.js` | independent public verifier | no secret shares, witnesses, or oracle | RPC receipts/events, exact binding, native replay | none |

## Evidence binding

The deterministic Q5 gate has mutual verification: `JS_VERIFIES_RUST_GATE=PASS`
and `RUST_VERIFIES_JS_GATE=PASS`. Fresh local Q5 runs passed at n=8, n=64, and
n=1024. The fresh Arbitrum Sepolia n=8 run accepted 8/8 ballots, used all five
final shares, passed independent public replay, and matched the isolated oracle.

The only theorem-level adapter assumptions remain Lemma FG (fixed Base8 under
fixed-base DDH) and Lemma BA (finite-board admission/extraction from ordinary
auxiliary-input computational knowledge soundness of the unchanged complete
Groth16 relation). Broadcast remains the approved authenticated canonical
common-view functionality; setup remains a test-only dealer. Correctness still
allows all trustees to be malicious and to abort/stall. Privacy is static active
against `f<q_dec`; for this concrete instance `f<=4`, and privacy is not claimed
when all five trustees are corrupted. No whole-voting SUC, blockchain UC,
adaptive-corruption, coercion-resistance, receipt-freeness, production-DKG, or
Byzantine-consensus claim is introduced.

```ini
GROUP_PROFILE_UNCHANGED=YES
FG_UNCHANGED=YES
BA_UNCHANGED=YES
BROADCAST_UNCHANGED=YES
GATE_PROOFS_UNCHANGED=YES
RERANDOMIZATION_UNCHANGED=YES
ARITHMETIC_UNCHANGED=YES
RESULT_ONLY_COROLLARY_UNCHANGED=YES
SOURCE_PROTOCOL_CHANGED=NO
THRESHOLD_PARAMETER_CHANGED=YES
FINAL_REFERENCE_THRESHOLD=5_OF_5
TOOLBOX_IMPLEMENTATION_INHERITANCE=CLOSED
CONCRETE_ACTIVE_PRIVACY_BOUND=F_LE_4
```
