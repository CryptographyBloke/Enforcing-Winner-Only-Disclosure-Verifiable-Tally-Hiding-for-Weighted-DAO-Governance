# Q5 paper handoff (factual, not manuscript prose)

```ini
FINAL_REFERENCE_IMPLEMENTATION=5_OF_5
Q3_REFERENCE_IMPLEMENTATION=SUPERSEDED
DO_NOT_MIX_Q3_AND_Q5_NUMBERS=YES
```

## 1. Generic theorem parameters

- `a`: number of trustees.
- `t`: Shamir polynomial degree.
- `q_dec=t+1`: exact verified decryption shares required by the source opening.
- static active privacy assumes `f<q_dec`.
- accepted-result correctness is separate and permits malicious trustees to
  abort/stall; any publicly accepted result is correct for the exact accepted
  board.

## 2. Concrete Q5 instantiation

`a=5`, degree `t=4`, `q_dec=5`, and concrete privacy bound `f<=4`. The setup is
`f(X)=a0+a1X+a2X^2+a3X^3+a4X^4`, `sk=f(0)`, `s_j=f(j)`, and all five distinct
verified shares are required for reconstruction.

## 3. Security boundaries

The tally layer inherits CGY restricted-I/O SUC encrypted-trace security under
the frozen BabyJub/Base8, fixed-base DDH, programmable group-valued oracle,
ordinary auxiliary-input Groth16 computational knowledge soundness plus Lemma
BA, and approved canonical broadcast assumptions. Winner-only disclosure is a
separate real-prefix/sealed-board suffix corollary. Do not claim whole-voting
SUC, blockchain UC, adaptive corruption, coercion resistance, receipt freeness,
production DKG, Byzantine broadcast consensus, or all-five-corrupted privacy.

## 4. Lemma references

- Lemma FG: fixed-generator specialization for BabyJub Base8 under fixed-base
  DDH; no cross-curve bridge and no public discrete logarithm of `htilde`.
- Lemma BA: finite-board adapter from ordinary auxiliary-input computational
  knowledge soundness of the unchanged complete ballot relation to legal
  accepted inputs; no Honest-Cast, `E_ctx`, or simulation extractability claim.

## 5. Local final numbers

| n | gates | depth | width | ballot s | admission s | backend s | release s | replay s | total s | JSONL B | compact B | result/oracle |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:---:|
| 8 | 134 | 72 | 4 | 10.043941 | 0.153007 | 4.054594 | 6.926112 | 0.919379 | 22.122671 | 27,315,984 | 7,360,585 | 0/0 |
| 64 | 1,086 | 147 | 32 | 146.507326 | 1.282232 | 15.980992 | 8.926647 | 11.684111 | 184.408306 | 221,173,348 | 59,657,477 | 0/0 |
| 1024 | 17,406 | 275 | 512 | 1,414.928296 | 19.163596 | 156.715285 | 4.568317 | 114.539565 | 1,709.946249 | 3,546,634,443 | 956,889,369 | 1/1 |

## 6. Sepolia n=8 final numbers

Arbitrum Sepolia chain ID `421614`; fresh poll `910004`; 8/8 accepted and 0
rejected; 134 gates; backend `3.797074 s`; final release `4.226528 s`; producer
total `63.223557 s`; independent public replay `62.143068 s`; JSONL transcript
`27,315,148 B`; compact `7,357,605 B`; result/oracle `1/1`; exact binding,
public replay, and on-chain claim all PASS. Final threshold is 5-of-5 with
trustees 1–5. Poll address:
`0x6a8ee332576C2cb6c7d513950f7Fd1b743cc88fC`; final claim:
`0x924845e39c7ac0c0e1274f8aa90d8da06cf5fad0337c7bb46313fc1d2ecb4ff7`.

## 7. Implementation tests

- native `cargo test --release`: 4 pass, including exact BabyJub vectors;
- full JS suite: 46 pass, 0 fail;
- Q5 threshold/final-release tests: 4 pass, including 3/4-share insufficiency,
  duplicate, foreign, wrong ciphertext/session, altered proof, and all-five
  success;
- deterministic Q5 single gate: JS verifies Rust and Rust verifies JS;
- local n=8, n=64, n=1024: independent replay and isolated oracle match;
- Sepolia n=8: public event replay, exact chain binding, five-share release,
  and isolated oracle match.

## 8. Obsolete Q3 material

Do not state or publish the Q3 3-of-5 instance as the final reference. Do not
use its 3-of-5 privacy bound, trustee subset, setup hashes, transcript hashes,
timings, result tables, Sepolia addresses, or Q3 public claim as Q5 evidence.
The Q3 package is historical development evidence only.

## 9. Required final labels

```ini
FINAL_REFERENCE_IMPLEMENTATION=5_OF_5
Q3_REFERENCE_IMPLEMENTATION=SUPERSEDED
DO_NOT_MIX_Q3_AND_Q5_NUMBERS=YES
```
