STATUS=PASS
PROFILE=FC2027-CGY-TOOLBOX-FULL-V1-Q5
PREVIOUS_REFERENCE_THRESHOLD=3_OF_5
FINAL_REFERENCE_THRESHOLD=5_OF_5
TRUSTEES=5
POLYNOMIAL_DEGREE=4
DECRYPTION_THRESHOLD=5
CONCRETE_ACTIVE_PRIVACY_BOUND=F_LE_4
SOURCE_PROTOCOL_CHANGED=NO
GROUP_PROFILE_UNCHANGED=YES
BALLOT_CIRCUIT_CHANGED=NO
CONTRACT_SEMANTICS_CHANGED=NO
TOOLBOX_IMPLEMENTATION_INHERITANCE=CLOSED
SOURCE_PARENT_COMMIT=0d49fed671ce33037a1b2d0a5b6007c3a5d17b97
Q5_PRODUCTION_SOURCE_MANIFEST_SHA256=68bb0d3cf2fbd9cee2981857989979455416160d3eeb8a079df01469c6458a84
CARGO_LOCK_SHA256=87e5ec008934ae9c3396cffcb133564c24d9a9699827babcc55a0ad454c33b86
Q5_SOURCE_SINGLE_GATE_PASS=YES
Q5_SINGLE_GATE_PUBLIC_REPLAY=PASS
ADVERSARIAL_SUITE_Q5_PASS=YES
Q5_N8_PASS=YES
Q5_N8_PUBLIC_REPLAY=PASS
Q5_N8_ORACLE_MATCH=YES
Q5_N64_PASS=YES
Q5_N64_PUBLIC_REPLAY=PASS
Q5_N64_ORACLE_MATCH=YES
Q5_N1024_PASS=YES
Q5_N1024_PUBLIC_REPLAY=PASS
Q5_N1024_ORACLE_MATCH=YES
Q5_SEPOLIA_PASS=YES
Q5_SEPOLIA_ACCEPTED=8
Q5_SEPOLIA_REJECTED=0
Q5_SEPOLIA_EXACT_BINDING=PASS
Q5_SEPOLIA_PUBLIC_REPLAY=PASS
Q5_SEPOLIA_ORACLE_MATCH=YES
Q5_SEPOLIA_FINAL_THRESHOLD=5_OF_5
Q5_SEPOLIA_ONCHAIN_CLAIM=PASS

# CGY Q5 final evidence

This is the final evidence package for the Q5 reference instance. It is
separate from the historical Q3 (3-of-5) evidence. The generic source theorem
uses `a` trustees, polynomial degree `t`, and decryption threshold
`q_dec=t+1`, with static-active privacy for `f<q_dec`. The concrete instance is
`a=5`, `t=4`, `q_dec=5`; all five trustees are required for every opening, and
privacy is claimed only for coalitions of at most four trustees. Accepted-result
correctness remains separate and allows all trustees to be malicious or to
abort/stall; any accepted result is still required to be correct.

## Local source-conforming scale

All rows use fresh Q5 setup, fresh proof-valid ballots, exact accepted input
coordinates, the native Rust backend, five-share release, independent replay,
and an isolated oracle. `JSONL transcript` includes the gate journal plus final
release record; `compact transcript` is the lossless compressed gate journal.

| n | gates | depth | max ready width | ballot proving (s) | admission (s) | backend (s) | final release (s) | public replay (s) | total (s) | JSONL transcript (B) | compact (B) | result/oracle |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:---:|
| 8 | 134 | 72 | 4 | 10.043941 | 0.153007 | 4.054594 | 6.926112 | 0.919379 | 22.122671 | 27,315,984 | 7,360,585 | 0/0 |
| 64 | 1,086 | 147 | 32 | 146.507326 | 1.282232 | 15.980992 | 8.926647 | 11.684111 | 184.408306 | 221,173,348 | 59,657,477 | 0/0 |
| 1024 | 17,406 | 275 | 512 | 1,414.928296 | 19.163596 | 156.715285 | 4.568317 | 114.539565 | 1,709.946249 | 3,546,634,443 | 956,889,369 | 1/1 |

Local run directories are `backend/cgy_toolbox_full_v1/evidence/`:
`q5_local_n8_20260923_01`, `q5_local_n64_20260923_01`, and
`q5_local_n1024_20260923_01`. The n=1024 full JSONL transcript is
3,546,581,462 bytes and its compact representation round-trips to the same
SHA-256; the table's transcript total also includes the final-release record.

## Fresh Arbitrum Sepolia n=8

Preflight observed chain ID `421614`, latest block `311760884`, deployer
`0x9c6D45e3EED75aeb832b08340763417103671D72`, and balance
`0.136262634226654914` ETH. No credential is retained. The unchanged frozen
`StrongN8Poll` N=8 contract was used; no batch or contract change was made.

| item | value |
| --- | --- |
| network / chain ID | Arbitrum Sepolia / 421614 |
| verifier / poll | `0x94CbB93c9a194Ec7F64B8cF643d8107562926d3d` / `0x6a8ee332576C2cb6c7d513950f7Fd1b743cc88fC` |
| poll ID / tau | 910004 / 500 |
| voters / accepted / rejected | 8 / 8 / 0 |
| threshold / share IDs | 5-of-5 / 1,2,3,4,5 |
| first / last admission block | 311761087 / 311761234 |
| board seal block | 311761234 |
| gates / depth / max ready width | 134 / 72 / 4 |
| ballot proving | 10.360267 s |
| chain admission (deployment + ballots) | 41.261974 s |
| CGY backend | 3.797074 s |
| final release | 4.226528 s |
| producer total (including claim) | 63.223557 s |
| independent public replay | 62.143068 s |
| JSONL transcript / compact | 27,315,148 B / 7,357,605 B |
| result / isolated oracle | 1 / 1 |
| deployment / verifier gas | 1,436,337 / 1,653,005 |
| ballot gas total / median / p95 | 4,438,147 / 558,892 / 584,778 |
| final claim gas | 76,652 |
| final claim transaction | `0x924845e39c7ac0c0e1274f8aa90d8da06cf5fad0337c7bb46313fc1d2ecb4ff7` |
| exact chain-to-backend binding | PASS |
| public replay | PASS |
| on-chain result claim | PASS |

The public run directory is
`backend/cgy_toolbox_full_v1/evidence/q5_sepolia_n8_20260923_02`. Its setup
hash is `67aeb61851bce4e66fca810a32ad8b54c8569b5835f2b9f0560207880a0d9627`,
sealed-board hash is
`0x64876090cba05fdd26b631ac3a23078d11e5f42cc516c854478c52c05610a172`, and
claimed transcript hash is
`0c48bb7062a4be1c599bebaad90557753338cd6764673207a26584419aa8d064`.
The independent public replay re-read all eight public receipts/events, checked
all 64 accepted ciphertext coordinate pairs, re-derived the sealed board,
verified all 134 native gates and the five-share final release, and used no
private witness, trustee secret, or cleartext oracle. The isolated oracle
artifact hash is
`9af97febe856b4bc6a4417f131c3ba9d4c924b79e830a45d2043dba0bbd64e3e`.

Ballot provenance is retained as
`q5_sepolia_n8_20260923_02/sepolia_ballot_transactions.jsonl` (8 records,
SHA-256 `9cacdd2262ef2a28f4a3b8ea6ed378d5a5d6fcb5f47b1d9f377fd2cf2ebfba7c`).
The first five transaction hashes are:

```text
0xa9b02f7270dcffb75e226b92386664408291fd2765a16fd4ce6e9d24edef9b37
0xb0168bd5e16e14a47563fa7d8add7f52d1d2947d8b71ac8be88bcbfff413489
0x85b733b1f73fb681638acb104011e6820bfa713cca3665b37ebfb02be7732069
0xed3ca63c0f7ddbca34cc483c6228922e75961a2c25cc80e452c4cfc93649efdb
0x9a8eb5d8e77676bb79ef609797142dc0ef6f779bd838d28867efb4d82b9dd86f
```

The last five are:

```text
0xed3ca63c0f7ddbca34cc483c6228922e75961a2c25cc80e452c4cfc93649efdb
0x9a8eb5d8e77676bb79ef609797142dc0ef6f779bd838d28867efb4d82b9dd86f
0x94e93933b774bf569fdc23dc5310cd7b9b2280d4bd3041cc0961513d87c64cc6
0xc906f2685763f0163764b8df35ef6324b2b5ac3dd219bedbdbfe2a472a0f66f2
0xa744311b18372b942367730c6252fe43126c3353b2b5ccd85b711a84fd0bcea7
```

## Test and provenance summary

`cargo test --release` passed 4 native tests (including exact BabyJub
compatibility), the full JS suite passed 46/46, the Q5 threshold/final-release
suite passed 4/4, and the deterministic Q5 gate was mutually verified by JS and
Rust. The compact transcript codec was verified losslessly for every local Q5
run and the Sepolia run. The old Q3 evidence remains historical and is not
mixed into the measurements above.

The source authority is `CGY_Q5_PARAMETER_AUTHORITY.md`; the conformance map is
`CGY_IMPLEMENTATION_CONFORMANCE_Q5.md`; adversarial status is in
`ADVERSARIAL_TEST_REPORT_Q5.md`. The production source is based on parent
commit `0d49fed671ce33037a1b2d0a5b6007c3a5d17b97`; the final Q5 tree and
production manifest hash are recorded with the committed artifact set.

```ini
SOURCE_CRYPTO_SEMANTICS_CHANGED=NO
SECURITY_PROTOCOL_CHANGED=NO
BALLOT_CIRCUIT_CHANGED=NO
CONTRACT_SEMANTICS_CHANGED=NO
THRESHOLD_PROFILE_CHANGED=YES_PARAMETER_ONLY
FINAL_REFERENCE_THRESHOLD=5_OF_5
FINAL_CONCRETE_PRIVACY=UP_TO_4_OF_5_STATIC_ACTIVE_TRUSTEES
FINAL_Q5_EVIDENCE=PASS
READY_FOR_MANUSCRIPT_HANDOFF=YES
```
