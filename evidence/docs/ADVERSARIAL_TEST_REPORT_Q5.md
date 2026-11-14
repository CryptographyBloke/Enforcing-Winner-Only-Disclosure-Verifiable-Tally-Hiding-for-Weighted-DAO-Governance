# Q5 adversarial test report

```ini
PROFILE=FC2027-CGY-TOOLBOX-FULL-V1-Q5
ADVERSARIAL_SUITE_Q5_PASS=YES
FULL_NPM_TESTS=46_PASS_0_FAIL
Q5_THRESHOLD_TESTS=4_PASS_0_FAIL
SOURCE_CRYPTO_SEMANTICS_CHANGED=NO
```

The existing mutation matrix was rerun with `npm test` (46 tests passed). It
continues to reject altered auxiliary elements, masking proofs, source context,
trustee identities, broadcast slots/equivocation, early reveal or missing
commitments, malformed rerandomization, wrong accepted ciphertexts, premature
decryption, altered shares/proofs, duplicate shares, reordered/replaced ballots,
wrong board hashes, physical `C_*`, changed result bits, and transcript
tampering with the source-defined reject, wait, or abort behavior.

The Q5-specific tests in `test/q5_threshold.test.js` and
`test/q5_final_release.test.js` cover:

| mutation or boundary | observed result |
| --- | --- |
| five valid shares | success |
| four valid shares | `E_THRESHOLD_INSUFFICIENT` |
| three valid shares | `E_THRESHOLD_INSUFFICIENT` |
| four valid plus one invalid share | proof reject |
| duplicate fifth trustee | `E_DUPLICATE_TRUSTEE` |
| foreign fifth share | setup/session reject |
| fifth share for wrong ciphertext | session/ciphertext reject |
| fifth share for wrong session | session reject |
| altered public secret share | setup/share-value reject |
| final release with four shares | `E_RELEASE_QUORUM` |

These are protocol-input rejection checks, not a replacement for the CGY
security theorem.

```ini
Q5_FIVE_VALID_SHARES=PASS
Q5_FOUR_VALID_SHARES=REJECT_INSUFFICIENT
Q5_THREE_VALID_SHARES=REJECT_INSUFFICIENT
Q5_FOUR_PLUS_ONE_INVALID=REJECT
Q5_DUPLICATE_FIFTH=REJECT
Q5_FOREIGN_FIFTH=REJECT
Q5_WRONG_CIPHERTEXT_FIFTH=REJECT
Q5_WRONG_SESSION_FIFTH=REJECT
Q5_FINAL_RELEASE_FIVE_OF_FIVE=PASS
```
