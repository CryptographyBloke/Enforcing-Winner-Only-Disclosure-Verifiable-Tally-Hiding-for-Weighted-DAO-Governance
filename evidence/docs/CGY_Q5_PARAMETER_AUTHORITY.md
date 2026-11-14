# Q5 threshold parameter authority

```ini
STATUS=PASS
SOURCE_CONDITION_ALGORITHMS_65_66=ALLOW_DEGREE_a_MINUS_1_THRESHOLD_a
Q5_PARAMETER_SPECIALIZATION=AUTHORIZED
TRUSTEES=5
POLYNOMIAL_DEGREE=4
DECRYPTION_THRESHOLD=5
CONCRETE_ACTIVE_PRIVACY_BOUND=F_LE_4
```

The full CGY paper's threshold setup (Appendix A.2) uses a Shamir polynomial of
degree `t`, with trustee shares `s_i=P(i)`. The source reconstruction algorithm
combines exactly `t+1` valid partial decryptions (Algorithms 65/66). Its privacy
quantification assumes `t<a`. Therefore the concrete specialization
`a=5`, `t=4`, `q_dec=t+1=5` is source-compatible: all five distinct verified
shares are required, and a coalition of at most four trustees remains below the
decryption threshold. This is a parameter specialization only; no equation,
group, random-oracle, ballot, broadcast, or verifier interface is changed.

Source authority: `Full A toolbox for verifiable tally-hiding e-voting systems.md`,
Appendix A.2 (Shamir setup and reconstruction), Algorithms 65/66 (threshold
opening), and the generic `t<a` privacy premise. The frozen gap-resolution
profile remains the controlling implementation specification.
