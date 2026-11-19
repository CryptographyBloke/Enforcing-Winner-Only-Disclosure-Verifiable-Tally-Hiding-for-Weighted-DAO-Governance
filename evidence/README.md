# Historical paper evidence

The main branch keeps the submission PDF and its maintained implementation easy to find. Detailed historical run files and the frozen Q5 source are preserved in the existing [`blocksys2027-evidence-v1 release`](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/releases/tag/blocksys2027-evidence-v1), rather than duplicated throughout this source tree.

The release asset `blocksys2027_evidence_package.zip` contains the Q5 run manifests, source and artifact hash records, public-chain records, replay materials, and frozen source snapshot. Its published SHA-256 is:

```text
7169b79aa099fa42de3c37cadcdd6c21125b7ca4ac63e6a7419e9475cc776a84
```

The release and its asset are historical records and remain unchanged. To download and verify the archive in PowerShell:

```powershell
$evidenceDir = Join-Path $env:TEMP ("blocksys2027-evidence-v1-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $evidenceDir | Out-Null
gh release download blocksys2027-evidence-v1 --repo CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance --pattern blocksys2027_evidence_package.zip --dir $evidenceDir
Get-FileHash (Join-Path $evidenceDir "blocksys2027_evidence_package.zip") -Algorithm SHA256
```

The post-cleanup engineering runs are in the separate [`evidence-v2 release`](https://github.com/CryptographyBloke/Enforcing-Winner-Only-Disclosure-Verifiable-Tally-Hiding-for-Weighted-DAO-Governance/releases/tag/blocksys2027-evidence-v2-cleaned-local-2026-11). They are not the measurements reported by the submission PDF. New runs from this checkout are written under the ignored `runs/` directory.
