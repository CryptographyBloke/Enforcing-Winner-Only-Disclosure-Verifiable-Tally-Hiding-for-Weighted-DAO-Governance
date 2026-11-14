#!/usr/bin/env python3
"""Derive the compact data files of the evidence package from the copied Q5 run records.

Reads  : runs/*/manifest.json, runs/q5_sepolia_n8_20260923_02/*.json, docs/CGY_Q5_EVIDENCE_MANIFEST.sha256
Writes : data/performance_local.csv, data/sepolia_identifiers.json, data/large_transcripts.csv
Run from the package root:  python tools/make_package_data.py
Every value is copied from a recorded file. Nothing is measured or estimated here.
"""
import csv, json, pathlib, re

root = pathlib.Path(__file__).resolve().parent.parent
runs = root / "runs"
data = root / "data"
data.mkdir(exist_ok=True)

# ------------------------------------------------------------ performance_local.csv
rows = []
for name in ("q5_local_n8_20260923_01", "q5_local_n64_20260923_01",
             "q5_local_n256_20260925_03", "q5_local_n1024_20260923_01"):
    m = json.loads((runs / name / "manifest.json").read_text(encoding="utf-8"))
    t = m["timing"]
    assert m["finalReferenceThreshold"] == "5_OF_5" and m["resultBit"] == m["oracleResult"]
    rows.append({
        "run": name, "n": m["count"], "tau": m["tau"], "gates": m["gates"], "depth": m["depth"],
        "max_ready_width": m["maxReadyWidth"], "result_bit": m["resultBit"], "oracle_bit": m["oracleResult"],
        "proving_s": t["ballotSeconds"], "admission_s": t["admissionSeconds"], "backend_s": t["backendSeconds"],
        "release_s": t["finalReleaseSeconds"], "replay_s": t["replaySeconds"], "total_s": t["totalSeconds"],
        "transcript_bytes": t["transcriptBytes"], "setup_hash": m["setupHash"], "transcript_hash": m["transcriptHash"],
        "execution_id": m["executionId"], "co_located": "yes", "scope": "local single host, no network latency"})
with open(data / "performance_local.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)

# ------------------------------------------------------------ sepolia_identifiers.json
s = runs / "q5_sepolia_n8_20260923_02"
m = json.loads((s / "manifest.json").read_text(encoding="utf-8"))
r = json.loads((s / "public_replay_q5.json").read_text(encoding="utf-8"))
snap = json.loads((s / "chain_snapshot.json").read_text(encoding="utf-8"))
dep = m["deployment"]
out = {
    "profile": m["profile"], "threshold": m["finalReferenceThreshold"], "network": r["network"], "chainId": int(r["chainId"]),
    "pollContract": dep["pollAddress"], "groth16Verifier": dep["verifierAddress"],
    "pollId": snap["pollConfiguration"]["pollId"], "tau": snap["pollConfiguration"]["tau"],
    "registryRoot": snap["pollConfiguration"]["registryRoot"],
    "acceptedBallots": r["acceptedBallots"], "rejectedBallots": 0, "gates": r["sourceGatesVerified"], "resultBit": m["resultBit"],
    "acceptedBallotCommitment_onChain": snap["ballotSetCommitment"],
    "sealedBoardHash_backend": m["sealedBoardHash"],
    "setupHash": m["setupHash"], "transcriptHash_claimed_H(T)": m["transcriptHash"], "executionId": m["executionId"],
    "deployment": {k: r["deploymentReceipts"][k] for k in ("verifier", "poll")},
    "ballotTransactions": r["receipts"],
    "outcomeClaim": r["claimReceipt"],
    "artifactHashes": m["artifactHashes"], "contractArtifactHashes": m["contractArtifactHashes"],
    "publicReplay": {"status": r["status"], "exactChainToBackendBinding": r["exactChainToBackendBinding"],
                     "exactCiphertextCoordinates": r["exactCiphertextCoordinates"],
                     "finalReleaseVerified": r["finalReleaseVerified"], "timing_ms": r["timing"]},
    "note": ("acceptedBallotCommitment_onChain is the contract's Keccak accumulator commitment. sealedBoardHash_backend is the "
             "hash of the canonical board object that contains that commitment. They are different values."),
}
(data / "sepolia_identifiers.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")

# ------------------------------------------------------------ large_transcripts.csv
lines = (root / "docs" / "CGY_Q5_EVIDENCE_MANIFEST.sha256").read_text(encoding="utf-8").splitlines()
prefix = "backend/cgy_toolbox_full_v1/evidence/"
with open(data / "large_transcripts.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["run", "file", "bytes", "sha256", "original_location", "in_this_archive"])
    for l in lines:
        mm = re.match(r"^([0-9a-f]{64})\s+(\d+)\s+(.+)$", l.strip())
        if mm and mm.group(3).startswith(prefix) and "gate_transcript" in mm.group(3):
            run, fname = mm.group(3)[len(prefix):].split("/", 1)
            here = (root / "runs" / run / fname).exists()
            w.writerow([run, fname, mm.group(2), mm.group(1),
                        "THproto-cgy-toolbox/" + mm.group(3), "yes" if here else "no"])
    # n=256 is covered by CGY_Q5_N256_AND_PARALLEL_EVIDENCE.md and its run manifest, not by the 49-line manifest
    n256 = json.loads((runs / "q5_local_n256_20260925_03" / "manifest.json").read_text(encoding="utf-8"))["hashes"]
    w.writerow(["q5_local_n256_20260925_03", "gate_transcript.jsonl", 886045853, n256["journalSha256"],
                "THproto-cgy-toolbox/backend/cgy_toolbox_full_v1/evidence/q5_local_n256_20260925_03/gate_transcript.jsonl", "no"])
    w.writerow(["q5_local_n256_20260925_03", "gate_transcript.compact.bin", 239114329,
                "ff735eb2b1333d692f731447b1f65e47394546376777f76fa7de5c53299c2b22",
                "THproto-cgy-toolbox/backend/cgy_toolbox_full_v1/evidence/q5_local_n256_20260925_03/gate_transcript.compact.bin", "no"])
print("wrote", data / "performance_local.csv", data / "sepolia_identifiers.json", data / "large_transcripts.csv")
