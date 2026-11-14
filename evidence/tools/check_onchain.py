#!/usr/bin/env python3
"""Re-read the 11 recorded Arbitrum Sepolia transactions and the outcome-claim event from a public RPC
and compare them with data/sepolia_identifiers.json. Standard library only; no key or account is needed.

Usage (package root):  python tools/check_onchain.py [rpc_url]
Exit code 0 means every receipt matches. A network failure is reported as an error, not as a mismatch.
"""
import json, pathlib, sys, urllib.request

rpc = sys.argv[1] if len(sys.argv) > 1 else "https://sepolia-rollup.arbitrum.io/rpc"
root = pathlib.Path(__file__).resolve().parent.parent
rec = json.loads((root / "data" / "sepolia_identifiers.json").read_text(encoding="utf-8"))


def call(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(rpc, data=body, headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
    return json.load(urllib.request.urlopen(req, timeout=60))["result"]


assert int(call("eth_chainId", []), 16) == rec["chainId"] == 421614
expected = [("deploy-verifier", rec["deployment"]["verifier"]), ("deploy-poll", rec["deployment"]["poll"])]
expected += [(f"ballot{i}", t) for i, t in enumerate(rec["ballotTransactions"])]
expected += [("claim", rec["outcomeClaim"])]
bad = 0
for name, r in expected:
    c = call("eth_getTransactionReceipt", [r["transactionHash"]])
    ok = (c is not None and int(c["status"], 16) == 1 and int(c["blockNumber"], 16) == r["blockNumber"]
          and int(c["gasUsed"], 16) == int(r["gasUsed"]))
    bad += 0 if ok else 1
    print(f"{'OK  ' if ok else 'FAIL'} {name:16s} block {r['blockNumber']} gas {r['gasUsed']}")
claim = call("eth_getTransactionReceipt", [rec["outcomeClaim"]["transactionHash"]])
data = claim["logs"][0]["data"][2:]
commit, ht, b = "0x" + data[:64], data[64:128], int(data[128:192], 16)
ok = (claim["logs"][0]["address"].lower() == rec["pollContract"].lower() and commit == rec["acceptedBallotCommitment_onChain"]
      and ht == rec["transcriptHash_claimed_H(T)"] and b == rec["resultBit"])
bad += 0 if ok else 1
print(f"{'OK  ' if ok else 'FAIL'} claim event: commitment {commit[:14]}..., H(T) {ht[:12]}..., b={b}")
sys.exit(1 if bad else 0)
