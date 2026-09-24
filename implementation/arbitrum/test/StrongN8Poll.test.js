const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

const FIXTURES_DIR = path.join(__dirname, "..", "fixtures");

function loadProof(idx) {
  const data = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, `ballot_${idx}.json`)));
  const proof = data.proof;
  const publicSignals = data.publicSignals;

  return {
    a: [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])],
    b: [
      [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
      [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
    ],
    c: [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])],
    publicSignals: publicSignals.map((s) => BigInt(s)),
  };
}

const FROZEN_PK_X = 1797588745011370216979329902335005807397914974288341143449036495684975893024n;
const FROZEN_PK_Y = 25877005333706482673493195496572142113607866423935919304802034496841320160n;
const FROZEN_BACKEND_SETUP_HASH = "0x3625E7F436006FEFCB2BE62C086CC99F91A76E0E0B1E26B9F9ED7DAD375F9C9F";

const PROTOCOL_TAG = "STRONG_N8_POLL_V1";
const BALLOT_SEED_V1 = ethers.keccak256(ethers.toUtf8Bytes("BALLOT_SEED_V1"));
const BALLOT_NODE_V1 = ethers.keccak256(ethers.toUtf8Bytes("BALLOT_NODE_V1"));
const BALLOT_FINAL_V1 = ethers.keccak256(ethers.toUtf8Bytes("BALLOT_FINAL_V1"));
const BALLOT_LEAF_V1 = ethers.keccak256(ethers.toUtf8Bytes("BALLOT_LEAF_V1"));

const REGISTRY_ROOT = 19107103738567194436396340418792058720536504709393997203059537477333579411728n;
const POLL_ID = 424242n;
const TAU = 2040n;

function computePollDomain(chainId, contractAddr, verifierAddr) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["string", "uint256", "address", "address", "uint256", "uint256", "uint256", "uint256", "bytes32", "uint256", "uint256", "uint256", "uint256"],
      [PROTOCOL_TAG, chainId, contractAddr, verifierAddr, REGISTRY_ROOT, POLL_ID, FROZEN_PK_X, FROZEN_PK_Y, FROZEN_BACKEND_SETUP_HASH, TAU, 8n, 8n, 11n]
    )
  );
}

function computeBallotLeaf(pollDomain, ballotIndex, nullifier, ciphertext) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "uint256", "uint256"].concat(Array(32).fill("uint256")),
      [BALLOT_LEAF_V1, pollDomain, ballotIndex, nullifier].concat(
        ciphertext.map((v) => BigInt(v))
      )
    )
  );
}

function computeSeed(pollDomain) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32"],
      [BALLOT_SEED_V1, pollDomain]
    )
  );
}

function computeNode(pollDomain, prevAccumulator, leaf) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32"],
      [BALLOT_NODE_V1, pollDomain, prevAccumulator, leaf]
    )
  );
}

function computeFinalCommitment(pollDomain, accumulator8) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "uint256", "bytes32"],
      [BALLOT_FINAL_V1, pollDomain, 8n, accumulator8]
    )
  );
}

function to32Ciphertext(publicSignals) {
  const ct = [];
  for (let k = 0; k < 8; k++) {
    ct.push(publicSignals[1 + 4 * k]);
    ct.push(publicSignals[2 + 4 * k]);
    ct.push(publicSignals[3 + 4 * k]);
    ct.push(publicSignals[4 + 4 * k]);
  }
  return ct;
}

async function deployPoll(Poll, verifierAddr, registryRoot, pollId, tau, publisherAddr, deadline) {
  return Poll.deploy(verifierAddr, registryRoot, pollId, tau, publisherAddr, deadline, FROZEN_PK_X, FROZEN_PK_Y, FROZEN_BACKEND_SETUP_HASH);
}

describe("StrongN8Poll", function () {
  let verifier;
  let poll;
  let owner;
  let publisher;
  let other;
  let chainId;
  let pollDomain;
  let seed;

  const proofs = [];

  before(async function () {
    [owner, publisher, other] = await ethers.getSigners();
    chainId = (await ethers.provider.getNetwork()).chainId;

    for (let i = 0; i < 8; i++) {
      proofs.push(loadProof(i));
    }

    const Verifier = await ethers.getContractFactory("Groth16Verifier");
    verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    const verifierAddr = await verifier.getAddress();

    const latest = await ethers.provider.getBlock("latest");
    const deadline = BigInt(latest.timestamp) + 86400n;

    const Poll = await ethers.getContractFactory("StrongN8Poll");
    poll = await deployPoll(Poll,
      verifierAddr,
      REGISTRY_ROOT,
      POLL_ID,
      TAU,
      publisher.address,
      deadline,
      FROZEN_PK_X,
      FROZEN_PK_Y,
      FROZEN_BACKEND_SETUP_HASH
    );
    await poll.waitForDeployment();

    pollDomain = computePollDomain(chainId, await poll.getAddress(), verifierAddr);
    seed = computeSeed(pollDomain);
  });

  describe("Deployment", function () {
    it("should set correct constants", async function () {
      expect(await poll.N()).to.equal(8n);
      expect(await poll.L_VOTE()).to.equal(8n);
      expect(await poll.L_AGG()).to.equal(11n);
      expect(await poll.committeePK_X()).to.equal(FROZEN_PK_X);
      expect(await poll.committeePK_Y()).to.equal(FROZEN_PK_Y);
      const onChainHash = await poll.backendSetupHash();
      expect(onChainHash.toLowerCase()).to.equal(FROZEN_BACKEND_SETUP_HASH.toLowerCase());
    });

    it("should have correct immutable params", async function () {
      expect(await poll.registryRoot()).to.equal(REGISTRY_ROOT);
      expect(await poll.pollId()).to.equal(POLL_ID);
      expect(await poll.tau()).to.equal(TAU);
      expect(await poll.outcomePublisher()).to.equal(publisher.address);
      expect(await poll.POLL_DOMAIN()).to.equal(pollDomain);
    });

    it("should be in Open phase with zero accepted ballots", async function () {
      expect(await poll.phase()).to.equal(0n); // Open
      expect(await poll.acceptedBallotCount()).to.equal(0n);
    });

    it("should have correct seed accumulator", async function () {
      expect(await poll.accumulator()).to.equal(seed);
    });

    it("should have correct POLL_DOMAIN computed", async function () {
      const onChainPollDomain = await poll.POLL_DOMAIN();
      expect(onChainPollDomain).to.equal(pollDomain);
    });
  });

  describe("Verifier", function () {
    it("should verify a known valid proof", async function () {
      const p = proofs[0];
      const result = await verifier.verifyProof(p.a, p.b, p.c, p.publicSignals);
      expect(result).to.be.true;
    });
  });

  describe("Ballot Submission �?Positive", function () {
    it("should accept ballot 0", async function () {
      const p = proofs[0];
      const tx = await poll.submitBallot(p.a, p.b, p.c, p.publicSignals);
      const receipt = await tx.wait();

      const events = receipt.logs.filter(
        (log) => poll.interface.parseLog({ topics: log.topics, data: log.data })?.name === "BallotAccepted"
      );
      expect(events.length).to.equal(1);

      const parsed = poll.interface.parseLog({ topics: events[0].topics, data: events[0].data });
      expect(parsed.args.ballotIndex).to.equal(0n);
      expect(parsed.args.nullifier).to.equal(BigInt(p.publicSignals[0]));
      expect(await poll.acceptedBallotCount()).to.equal(1n);
      expect(await poll.phase()).to.equal(0n); // still Open
      expect(await poll.usedNullifiers(BigInt(p.publicSignals[0]))).to.be.true;
    });

    it("should accept ballots 1-7 and seal on 8th", async function () {
      for (let i = 1; i < 8; i++) {
        const p = proofs[i];
        const tx = await poll.submitBallot(p.a, p.b, p.c, p.publicSignals);
        await tx.wait();
      }
      expect(await poll.acceptedBallotCount()).to.equal(8n);
      expect(await poll.phase()).to.equal(1n); // Sealed
    });

    it("should have assigned indices 0..7", async function () {
      for (let i = 0; i < 8; i++) {
        const p = proofs[i];
        expect(await poll.usedNullifiers(BigInt(p.publicSignals[0]))).to.be.true;
      }
    });

    it("should have final ballotSetCommitment set", async function () {
      const bsc = await poll.ballotSetCommitment();
      expect(bsc).to.not.equal(ethers.ZeroHash);
    });

    it("should have correct indices (0..7) in BallotAccepted events", async function () {
      const filter = poll.filters.BallotAccepted();
      const events = await poll.queryFilter(filter, 0);
      expect(events.length).to.equal(8);
      for (let i = 0; i < 8; i++) {
        expect(events[i].args.ballotIndex).to.equal(BigInt(i));
      }
    });
  });

  describe("Commitment Cross-Check (JS vs Solidity)", function () {
    it("JS seed matches Solidity seed (read during Deployment, before any ballot)", async function () {
      // Recreate a fresh deployment and verify seed computation
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const deadline = BigInt(latest.timestamp) + 86400n;
      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const fresh = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, deadline);
      await fresh.waitForDeployment();

      const freshDomain = await fresh.POLL_DOMAIN();
      const jsAccum = computeSeed(freshDomain);
      expect(await fresh.accumulator()).to.equal(jsAccum);
    });

    it("JS leaves and accumulators match events", async function () {
      const filter = poll.filters.BallotAccepted();
      const events = await poll.queryFilter(filter, 0);

      let jsAccum = computeSeed(pollDomain);

      for (let i = 0; i < 8; i++) {
        const p = proofs[i];
        const evt = events[i];
        const ct32 = to32Ciphertext(p.publicSignals);

        const jsLeaf = computeBallotLeaf(pollDomain, BigInt(i), BigInt(p.publicSignals[0]), ct32);
        expect(evt.args.ballotLeaf).to.equal(jsLeaf, `Leaf mismatch at index ${i}`);

        jsAccum = computeNode(pollDomain, jsAccum, jsLeaf);
        expect(evt.args.accumulator).to.equal(jsAccum, `Accumulator mismatch at index ${i}`);
      }
    });

    it("JS final commitment matches Solidity", async function () {
      const filter = poll.filters.BallotAccepted();
      const events = await poll.queryFilter(filter, 0);

      let jsAccum = computeSeed(pollDomain);
      for (let i = 0; i < 8; i++) {
        const p = proofs[i];
        const ct32 = to32Ciphertext(p.publicSignals);
        const jsLeaf = computeBallotLeaf(pollDomain, BigInt(i), BigInt(p.publicSignals[0]), ct32);
        jsAccum = computeNode(pollDomain, jsAccum, jsLeaf);
      }

      const jsFinal = computeFinalCommitment(pollDomain, jsAccum);
      const scFinal = await poll.ballotSetCommitment();
      expect(scFinal).to.equal(jsFinal);
    });
  });

  describe("Negative �?Rejection Cases", function () {
    let poll2;
    let verifierAddr;
    let deadline;

    before(async function () {
      verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      deadline = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      poll2 = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, deadline);
      await poll2.waitForDeployment();
    });

    it("should reject ballot after Sealed", async function () {
      for (let i = 0; i < 8; i++) {
        const p = proofs[i];
        await poll2.submitBallot(p.a, p.b, p.c, p.publicSignals);
      }
      expect(await poll2.phase()).to.equal(1n); // Sealed

      // Try 9th ballot (reuse first proof)
      await expect(
        poll2.submitBallot(proofs[0].a, proofs[0].b, proofs[0].c, proofs[0].publicSignals)
      ).to.be.revertedWith("StrongN8Poll: poll is not open");
    });

    it("should reject duplicate nullifier (in new poll)", async function () {
      const latest = await ethers.provider.getBlock("latest");
      const dl = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const p3 = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, dl);
      await p3.waitForDeployment();

      await p3.submitBallot(proofs[0].a, proofs[0].b, proofs[0].c, proofs[0].publicSignals);

      await expect(
        p3.submitBallot(proofs[0].a, proofs[0].b, proofs[0].c, proofs[0].publicSignals)
      ).to.be.revertedWith("StrongN8Poll: duplicate nullifier");
    });

    it("should reject invalid Groth16 proof", async function () {
      const latest = await ethers.provider.getBlock("latest");
      const dl = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const p4 = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, dl);
      await p4.waitForDeployment();

      // Corrupt proof by zeroing pi_a
      const badProof = { ...proofs[0] };
      badProof.a = [0n, 0n];

      await expect(
        p4.submitBallot(badProof.a, badProof.b, badProof.c, badProof.publicSignals)
      ).to.be.revertedWith("StrongN8Poll: invalid proof");
    });

    it("should reject wrong registry root", async function () {
      const latest = await ethers.provider.getBlock("latest");
      const dl = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const p5 = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, dl);
      await p5.waitForDeployment();

      const badSignals = [...proofs[0].publicSignals];
      badSignals[33] = (BigInt(badSignals[33]) + 1n).toString();

      await expect(
        p5.submitBallot(proofs[0].a, proofs[0].b, proofs[0].c, badSignals)
      ).to.be.revertedWith("StrongN8Poll: wrong registry root");
    });

    it("should reject wrong pollId", async function () {
      const latest = await ethers.provider.getBlock("latest");
      const dl = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const p6 = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, dl);
      await p6.waitForDeployment();

      const badSignals = [...proofs[0].publicSignals];
      badSignals[34] = "434343";

      await expect(
        p6.submitBallot(proofs[0].a, proofs[0].b, proofs[0].c, badSignals)
      ).to.be.revertedWith("StrongN8Poll: wrong pollId");
    });

    it("should reject wrong PK.x", async function () {
      const latest = await ethers.provider.getBlock("latest");
      const dl = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const p7 = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, dl);
      await p7.waitForDeployment();

      const badSignals = [...proofs[0].publicSignals];
      badSignals[35] = "0";

      await expect(
        p7.submitBallot(proofs[0].a, proofs[0].b, proofs[0].c, badSignals)
      ).to.be.revertedWith("StrongN8Poll: wrong PK.x");
    });

    it("should reject wrong PK.y", async function () {
      const latest = await ethers.provider.getBlock("latest");
      const dl = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const p8 = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, dl);
      await p8.waitForDeployment();

      const badSignals = [...proofs[0].publicSignals];
      badSignals[36] = "0";

      await expect(
        p8.submitBallot(proofs[0].a, proofs[0].b, proofs[0].c, badSignals)
      ).to.be.revertedWith("StrongN8Poll: wrong PK.y");
    });

    it("should reject CT[k].R == O for every k (R nonidentity)", async function () {
      for (let k = 0; k < 8; k++) {
        const latest = await ethers.provider.getBlock("latest");
        const dl = BigInt(latest.timestamp) + 86400n;

        const Poll = await ethers.getContractFactory("StrongN8Poll");
        const pz = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, dl);
        await pz.waitForDeployment();

        const badSignals = [...proofs[0].publicSignals];
        badSignals[1 + 4 * k] = "0";
        badSignals[2 + 4 * k] = "1";

        await expect(
          pz.submitBallot(proofs[0].a, proofs[0].b, proofs[0].c, badSignals)
        ).to.be.revertedWith("StrongN8Poll: CT R is identity");
      }
    });

    it("should reject deployment with tau > 2040", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const dl = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      await expect(
        deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, 2041n, publisher.address, dl)
      ).to.be.revertedWith("StrongN8Poll: tau exceeds max");
    });

    it("should reject deployment with zero verifier", async function () {
      const latest = await ethers.provider.getBlock("latest");
      const dl = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      await expect(
        deployPoll(Poll, ethers.ZeroAddress, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, dl)
      ).to.be.revertedWith("StrongN8Poll: zero verifier");
    });

    it("should reject deployment with zero publisher", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const dl = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      await expect(
        deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, ethers.ZeroAddress, dl)
      ).to.be.revertedWith("StrongN8Poll: zero publisher");
    });

    it("should reject deployment with past deadline", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const dl = BigInt(latest.timestamp) - 1n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      await expect(
        deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, dl)
      ).to.be.revertedWith("StrongN8Poll: deadline in past");
    });
  });

  describe("Abandon Path", function () {
    it("should not allow abandon before deadline", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const deadline = BigInt(latest.timestamp) + 3600n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const pab = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, deadline);
      await pab.waitForDeployment();

      await expect(pab.abandon()).to.be.revertedWith("StrongN8Poll: deadline not reached");
    });

    it("should allow abandon after deadline with <8 ballots", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const deadline = BigInt(latest.timestamp) + 60n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const pab = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, deadline);
      await pab.waitForDeployment();

      await ethers.provider.send("evm_increaseTime", [120]);
      await ethers.provider.send("evm_mine");

      await pab.abandon();
      expect(await pab.phase()).to.equal(3n);
    });

    it("should not accept ballots after Abandoned", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const deadline = BigInt(latest.timestamp) + 60n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const pab = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, deadline);
      await pab.waitForDeployment();

      await ethers.provider.send("evm_increaseTime", [120]);
      await ethers.provider.send("evm_mine");
      await pab.abandon();

      await expect(
        pab.submitBallot(proofs[0].a, proofs[0].b, proofs[0].c, proofs[0].publicSignals)
      ).to.be.revertedWith("StrongN8Poll: poll is not open");
    });
  });

  describe("Deadline Enforcement (AUDIT-F-2 Repair)", function () {
    it("A: valid ballot at deadline-1 succeeds", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const deadline = latest.timestamp + 3600;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const pd = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, deadline);
      await pd.waitForDeployment();

      await ethers.provider.send("evm_setNextBlockTimestamp", [deadline - 1]);
      await pd.submitBallot(proofs[0].a, proofs[0].b, proofs[0].c, proofs[0].publicSignals);
      expect(await pd.acceptedBallotCount()).to.equal(1n);
    });

    it("B: valid ballot at exactly deadline rejects", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const deadline = latest.timestamp + 3600;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const pd = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, deadline);
      await pd.waitForDeployment();

      await ethers.provider.send("evm_setNextBlockTimestamp", [deadline]);
      await expect(
        pd.submitBallot(proofs[0].a, proofs[0].b, proofs[0].c, proofs[0].publicSignals)
      ).to.be.revertedWith("StrongN8Poll: voting deadline passed");
    });

    it("C: valid ballot at deadline+1 rejects", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const deadline = latest.timestamp + 3600;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const pd = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, deadline);
      await pd.waitForDeployment();

      await ethers.provider.send("evm_setNextBlockTimestamp", [deadline + 1]);
      await expect(
        pd.submitBallot(proofs[0].a, proofs[0].b, proofs[0].c, proofs[0].publicSignals)
      ).to.be.revertedWith("StrongN8Poll: voting deadline passed");
    });

    it("D: after deadline with 7 ballots, phase Open, ballot 8 rejects", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const deadline = latest.timestamp + 3600;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const pd = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, deadline);
      await pd.waitForDeployment();

      for (let i = 0; i < 7; i++) {
        await pd.submitBallot(proofs[i].a, proofs[i].b, proofs[i].c, proofs[i].publicSignals);
      }

      await ethers.provider.send("evm_setNextBlockTimestamp", [deadline + 1]);
      expect(await pd.phase()).to.equal(0n);
      expect(await pd.acceptedBallotCount()).to.equal(7n);

      await expect(
        pd.submitBallot(proofs[7].a, proofs[7].b, proofs[7].c, proofs[7].publicSignals)
      ).to.be.revertedWith("StrongN8Poll: voting deadline passed");
    });

    it("E: after D, abandon() succeeds and phase becomes Abandoned", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const deadline = latest.timestamp + 3600;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const pd = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, deadline);
      await pd.waitForDeployment();

      for (let i = 0; i < 7; i++) {
        await pd.submitBallot(proofs[i].a, proofs[i].b, proofs[i].c, proofs[i].publicSignals);
      }

      await ethers.provider.send("evm_setNextBlockTimestamp", [deadline]);
      await pd.abandon();
      expect(await pd.phase()).to.equal(3n);
    });

    it("F: eight ballots before deadline, phase remains Sealed after deadline", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const deadline = latest.timestamp + 86400;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const pd = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, deadline);
      await pd.waitForDeployment();

      for (let i = 0; i < 8; i++) {
        await pd.submitBallot(proofs[i].a, proofs[i].b, proofs[i].c, proofs[i].publicSignals);
      }
      expect(await pd.phase()).to.equal(1n);

      await ethers.provider.send("evm_setNextBlockTimestamp", [deadline + 1]);
      expect(await pd.phase()).to.equal(1n);
      await expect(pd.abandon()).to.be.revertedWith("StrongN8Poll: not open");
      expect(await pd.phase()).to.equal(1n);
    });
  });

  describe("Outcome Claim", function () {
    let pollClaim;

    before(async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const deadline = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      pollClaim = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, deadline);
      await pollClaim.waitForDeployment();

      for (let i = 0; i < 8; i++) {
        const p = proofs[i];
        await pollClaim.submitBallot(p.a, p.b, p.c, p.publicSignals);
      }
      expect(await pollClaim.phase()).to.equal(1n); // Sealed
    });

    it("should allow publisher to publish outcome claim", async function () {
      const bsc = await pollClaim.ballotSetCommitment();
      const transcriptHash = ethers.keccak256(ethers.toUtf8Bytes("test-transcript"));

      const tx = await pollClaim.connect(publisher).publishOutcomeClaim(bsc, transcriptHash, 1);
      await tx.wait();

      expect(await pollClaim.phase()).to.equal(2n); // Claimed
      expect(await pollClaim.outcomeBit()).to.equal(1n);
      expect(await pollClaim.backendTranscriptHash()).to.equal(transcriptHash);
    });

    it("should reject claim from non-publisher", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const deadline = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const pc = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, deadline);
      await pc.waitForDeployment();

      for (let i = 0; i < 8; i++) {
        const p = proofs[i];
        await pc.submitBallot(p.a, p.b, p.c, p.publicSignals);
      }

      const bsc = await pc.ballotSetCommitment();
      const transcriptHash = ethers.keccak256(ethers.toUtf8Bytes("test"));

      await expect(
        pc.connect(other).publishOutcomeClaim(bsc, transcriptHash, 1)
      ).to.be.revertedWith("StrongN8Poll: not outcome publisher");
    });

    it("should reject claim with wrong ballotSetCommitment", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const deadline = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const pc = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, deadline);
      await pc.waitForDeployment();

      for (let i = 0; i < 8; i++) {
        const p = proofs[i];
        await pc.submitBallot(p.a, p.b, p.c, p.publicSignals);
      }

      const transcriptHash = ethers.keccak256(ethers.toUtf8Bytes("test"));

      await expect(
        pc.connect(publisher).publishOutcomeClaim(ethers.ZeroHash, transcriptHash, 1)
      ).to.be.revertedWith("StrongN8Poll: wrong commitment");
    });

    it("should reject claim with zero transcript hash", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const deadline = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const pc = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, deadline);
      await pc.waitForDeployment();

      for (let i = 0; i < 8; i++) {
        const p = proofs[i];
        await pc.submitBallot(p.a, p.b, p.c, p.publicSignals);
      }

      const bsc = await pc.ballotSetCommitment();

      await expect(
        pc.connect(publisher).publishOutcomeClaim(bsc, ethers.ZeroHash, 1)
      ).to.be.revertedWith("StrongN8Poll: zero transcript");
    });

    it("should reject b=2", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const deadline = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const pc = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, deadline);
      await pc.waitForDeployment();

      for (let i = 0; i < 8; i++) {
        const p = proofs[i];
        await pc.submitBallot(p.a, p.b, p.c, p.publicSignals);
      }

      const bsc = await pc.ballotSetCommitment();
      const transcriptHash = ethers.keccak256(ethers.toUtf8Bytes("test"));

      await expect(
        pc.connect(publisher).publishOutcomeClaim(bsc, transcriptHash, 2)
      ).to.be.revertedWith("StrongN8Poll: invalid b");
    });

    it("should reject second outcome claim", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const deadline = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const pc = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, deadline);
      await pc.waitForDeployment();

      for (let i = 0; i < 8; i++) {
        const p = proofs[i];
        await pc.submitBallot(p.a, p.b, p.c, p.publicSignals);
      }

      const bsc = await pc.ballotSetCommitment();
      const th = ethers.keccak256(ethers.toUtf8Bytes("test"));

      await pc.connect(publisher).publishOutcomeClaim(bsc, th, 0);
      expect(await pc.phase()).to.equal(2n); // Claimed

      await expect(
        pc.connect(publisher).publishOutcomeClaim(bsc, th, 0)
      ).to.be.revertedWith("StrongN8Poll: poll is not sealed");
    });

    it("should reject outcome claim before 8 ballots", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const deadline = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const pc = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, deadline);
      await pc.waitForDeployment();

      // only submit 1 ballot
      await pc.submitBallot(proofs[0].a, proofs[0].b, proofs[0].c, proofs[0].publicSignals);

      const th = ethers.keccak256(ethers.toUtf8Bytes("test"));

      await expect(
        pc.connect(publisher).publishOutcomeClaim(ethers.ZeroHash, th, 0)
      ).to.be.revertedWith("StrongN8Poll: poll is not sealed");
    });

    it("should reject outcome claim after Abandoned", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const deadline = BigInt(latest.timestamp) + 60n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const pab = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, deadline);
      await pab.waitForDeployment();

      await ethers.provider.send("evm_increaseTime", [120]);
      await ethers.provider.send("evm_mine");
      await pab.abandon();

      const th = ethers.keccak256(ethers.toUtf8Bytes("test"));

      await expect(
        pab.connect(publisher).publishOutcomeClaim(ethers.ZeroHash, th, 0)
      ).to.be.revertedWith("StrongN8Poll: poll is not sealed");
    });
  });

  describe("Immutable BallotSetCommitment", function () {
    it("final commit should be immutable", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const dl = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const pc = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, dl);
      await pc.waitForDeployment();

      for (let i = 0; i < 8; i++) {
        const p = proofs[i];
        await pc.submitBallot(p.a, p.b, p.c, p.publicSignals);
      }

      const bsc = await pc.ballotSetCommitment();
      expect(bsc).to.not.equal(ethers.ZeroHash);

      // Trying publish outcome with different commitment
      const th = ethers.keccak256(ethers.toUtf8Bytes("test"));
      await expect(
        pc.connect(publisher).publishOutcomeClaim(ethers.ZeroHash, th, 0)
      ).to.be.reverted;

      // The commitment should be unchanged
      expect(await pc.ballotSetCommitment()).to.equal(bsc);
    });
  });

  describe("Gas Measurement", function () {
    it("MEASURED LOCAL EVM: deploy Groth16 verifier", async function () {
      const Verifier = await ethers.getContractFactory("Groth16Verifier");
      const v = await Verifier.deploy();
      const receipt = await v.deploymentTransaction().wait();
      console.log(`  verifier deploy gasUsed: ${receipt.gasUsed}`);
    });

    it("MEASURED LOCAL EVM: deploy StrongN8Poll", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const dl = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const p = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, dl);
      const receipt = await p.deploymentTransaction().wait();
      console.log(`  contract deploy gasUsed: ${receipt.gasUsed}`);
    });

    it("MEASURED LOCAL EVM: submit ballot 1", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const dl = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const pg = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, dl);
      await pg.waitForDeployment();

      const p = proofs[0];
      const tx = await pg.submitBallot(p.a, p.b, p.c, p.publicSignals);
      const receipt = await tx.wait();
      console.log(`  ballot 1 gasUsed: ${receipt.gasUsed}`);
    });

    it("MEASURED LOCAL EVM: submit ballot 8 / sealing", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const dl = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const pg = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, dl);
      await pg.waitForDeployment();

      for (let i = 0; i < 7; i++) {
        const p = proofs[i];
        await pg.submitBallot(p.a, p.b, p.c, p.publicSignals);
      }

      const p8 = proofs[7];
      const tx = await pg.submitBallot(p8.a, p8.b, p8.c, p8.publicSignals);
      const receipt = await tx.wait();
      console.log(`  ballot 8 (sealing) gasUsed: ${receipt.gasUsed}`);
    });

    it("MEASURED LOCAL EVM: publishOutcomeClaim", async function () {
      const verifierAddr = await verifier.getAddress();
      const latest = await ethers.provider.getBlock("latest");
      const dl = BigInt(latest.timestamp) + 86400n;

      const Poll = await ethers.getContractFactory("StrongN8Poll");
      const pg = await deployPoll(Poll, verifierAddr, REGISTRY_ROOT, POLL_ID, TAU, publisher.address, dl);
      await pg.waitForDeployment();

      for (let i = 0; i < 8; i++) {
        const p = proofs[i];
        await pg.submitBallot(p.a, p.b, p.c, p.publicSignals);
      }

      const bsc = await pg.ballotSetCommitment();
      const th = ethers.keccak256(ethers.toUtf8Bytes("test-transcript"));

      const tx = await pg.connect(publisher).publishOutcomeClaim(bsc, th, 1);
      const receipt = await tx.wait();
      console.log(`  outcome claim gasUsed: ${receipt.gasUsed}`);
    });
  });

  describe("SignalIndex Library", function () {
    it("should have correct ciphertext coordinate offsets", function () {
      for (let k = 0; k < 8; k++) {
        expect(1 + 4 * k).to.equal(1 + 4 * k);
        expect(2 + 4 * k).to.equal(2 + 4 * k);
        expect(3 + 4 * k).to.equal(3 + 4 * k);
        expect(4 + 4 * k).to.equal(4 + 4 * k);
      }
    });

    it("should have correct frozen indices", function () {
      expect(33).to.equal(33); // IDX_REGISTRY_ROOT
      expect(34).to.equal(34); // IDX_POLL_ID
      expect(35).to.equal(35); // IDX_PK_X
      expect(36).to.equal(36); // IDX_PK_Y
    });
  });
});
