const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");

const bundlePath = process.env.CGY_RUST_BALLOT_BUNDLE;
const suite = bundlePath ? describe : describe.skip;

suite("Rust-generated ballot proof compatibility", function () {
  it("accepts every ballot using the unchanged Solidity Groth16 verifier", async function () {
    const bundle = JSON.parse(fs.readFileSync(bundlePath, "utf8"));
    expect(bundle.ballots.length).to.be.greaterThan(0);

    const Verifier = await ethers.getContractFactory("Groth16Verifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    for (const [index, ballot] of bundle.ballots.entries()) {
      const proof = ballot.proof;
      const a = [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])];
      // SnarkJS serializes Fq2 limbs in the opposite order expected by Solidity.
      const b = [
        [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
        [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
      ];
      const c = [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])];
      const publicSignals = ballot.publicSignals.map(BigInt);
      expect(publicSignals).to.have.length(37);
      expect(
        await verifier.verifyProof(a, b, c, publicSignals),
        `ballot ${index}`,
      ).to.equal(true);
    }
  });
});
