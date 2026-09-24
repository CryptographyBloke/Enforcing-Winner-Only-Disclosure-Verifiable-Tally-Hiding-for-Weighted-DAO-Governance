pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "bit_elgamal_lib.circom";

template StrongBitDualMux() {
    signal input in[2];
    signal input s;
    signal output out[2];

    s * (1 - s) === 0;
    out[0] <== (in[1] - in[0]) * s + in[0];
    out[1] <== (in[0] - in[1]) * s + in[1];
}

template StrongBitMerkleTreeChecker(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    component hashers[levels];
    component muxes[levels];
    signal levelHash[levels + 1];
    levelHash[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        muxes[i] = StrongBitDualMux();
        muxes[i].in[0] <== levelHash[i];
        muxes[i].in[1] <== pathElements[i];
        muxes[i].s <== pathIndices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== muxes[i].out[0];
        hashers[i].inputs[1] <== muxes[i].out[1];
        levelHash[i + 1] <== hashers[i].out;
    }

    root === levelHash[levels];
}

template VoteBitFull8(levels) {
    // Private witnesses.
    signal input identitySecret;
    signal input weight;
    signal input vote;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal input r[8];

    // Runtime public inputs.
    signal input root;
    signal input pollId;
    signal input PK[2];

    // Always-public outputs.
    signal output nullifierHash;
    signal output CT[8][4];

    component idCommitment = Poseidon(1);
    idCommitment.inputs[0] <== identitySecret;

    // The prototype registry stores one integer weight in [0, 255].
    component weightBits = Num2Bits(8);
    weightBits.in <== weight;

    component leafHash = Poseidon(2);
    leafHash.inputs[0] <== idCommitment.out;
    leafHash.inputs[1] <== weight;

    component tree = StrongBitMerkleTreeChecker(levels);
    tree.leaf <== leafHash.out;
    tree.root <== root;
    for (var i = 0; i < levels; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }

    vote * (vote - 1) === 0;

    // Explicitly prove x = vote*weight and its LSB-first bit decomposition.
    signal contribution;
    signal contributionBit[8];
    signal contributionAcc[9];
    contribution <== vote * weight;
    contributionAcc[0] <== 0;
    for (var k = 0; k < 8; k++) {
        contributionBit[k] <== vote * weightBits.out[k];
        contributionAcc[k + 1] <== contributionAcc[k] + (1 << k) * contributionBit[k];
    }
    contribution === contributionAcc[8];

    component enc[8];
    for (var j = 0; j < 8; j++) {
        enc[j] = StrongBitElGamal();
        enc[j].beta <== contributionBit[j];
        enc[j].r <== r[j];
        enc[j].PK[0] <== PK[0];
        enc[j].PK[1] <== PK[1];

        CT[j][0] <== enc[j].R[0];
        CT[j][1] <== enc[j].R[1];
        CT[j][2] <== enc[j].S[0];
        CT[j][3] <== enc[j].S[1];
    }

    component nullifier = Poseidon(2);
    nullifier.inputs[0] <== identitySecret;
    nullifier.inputs[1] <== pollId;
    nullifierHash <== nullifier.out;
}

component main {public [root, pollId, PK]} = VoteBitFull8(10);
