pragma circom 2.1.6;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/escalarmulany.circom";
include "circomlib/circuits/escalarmulfix.circom";
include "circomlib/circuits/babyjub.circom";

// Audit-only, bit-specialized exponential ElGamal over BabyJub Base8.
// It intentionally preserves VoteFull's 253-bit handling of r.
template StrongBitElGamal() {
    signal input beta;
    signal input r;
    signal input PK[2];

    signal output R[2];
    signal output S[2];

    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    // Same scalar decomposition and fixed-base component as production VoteFull.
    component rBits = Num2Bits(253);
    rBits.in <== r;

    component rG = EscalarMulFix(253, BASE8);
    for (var i = 0; i < 253; i++) {
        rG.e[i] <== rBits.out[i];
    }
    R[0] <== rG.out[0];
    R[1] <== rG.out[1];

    // Same runtime-PK variable-base component as production VoteFull.
    component rPK = EscalarMulAny(253);
    for (var j = 0; j < 253; j++) {
        rPK.e[j] <== rBits.out[j];
    }
    rPK.p[0] <== PK[0];
    rPK.p[1] <== PK[1];

    // Sound bit-specific selection: beta=0 selects O=(0,1), beta=1 selects Base8.
    // No scalar-multiplication gadget is instantiated for the message point.
    beta * (beta - 1) === 0;
    signal messagePoint[2];
    messagePoint[0] <== beta * BASE8[0];
    messagePoint[1] <== 1 + beta * (BASE8[1] - 1);

    component add = BabyAdd();
    add.x1 <== rPK.out[0];
    add.y1 <== rPK.out[1];
    add.x2 <== messagePoint[0];
    add.y2 <== messagePoint[1];
    S[0] <== add.xout;
    S[1] <== add.yout;
}

// Audit-only variant for measuring a nonzero-r rule. The inverse is private.
// r*rInv=1 adds one nonlinear constraint and rejects r=0 without changing
// the primary prototype's scalar-domain behavior.
template StrongBitElGamalNonZero() {
    signal input beta;
    signal input r;
    signal input rInv;
    signal input PK[2];
    signal output R[2];
    signal output S[2];

    component enc = StrongBitElGamal();
    enc.beta <== beta;
    enc.r <== r;
    enc.PK[0] <== PK[0];
    enc.PK[1] <== PK[1];
    r * rInv === 1;

    R[0] <== enc.R[0];
    R[1] <== enc.R[1];
    S[0] <== enc.S[0];
    S[1] <== enc.S[1];
}
