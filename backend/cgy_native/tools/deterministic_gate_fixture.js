"use strict";

// Deterministic single-gate fixture for native and JavaScript compatibility checks. This script
// uses the JavaScript reference implementation and
// emits the same compact public gate schema as the Rust producer.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..", "..", "js_protocol", "src");
const {
  SUBGROUP_ORDER,
  BASE8,
  IDENTITY,
  PointRole,
  addPoints,
  negatePoint,
  scalarMultiply,
  pointEquals,
  encodePoint,
  decodeAffineCoordinates,
} = require(path.join(ROOT, "group"));
const {
  encryptScalar,
  addCiphertexts,
  scaleCiphertext,
  ciphertextEquals,
  encodeCiphertext,
  ciphertextHash,
} = require(path.join(ROOT, "elgamal"));
const {
  PROTOCOL_VERSION,
  deriveAuxiliaryPoint,
} = require(path.join(ROOT, "group_oracle"));
const { hashToScalar } = require(path.join(ROOT, "hash_to_scalar"));
const {
  computeSetupHash,
  evaluateCommitments,
  verifyPublicSetup,
  lagrangeCoefficientAtZero,
} = require(path.join(ROOT, "threshold_setup"));
const {
  maskingChallenge,
  encZero,
  signedRerandomize,
  verifyMaskingTransition,
  zeroEncryptionChallenge,
  verifyZeroEncryption,
} = require(path.join(ROOT, "proofs"));
const {
  authorizationId,
  receive,
  markProofValidated,
  markBroadcastAgreed,
  markRerandomizationValidated,
  authorizeForDecryption,
  emitPartialShare,
} = require(path.join(ROOT, "validation_state"));
const {
  challengeScalar,
  verifyPartialDecryptionShare,
  combineVerifiedPartialDecryptions,
} = require(path.join(ROOT, "threshold_decryption"));

const MASK_DOMAIN = "-CGY-TOOLBOX-FULL-V1/CGY/ALGORITHM-9/POK-CSZ/V1";
const ZERO_DOMAIN = "-CGY-TOOLBOX-FULL-V1/CGY/ALGORITHM-63/ZERO-ENCRYPTION/V1";
const SETUP_KIND = "TEST_ONLY_FRESH_CSPRNG_DEALER";

function scalarMod(value) {
  const result = value % SUBGROUP_ORDER;
  return result >= 0n ? result : result + SUBGROUP_ORDER;
}

function pointJson(value) {
  return { x: value.x.toString(10), y: value.y.toString(10) };
}

function pointFromJson(value, role = PointRole.PROOF_ELEMENT) {
  return decodeAffineCoordinates(value, role);
}

function cipherJson(value) {
  return { R: pointJson(value.R), S: pointJson(value.S) };
}

function cipherFromJson(value) {
  return { R: pointFromJson(value.R), S: pointFromJson(value.S) };
}

function sessionJson(value) {
  return {
    protocolVersion: value.protocolVersion,
    setupHash: value.setupHash,
    executionId: value.executionId,
    gateId: value.gateId.toString(10),
    invocation: value.invocation.toString(10),
  };
}

function sessionFromJson(value) {
  return {
    protocolVersion: value.protocolVersion,
    setupHash: value.setupHash,
    executionId: value.executionId,
    gateId: BigInt(value.gateId),
    invocation: BigInt(value.invocation),
  };
}

function setupFixture() {
  const coefficients = [
    123456789012345678901234567890123456789n,
    987654321098765432109876543210987654321n,
    222222222222222222222222222222222222222n,
    333333333333333333333333333333333333333n,
    444444444444444444444444444444444444444n,
  ];
  const coefficientCommitments = coefficients.map((coefficient) => scalarMultiply(BASE8, coefficient));
  const verificationKeys = [];
  const secretShares = [];
  for (let trusteeId = 1; trusteeId <= 5; trusteeId += 1) {
    const x = BigInt(trusteeId);
    let value = 0n;
    let power = 1n;
    for (const coefficient of coefficients) {
      value = scalarMod(value + coefficient * power);
      power *= x;
    }
    secretShares.push(value);
    verificationKeys.push({ trusteeId, point: scalarMultiply(BASE8, value) });
  }
  const withoutHash = {
    protocolVersion: PROTOCOL_VERSION,
    kind: SETUP_KIND,
    trustees: 5,
    degree: 4,
    threshold: 5,
    generator: BASE8,
    committeeKey: coefficientCommitments[0],
    coefficientCommitments,
    verificationKeys,
  };
  const publicSetup = { ...withoutHash, setupHash: computeSetupHash(withoutHash) };
  verifyPublicSetup(publicSetup);
  return { publicSetup, secretShares };
}

function session(setup, invocation) {
  return {
    protocolVersion: PROTOCOL_VERSION,
    setupHash: setup.publicSetup.setupHash,
    executionId: "11".repeat(32),
    gateId: 1n,
    invocation: BigInt(invocation),
  };
}

function branchDelta(next, previous, branch) {
  const signedPrevious = branch === 1 ? previous : scaleCiphertext(previous, SUBGROUP_ORDER - 1n);
  return addCiphertexts(next, scaleCiphertext(signedPrevious, SUBGROUP_ORDER - 1n));
}

function simulateCiphertextCommitment(key, response, statementDelta, branchChallenge) {
  return addCiphertexts(encZero(key, response), scaleCiphertext(statementDelta, scalarMod(-branchChallenge)));
}

function simulatePointCommitment(base, response, statement, branchChallenge) {
  return addPoints(scalarMultiply(base, response), negatePoint(scalarMultiply(statement, branchChallenge)));
}

function makeMask(setup, source, htilde, previousX, previousY, sign, rX, rY, alpha, beta, fakeChallenge, fakeResponseX, fakeResponseY) {
  const nextX = signedRerandomize(previousX, sign, setup.publicSetup.committeeKey, rX);
  const nextY = signedRerandomize(previousY, sign, setup.publicSetup.committeeKey, rY);
  const e = scalarMultiply(htilde, rX);
  const real = {
    X: encZero(setup.publicSetup.committeeKey, alpha),
    Y: encZero(setup.publicSetup.committeeKey, beta),
    E: scalarMultiply(htilde, alpha),
  };
  const fakeBranch = -sign;
  const fake = {
    X: simulateCiphertextCommitment(setup.publicSetup.committeeKey, fakeResponseX, branchDelta(nextX, previousX, fakeBranch), fakeChallenge),
    Y: simulateCiphertextCommitment(setup.publicSetup.committeeKey, fakeResponseY, branchDelta(nextY, previousY, fakeBranch), fakeChallenge),
    E: simulatePointCommitment(htilde, fakeResponseX, e, fakeChallenge),
  };
  const proof = sign === 1
    ? {
      cPlusX: real.X, cPlusY: real.Y, cMinusX: fake.X, cMinusY: fake.Y,
      cPlusE: real.E, cMinusE: fake.E,
      dPlus: 0n, dMinus: fakeChallenge, aPlusX: 0n, aPlusY: 0n,
      aMinusX: fakeResponseX, aMinusY: fakeResponseY,
    }
    : {
      cPlusX: fake.X, cPlusY: fake.Y, cMinusX: real.X, cMinusY: real.Y,
      cPlusE: fake.E, cMinusE: real.E,
      dPlus: fakeChallenge, dMinus: 0n, aPlusX: fakeResponseX, aPlusY: fakeResponseY,
      aMinusX: 0n, aMinusY: 0n,
    };
  const totalChallenge = maskingChallenge(setup.publicSetup, source, previousX, previousY, nextX, nextY, proof);
  const realChallenge = scalarMod(totalChallenge - fakeChallenge);
  const realResponseX = scalarMod(alpha + rX * realChallenge);
  const realResponseY = scalarMod(beta + rY * realChallenge);
  if (sign === 1) {
    proof.dPlus = realChallenge;
    proof.aPlusX = realResponseX;
    proof.aPlusY = realResponseY;
  } else {
    proof.dMinus = realChallenge;
    proof.aMinusX = realResponseX;
    proof.aMinusY = realResponseY;
  }
  return { previousX, previousY, nextX, nextY, e, proof };
}

function maskProofJson(proof) {
  return {
    cPlusX: cipherJson(proof.cPlusX), cPlusY: cipherJson(proof.cPlusY),
    cMinusX: cipherJson(proof.cMinusX), cMinusY: cipherJson(proof.cMinusY),
    cPlusE: pointJson(proof.cPlusE), cMinusE: pointJson(proof.cMinusE),
    dPlus: proof.dPlus.toString(10), dMinus: proof.dMinus.toString(10),
    aPlusX: proof.aPlusX.toString(10), aPlusY: proof.aPlusY.toString(10),
    aMinusX: proof.aMinusX.toString(10), aMinusY: proof.aMinusY.toString(10),
  };
}

function makeZero(setup, source, input, randomness, alpha) {
  const contribution = encZero(setup.publicSetup.committeeKey, randomness);
  const commitment = encZero(setup.publicSetup.committeeKey, alpha);
  const challenge = zeroEncryptionChallenge(setup.publicSetup, source, input, contribution, commitment);
  return { contribution, proof: { commitment, response: scalarMod(alpha + randomness * challenge) } };
}

function zeroJson(value) {
  return {
    contribution: cipherJson(value.contribution),
    proof: { commitment: cipherJson(value.proof.commitment), response: value.proof.response.toString(10) },
  };
}

function makePartial(setup, source, ciphertext, trusteeId, alpha) {
  const secret = setup.secretShares[trusteeId - 1];
  const verification = setup.publicSetup.verificationKeys[trusteeId - 1].point;
  const w = scalarMultiply(ciphertext.R, secret);
  const cG = scalarMultiply(BASE8, alpha);
  const cU = scalarMultiply(ciphertext.R, alpha);
  const context = {
    protocolVersion: PROTOCOL_VERSION,
    setupHash: setup.publicSetup.setupHash,
    executionId: source.executionId,
    gateId: source.gateId,
    invocation: source.invocation,
    phase: "GATE_SELECTOR_DECRYPTION",
    purpose: "CGY_GATE_SELECTOR",
  };
  const authorization = {
    context,
    authorizationId: authorizationId(context, ciphertext),
    ciphertext,
    ciphertextHash: ciphertextHash(ciphertext),
  };
  const d = challengeScalar(authorization, trusteeId, verification, w, cG, cU);
  return { trusteeId, w, cG, cU, a: scalarMod(alpha + d * secret) };
}

function buildGate() {
  const setup = setupFixture();
  const maskingSession = session(setup, 0);
  const auxiliary = deriveAuxiliaryPoint(maskingSession, setup.publicSetup.committeeKey);
  const inputX = encryptScalar(setup.publicSetup.committeeKey, 1n, 11n);
  const inputY = encryptScalar(setup.publicSetup.committeeKey, 0n, 13n);
  let previousX = inputX;
  let previousY = addCiphertexts({ R: IDENTITY, S: negatePoint(BASE8) }, scaleCiphertext(inputY, 2n));
  const masking = [];
  for (let i = 0; i < 5; i += 1) {
    const record = makeMask(
      setup,
      maskingSession,
      auxiliary.point,
      previousX,
      previousY,
      i % 2 === 0 ? 1 : -1,
      101n + BigInt(i),
      201n + BigInt(i),
      301n + BigInt(i),
      401n + BigInt(i),
      501n + BigInt(i),
      601n + BigInt(i),
      701n + BigInt(i),
    );
    verifyMaskingTransition({ setup: setup.publicSetup, sourceSession: maskingSession, htilde: auxiliary.point, previousX, previousY, nextX: record.nextX, nextY: record.nextY, e: record.e, proof: record.proof });
    previousX = record.nextX;
    previousY = record.nextY;
    masking.push(record);
  }
  const xSource = session(setup, 1);
  const ySource = session(setup, 2);
  const xInput = previousX;
  const yInput = previousY;
  let xOutput = xInput;
  let yOutput = yInput;
  const xRecords = [];
  const yRecords = [];
  for (let i = 0; i < 5; i += 1) {
    const x = makeZero(setup, xSource, xInput, 801n + BigInt(i), 901n + BigInt(i));
    const y = makeZero(setup, ySource, yInput, 1001n + BigInt(i), 1101n + BigInt(i));
    verifyZeroEncryption({ setup: setup.publicSetup, sourceSession: xSource, input: xInput, contribution: x.contribution, proof: x.proof });
    verifyZeroEncryption({ setup: setup.publicSetup, sourceSession: ySource, input: yInput, contribution: y.contribution, proof: y.proof });
    xOutput = addCiphertexts(xOutput, x.contribution);
    yOutput = addCiphertexts(yOutput, y.contribution);
    xRecords.push(x);
    yRecords.push(y);
  }
  const td = session(setup, 3);
  const shares = [];
  const authorization = authorizationFor(setup.publicSetup, td, yOutput);
  for (let i = 0; i < 5; i += 1) {
    const share = makePartial(setup, td, yOutput, i + 1, 1201n + BigInt(i));
    const typed = emitPartialShare(authorization, {
      trusteeId: share.trusteeId,
      setupHash: setup.publicSetup.setupHash,
      authorizationId: authorization.authorizationId,
      ciphertextHash: authorization.ciphertextHash,
      w: share.w,
      cG: share.cG,
      cU: share.cU,
      a: share.a,
    });
    verifyPartialDecryptionShare(setup.publicSetup, authorization, typed);
    shares.push(share);
  }
  const verified = shares.map((share) => verifyPartialDecryptionShare(setup.publicSetup, authorization, emitPartialShare(authorization, {
    trusteeId: share.trusteeId,
    setupHash: setup.publicSetup.setupHash,
    authorizationId: authorization.authorizationId,
    ciphertextHash: authorization.ciphertextHash,
    w: share.w,
    cG: share.cG,
    cU: share.cU,
    a: share.a,
  })));
  const opened = combineVerifiedPartialDecryptions(setup.publicSetup, authorization, verified);
  let factor = IDENTITY;
  for (const share of shares) {
    factor = addPoints(factor, scalarMultiply(share.w, lagrangeCoefficientAtZero([1, 2, 3, 4, 5], share.trusteeId)));
  }
  const openedExpected = addPoints(yOutput.S, negatePoint(factor));
  if (!pointEquals(opened, openedExpected)) throw new Error("JS threshold opening mismatch");
  const negativeBase = negatePoint(BASE8);
  const openedSign = pointEquals(opened, BASE8) ? 1 : (pointEquals(opened, negativeBase) ? -1 : (() => { throw new Error("selector opening is not +/-Base8"); })());
  const signedX = openedSign === 1 ? xOutput : scaleCiphertext(xOutput, SUBGROUP_ORDER - 1n);
  // `scaleCiphertext` expects the subgroup scalar 2^{-1}; the frozen
  // implementation defines this as (q+1)/2.
  const outputCorrect = scaleCiphertext(addCiphertexts(inputX, signedX), (SUBGROUP_ORDER + 1n) / 2n);

  const gate = {
    schema: "-CGY-NATIVE/SINGLE-GATE/V1",
    setup: {
      protocolVersion: setup.publicSetup.protocolVersion,
      kind: setup.publicSetup.kind,
      trustees: setup.publicSetup.trustees,
      degree: setup.publicSetup.degree,
      threshold: setup.publicSetup.threshold,
      generator: pointJson(setup.publicSetup.generator),
      committeeKey: pointJson(setup.publicSetup.committeeKey),
      coefficientCommitments: setup.publicSetup.coefficientCommitments.map(pointJson),
      verificationKeys: setup.publicSetup.verificationKeys.map((entry) => ({ trusteeId: entry.trusteeId, point: pointJson(entry.point) })),
      setupHash: setup.publicSetup.setupHash,
    },
    maskingSession: sessionJson(maskingSession),
    htilde: pointJson(auxiliary.point),
    htildeCounter: auxiliary.counter,
    inputX: cipherJson(inputX),
    inputY: cipherJson(inputY),
    masking: masking.map((record) => ({ previousX: cipherJson(record.previousX), previousY: cipherJson(record.previousY), nextX: cipherJson(record.nextX), nextY: cipherJson(record.nextY), e: pointJson(record.e), proof: maskProofJson(record.proof) })),
    xRerandomization: { sourceSession: sessionJson(xSource), input: cipherJson(xInput), output: cipherJson(xOutput), records: xRecords.map(zeroJson) },
    yRerandomization: { sourceSession: sessionJson(ySource), input: cipherJson(yInput), output: cipherJson(yOutput), records: yRecords.map(zeroJson) },
    partialSession: sessionJson(td),
    partialShares: shares.map((share) => ({ trusteeId: share.trusteeId, w: pointJson(share.w), cG: pointJson(share.cG), cU: pointJson(share.cU), a: share.a.toString(10) })),
    openedSign,
    output: cipherJson(outputCorrect),
  };
  return gate;
}

function authorizationFor(setup, source, ciphertext) {
  const context = {
    protocolVersion: PROTOCOL_VERSION,
    setupHash: setup.setupHash,
    executionId: source.executionId,
    gateId: BigInt(source.gateId),
    invocation: BigInt(source.invocation),
    phase: "GATE_SELECTOR_DECRYPTION",
    purpose: "CGY_GATE_SELECTOR",
  };
  const received = receive(ciphertext, context, { source: "CGY_NATIVE", ciphertextHash: ciphertextHash(ciphertext) });
  const proof = markProofValidated(received, { valid: true, verifier: "NATIVE_CHECKPOINT" });
  const broadcast = markBroadcastAgreed(proof, { agreed: true, transcriptHash: "00".repeat(32) });
  const rerand = markRerandomizationValidated(broadcast, ciphertext, { valid: true, verifier: "NATIVE_CHECKPOINT" });
  return authorizeForDecryption(rerand, { authorized: true, policy: "CGY_GATE_SELECTOR_ONLY" });
}

function verifyNativeGate(gate) {
  if (gate.schema !== "-CGY-NATIVE/SINGLE-GATE/V1") throw new Error("schema");
  const setup = {
    ...gate.setup,
    generator: pointFromJson(gate.setup.generator, PointRole.GENERATOR),
    committeeKey: pointFromJson(gate.setup.committeeKey, PointRole.COMMITTEE_KEY),
    coefficientCommitments: gate.setup.coefficientCommitments.map((p, i) => pointFromJson(p, i === 0 ? PointRole.COMMITTEE_KEY : PointRole.PROOF_ELEMENT)),
    verificationKeys: gate.setup.verificationKeys.map((entry) => ({ trusteeId: entry.trusteeId, point: pointFromJson(entry.point, PointRole.TRUSTEE_VERIFICATION_KEY) })),
  };
  verifyPublicSetup(setup);
  const maskingSession = sessionFromJson(gate.maskingSession);
  const aux = deriveAuxiliaryPoint(maskingSession, setup.committeeKey);
  if (aux.counter !== gate.htildeCounter || !pointEquals(aux.point, pointFromJson(gate.htilde, PointRole.AUXILIARY))) throw new Error("auxiliary");
  const inputX = cipherFromJson(gate.inputX);
  const inputY = cipherFromJson(gate.inputY);
  let previousX = inputX;
  let previousY = addCiphertexts({ R: IDENTITY, S: negatePoint(BASE8) }, scaleCiphertext(inputY, 2n));
  for (const record of gate.masking) {
    const nextX = cipherFromJson(record.nextX);
    const nextY = cipherFromJson(record.nextY);
    const proof = {
      cPlusX: cipherFromJson(record.proof.cPlusX), cPlusY: cipherFromJson(record.proof.cPlusY), cMinusX: cipherFromJson(record.proof.cMinusX), cMinusY: cipherFromJson(record.proof.cMinusY),
      cPlusE: pointFromJson(record.proof.cPlusE), cMinusE: pointFromJson(record.proof.cMinusE),
      dPlus: BigInt(record.proof.dPlus), dMinus: BigInt(record.proof.dMinus), aPlusX: BigInt(record.proof.aPlusX), aPlusY: BigInt(record.proof.aPlusY), aMinusX: BigInt(record.proof.aMinusX), aMinusY: BigInt(record.proof.aMinusY),
    };
    verifyMaskingTransition({ setup, sourceSession: maskingSession, htilde: aux.point, previousX, previousY, nextX, nextY, e: pointFromJson(record.e), proof });
    previousX = nextX;
    previousY = nextY;
  }
  const xInput = cipherFromJson(gate.xRerandomization.input);
  const yInput = cipherFromJson(gate.yRerandomization.input);
  if (!ciphertextEquals(previousX, xInput) || !ciphertextEquals(previousY, yInput)) throw new Error("mask output");
  const verifyZeroVector = (rerandomization, source) => {
    let current = cipherFromJson(rerandomization.input);
    const fixedInput = current;
    for (const entry of rerandomization.records) {
      const contribution = cipherFromJson(entry.contribution);
      const proof = { commitment: cipherFromJson(entry.proof.commitment), response: BigInt(entry.proof.response) };
      verifyZeroEncryption({ setup, sourceSession: source, input: fixedInput, contribution, proof });
      current = addCiphertexts(current, contribution);
    }
    if (!ciphertextEquals(current, cipherFromJson(rerandomization.output))) throw new Error("rerandomization output");
  };
  const xSource = sessionFromJson(gate.xRerandomization.sourceSession);
  const ySource = sessionFromJson(gate.yRerandomization.sourceSession);
  verifyZeroVector(gate.xRerandomization, xSource);
  verifyZeroVector(gate.yRerandomization, ySource);
  const yOutput = cipherFromJson(gate.yRerandomization.output);
  const authorization = authorizationFor(setup, sessionFromJson(gate.partialSession), yOutput);
  const typed = gate.partialShares.map((share) => emitPartialShare(authorization, {
    trusteeId: share.trusteeId,
    setupHash: setup.setupHash,
    authorizationId: authorization.authorizationId,
    ciphertextHash: authorization.ciphertextHash,
    w: pointFromJson(share.w, PointRole.PARTIAL_DECRYPTION),
    cG: pointFromJson(share.cG),
    cU: pointFromJson(share.cU),
    a: BigInt(share.a),
  }));
  const verified = typed.map((share) => verifyPartialDecryptionShare(setup, authorization, share));
  const opened = combineVerifiedPartialDecryptions(setup, authorization, verified.slice(0, setup.threshold));
  const expected = gate.openedSign === 1 ? BASE8 : negatePoint(BASE8);
  if (!pointEquals(opened, expected)) throw new Error("opened sign");
  const signedX = gate.openedSign === 1 ? cipherFromJson(gate.xRerandomization.output) : scaleCiphertext(cipherFromJson(gate.xRerandomization.output), SUBGROUP_ORDER - 1n);
  const output = scaleCiphertext(addCiphertexts(inputX, signedX), (SUBGROUP_ORDER + 1n) / 2n);
  if (!ciphertextEquals(output, cipherFromJson(gate.output))) throw new Error("output");
  return true;
}

function main() {
  const mode = process.argv[2] || "generate";
  if (mode === "verify") {
    const value = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
    verifyNativeGate(value.gate || value);
    process.stdout.write("JS_VERIFIES_RUST_GATE=PASS\n");
    return;
  }
  const started = process.hrtime.bigint();
  const gate = buildGate();
  const generationMs = Number(process.hrtime.bigint() - started) / 1e6;
  const verifyStarted = process.hrtime.bigint();
  verifyNativeGate(gate);
  const verificationMs = Number(process.hrtime.bigint() - verifyStarted) / 1e6;
  const result = { gate, secretShares: setupFixture().secretShares.map((value) => value.toString(10)), generationMs, verificationMs };
  if (process.argv[3]) fs.writeFileSync(process.argv[3], `${JSON.stringify(result)}\n`);
  else process.stdout.write(`${JSON.stringify(result)}\n`);
}

main();
