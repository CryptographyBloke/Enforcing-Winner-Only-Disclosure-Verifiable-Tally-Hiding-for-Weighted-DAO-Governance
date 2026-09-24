//! One deterministic source-conforming CGY conditional gate.
//!
//! This module is deliberately self-contained for the native checkpoint. It
//! implements the frozen masking, Algorithm 63 zero-encryption
//! rerandomization, and Algorithm 65 verified threshold-share equations over
//! the exact external BabyJub profile exposed by `ValidatedPoint`.

use crate::{ValidatedPoint, POINT_BYTES};
use ark_ff::{BigInteger, Field, PrimeField};
use num_bigint::BigUint;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sha3::{digest::{ExtendableOutput, Update, XofReader}, Shake256};
use rand::{rngs::OsRng, RngCore};
use rayon::prelude::*;
use std::{collections::HashSet, fs::File, io::{BufRead, BufReader}, str::FromStr, time::Instant};
use taceo_ark_babyjubjub::{Fq, Fr};

pub const PROTOCOL_VERSION: &str = "-CGY-TOOLBOX-FULL-V1";
const SOURCE_SESSION_DOMAIN: &str = "-CGY-TOOLBOX-FULL-V1/SOURCE-SESSION/V1";
const POINT_ENCODING_DOMAIN: &str = "-CGY-TOOLBOX-FULL-V1/BABYJUB-AFFINE-LE64/V1";
const AUX_DOMAIN: &str = "-CGY-TOOLBOX-FULL-V1/H_G/AUXILIARY/V1";
const MASK_DOMAIN: &str = "-CGY-TOOLBOX-FULL-V1/CGY/ALGORITHM-9/POK-CSZ/V1";
const ZERO_DOMAIN: &str = "-CGY-TOOLBOX-FULL-V1/CGY/ALGORITHM-63/ZERO-ENCRYPTION/V1";
const PARTIAL_DOMAIN: &str = "-CGY-TOOLBOX-FULL-V1/CGY/ALGORITHM-65/PARTIAL-DECRYPTION/V1";
const AUTH_DOMAIN: &str = "-CGY-TOOLBOX-FULL-V1/DECRYPTION-AUTHORIZATION/V1";
const SETUP_DOMAIN: &str = "-CGY-TOOLBOX-FULL-V1/THRESHOLD-SETUP/V1";

#[derive(Clone)] struct Cipher { r: ValidatedPoint, s: ValidatedPoint }
#[derive(Clone)] struct Session { setup_hash: [u8; 32], execution_id: [u8; 32], gate_id: u64, invocation: u64 }
#[derive(Clone)] struct Setup { committee: ValidatedPoint, commitments: Vec<ValidatedPoint>, shares: Vec<Fr>, verification: Vec<ValidatedPoint>, setup_hash: [u8; 32] }
#[derive(Clone)] struct MaskProof { cpx: Cipher, cpy: Cipher, cmx: Cipher, cmy: Cipher, cpe: ValidatedPoint, cme: ValidatedPoint, dp: Fr, dm: Fr, apx: Fr, apy: Fr, amx: Fr, amy: Fr }
#[derive(Clone)] struct MaskRecord { previous_x: Cipher, previous_y: Cipher, next_x: Cipher, next_y: Cipher, e: ValidatedPoint, proof: MaskProof }
#[derive(Clone)] struct ZeroProof { contribution: Cipher, commitment: Cipher, response: Fr }
#[derive(Clone)] struct Share { trustee: usize, w: ValidatedPoint, cg: ValidatedPoint, cu: ValidatedPoint, a: Fr }

fn fr(value: &str) -> Fr { Fr::from_str(value).expect("canonical scalar") }
fn fr_u64(value: u64) -> Fr { Fr::from(value) }
fn lp(value: &[u8]) -> Vec<u8> { let mut out = u32be(value.len() as u32); out.extend_from_slice(value); out }
fn u32be(value: u32) -> Vec<u8> { value.to_be_bytes().to_vec() }
fn u64be(value: u64) -> Vec<u8> { value.to_be_bytes().to_vec() }
fn point_bytes(value: &ValidatedPoint) -> [u8; POINT_BYTES] { value.encode_affine_le64() }
fn point_json(value: &ValidatedPoint) -> Value { let (x, y) = value.affine_decimal(); json!({"x": x, "y": y}) }
fn cipher_json(value: &Cipher) -> Value { json!({"R": point_json(&value.r), "S": point_json(&value.s)}) }
fn scalar_json(value: &Fr) -> Value { Value::String(value.into_bigint().to_string()) }
fn add_cipher(a: &Cipher, b: &Cipher) -> Cipher { Cipher { r: a.r.add(&b.r), s: a.s.add(&b.s) } }
fn scale_cipher(a: &Cipher, k: Fr) -> Cipher { Cipher { r: a.r.scalar_mul_fr(k), s: a.s.scalar_mul_fr(k) } }
fn neg_cipher(a: &Cipher) -> Cipher { scale_cipher(a, -Fr::from(1u64)) }
fn enc_zero(key: &ValidatedPoint, randomness: Fr) -> Cipher { Cipher { r: ValidatedPoint::base8().scalar_mul_fr(randomness), s: key.scalar_mul_fr(randomness) } }
fn encrypt(key: &ValidatedPoint, message: Fr, randomness: Fr) -> Cipher { add_cipher(&enc_zero(key, randomness), &Cipher { r: ValidatedPoint::identity(), s: ValidatedPoint::base8().scalar_mul_fr(message) }) }
fn ciphertext_bytes(value: &Cipher) -> Vec<u8> { let mut out = point_bytes(&value.r).to_vec(); out.extend_from_slice(&point_bytes(&value.s)); out }
fn sha256(value: &[u8]) -> [u8; 32] { let mut hasher = Sha256::new(); Digest::update(&mut hasher, value); hasher.finalize().into() }

fn encode_session(session: &Session) -> Vec<u8> {
    let mut out = lp(SOURCE_SESSION_DOMAIN.as_bytes());
    out.extend_from_slice(&lp(PROTOCOL_VERSION.as_bytes()));
    out.extend_from_slice(&session.setup_hash);
    out.extend_from_slice(&session.execution_id);
    out.extend_from_slice(&u64be(session.gate_id));
    out.extend_from_slice(&u64be(session.invocation));
    out
}
fn encode_context(session: &Session, phase: &str, purpose: &str) -> Vec<u8> {
    let mut out = lp(PROTOCOL_VERSION.as_bytes());
    out.extend_from_slice(&session.setup_hash);
    out.extend_from_slice(&session.execution_id);
    out.extend_from_slice(&u64be(session.gate_id));
    out.extend_from_slice(&u64be(session.invocation));
    out.extend_from_slice(&lp(phase.as_bytes()));
    out.extend_from_slice(&lp(purpose.as_bytes()));
    out
}
fn shake(input: &[u8], length: usize) -> Vec<u8> {
    let mut hasher = Shake256::default(); hasher.update(input); let mut reader = hasher.finalize_xof(); let mut out = vec![0; length]; reader.read(&mut out); out
}
fn candidate_scalar(prefix: &[u8]) -> Fr {
    let modulus = BigUint::from_bytes_le(&Fr::MODULUS.to_bytes_le());
    for counter in 0..=u32::MAX {
        let mut input = prefix.to_vec(); input.extend_from_slice(&u32be(counter));
        let bytes = shake(&input, 32);
        let candidate = BigUint::from_bytes_le(&bytes);
        if candidate < modulus { return Fr::from_le_bytes_mod_order(&bytes); }
    }
    panic!("scalar rejection sampler exhausted")
}
fn hash_scalar(domain: &str, parts: &[Vec<u8>]) -> Fr {
    let mut prefix = lp(domain.as_bytes()); prefix.extend_from_slice(&u32be(parts.len() as u32));
    for part in parts { prefix.extend_from_slice(&lp(part)); }
    candidate_scalar(&prefix)
}
fn fixed_field(bytes: &[u8]) -> Option<Fq> {
    let modulus = BigUint::from_bytes_le(&Fq::MODULUS.to_bytes_le());
    let value = BigUint::from_bytes_le(bytes);
    if value >= modulus { return None; }
    Some(Fq::from_le_bytes_mod_order(bytes))
}
fn derive_htilde(session: &Session, committee: &ValidatedPoint) -> (ValidatedPoint, u32) {
    let mut prefix = lp(AUX_DOMAIN.as_bytes()); prefix.extend_from_slice(&lp(&encode_session(session))); prefix.extend_from_slice(&lp(POINT_ENCODING_DOMAIN.as_bytes())); prefix.extend_from_slice(&point_bytes(&ValidatedPoint::base8())); prefix.extend_from_slice(&point_bytes(committee));
    for counter in 0..=u32::MAX {
        let expanded = shake(&[prefix.as_slice(), &u32be(counter)].concat(), 33);
        if let Some(y) = fixed_field(&expanded[..32]) {
            let y2 = y * y; let denominator = Fq::from(168700u64) - Fq::from(168696u64) * y2;
            if let Some(mut x) = ((Fq::from(1u64) - y2) * denominator.inverse().unwrap()).sqrt() {
                if (x.into_bigint().to_bytes_le()[0] & 1) != (expanded[32] & 1) { x = -x; }
                if let Ok(point) = ValidatedPoint::from_fq(x, y) { return (point, counter); }
            }
        }
    }
    panic!("auxiliary oracle exhausted")
}

fn setup() -> Setup {
    let coefficients = [fr("123456789012345678901234567890123456789"), fr("987654321098765432109876543210987654321"), fr("222222222222222222222222222222222222222")];
    let commitments: Vec<_> = coefficients.iter().map(|value| ValidatedPoint::base8().scalar_mul_fr(*value)).collect();
    let shares: Vec<_> = (1..=5).map(|id| coefficients.iter().enumerate().fold(Fr::from(0u64), |acc, (power, coefficient)| acc + *coefficient * fr_u64(id as u64).pow([power as u64]))).collect();
    let verification: Vec<_> = shares.iter().map(|value| ValidatedPoint::base8().scalar_mul_fr(*value)).collect();
    let mut encoded = lp(SETUP_DOMAIN.as_bytes()); encoded.extend_from_slice(&lp(PROTOCOL_VERSION.as_bytes())); encoded.extend_from_slice(&u32be(5)); encoded.extend_from_slice(&u32be(2)); encoded.extend_from_slice(&u32be(3)); encoded.extend_from_slice(&point_bytes(&ValidatedPoint::base8())); encoded.extend_from_slice(&point_bytes(&commitments[0])); encoded.extend_from_slice(&u32be(3)); for point in &commitments { encoded.extend_from_slice(&point_bytes(point)); } encoded.extend_from_slice(&u32be(5)); for (index, point) in verification.iter().enumerate() { encoded.extend_from_slice(&u32be((index + 1) as u32)); encoded.extend_from_slice(&point_bytes(point)); }
    Setup { committee: commitments[0].clone(), commitments, shares, verification, setup_hash: sha256(&encoded) }
}
fn session(setup: &Setup, invocation: u64) -> Session { Session { setup_hash: setup.setup_hash, execution_id: [0x11; 32], gate_id: 1, invocation } }

fn branch_delta(next: &Cipher, previous: &Cipher, branch: i8) -> Cipher { let signed = if branch == 1 { previous.clone() } else { neg_cipher(previous) }; add_cipher(next, &neg_cipher(&signed)) }
fn masking_challenge(setup: &Setup, source: &Session, previous_x: &Cipher, previous_y: &Cipher, next_x: &Cipher, next_y: &Cipher, proof: &MaskProof) -> Fr {
    hash_scalar(MASK_DOMAIN, &[
        encode_session(source), point_bytes(&ValidatedPoint::base8()).to_vec(), point_bytes(&setup.committee).to_vec(), ciphertext_bytes(previous_x), ciphertext_bytes(previous_y), ciphertext_bytes(next_x), ciphertext_bytes(next_y), ciphertext_bytes(&proof.cpx), ciphertext_bytes(&proof.cpy), ciphertext_bytes(&proof.cmx), ciphertext_bytes(&proof.cmy), point_bytes(&proof.cpe).to_vec(), point_bytes(&proof.cme).to_vec(),
    ])
}
fn simulate_cipher(key: &ValidatedPoint, response: Fr, delta: &Cipher, challenge: Fr) -> Cipher { add_cipher(&enc_zero(key, response), &scale_cipher(delta, -challenge)) }
fn simulate_point(base: &ValidatedPoint, response: Fr, statement: &ValidatedPoint, challenge: Fr) -> ValidatedPoint { base.scalar_mul_fr(response).add(&statement.scalar_mul_fr(-challenge)) }
fn verify_mask(setup: &Setup, source: &Session, htilde: &ValidatedPoint, record: &MaskRecord) {
    let total = masking_challenge(setup, source, &record.previous_x, &record.previous_y, &record.next_x, &record.next_y, &record.proof);
    assert_eq!(record.proof.dp + record.proof.dm, total);
    for (branch, challenge, rx, ry, cx, cy, ce) in [(1, record.proof.dp, record.proof.apx, record.proof.apy, &record.proof.cpx, &record.proof.cpy, &record.proof.cpe), (-1, record.proof.dm, record.proof.amx, record.proof.amy, &record.proof.cmx, &record.proof.cmy, &record.proof.cme)] {
        let expected_x = simulate_cipher(&setup.committee, rx, &branch_delta(&record.next_x, &record.previous_x, branch), challenge);
        let expected_y = simulate_cipher(&setup.committee, ry, &branch_delta(&record.next_y, &record.previous_y, branch), challenge);
        assert_eq!(expected_x.r.affine_decimal(), cx.r.affine_decimal());
        assert_eq!(expected_x.s.affine_decimal(), cx.s.affine_decimal());
        assert_eq!(expected_y.r.affine_decimal(), cy.r.affine_decimal());
        assert_eq!(expected_y.s.affine_decimal(), cy.s.affine_decimal());
        assert_eq!(simulate_point(htilde, rx, &record.e, challenge).affine_decimal(), ce.affine_decimal());
    }
}

fn zero_challenge(setup: &Setup, source: &Session, input: &Cipher, contribution: &Cipher, commitment: &Cipher) -> Fr { hash_scalar(ZERO_DOMAIN, &[encode_session(source), point_bytes(&ValidatedPoint::base8()).to_vec(), point_bytes(&setup.committee).to_vec(), ciphertext_bytes(input), ciphertext_bytes(contribution), ciphertext_bytes(commitment)]) }
fn verify_zero(setup: &Setup, source: &Session, input: &Cipher, proof: &ZeroProof) { let challenge = zero_challenge(setup, source, input, &proof.contribution, &proof.commitment); assert_eq!(simulate_cipher(&setup.committee, proof.response, &proof.contribution, challenge).r.affine_decimal(), proof.commitment.r.affine_decimal()); assert_eq!(simulate_cipher(&setup.committee, proof.response, &proof.contribution, challenge).s.affine_decimal(), proof.commitment.s.affine_decimal()); }

fn lagrange(ids: &[usize], target: usize) -> Fr { let mut numerator = Fr::from(1u64); let mut denominator = Fr::from(1u64); for other in ids { if *other != target { numerator *= -fr_u64(*other as u64); denominator *= fr_u64(target as u64) - fr_u64(*other as u64); } } numerator * denominator.inverse().unwrap() }
fn authorization_id(source: &Session, ciphertext: &Cipher, phase: &str, purpose: &str) -> [u8; 32] { let mut bytes = lp(AUTH_DOMAIN.as_bytes()); bytes.extend_from_slice(&encode_context(source, phase, purpose)); bytes.extend_from_slice(&ciphertext_bytes(ciphertext)); sha256(&bytes) }
fn partial_preimage(source: &Session, authorization: &[u8; 32], ciphertext: &Cipher, trustee: usize, verification: &ValidatedPoint, w: &ValidatedPoint, cg: &ValidatedPoint, cu: &ValidatedPoint) -> Vec<u8> { let mut preimage = lp(PARTIAL_DOMAIN.as_bytes()); preimage.extend_from_slice(&encode_context(source, "GATE_SELECTOR_DECRYPTION", "CGY_GATE_SELECTOR")); preimage.extend_from_slice(authorization); preimage.extend_from_slice(&point_bytes(&ValidatedPoint::base8())); preimage.extend_from_slice(&point_bytes(verification)); preimage.extend_from_slice(&ciphertext_bytes(ciphertext)); preimage.extend_from_slice(&u32be(trustee as u32)); preimage.extend_from_slice(&point_bytes(w)); preimage.extend_from_slice(&point_bytes(cg)); preimage.extend_from_slice(&point_bytes(cu)); preimage }
fn partial_challenge(source: &Session, authorization: &[u8; 32], ciphertext: &Cipher, trustee: usize, verification: &ValidatedPoint, w: &ValidatedPoint, cg: &ValidatedPoint, cu: &ValidatedPoint) -> Fr { candidate_scalar(&partial_preimage(source, authorization, ciphertext, trustee, verification, w, cg, cu)) }
fn verify_share(setup: &Setup, source: &Session, authorization: &[u8; 32], ciphertext: &Cipher, share: &Share) { let d = partial_challenge(source, authorization, ciphertext, share.trustee, &setup.verification[share.trustee - 1], &share.w, &share.cg, &share.cu); assert_eq!(share.cg.affine_decimal(), ValidatedPoint::base8().scalar_mul_fr(share.a).add(&setup.verification[share.trustee - 1].scalar_mul_fr(-d)).affine_decimal()); assert_eq!(share.cu.affine_decimal(), ciphertext.r.scalar_mul_fr(share.a).add(&share.w.scalar_mul_fr(-d)).affine_decimal()); }

fn mask_record(setup: &Setup, source: &Session, htilde: &ValidatedPoint, previous_x: Cipher, previous_y: Cipher, sign: i8, rx: Fr, ry: Fr, alpha: Fr, beta: Fr, fake_challenge: Fr, fake_rx: Fr, fake_ry: Fr) -> MaskRecord {
    let next_x = add_cipher(&if sign == 1 { previous_x.clone() } else { neg_cipher(&previous_x) }, &enc_zero(&setup.committee, rx));
    let next_y = add_cipher(&if sign == 1 { previous_y.clone() } else { neg_cipher(&previous_y) }, &enc_zero(&setup.committee, ry));
    let e = htilde.scalar_mul_fr(rx); let real_x = enc_zero(&setup.committee, alpha); let real_y = enc_zero(&setup.committee, beta); let real_e = htilde.scalar_mul_fr(alpha); let fake_branch = -sign; let fake_x = simulate_cipher(&setup.committee, fake_rx, &branch_delta(&next_x, &previous_x, fake_branch), fake_challenge); let fake_y = simulate_cipher(&setup.committee, fake_ry, &branch_delta(&next_y, &previous_y, fake_branch), fake_challenge); let fake_e = simulate_point(htilde, fake_rx, &e, fake_challenge);
    let mut proof = if sign == 1 { MaskProof { cpx: real_x, cpy: real_y, cmx: fake_x, cmy: fake_y, cpe: real_e, cme: fake_e, dp: Fr::from(0u64), dm: fake_challenge, apx: Fr::from(0u64), apy: Fr::from(0u64), amx: fake_rx, amy: fake_ry } } else { MaskProof { cpx: fake_x, cpy: fake_y, cmx: real_x, cmy: real_y, cpe: fake_e, cme: real_e, dp: fake_challenge, dm: Fr::from(0u64), apx: fake_rx, apy: fake_ry, amx: Fr::from(0u64), amy: Fr::from(0u64) } };
    let total = masking_challenge(setup, source, &previous_x, &previous_y, &next_x, &next_y, &proof); let real_challenge = total - fake_challenge; let real_rx = alpha + rx * real_challenge; let real_ry = beta + ry * real_challenge; if sign == 1 { proof.dp = real_challenge; proof.apx = real_rx; proof.apy = real_ry; } else { proof.dm = real_challenge; proof.amx = real_rx; proof.amy = real_ry; }
    MaskRecord { previous_x, previous_y, next_x, next_y, e, proof }
}

fn zero_record(setup: &Setup, source: &Session, input: &Cipher, randomness: Fr, alpha: Fr) -> ZeroProof { let contribution = enc_zero(&setup.committee, randomness); let commitment = enc_zero(&setup.committee, alpha); let challenge = zero_challenge(setup, source, input, &contribution, &commitment); ZeroProof { contribution, commitment, response: alpha + randomness * challenge } }

pub struct GateRun { pub value: Value, pub generation_ms: f64, pub verification_ms: f64 }

pub fn run_gate() -> GateRun {
    let started = Instant::now(); let setup = setup(); let masking = session(&setup, 0); let (htilde, counter) = derive_htilde(&masking, &setup.committee); let input_x = encrypt(&setup.committee, fr_u64(1), fr_u64(11)); let input_y = encrypt(&setup.committee, fr_u64(0), fr_u64(13)); let mut previous_x = input_x.clone(); let mut previous_y = add_cipher(&Cipher { r: ValidatedPoint::identity(), s: ValidatedPoint::base8().negate() }, &scale_cipher(&input_y, Fr::from(2u64))); let mut masks = Vec::new();
    for i in 0..5 { let record = mask_record(&setup, &masking, &htilde, previous_x.clone(), previous_y.clone(), if i % 2 == 0 { 1 } else { -1 }, fr_u64(101 + i as u64), fr_u64(201 + i as u64), fr_u64(301 + i as u64), fr_u64(401 + i as u64), fr_u64(501 + i as u64), fr_u64(601 + i as u64), fr_u64(701 + i as u64)); previous_x = record.next_x.clone(); previous_y = record.next_y.clone(); masks.push(record); }
    let x_source = session(&setup, 1); let y_source = session(&setup, 2); let x_input = masks.last().unwrap().next_x.clone(); let y_input = masks.last().unwrap().next_y.clone(); let mut x_rerand = x_input.clone(); let mut y_rerand = y_input.clone(); let mut x_zero = Vec::new(); let mut y_zero = Vec::new(); for i in 0..5 { let xp = zero_record(&setup, &x_source, &x_input, fr_u64(801 + i as u64), fr_u64(901 + i as u64)); let yp = zero_record(&setup, &y_source, &y_input, fr_u64(1001 + i as u64), fr_u64(1101 + i as u64)); x_rerand = add_cipher(&x_rerand, &xp.contribution); y_rerand = add_cipher(&y_rerand, &yp.contribution); x_zero.push(xp); y_zero.push(yp); }
    let td = session(&setup, 3); let authorization = authorization_id(&td, &y_rerand, "GATE_SELECTOR_DECRYPTION", "CGY_GATE_SELECTOR"); let mut shares = Vec::new(); for i in 0..5 { let w = y_rerand.r.scalar_mul_fr(setup.shares[i]); let alpha = fr_u64(1201 + i as u64); let cg = ValidatedPoint::base8().scalar_mul_fr(alpha); let cu = y_rerand.r.scalar_mul_fr(alpha); let d = partial_challenge(&td, &authorization, &y_rerand, i + 1, &setup.verification[i], &w, &cg, &cu); shares.push(Share { trustee: i + 1, w, cg, cu, a: alpha + d * setup.shares[i] }); }
    let ids: Vec<usize> = (1..=setup.commitments.len()).collect(); let mut factor = ValidatedPoint::identity(); for share in shares.iter().take(setup.commitments.len()) { factor = factor.add(&share.w.scalar_mul_fr(lagrange(&ids, share.trustee))); } let opened = y_rerand.s.add(&factor.negate()); let base = ValidatedPoint::base8(); let negative = base.negate(); let opened_sign = if opened.affine_decimal() == base.affine_decimal() { 1 } else { assert_eq!(opened.affine_decimal(), negative.affine_decimal()); -1 }; let signed_x = if opened_sign == 1 { x_rerand.clone() } else { neg_cipher(&x_rerand) }; let output = scale_cipher(&add_cipher(&input_x, &signed_x), (Fr::from(2u64)).inverse().unwrap()); let generation_ms = started.elapsed().as_secs_f64() * 1000.0;
    let verify_started = Instant::now(); for record in &masks { verify_mask(&setup, &masking, &htilde, record); } for proof in &x_zero { verify_zero(&setup, &x_source, &masks.last().unwrap().next_x, proof); } for proof in &y_zero { verify_zero(&setup, &y_source, &masks.last().unwrap().next_y, proof); } for share in &shares { verify_share(&setup, &td, &authorization, &y_rerand, share); } let verification_ms = verify_started.elapsed().as_secs_f64() * 1000.0;
    GateRun { value: gate_json(&setup, &masking, counter, &input_x, &input_y, &htilde, &masks, &x_source, &y_source, &x_zero, &y_zero, &td, &shares, opened_sign, &output), generation_ms, verification_ms }
}

fn setup_json(setup: &Setup) -> Value { json!({"protocolVersion": PROTOCOL_VERSION, "kind":"TEST_ONLY_FRESH_CSPRNG_DEALER", "trustees":setup.verification.len(), "degree":setup.commitments.len() - 1, "threshold":setup.commitments.len(), "generator":point_json(&ValidatedPoint::base8()), "committeeKey":point_json(&setup.committee), "coefficientCommitments":setup.commitments.iter().map(point_json).collect::<Vec<_>>(), "verificationKeys":setup.verification.iter().enumerate().map(|(i,p)| json!({"trusteeId":i+1,"point":point_json(p)})).collect::<Vec<_>>(), "setupHash":hex::encode(setup.setup_hash)}) }
fn session_json(session: &Session) -> Value { json!({"protocolVersion":PROTOCOL_VERSION,"setupHash":hex::encode(session.setup_hash),"executionId":hex::encode(session.execution_id),"gateId":session.gate_id.to_string(),"invocation":session.invocation.to_string()}) }
fn mask_proof_json(proof: &MaskProof) -> Value { json!({"cPlusX":cipher_json(&proof.cpx),"cPlusY":cipher_json(&proof.cpy),"cMinusX":cipher_json(&proof.cmx),"cMinusY":cipher_json(&proof.cmy),"cPlusE":point_json(&proof.cpe),"cMinusE":point_json(&proof.cme),"dPlus":scalar_json(&proof.dp),"dMinus":scalar_json(&proof.dm),"aPlusX":scalar_json(&proof.apx),"aPlusY":scalar_json(&proof.apy),"aMinusX":scalar_json(&proof.amx),"aMinusY":scalar_json(&proof.amy)}) }
fn gate_json(setup:&Setup, masking:&Session, counter:u32, input_x:&Cipher, input_y:&Cipher, htilde:&ValidatedPoint, masks:&[MaskRecord], x_source:&Session, y_source:&Session, x_zero:&[ZeroProof], y_zero:&[ZeroProof], td:&Session, shares:&[Share], opened_sign:i8, output:&Cipher) -> Value {
    let mask_json: Vec<_> = masks.iter().map(|record| json!({"previousX":cipher_json(&record.previous_x),"previousY":cipher_json(&record.previous_y),"nextX":cipher_json(&record.next_x),"nextY":cipher_json(&record.next_y),"e":point_json(&record.e),"proof":mask_proof_json(&record.proof)})).collect();
    let zero_json = |record:&ZeroProof| json!({"contribution":cipher_json(&record.contribution),"proof":{"commitment":cipher_json(&record.commitment),"response":scalar_json(&record.response)}});
    let share_json: Vec<_> = shares.iter().map(|share| json!({"trusteeId":share.trustee,"w":point_json(&share.w),"cG":point_json(&share.cg),"cU":point_json(&share.cu),"a":scalar_json(&share.a)})).collect();
    let y_output = y_zero.iter().fold(masks.last().unwrap().next_y.clone(), |acc,p| add_cipher(&acc,&p.contribution));
    json!({"schema":"-CGY-NATIVE/SINGLE-GATE/V1","setup":setup_json(setup),"maskingSession":session_json(masking),"htilde":point_json(htilde),"htildeCounter":counter,"inputX":cipher_json(input_x),"inputY":cipher_json(input_y),"masking":mask_json,"xRerandomization":{"sourceSession":session_json(x_source),"input":cipher_json(&masks.last().unwrap().next_x),"output":cipher_json(&x_zero.iter().fold(masks.last().unwrap().next_x.clone(), |acc,p| add_cipher(&acc,&p.contribution))),"records":x_zero.iter().map(zero_json).collect::<Vec<_>>()},"yRerandomization":{"sourceSession":session_json(y_source),"input":cipher_json(&masks.last().unwrap().next_y),"output":cipher_json(&y_output),"records":y_zero.iter().map(zero_json).collect::<Vec<_>>()},"partialSession":session_json(td),"partialShares":share_json,"openedSign":opened_sign,"output":cipher_json(output)})
}

fn json_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value.get(key).and_then(Value::as_str).ok_or_else(|| format!("missing string field {key}"))
}

fn json_u64(value: &Value, key: &str) -> Result<u64, String> {
    json_string(value, key)?.parse::<u64>().map_err(|_| format!("invalid uint64 field {key}"))
}

fn parse_hex32(value: &Value, key: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(json_string(value, key)?).map_err(|_| format!("invalid hex field {key}"))?;
    bytes.try_into().map_err(|_| format!("field {key} is not 32 bytes"))
}

fn parse_fr_json(value: &Value, key: &str) -> Result<Fr, String> {
    let text = json_string(value, key)?;
    let parsed = Fr::from_str(text).map_err(|_| format!("invalid scalar field {key}"))?;
    if parsed.into_bigint().to_string() != text { return Err(format!("noncanonical scalar field {key}")); }
    Ok(parsed)
}

fn parse_point_json(value: &Value, key: &str) -> Result<ValidatedPoint, String> {
    let object = value.get(key).ok_or_else(|| format!("missing point field {key}"))?;
    let x = json_string(object, "x")?;
    let y = json_string(object, "y")?;
    ValidatedPoint::from_decimal(x, y).map_err(|error| format!("invalid point {key}: {error}"))
}

fn parse_point_value(value: &Value, label: &str) -> Result<ValidatedPoint, String> {
    let x = json_string(value, "x")?;
    let y = json_string(value, "y")?;
    ValidatedPoint::from_decimal(x, y).map_err(|error| format!("invalid point {label}: {error}"))
}

fn parse_cipher_json(value: &Value, key: &str) -> Result<Cipher, String> {
    let object = value.get(key).ok_or_else(|| format!("missing ciphertext field {key}"))?;
    Ok(Cipher { r: parse_point_value(object.get("R").ok_or_else(|| format!("missing {key}.R"))?, &format!("{key}.R"))?, s: parse_point_value(object.get("S").ok_or_else(|| format!("missing {key}.S"))?, &format!("{key}.S"))? })
}

// Arkworks projective equality performs the homogeneous cross-multiplication
// check without normalizing either operand.  Affine string comparison here
// would reintroduce a field inversion on every proof equation.
fn point_equal(left: &ValidatedPoint, right: &ValidatedPoint) -> bool { left == right }
fn cipher_equal(left: &Cipher, right: &Cipher) -> bool { point_equal(&left.r, &right.r) && point_equal(&left.s, &right.s) }

fn parse_session_json(value: &Value, setup_hash: [u8; 32]) -> Result<Session, String> {
    if json_string(value, "protocolVersion")? != PROTOCOL_VERSION { return Err("session protocol mismatch".into()); }
    let parsed_hash = parse_hex32(value, "setupHash")?;
    if parsed_hash != setup_hash { return Err("session setup hash mismatch".into()); }
    let execution_id = parse_hex32(value, "executionId")?;
    Ok(Session { setup_hash, execution_id, gate_id: json_u64(value, "gateId")?, invocation: json_u64(value, "invocation")? })
}

fn setup_hash_for(commitments: &[ValidatedPoint], verification: &[ValidatedPoint]) -> [u8; 32] {
    let mut encoded = lp(SETUP_DOMAIN.as_bytes());
    encoded.extend_from_slice(&lp(PROTOCOL_VERSION.as_bytes()));
    encoded.extend_from_slice(&u32be(verification.len() as u32));
    encoded.extend_from_slice(&u32be((commitments.len() - 1) as u32));
    encoded.extend_from_slice(&u32be(commitments.len() as u32));
    encoded.extend_from_slice(&point_bytes(&ValidatedPoint::base8()));
    encoded.extend_from_slice(&point_bytes(&commitments[0]));
    encoded.extend_from_slice(&u32be(commitments.len() as u32));
    for point in commitments { encoded.extend_from_slice(&point_bytes(point)); }
    encoded.extend_from_slice(&u32be(verification.len() as u32));
    for (index, point) in verification.iter().enumerate() {
        encoded.extend_from_slice(&u32be((index + 1) as u32));
        encoded.extend_from_slice(&point_bytes(point));
    }
    sha256(&encoded)
}

fn setup_from_json(value: &Value) -> Result<Setup, String> {
    if json_string(value, "protocolVersion")? != PROTOCOL_VERSION { return Err("setup protocol mismatch".into()); }
    if json_string(value, "kind")? != "TEST_ONLY_FRESH_CSPRNG_DEALER" { return Err("setup provisioning kind mismatch".into()); }
    let trustees = value.get("trustees").and_then(Value::as_u64).ok_or("trustee count missing")? as usize;
    let degree = value.get("degree").and_then(Value::as_u64).ok_or("polynomial degree missing")? as usize;
    let threshold = value.get("threshold").and_then(Value::as_u64).ok_or("decryption threshold missing")? as usize;
    if trustees < 2 || degree < 1 || degree + 1 != threshold || threshold > trustees { return Err("setup threshold profile mismatch".into()); }
    let generator = parse_point_json(value, "generator")?;
    if !point_equal(&generator, &ValidatedPoint::base8()) { return Err("setup generator is not Base8".into()); }
    let committee = parse_point_json(value, "committeeKey")?;
    let commitments_value = value.get("coefficientCommitments").and_then(Value::as_array).ok_or("setup commitments missing")?;
    if commitments_value.len() != degree + 1 { return Err("setup commitment count mismatch".into()); }
    let commitments: Vec<_> = commitments_value.iter().enumerate().map(|(index, entry)| parse_point_value(entry, &format!("coefficientCommitments[{index}]"))).collect::<Result<_, _>>()?;
    if !point_equal(&committee, &commitments[0]) { return Err("committee commitment mismatch".into()); }
    let verification_value = value.get("verificationKeys").and_then(Value::as_array).ok_or("setup verification keys missing")?;
    if verification_value.len() != trustees { return Err("setup verification key count mismatch".into()); }
    let mut verification = Vec::with_capacity(trustees);
    for (index, entry) in verification_value.iter().enumerate() {
        if entry.get("trusteeId").and_then(Value::as_u64) != Some((index + 1) as u64) { return Err("verification key order mismatch".into()); }
        let point = parse_point_json(entry, "point")?;
        let mut expected = ValidatedPoint::identity();
        let id = fr_u64((index + 1) as u64);
        let mut power = Fr::from(1u64);
        for commitment in &commitments {
            expected = expected.add(&commitment.scalar_mul_fr(power));
            power *= id;
        }
        if !point_equal(&point, &expected) { return Err(format!("verification key {} is inconsistent", index + 1)); }
        verification.push(point);
    }
    let expected_hash = setup_hash_for(&commitments, &verification);
    let encoded_hash = json_string(value, "setupHash")?;
    if encoded_hash != hex::encode(expected_hash) { return Err("setup hash mismatch".into()); }
    Ok(Setup { committee, commitments, shares: vec![Fr::from(0u64); trustees], verification, setup_hash: expected_hash })
}

fn verify_mask_checked(setup: &Setup, source: &Session, htilde: &ValidatedPoint, record: &MaskRecord) -> Result<(), String> {
    if point_equal(&record.next_x.r, &ValidatedPoint::identity()) { return Err("mask X first component is identity".into()); }
    let total = masking_challenge(setup, source, &record.previous_x, &record.previous_y, &record.next_x, &record.next_y, &record.proof);
    if record.proof.dp + record.proof.dm != total { return Err("mask challenges do not sum to oracle challenge".into()); }
    for (branch, challenge, rx, ry, cx, cy, ce) in [(1_i8, record.proof.dp, record.proof.apx, record.proof.apy, &record.proof.cpx, &record.proof.cpy, &record.proof.cpe), (-1_i8, record.proof.dm, record.proof.amx, record.proof.amy, &record.proof.cmx, &record.proof.cmy, &record.proof.cme)] {
        if !cipher_equal(&simulate_cipher(&setup.committee, rx, &branch_delta(&record.next_x, &record.previous_x, branch), challenge), cx) { return Err("mask X proof equation failed".into()); }
        if !cipher_equal(&simulate_cipher(&setup.committee, ry, &branch_delta(&record.next_y, &record.previous_y, branch), challenge), cy) { return Err("mask Y proof equation failed".into()); }
        if !point_equal(&simulate_point(htilde, rx, &record.e, challenge), ce) { return Err("mask auxiliary proof equation failed".into()); }
    }
    Ok(())
}

fn verify_zero_checked(setup: &Setup, source: &Session, input: &Cipher, proof: &ZeroProof) -> Result<(), String> {
    let challenge = zero_challenge(setup, source, input, &proof.contribution, &proof.commitment);
    if !cipher_equal(&simulate_cipher(&setup.committee, proof.response, &proof.contribution, challenge), &proof.commitment) { return Err("zero-encryption proof failed".into()); }
    Ok(())
}

fn verify_share_checked(setup: &Setup, source: &Session, authorization: &[u8; 32], ciphertext: &Cipher, share: &Share) -> Result<(), String> {
    if share.trustee == 0 || share.trustee > setup.verification.len() { return Err("partial share trustee identity invalid".into()); }
    let d = partial_challenge(source, authorization, ciphertext, share.trustee, &setup.verification[share.trustee - 1], &share.w, &share.cg, &share.cu);
    let expected_g = ValidatedPoint::base8().scalar_mul_fr(share.a).add(&setup.verification[share.trustee - 1].scalar_mul_fr(-d));
    let expected_u = ciphertext.r.scalar_mul_fr(share.a).add(&share.w.scalar_mul_fr(-d));
    if !point_equal(&expected_g, &share.cg) || !point_equal(&expected_u, &share.cu) { return Err("partial-decryption proof failed".into()); }
    Ok(())
}

pub fn verify_gate_json(value: &Value) -> Result<(), String> {
    if value.get("schema").and_then(Value::as_str) != Some("-CGY-NATIVE/SINGLE-GATE/V1") { return Err("schema mismatch".into()); }
    let setup = setup_from_json(value.get("setup").ok_or("setup missing")?)?;
    verify_gate_json_with_setup(value, &setup)
}

fn verify_gate_json_with_setup(value: &Value, setup: &Setup) -> Result<(), String> {
    if value.get("schema").and_then(Value::as_str) != Some("-CGY-NATIVE/SINGLE-GATE/V1") { return Err("schema mismatch".into()); }
    let masking = parse_session_json(value.get("maskingSession").ok_or("masking session missing")?, setup.setup_hash)?;
    let (htilde, counter) = derive_htilde(&masking, &setup.committee);
    if value.get("htildeCounter").and_then(Value::as_u64) != Some(counter as u64) || !point_equal(&htilde, &parse_point_json(value, "htilde")?) { return Err("auxiliary oracle output mismatch".into()); }
    let input_x = parse_cipher_json(value, "inputX")?;
    let input_y = parse_cipher_json(value, "inputY")?;
    let mut previous_x = input_x.clone();
    let mut previous_y = add_cipher(&Cipher { r: ValidatedPoint::identity(), s: ValidatedPoint::base8().negate() }, &scale_cipher(&input_y, Fr::from(2u64)));
    let masks = value.get("masking").and_then(Value::as_array).ok_or("masking vector missing")?;
    if masks.len() != setup.verification.len() { return Err("masking vector length mismatch".into()); }
    for (index, entry) in masks.iter().enumerate() {
        let entry_previous_x = parse_cipher_json(entry, "previousX")?;
        let entry_previous_y = parse_cipher_json(entry, "previousY")?;
        let next_x = parse_cipher_json(entry, "nextX")?;
        let next_y = parse_cipher_json(entry, "nextY")?;
        if !cipher_equal(&entry_previous_x, &previous_x) || !cipher_equal(&entry_previous_y, &previous_y) { return Err(format!("mask predecessor mismatch at {}", index + 1)); }
        let e = parse_point_json(entry, "e")?;
        let proof_value = entry.get("proof").ok_or("mask proof missing")?;
        let proof = MaskProof { cpx: parse_cipher_json(proof_value, "cPlusX")?, cpy: parse_cipher_json(proof_value, "cPlusY")?, cmx: parse_cipher_json(proof_value, "cMinusX")?, cmy: parse_cipher_json(proof_value, "cMinusY")?, cpe: parse_point_json(proof_value, "cPlusE")?, cme: parse_point_json(proof_value, "cMinusE")?, dp: parse_fr_json(proof_value, "dPlus")?, dm: parse_fr_json(proof_value, "dMinus")?, apx: parse_fr_json(proof_value, "aPlusX")?, apy: parse_fr_json(proof_value, "aPlusY")?, amx: parse_fr_json(proof_value, "aMinusX")?, amy: parse_fr_json(proof_value, "aMinusY")? };
        let record = MaskRecord { previous_x, previous_y, next_x: next_x.clone(), next_y: next_y.clone(), e, proof };
        verify_mask_checked(&setup, &masking, &htilde, &record)?;
        previous_x = next_x;
        previous_y = next_y;
    }
    let x_rerand = value.get("xRerandomization").ok_or("X rerandomization missing")?;
    let y_rerand = value.get("yRerandomization").ok_or("Y rerandomization missing")?;
    let x_input = parse_cipher_json(x_rerand, "input")?;
    let y_input = parse_cipher_json(y_rerand, "input")?;
    if !cipher_equal(&previous_x, &x_input) || !cipher_equal(&previous_y, &y_input) { return Err("rerandomization input does not match mask output".into()); }
    let verify_rerand = |record: &Value, source: &Session, expected_input: &Cipher| -> Result<Cipher, String> {
        let input = parse_cipher_json(record, "input")?;
        if !cipher_equal(&input, expected_input) { return Err("rerandomization input mismatch".into()); }
        let records = record.get("records").and_then(Value::as_array).ok_or("rerandomization records missing")?;
        if records.len() != setup.verification.len() { return Err("rerandomization record count mismatch".into()); }
        let mut output = input.clone();
        for entry in records {
            let contribution = parse_cipher_json(entry, "contribution")?;
            let proof_value = entry.get("proof").ok_or("zero proof missing")?;
            let proof = ZeroProof { contribution: contribution.clone(), commitment: parse_cipher_json(proof_value, "commitment")?, response: parse_fr_json(proof_value, "response")? };
            verify_zero_checked(&setup, source, &input, &proof)?;
            output = add_cipher(&output, &contribution);
        }
        let recorded = parse_cipher_json(record, "output")?;
        if !cipher_equal(&output, &recorded) { return Err("rerandomization output mismatch".into()); }
        Ok(output)
    };
    let x_source = parse_session_json(x_rerand.get("sourceSession").ok_or("X source session missing")?, setup.setup_hash)?;
    let y_source = parse_session_json(y_rerand.get("sourceSession").ok_or("Y source session missing")?, setup.setup_hash)?;
    let x_output = verify_rerand(x_rerand, &x_source, &x_input)?;
    let y_output = verify_rerand(y_rerand, &y_source, &y_input)?;
    let td = parse_session_json(value.get("partialSession").ok_or("partial session missing")?, setup.setup_hash)?;
    let auth_id = authorization_id(&td, &y_output, "GATE_SELECTOR_DECRYPTION", "CGY_GATE_SELECTOR");
    let shares_value = value.get("partialShares").and_then(Value::as_array).ok_or("partial shares missing")?;
    if shares_value.len() != setup.verification.len() { return Err("partial share count mismatch".into()); }
    let mut shares = Vec::with_capacity(setup.verification.len());
    for entry in shares_value {
        let trustee = entry.get("trusteeId").and_then(Value::as_u64).ok_or("partial trustee id missing")? as usize;
        let share = Share { trustee, w: parse_point_json(entry, "w")?, cg: parse_point_json(entry, "cG")?, cu: parse_point_json(entry, "cU")?, a: parse_fr_json(entry, "a")? };
        verify_share_checked(&setup, &td, &auth_id, &y_output, &share)?;
        shares.push(share);
    }
     let mut ids = Vec::with_capacity(setup.commitments.len());
     let mut seen = HashSet::with_capacity(shares.len());
     for share in &shares {
         if share.trustee == 0 || share.trustee > setup.verification.len() || !seen.insert(share.trustee) { return Err("partial share trustee set is invalid".into()); }
     }
     if seen.len() != setup.verification.len() || !seen.iter().all(|trustee| *trustee >= 1 && *trustee <= setup.verification.len()) { return Err("partial share trustee set is incomplete".into()); }
     ids.extend(1..=setup.commitments.len());
    let mut factor = ValidatedPoint::identity();
    for share in shares.iter().take(setup.commitments.len()) { factor = factor.add(&share.w.scalar_mul_fr(lagrange(&ids, share.trustee))); }
    let opened = y_output.s.add(&factor.negate());
    let opened_sign = value.get("openedSign").and_then(Value::as_i64).ok_or("opened sign missing")?;
    let expected_opened = if opened_sign == 1 { ValidatedPoint::base8() } else if opened_sign == -1 { ValidatedPoint::base8().negate() } else { return Err("opened sign is invalid".into()); };
    if !point_equal(&opened, &expected_opened) { return Err("opened selector mismatch".into()); }
    let signed_x = if opened_sign == 1 { x_output } else { neg_cipher(&x_output) };
    let expected_output = scale_cipher(&add_cipher(&input_x, &signed_x), (Fr::from(2u64)).inverse().unwrap());
    let recorded_output = parse_cipher_json(value, "output")?;
    if !cipher_equal(&expected_output, &recorded_output) { return Err("gate output mismatch".into()); }
    Ok(())
}

#[derive(Clone)]
struct MaskRandomness {
    sign: i8,
    rx: Fr,
    ry: Fr,
    alpha: Fr,
    beta: Fr,
    fake_challenge: Fr,
    fake_rx: Fr,
    fake_ry: Fr,
}

#[derive(Clone)]
struct ZeroRandomness { randomness: Fr, alpha: Fr }

fn parse_fr_text(text: &str, label: &str) -> Result<Fr, String> {
    let parsed = Fr::from_str(text).map_err(|_| format!("invalid scalar {label}"))?;
    if parsed.into_bigint().to_string() != text { return Err(format!("noncanonical scalar {label}")); }
    Ok(parsed)
}

fn parse_fr_field(object: &Value, key: &str, label: &str) -> Result<Fr, String> {
    parse_fr_text(json_string(object, key)?, label)
}

fn setup_with_secret_shares(value: &Value) -> Result<Setup, String> {
    let mut setup = setup_from_json(value.get("setup").ok_or("setup missing")?)?;
    let shares_value = value.get("secretShares").and_then(Value::as_array).ok_or("secretShares missing")?;
    if shares_value.len() != setup.verification.len() { return Err("secret share count mismatch".into()); }
    let mut shares = Vec::with_capacity(shares_value.len());
    for (index, entry) in shares_value.iter().enumerate() {
        let text = entry.as_str().ok_or_else(|| format!("secret share {index} is not a string"))?;
        let share = parse_fr_text(text, &format!("secretShares[{index}]"))?;
        if !point_equal(&ValidatedPoint::base8().scalar_mul_fr(share), &setup.verification[index]) { return Err(format!("secret share {} does not match verification key", index + 1)); }
        shares.push(share);
    }
    setup.shares = shares;
    Ok(setup)
}

fn derived_session(base: &Session, offset: u64) -> Result<Session, String> {
    let invocation = base.invocation.checked_mul(16).and_then(|value| value.checked_add(offset)).ok_or("derived invocation overflow")?;
    Ok(Session { setup_hash: base.setup_hash, execution_id: base.execution_id, gate_id: base.gate_id, invocation })
}

fn parse_mask_randomness(value: &Value) -> Result<MaskRandomness, String> {
    let sign = value.get("sign").and_then(Value::as_i64).ok_or("mask sign missing")?;
    if sign != 1 && sign != -1 { return Err("mask sign must be +1 or -1".into()); }
    Ok(MaskRandomness { sign: sign as i8, rx: parse_fr_field(value, "rX", "mask rX")?, ry: parse_fr_field(value, "rY", "mask rY")?, alpha: parse_fr_field(value, "alpha", "mask alpha")?, beta: parse_fr_field(value, "beta", "mask beta")?, fake_challenge: parse_fr_field(value, "fakeChallenge", "mask fake challenge")?, fake_rx: parse_fr_field(value, "fakeResponseX", "mask fake response X")?, fake_ry: parse_fr_field(value, "fakeResponseY", "mask fake response Y")? })
}

fn parse_zero_randomness(value: &Value) -> Result<ZeroRandomness, String> {
    Ok(ZeroRandomness { randomness: parse_fr_field(value, "randomness", "rerandomization randomness")?, alpha: parse_fr_field(value, "alpha", "rerandomization alpha")? })
}

struct CoreGateRun {
    value: Value,
    output: Cipher,
    generation_ms: f64,
    verification_ms: f64,
}

#[derive(Clone)]
struct GateRandomness {
    masks: Vec<MaskRandomness>,
    x: Vec<ZeroRandomness>,
    y: Vec<ZeroRandomness>,
    partial: Vec<Fr>,
}

fn random_scalar_nonzero(rng: &mut OsRng) -> Fr {
    loop {
        let mut bytes = [0_u8; 32];
        rng.fill_bytes(&mut bytes);
        let scalar = Fr::from_le_bytes_mod_order(&bytes);
        if scalar != Fr::from(0_u64) { return scalar; }
    }
}

fn fresh_gate_randomness(trustees: usize) -> GateRandomness {
    let mut rng = OsRng;
    let mut masks = Vec::with_capacity(trustees);
    let mut x = Vec::with_capacity(trustees);
    let mut y = Vec::with_capacity(trustees);
    let mut partial = Vec::with_capacity(trustees);
    for _ in 0..trustees {
        let sign = if (rng.next_u32() & 1) == 0 { 1 } else { -1 };
        masks.push(MaskRandomness {
            sign,
            rx: random_scalar_nonzero(&mut rng),
            ry: random_scalar_nonzero(&mut rng),
            alpha: random_scalar_nonzero(&mut rng),
            beta: random_scalar_nonzero(&mut rng),
            fake_challenge: random_scalar_nonzero(&mut rng),
            fake_rx: random_scalar_nonzero(&mut rng),
            fake_ry: random_scalar_nonzero(&mut rng),
        });
        x.push(ZeroRandomness { randomness: random_scalar_nonzero(&mut rng), alpha: random_scalar_nonzero(&mut rng) });
        y.push(ZeroRandomness { randomness: random_scalar_nonzero(&mut rng), alpha: random_scalar_nonzero(&mut rng) });
        partial.push(random_scalar_nonzero(&mut rng));
    }
    GateRandomness { masks, x, y, partial }
}

fn run_gate_core(setup: &Setup, base: &Session, input_x: Cipher, input_y: Cipher, randomness: &GateRandomness) -> Result<CoreGateRun, String> {
    let started = Instant::now();
    let masking = derived_session(base, 0)?;
    let (htilde, counter) = derive_htilde(&masking, &setup.committee);
    if randomness.masks.len() != setup.verification.len() || randomness.x.len() != setup.verification.len() || randomness.y.len() != setup.verification.len() || randomness.partial.len() != setup.verification.len() {
        return Err("gate randomness count mismatch".into());
    }
    let mut previous_x = input_x.clone();
    let mut previous_y = add_cipher(&Cipher { r: ValidatedPoint::identity(), s: ValidatedPoint::base8().negate() }, &scale_cipher(&input_y, Fr::from(2u64)));
    let mut masks = Vec::with_capacity(randomness.masks.len());
    for random in &randomness.masks {
        let record = mask_record(&setup, &masking, &htilde, previous_x.clone(), previous_y.clone(), random.sign, random.rx, random.ry, random.alpha, random.beta, random.fake_challenge, random.fake_rx, random.fake_ry);
        previous_x = record.next_x.clone();
        previous_y = record.next_y.clone();
        masks.push(record);
    }
    let x_source = derived_session(base, 1)?;
    let y_source = derived_session(base, 2)?;
    let x_input = previous_x.clone();
    let y_input = previous_y.clone();
    let mut x_rerand = x_input.clone();
    let mut y_rerand = y_input.clone();
    let mut x_zero = Vec::with_capacity(randomness.x.len());
    let mut y_zero = Vec::with_capacity(randomness.y.len());
    for (xr, yr) in randomness.x.iter().zip(randomness.y.iter()) {
        let xp = zero_record(&setup, &x_source, &x_input, xr.randomness, xr.alpha);
        let yp = zero_record(&setup, &y_source, &y_input, yr.randomness, yr.alpha);
        x_rerand = add_cipher(&x_rerand, &xp.contribution);
        y_rerand = add_cipher(&y_rerand, &yp.contribution);
        x_zero.push(xp);
        y_zero.push(yp);
    }
    let td = derived_session(base, 3)?;
    let authorization = authorization_id(&td, &y_rerand, "GATE_SELECTOR_DECRYPTION", "CGY_GATE_SELECTOR");
    let mut shares = Vec::with_capacity(randomness.partial.len());
    for (index, alpha) in randomness.partial.iter().enumerate() {
        let trustee = index + 1;
        let w = y_rerand.r.scalar_mul_fr(setup.shares[index]);
        let cg = ValidatedPoint::base8().scalar_mul_fr(*alpha);
        let cu = y_rerand.r.scalar_mul_fr(*alpha);
        let d = partial_challenge(&td, &authorization, &y_rerand, trustee, &setup.verification[index], &w, &cg, &cu);
        shares.push(Share { trustee, w, cg, cu, a: *alpha + d * setup.shares[index] });
    }
    let ids: Vec<usize> = (1..=setup.commitments.len()).collect();
    let mut factor = ValidatedPoint::identity();
    for share in &shares { factor = factor.add(&share.w.scalar_mul_fr(lagrange(&ids, share.trustee))); }
    let opened = y_rerand.s.add(&factor.negate());
    let base_point = ValidatedPoint::base8();
    let opened_sign = if point_equal(&opened, &base_point) { 1 } else if point_equal(&opened, &base_point.negate()) { -1 } else { return Err("selector opening is not +/-Base8".into()); };
    let signed_x = if opened_sign == 1 { x_rerand.clone() } else { neg_cipher(&x_rerand) };
    let output = scale_cipher(&add_cipher(&input_x, &signed_x), (Fr::from(2u64)).inverse().unwrap());
    let verification_started = Instant::now();
    for record in &masks { verify_mask_checked(&setup, &masking, &htilde, record)?; }
    for proof in &x_zero { verify_zero_checked(&setup, &x_source, &x_input, proof)?; }
    for proof in &y_zero { verify_zero_checked(&setup, &y_source, &y_input, proof)?; }
    for share in &shares { verify_share_checked(&setup, &td, &authorization, &y_rerand, share)?; }
    let verification_ms = verification_started.elapsed().as_secs_f64() * 1000.0;
    let generation_ms = started.elapsed().as_secs_f64() * 1000.0;
    let mut value = gate_json(&setup, &masking, counter, &input_x, &input_y, &htilde, &masks, &x_source, &y_source, &x_zero, &y_zero, &td, &shares, opened_sign, &output);
    value.as_object_mut().expect("gate JSON object").insert("baseSession".into(), session_json(base));
    Ok(CoreGateRun { value, output, generation_ms, verification_ms })
}

/// Evaluate one source-conforming CGY gate from a public setup, test-only
/// secret shares, exact ciphertext inputs, and fresh per-gate randomness.
/// The request format is deliberately narrow so the application layer can
/// remain in Node while all group/proof work stays in this native module.
pub fn run_gate_request(request: &Value) -> Result<GateRun, String> {
    let setup = setup_with_secret_shares(request)?;
    let base = parse_session_json(request.get("baseSession").ok_or("baseSession missing")?, setup.setup_hash)?;
    let input_x = parse_cipher_json(request, "inputX")?;
    let input_y = parse_cipher_json(request, "inputY")?;
    let mask_values = request.get("maskRandomness").and_then(Value::as_array).ok_or("maskRandomness missing")?;
    let x_values = request.get("xRandomness").and_then(Value::as_array).ok_or("xRandomness missing")?;
    let y_values = request.get("yRandomness").and_then(Value::as_array).ok_or("yRandomness missing")?;
    let partial_values = request.get("partialRandomness").and_then(Value::as_array).ok_or("partialRandomness missing")?;
    let mut masks = Vec::with_capacity(mask_values.len());
    for value in mask_values { masks.push(parse_mask_randomness(value)?); }
    let mut x = Vec::with_capacity(x_values.len());
    let mut y = Vec::with_capacity(y_values.len());
    for (x_value, y_value) in x_values.iter().zip(y_values.iter()) { x.push(parse_zero_randomness(x_value)?); y.push(parse_zero_randomness(y_value)?); }
    let mut partial = Vec::with_capacity(partial_values.len());
    for value in partial_values { partial.push(parse_fr_field(value, "alpha", "partial alpha")?); }
    let run = run_gate_core(&setup, &base, input_x, input_y, &GateRandomness { masks, x, y, partial })?;
    Ok(GateRun { value: run.value, generation_ms: run.generation_ms, verification_ms: run.verification_ms })
}

fn parse_cipher_value(value: &Value, label: &str) -> Result<Cipher, String> {
    Ok(Cipher {
        r: parse_point_value(value.get("R").ok_or_else(|| format!("missing {label}.R"))?, &format!("{label}.R"))?,
        s: parse_point_value(value.get("S").ok_or_else(|| format!("missing {label}.S"))?, &format!("{label}.S"))?,
    })
}

fn dag_public_bit(bit: u64) -> Cipher {
    if bit == 0 { Cipher { r: ValidatedPoint::identity(), s: ValidatedPoint::identity() } }
    else { Cipher { r: ValidatedPoint::identity(), s: ValidatedPoint::base8() } }
}

fn dag_affine_subtract(left: &Cipher, right: &Cipher) -> Cipher { add_cipher(left, &scale_cipher(right, -Fr::from(1u64))) }
fn dag_xor_with_product(left: &Cipher, right: &Cipher, product: &Cipher) -> Cipher { add_cipher(&add_cipher(left, right), &scale_cipher(product, -Fr::from(2u64))) }

struct DagExecutor {
    setup: Setup,
    execution_id: [u8; 32],
    values: Vec<Cipher>,
    gate_records: Vec<Value>,
    generation_ms: Vec<f64>,
    verification_ms: Vec<f64>,
    next_gate_id: u64,
}

trait GateRunner {
    fn gate(&mut self, left: &Cipher, right: &Cipher, label: &str) -> Result<Cipher, String>;
}

impl GateRunner for DagExecutor {
    fn gate(&mut self, left: &Cipher, right: &Cipher, label: &str) -> Result<Cipher, String> {
        let gate_id = self.next_gate_id;
        self.next_gate_id = self.next_gate_id.checked_add(1).ok_or("gate id overflow")?;
        let base = Session { setup_hash: self.setup.setup_hash, execution_id: self.execution_id, gate_id, invocation: 0 };
        let run = run_gate_core(&self.setup, &base, left.clone(), right.clone(), &fresh_gate_randomness(self.setup.verification.len()))?;
        self.generation_ms.push(run.generation_ms);
        self.verification_ms.push(run.verification_ms);
        self.gate_records.push(json!({"gateIndex": gate_id, "label": label, "backend": "RUST", "record": run.value}));
        let output = run.output;
        self.values.push(output.clone());
        Ok(output)
    }
}

struct LocalDagExecutor<'a> {
    setup: &'a Setup,
    execution_id: [u8; 32],
    next_gate_id: u64,
    gate_records: Vec<Value>,
    generation_ms: Vec<f64>,
    verification_ms: Vec<f64>,
    output: Option<Vec<Cipher>>,
}

impl GateRunner for LocalDagExecutor<'_> {
    fn gate(&mut self, left: &Cipher, right: &Cipher, label: &str) -> Result<Cipher, String> {
        let gate_id = self.next_gate_id;
        self.next_gate_id = self.next_gate_id.checked_add(1).ok_or("gate id overflow")?;
        let base = Session { setup_hash: self.setup.setup_hash, execution_id: self.execution_id, gate_id, invocation: 0 };
        let run = run_gate_core(self.setup, &base, left.clone(), right.clone(), &fresh_gate_randomness(self.setup.verification.len()))?;
        self.generation_ms.push(run.generation_ms);
        self.verification_ms.push(run.verification_ms);
        self.gate_records.push(json!({"gateIndex": gate_id, "label": label, "backend": "RUST", "record": run.value}));
        Ok(run.output)
    }
}

fn dag_add_bits<R: GateRunner>(executor: &mut R, left: &[Cipher], right: &[Cipher], label: &str) -> Result<Vec<Cipher>, String> {
    if left.len() != right.len() || left.is_empty() { return Err("AddBits width mismatch".into()); }
    let mut output = Vec::with_capacity(left.len() + 1);
    let mut carry = executor.gate(&left[0], &right[0], &format!("{label}/BIT_0/CARRY"))?;
    output.push(dag_xor_with_product(&left[0], &right[0], &carry));
    for bit in 1..left.len() {
        let product = executor.gate(&left[bit], &right[bit], &format!("{label}/BIT_{bit}/PAIR_PRODUCT"))?;
        let pair_xor = dag_xor_with_product(&left[bit], &right[bit], &product);
        let carry_product = executor.gate(&pair_xor, &carry, &format!("{label}/BIT_{bit}/CARRY_PRODUCT"))?;
        let sum_bit = dag_xor_with_product(&pair_xor, &carry, &carry_product);
        carry = scale_cipher(&add_cipher(&add_cipher(&add_cipher(&left[bit], &right[bit]), &carry), &scale_cipher(&sum_bit, -Fr::from(1u64))), Fr::from(2u64).inverse().unwrap());
        output.push(sum_bit);
    }
    output.push(carry);
    Ok(output)
}

fn dag_sub_lt_bits<R: GateRunner>(executor: &mut R, left: &[Cipher], right: &[Cipher], label: &str) -> Result<(Vec<Cipher>, Cipher, Cipher, Cipher, Cipher), String> {
    if left.len() != right.len() || left.is_empty() { return Err("SubLTBits width mismatch".into()); }
    let mut difference = Vec::with_capacity(left.len());
    let mut physical_last = executor.gate(&left[0], &right[0], &format!("{label}/BIT_0/PRODUCT"))?;
    difference.push(dag_xor_with_product(&left[0], &right[0], &physical_last));
    let mut affine_term = right[0].clone();
    let mut borrow = dag_affine_subtract(&affine_term, &physical_last);
    for bit in 1..left.len() {
        let y_borrow = executor.gate(&right[bit], &borrow, &format!("{label}/BIT_{bit}/Y_BORROW"))?;
        let y_xor_borrow = dag_xor_with_product(&right[bit], &borrow, &y_borrow);
        let x_product = executor.gate(&left[bit], &y_xor_borrow, &format!("{label}/BIT_{bit}/X_PRODUCT"))?;
        difference.push(dag_xor_with_product(&left[bit], &y_xor_borrow, &x_product));
        affine_term = dag_affine_subtract(&add_cipher(&right[bit], &borrow), &y_borrow);
        physical_last = x_product;
        borrow = dag_affine_subtract(&affine_term, &physical_last);
    }
    Ok((difference, borrow.clone(), affine_term, physical_last, borrow))
}

/// Execute the complete weighted-bit DAG in one native process.  The request
/// contains the setup, exact admitted ciphertext vector, execution id, and
/// public threshold once; all gate inputs and affine arithmetic remain native
/// until the single result/transcript serialization boundary.
pub fn run_dag_request(request: &Value) -> Result<Value, String> {
    let started = Instant::now();
    let setup = setup_with_secret_shares(request)?;
    let execution_id = parse_hex32(request, "executionId")?;
    let tau = request.get("tau").and_then(Value::as_u64).ok_or("tau missing")?;
    let label_prefix = request.get("labelPrefix").and_then(Value::as_str).unwrap_or("N8");
    let vectors = request.get("bitVectors").and_then(Value::as_array).ok_or("bitVectors missing")?;
    if vectors.is_empty() || (vectors.len() & (vectors.len() - 1)) != 0 { return Err("bitVectors must be a nonempty power of two".into()); }
    let mut inputs = Vec::with_capacity(vectors.len());
    let mut width = None;
    for (row, vector) in vectors.iter().enumerate() {
        let entries = vector.as_array().ok_or("bit vector is not an array")?;
        if entries.is_empty() || width.is_some_and(|expected| expected != entries.len()) { return Err("bit vector widths disagree".into()); }
        width = Some(entries.len());
        inputs.push(entries.iter().enumerate().map(|(bit, value)| parse_cipher_value(value, &format!("bitVectors[{row}][{bit}]"))).collect::<Result<Vec<_>, _>>()?);
    }
    let width = width.ok_or("empty bit vectors")?;
    let mut executor = DagExecutor { setup, execution_id, values: Vec::new(), gate_records: Vec::new(), generation_ms: Vec::new(), verification_ms: Vec::new(), next_gate_id: 1 };
    let mut frontier = inputs;
    let mut aggregate_depth = 0_u64;
    while frontier.len() > 1 {
        let node_count = frontier.len() / 2;
        let width = frontier[0].len();
        let gates_per_node = (2 * width - 1) as u64;
        let setup_ref = &executor.setup;
        let execution_id = executor.execution_id;
        let start_gate_id = executor.next_gate_id;
        let level_results: Vec<Result<LocalDagExecutor<'_>, String>> = (0..node_count).into_par_iter().map(|pair_index| {
            let pair = &frontier[2 * pair_index..2 * pair_index + 2];
            let mut local = LocalDagExecutor { setup: setup_ref, execution_id, next_gate_id: start_gate_id + pair_index as u64 * gates_per_node, gate_records: Vec::new(), generation_ms: Vec::new(), verification_ms: Vec::new(), output: None };
            let label = format!("{label_prefix}_WEIGHTED_SUM/LEVEL_{aggregate_depth}/PAIR_{pair_index}");
            local.output = Some(dag_add_bits(&mut local, &pair[0], &pair[1], &label)?);
            Ok(local)
        }).collect();
        let mut next = Vec::with_capacity(node_count);
        for local in level_results {
            let local = local?;
            let output = local.output.ok_or("parallel AddBits produced no output")?;
            executor.gate_records.extend(local.gate_records);
            executor.generation_ms.extend(local.generation_ms);
            executor.verification_ms.extend(local.verification_ms);
            next.push(output);
        }
        executor.next_gate_id += node_count as u64 * gates_per_node;
        frontier = next;
        aggregate_depth += 1;
    }
    let aggregate = frontier.pop().ok_or("aggregate is empty")?;
    if aggregate.len() != width + aggregate_depth as usize { return Err("aggregate width mismatch".into()); }
    let threshold_bits: Vec<_> = (0..aggregate.len()).map(|bit| dag_public_bit((tau >> bit) & 1)).collect();
    let (difference, borrow, affine_term, physical_last, q) = dag_sub_lt_bits(&mut executor, &aggregate, &threshold_bits, &format!("{label_prefix}_THRESHOLD")).map_err(|e| e.to_string())?;
    if !cipher_equal(&borrow, &q) { return Err("terminal Q mismatch".into()); }
    let result = dag_affine_subtract(&dag_public_bit(1), &borrow);
    let total_generation: f64 = executor.generation_ms.iter().sum();
    let total_verification: f64 = executor.verification_ms.iter().sum();
    let output = json!({
        "schema": "-CGY-NATIVE/WEIGHTED-DAG/V1",
        "gateCount": executor.next_gate_id - 1,
        "aggregateDepth": aggregate_depth,
        "aggregate": aggregate.iter().map(cipher_json).collect::<Vec<_>>(),
        "comparison": {
            "difference": difference.iter().map(cipher_json).collect::<Vec<_>>(),
            "borrow": cipher_json(&borrow),
            "terminal": {"D": cipher_json(&affine_term), "CStar": cipher_json(&physical_last), "Q": cipher_json(&q)},
        },
        "result": cipher_json(&result),
        "gates": executor.gate_records,
        "timing": {
            "backendMs": started.elapsed().as_secs_f64() * 1000.0,
            "gateGenerationMs": executor.generation_ms,
            "gateVerificationMs": executor.verification_ms,
            "gateGenerationMsTotal": total_generation,
            "gateVerificationMsTotal": total_verification,
            "inputDecodeMs": 0.0,
        },
    });
    Ok(output)
}

struct DagVerifier<'a> {
    setup: &'a Setup,
    execution_id: [u8; 32],
    entries: &'a [Value],
    cursor: usize,
}

trait DagGateVerifier {
    fn gate(&mut self, left: &Cipher, right: &Cipher, label: &str) -> Result<Cipher, String>;
}

impl<'a> DagGateVerifier for DagVerifier<'a> {
    fn gate(&mut self, left: &Cipher, right: &Cipher, label: &str) -> Result<Cipher, String> {
        let entry = self.entries.get(self.cursor).ok_or("native DAG transcript ended before the expected gate")?;
        let expected_index = self.cursor + 1;
        if entry.get("gateIndex").and_then(Value::as_u64) != Some(expected_index as u64) || entry.get("label").and_then(Value::as_str) != Some(label) || entry.get("backend").and_then(Value::as_str) != Some("RUST") {
            return Err(format!("native DAG gate {} label/order mismatch", expected_index));
        }
        let record = entry.get("record").ok_or("native DAG gate record missing")?;
        let base = parse_session_json(record.get("baseSession").ok_or("native DAG base session missing")?, self.setup.setup_hash)?;
        if base.execution_id != self.execution_id || base.gate_id != expected_index as u64 || base.invocation != 0 { return Err(format!("native DAG gate {} session mismatch", expected_index)); }
        let input_x = parse_cipher_json(record, "inputX")?;
        let input_y = parse_cipher_json(record, "inputY")?;
        if !cipher_equal(&input_x, left) || !cipher_equal(&input_y, right) { return Err(format!("native DAG gate {} input mismatch", expected_index)); }
        let record_setup_hash = record.get("setup").and_then(|value| value.get("setupHash")).and_then(Value::as_str).ok_or("native DAG gate setup hash missing")?;
        if record_setup_hash != hex::encode(self.setup.setup_hash) { return Err(format!("native DAG gate {} setup mismatch", expected_index)); }
        let output = parse_cipher_json(record, "output")?;
        self.cursor += 1;
        Ok(output)
    }
}

struct StreamDagVerifier<'a, R: BufRead> {
    setup: &'a Setup,
    execution_id: [u8; 32],
    reader: R,
    cursor: usize,
    batch: Vec<Value>,
    batch_index: usize,
}

impl<'a, R: BufRead> DagGateVerifier for StreamDagVerifier<'a, R> {
    fn gate(&mut self, left: &Cipher, right: &Cipher, label: &str) -> Result<Cipher, String> {
        if self.batch_index == self.batch.len() {
            self.batch.clear();
            self.batch_index = 0;
            for _ in 0..256 {
                let mut line = String::new();
                if self.reader.read_line(&mut line).map_err(|error| error.to_string())? == 0 { break; }
                self.batch.push(serde_json::from_str(&line).map_err(|error| format!("native DAG transcript JSON: {error}"))?);
            }
            if self.batch.is_empty() { return Err("native DAG transcript ended before the expected gate".into()); }
            self.batch.par_iter().enumerate().try_for_each(|(index, entry)| -> Result<(), String> {
                let record = entry.get("record").ok_or("native DAG gate record missing")?;
                verify_gate_json_with_setup(record, self.setup).map_err(|error| format!("native DAG batch gate {}: {error}", self.cursor + index + 1))
            })?;
        }
        let entry = &self.batch[self.batch_index];
        self.batch_index += 1;
        let expected_index = self.cursor + 1;
        if entry.get("gateIndex").and_then(Value::as_u64) != Some(expected_index as u64)
            || entry.get("label").and_then(Value::as_str) != Some(label)
            || entry.get("backend").and_then(Value::as_str) != Some("RUST") {
            return Err(format!("native DAG gate {} label/order mismatch", expected_index));
        }
        let record = entry.get("record").ok_or("native DAG gate record missing")?;
        let base = parse_session_json(record.get("baseSession").ok_or("native DAG base session missing")?, self.setup.setup_hash)?;
        if base.execution_id != self.execution_id || base.gate_id != expected_index as u64 || base.invocation != 0 {
            return Err(format!("native DAG gate {} session mismatch", expected_index));
        }
        let input_x = parse_cipher_json(record, "inputX")?;
        let input_y = parse_cipher_json(record, "inputY")?;
        if !cipher_equal(&input_x, left) || !cipher_equal(&input_y, right) {
            return Err(format!("native DAG gate {} input mismatch", expected_index));
        }
        let record_setup_hash = record.get("setup").and_then(|value| value.get("setupHash")).and_then(Value::as_str).ok_or("native DAG gate setup hash missing")?;
        if record_setup_hash != hex::encode(self.setup.setup_hash) {
            return Err(format!("native DAG gate {} setup mismatch", expected_index));
        }
        let output = parse_cipher_json(record, "output")?;
        self.cursor += 1;
        Ok(output)
    }
}

fn verify_dag_add_bits<V: DagGateVerifier>(verifier: &mut V, left: &[Cipher], right: &[Cipher], label: &str) -> Result<Vec<Cipher>, String> {
    if left.len() != right.len() || left.is_empty() { return Err("AddBits width mismatch".into()); }
    let mut output = Vec::with_capacity(left.len() + 1);
    let mut carry = verifier.gate(&left[0], &right[0], &format!("{label}/BIT_0/CARRY"))?;
    output.push(dag_xor_with_product(&left[0], &right[0], &carry));
    for bit in 1..left.len() {
        let product = verifier.gate(&left[bit], &right[bit], &format!("{label}/BIT_{bit}/PAIR_PRODUCT"))?;
        let pair_xor = dag_xor_with_product(&left[bit], &right[bit], &product);
        let carry_product = verifier.gate(&pair_xor, &carry, &format!("{label}/BIT_{bit}/CARRY_PRODUCT"))?;
        let sum_bit = dag_xor_with_product(&pair_xor, &carry, &carry_product);
        carry = scale_cipher(&add_cipher(&add_cipher(&add_cipher(&left[bit], &right[bit]), &carry), &scale_cipher(&sum_bit, -Fr::from(1u64))), Fr::from(2u64).inverse().unwrap());
        output.push(sum_bit);
    }
    output.push(carry);
    Ok(output)
}

fn verify_dag_sub_lt_bits<V: DagGateVerifier>(verifier: &mut V, left: &[Cipher], right: &[Cipher], label: &str) -> Result<(Vec<Cipher>, Cipher, Cipher, Cipher), String> {
    if left.len() != right.len() || left.is_empty() { return Err("SubLTBits width mismatch".into()); }
    let mut difference = Vec::with_capacity(left.len());
    let mut physical_last = verifier.gate(&left[0], &right[0], &format!("{label}/BIT_0/PRODUCT"))?;
    difference.push(dag_xor_with_product(&left[0], &right[0], &physical_last));
    let mut affine_term = right[0].clone();
    let mut borrow = dag_affine_subtract(&affine_term, &physical_last);
    for bit in 1..left.len() {
        let y_borrow = verifier.gate(&right[bit], &borrow, &format!("{label}/BIT_{bit}/Y_BORROW"))?;
        let y_xor_borrow = dag_xor_with_product(&right[bit], &borrow, &y_borrow);
        let x_product = verifier.gate(&left[bit], &y_xor_borrow, &format!("{label}/BIT_{bit}/X_PRODUCT"))?;
        difference.push(dag_xor_with_product(&left[bit], &y_xor_borrow, &x_product));
        affine_term = dag_affine_subtract(&add_cipher(&right[bit], &borrow), &y_borrow);
        physical_last = x_product;
        borrow = dag_affine_subtract(&affine_term, &physical_last);
    }
    Ok((difference, borrow, affine_term, physical_last))
}

/// Verify a complete native DAG in one public native process.  This path
/// validates the same gate equations as the single-gate verifier, checks every
/// canonical gate input/label/session edge, and reconstructs all affine
/// arithmetic in native projective form.
pub fn verify_dag_request(request: &Value) -> Result<Value, String> {
    let started = Instant::now();
    let setup = setup_from_json(request.get("setup").ok_or("setup missing")?)?;
    let execution_id = parse_hex32(request, "executionId")?;
    let tau = request.get("tau").and_then(Value::as_u64).ok_or("tau missing")?;
    let label_prefix = request.get("labelPrefix").and_then(Value::as_str).unwrap_or("N8");
    let vectors = request.get("bitVectors").and_then(Value::as_array).ok_or("bitVectors missing")?;
    let mut inputs = Vec::with_capacity(vectors.len());
    let mut width = None;
    for (row, vector) in vectors.iter().enumerate() {
        let entries = vector.as_array().ok_or("bit vector is not an array")?;
        if entries.is_empty() || width.is_some_and(|expected| expected != entries.len()) { return Err("bit vector widths disagree".into()); }
        width = Some(entries.len());
        inputs.push(entries.iter().enumerate().map(|(bit, value)| parse_cipher_value(value, &format!("bitVectors[{row}][{bit}]"))).collect::<Result<Vec<_>, _>>()?);
    }
    let width = width.ok_or("empty bit vectors")?;
    let entries = request.get("gates").and_then(Value::as_array).ok_or("native DAG gates missing")?;
    entries.par_iter().enumerate().try_for_each(|(index, entry)| -> Result<(), String> {
        let record = entry.get("record").ok_or("native DAG gate record missing")?;
        let record_setup_hash = record.get("setup").and_then(|value| value.get("setupHash")).and_then(Value::as_str).ok_or("native DAG gate setup hash missing")?;
        if record_setup_hash != hex::encode(setup.setup_hash) { return Err(format!("native DAG gate {} setup mismatch", index + 1)); }
        verify_gate_json_with_setup(record, &setup)
    })?;
    let mut verifier = DagVerifier { setup: &setup, execution_id, entries, cursor: 0 };
    let mut frontier = inputs;
    let mut aggregate_depth = 0_u64;
    while frontier.len() > 1 {
        let mut next = Vec::with_capacity(frontier.len() / 2);
        for pair in frontier.chunks_exact(2) {
            next.push(verify_dag_add_bits(&mut verifier, &pair[0], &pair[1], &format!("{label_prefix}_WEIGHTED_SUM/LEVEL_{aggregate_depth}/PAIR_{}", next.len()))?);
        }
        frontier = next;
        aggregate_depth += 1;
    }
    let aggregate = frontier.pop().ok_or("aggregate is empty")?;
    if aggregate.len() != width + aggregate_depth as usize { return Err("aggregate width mismatch".into()); }
    let threshold_bits: Vec<_> = (0..aggregate.len()).map(|bit| dag_public_bit((tau >> bit) & 1)).collect();
    let (difference, borrow, affine_term, physical_last) = verify_dag_sub_lt_bits(&mut verifier, &aggregate, &threshold_bits, &format!("{label_prefix}_THRESHOLD"))?;
    if verifier.cursor != entries.len() { return Err("native DAG transcript contains extra gates".into()); }
    let q = dag_affine_subtract(&affine_term, &physical_last);
    if !cipher_equal(&borrow, &q) { return Err("terminal Q mismatch".into()); }
    let result = dag_affine_subtract(&dag_public_bit(1), &borrow);
    Ok(json!({
        "schema": "-CGY-NATIVE/WEIGHTED-DAG-VERIFIED/V1",
        "gateCount": verifier.cursor,
        "aggregateDepth": aggregate_depth,
        "aggregate": aggregate.iter().map(cipher_json).collect::<Vec<_>>(),
        "comparison": {"difference": difference.iter().map(cipher_json).collect::<Vec<_>>(), "borrow": cipher_json(&borrow), "terminal": {"D": cipher_json(&affine_term), "CStar": cipher_json(&physical_last), "Q": cipher_json(&q)}},
        "result": cipher_json(&result),
        "verificationMs": started.elapsed().as_secs_f64() * 1000.0,
    }))
}

/// Public replay variant that consumes the canonical JSONL journal one gate at
/// a time.  It performs the same full gate verification and DAG edge checks as
/// `verify_dag_request`, but does not materialize all records in one JSON array.
pub fn verify_dag_file_request(request: &Value) -> Result<Value, String> {
    let started = Instant::now();
    let setup = setup_from_json(request.get("setup").ok_or("setup missing")?)?;
    let execution_id = parse_hex32(request, "executionId")?;
    let tau = request.get("tau").and_then(Value::as_u64).ok_or("tau missing")?;
    let label_prefix = request.get("labelPrefix").and_then(Value::as_str).unwrap_or("N8");
    let vectors = request.get("bitVectors").and_then(Value::as_array).ok_or("bitVectors missing")?;
    let transcript_path = request.get("transcriptPath").and_then(Value::as_str).ok_or("transcriptPath missing")?;
    let mut inputs = Vec::with_capacity(vectors.len());
    let mut width = None;
    for (row, vector) in vectors.iter().enumerate() {
        let entries = vector.as_array().ok_or("bit vector is not an array")?;
        if entries.is_empty() || width.is_some_and(|expected| expected != entries.len()) { return Err("bit vector widths disagree".into()); }
        width = Some(entries.len());
        inputs.push(entries.iter().enumerate().map(|(bit, value)| parse_cipher_value(value, &format!("bitVectors[{row}][{bit}]"))).collect::<Result<Vec<_>, _>>()?);
    }
    let width = width.ok_or("empty bit vectors")?;
    let reader = BufReader::new(File::open(transcript_path).map_err(|error| format!("open transcript: {error}"))?);
    let mut verifier = StreamDagVerifier { setup: &setup, execution_id, reader, cursor: 0, batch: Vec::new(), batch_index: 0 };
    let mut frontier = inputs;
    let mut aggregate_depth = 0_u64;
    while frontier.len() > 1 {
        let mut next = Vec::with_capacity(frontier.len() / 2);
        for pair in frontier.chunks_exact(2) {
            next.push(verify_dag_add_bits(&mut verifier, &pair[0], &pair[1], &format!("{label_prefix}_WEIGHTED_SUM/LEVEL_{aggregate_depth}/PAIR_{}", next.len()))?);
        }
        frontier = next;
        aggregate_depth += 1;
    }
    let aggregate = frontier.pop().ok_or("aggregate is empty")?;
    if aggregate.len() != width + aggregate_depth as usize { return Err("aggregate width mismatch".into()); }
    let threshold_bits: Vec<_> = (0..aggregate.len()).map(|bit| dag_public_bit((tau >> bit) & 1)).collect();
    let (difference, borrow, affine_term, physical_last) = verify_dag_sub_lt_bits(&mut verifier, &aggregate, &threshold_bits, &format!("{label_prefix}_THRESHOLD"))?;
    let mut trailing = String::new();
    if verifier.batch_index < verifier.batch.len() || verifier.reader.read_line(&mut trailing).map_err(|error| error.to_string())? != 0 {
        return Err("native DAG transcript contains extra gates".into());
    }
    let q = dag_affine_subtract(&affine_term, &physical_last);
    if !cipher_equal(&borrow, &q) { return Err("terminal Q mismatch".into()); }
    let result = dag_affine_subtract(&dag_public_bit(1), &borrow);
    Ok(json!({
        "schema": "-CGY-NATIVE/WEIGHTED-DAG-VERIFIED/V1",
        "gateCount": verifier.cursor,
        "aggregateDepth": aggregate_depth,
        "aggregate": aggregate.iter().map(cipher_json).collect::<Vec<_>>(),
        "comparison": {"difference": difference.iter().map(cipher_json).collect::<Vec<_>>(), "borrow": cipher_json(&borrow), "terminal": {"D": cipher_json(&affine_term), "CStar": cipher_json(&physical_last), "Q": cipher_json(&q)}},
        "result": cipher_json(&result),
        "verificationMs": started.elapsed().as_secs_f64() * 1000.0,
    }))
}
