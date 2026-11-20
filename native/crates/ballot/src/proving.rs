//! Rust-native generation and verification for the frozen Circom ballot.
//!
//! The witness generator is ark-circom's Circom WASM interpreter and the
//! proving key is read from the original SnarkJS `.zkey`. The proof system,
//! circuit relation, and public-signal layout therefore remain unchanged.

use crate::{AdmittedBallotSignals, PUBLIC_SIGNAL_COUNT, poseidon};
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_circom::{CircomCircuit, CircomConfig, CircomReduction, read_zkey};
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField, Zero};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use cgy_crypto::{SUBGROUP_ORDER_DECIMAL, ValidatedPoint};
use num_bigint::{BigInt, BigUint};
use rand::{RngCore, thread_rng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    path::Path,
    str::FromStr,
    time::Instant,
};

const REGISTRY_DEPTH: usize = 10;
const REGISTRY_CAPACITY: usize = 1 << REGISTRY_DEPTH;
const WEIGHT_WIDTH: usize = 8;

#[derive(Clone, Debug)]
pub struct BallotWitness {
    pub identity_secret: String,
    pub weight: String,
    pub vote: String,
    pub path_elements: Vec<String>,
    pub path_indices: Vec<u8>,
    pub randomness: Vec<String>,
    pub root: String,
    pub poll_id: String,
    pub committee_key: [String; 2],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnarkJsProof {
    pub pi_a: [String; 3],
    pub pi_b: [[String; 2]; 3],
    pub pi_c: [String; 3],
    pub protocol: String,
    pub curve: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BallotProof {
    pub proof: SnarkJsProof,
    #[serde(rename = "publicSignals")]
    pub public_signals: Vec<String>,
    #[serde(default)]
    pub witness_ms: f64,
    #[serde(default)]
    pub proving_ms: f64,
    #[serde(default)]
    pub verification_ms: f64,
    #[serde(default)]
    pub ballot_pipeline_ms: f64,
}

pub struct BallotProver {
    config: CircomConfig<Fr>,
    proving_key: ProvingKey<Bn254>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BallotProfile {
    pub registry_root: String,
    pub poll_id: String,
    pub public_key: [String; 2],
    pub ballots: Vec<BallotProof>,
}

impl BallotProver {
    pub fn new(
        wasm_path: impl AsRef<Path>,
        r1cs_path: impl AsRef<Path>,
        zkey_path: impl AsRef<Path>,
    ) -> Result<Self, String> {
        let config = CircomConfig::<Fr>::new(wasm_path, r1cs_path)
            .map_err(|error| format!("load Circom WASM/R1CS: {error}"))?;
        let mut zkey = File::open(zkey_path.as_ref()).map_err(|error| {
            format!(
                "open Groth16 zkey {}: {error}",
                zkey_path.as_ref().display()
            )
        })?;
        let (proving_key, r1cs_matrices) =
            read_zkey(&mut zkey).map_err(|error| format!("parse SnarkJS zkey: {error}"))?;
        let public_signal_count = proving_key.vk.gamma_abc_g1.len().saturating_sub(1);
        if public_signal_count != PUBLIC_SIGNAL_COUNT {
            return Err(format!(
                "zkey public input count is {public_signal_count}; expected {PUBLIC_SIGNAL_COUNT}"
            ));
        }
        if config.r1cs.num_inputs != r1cs_matrices.num_instance_variables
            || config.r1cs.constraints.len() != r1cs_matrices.num_constraints
        {
            return Err(format!(
                "Circom WASM/R1CS does not match the proving key (inputs {}/{}, constraints {}/{})",
                config.r1cs.num_inputs,
                r1cs_matrices.num_instance_variables,
                config.r1cs.constraints.len(),
                r1cs_matrices.num_constraints,
            ));
        }
        Ok(Self {
            config,
            proving_key,
        })
    }

    pub fn prove(&mut self, witness: &BallotWitness) -> Result<BallotProof, String> {
        validate_witness(witness)?;
        let mut inputs: HashMap<String, Vec<BigInt>> = HashMap::new();
        push(&mut inputs, "identitySecret", &witness.identity_secret)?;
        push(&mut inputs, "weight", &witness.weight)?;
        push(&mut inputs, "vote", &witness.vote)?;
        for value in &witness.path_elements {
            push(&mut inputs, "pathElements", value)?;
        }
        for value in &witness.path_indices {
            inputs
                .entry("pathIndices".to_owned())
                .or_default()
                .push(BigInt::from(*value));
        }
        for value in &witness.randomness {
            push(&mut inputs, "r", value)?;
        }
        push(&mut inputs, "root", &witness.root)?;
        push(&mut inputs, "pollId", &witness.poll_id)?;
        for value in &witness.committee_key {
            push(&mut inputs, "PK", value)?;
        }

        let started = Instant::now();
        self.config.sanity_check = true;
        let witness_started = Instant::now();
        let assignment = self
            .config
            .wtns
            .calculate_witness_element::<Fr, _>(&mut self.config.store, inputs, true)
            .map_err(|error| format!("Circom witness generation failed: {error}"))?;
        let witness_ms = witness_started.elapsed().as_secs_f64() * 1000.0;
        // CircomBuilder::setup in ark-circom disables this map before proving:
        // the WASM-generated witness already follows the R1CS wire order.
        let mut r1cs = self.config.r1cs.clone();
        r1cs.wire_mapping = None;
        let circuit = CircomCircuit {
            r1cs,
            witness: Some(assignment),
        };
        let public = circuit
            .get_public_inputs()
            .ok_or("Circom witness did not contain public inputs")?;
        if public.len() != PUBLIC_SIGNAL_COUNT {
            return Err(format!(
                "generated {} public signals; expected {PUBLIC_SIGNAL_COUNT}",
                public.len()
            ));
        }

        let mut rng = thread_rng();
        let proving_started = Instant::now();
        let proof = Groth16::<Bn254, CircomReduction>::prove(&self.proving_key, circuit, &mut rng)
            .map_err(|error| format!("Rust Groth16 proving failed: {error}"))?;
        let proving_ms = proving_started.elapsed().as_secs_f64() * 1000.0;
        let verification_started = Instant::now();
        let valid =
            Groth16::<Bn254, CircomReduction>::verify(&self.proving_key.vk, &public, &proof)
                .map_err(|error| format!("Rust Groth16 verification failed: {error}"))?;
        let verification_ms = verification_started.elapsed().as_secs_f64() * 1000.0;
        if !valid {
            return Err(
                "Rust-generated Groth16 proof did not verify against the zkey verification key"
                    .into(),
            );
        }

        let public_signals: Vec<String> = public
            .iter()
            .map(|signal| signal.into_bigint().to_string())
            .collect();
        AdmittedBallotSignals::parse(&public_signals).map_err(|error| {
            format!("generated public signals failed ballot structural validation: {error}")
        })?;
        if public_signals[33] != witness.root
            || public_signals[34] != witness.poll_id
            || public_signals[35] != witness.committee_key[0]
            || public_signals[36] != witness.committee_key[1]
        {
            return Err("generated public signal order/root/poll/committee key differs from the supplied ballot witness".into());
        }
        Ok(BallotProof {
            proof: snarkjs_proof(&proof),
            public_signals,
            witness_ms,
            proving_ms,
            verification_ms,
            ballot_pipeline_ms: started.elapsed().as_secs_f64() * 1000.0,
        })
    }

    pub fn verification_key(&self) -> &VerifyingKey<Bn254> {
        &self.proving_key.vk
    }
}

/// Generate the fixed-depth Poseidon registry and fresh ballot witnesses, then
/// prove each ballot with the frozen circuit's original SnarkJS zkey.
pub fn prove_fresh_profile(
    prover: &mut BallotProver,
    count: usize,
    votes: &[u8],
    weights: &[u8],
    poll_id: &str,
    committee_key: [String; 2],
) -> Result<BallotProfile, String> {
    if count == 0 || count > REGISTRY_CAPACITY || votes.len() != count || weights.len() != count {
        return Err(format!(
            "profile requires 1..{REGISTRY_CAPACITY} ballots and matching vote/weight arrays"
        ));
    }
    if votes.iter().any(|vote| *vote > 1) {
        return Err("vote vector must contain only bits".into());
    }
    let _ = parse_fr(poll_id, "pollId")?;
    ValidatedPoint::from_decimal(&committee_key[0], &committee_key[1])
        .map_err(|error| format!("committee public key is invalid: {error}"))?;

    let mut rng = thread_rng();
    let mut identities = Vec::with_capacity(count);
    let mut unique = HashSet::with_capacity(count);
    while identities.len() < count {
        let identity = random_subgroup_scalar(&mut rng);
        if unique.insert(identity.to_string()) {
            identities.push(identity);
        }
    }
    let mut levels: Vec<Vec<Fr>> = Vec::with_capacity(REGISTRY_DEPTH + 1);
    let mut leaves = vec![Fr::ZERO; REGISTRY_CAPACITY];
    let mut id_commitments = Vec::with_capacity(count);
    for (index, identity) in identities.iter().enumerate() {
        let commitment = poseidon::hash(&[*identity]).map_err(str::to_owned)?;
        let leaf = poseidon::hash(&[commitment, Fr::from(weights[index] as u64)])
            .map_err(str::to_owned)?;
        id_commitments.push(commitment);
        leaves[index] = leaf;
    }
    levels.push(leaves);
    for _ in 0..REGISTRY_DEPTH {
        let previous = levels.last().expect("registry has a leaf level");
        let mut next = Vec::with_capacity(previous.len() / 2);
        for pair in previous.chunks_exact(2) {
            next.push(poseidon::hash(&[pair[0], pair[1]]).map_err(str::to_owned)?);
        }
        levels.push(next);
    }
    let root = levels[REGISTRY_DEPTH][0];
    let root_decimal = root.into_bigint().to_string();

    let mut ballots = Vec::with_capacity(count);
    for index in 0..count {
        let mut path_elements = Vec::with_capacity(REGISTRY_DEPTH);
        let mut path_indices = Vec::with_capacity(REGISTRY_DEPTH);
        let mut position = index;
        for level in levels.iter().take(REGISTRY_DEPTH) {
            path_elements.push(level[position ^ 1].into_bigint().to_string());
            path_indices.push((position & 1) as u8);
            position >>= 1;
        }
        let randomness = (0..WEIGHT_WIDTH)
            .map(|_| random_subgroup_scalar(&mut rng).to_string())
            .collect();
        let witness = BallotWitness {
            identity_secret: identities[index].into_bigint().to_string(),
            weight: weights[index].to_string(),
            vote: votes[index].to_string(),
            path_elements,
            path_indices,
            randomness,
            root: root_decimal.clone(),
            poll_id: poll_id.to_owned(),
            committee_key: committee_key.clone(),
        };
        let ballot = prover.prove(&witness)?;
        if ballot.public_signals[33] != root_decimal {
            return Err("ballot registry root differs from generated registry".into());
        }
        ballots.push(ballot);
    }
    // Keep only public proofs in the returned object; identity secrets and paths
    // are local temporaries and are never serialized into an evidence bundle.
    let _ = id_commitments;
    Ok(BallotProfile {
        registry_root: root_decimal,
        poll_id: poll_id.to_owned(),
        public_key: committee_key,
        ballots,
    })
}

pub fn verify_snarkjs_proof(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_signals: &[String],
) -> Result<bool, String> {
    if public_signals.len() != PUBLIC_SIGNAL_COUNT {
        return Err("SnarkJS proof must contain exactly 37 public signals".into());
    }
    let public: Result<Vec<Fr>, _> = public_signals
        .iter()
        .map(|value| parse_fr(value, "public signal"))
        .collect();
    let public = public.map_err(|_| "public signal is not a canonical BN254 scalar")?;
    Groth16::<Bn254, CircomReduction>::verify(vk, &public, proof)
        .map_err(|error| format!("Groth16 verification failed: {error}"))
}

pub fn parse_snarkjs_proof(value: &Value) -> Result<Proof<Bn254>, String> {
    if value.get("protocol").and_then(Value::as_str) != Some("groth16")
        || value.get("curve").and_then(Value::as_str) != Some("bn128")
    {
        return Err("proof must be Groth16 over bn128".into());
    }
    let a = value
        .get("pi_a")
        .and_then(Value::as_array)
        .ok_or("proof.pi_a missing")?;
    let b = value
        .get("pi_b")
        .and_then(Value::as_array)
        .ok_or("proof.pi_b missing")?;
    let c = value
        .get("pi_c")
        .and_then(Value::as_array)
        .ok_or("proof.pi_c missing")?;
    if a.len() < 2 || b.len() < 2 || c.len() < 2 {
        return Err("proof point coordinates are incomplete".into());
    }
    let read = |v: &Value| -> Result<String, String> {
        v.as_str()
            .map(str::to_owned)
            .or_else(|| v.as_number().map(ToString::to_string))
            .ok_or_else(|| "proof coordinate must be a decimal string".to_owned())
    };
    let g1 = |point: &[Value]| -> Result<G1Affine, String> {
        checked_g1(parse_fq(&read(&point[0])?)?, parse_fq(&read(&point[1])?)?)
    };
    let b0 = b[0].as_array().ok_or("proof.pi_b[0] missing")?;
    let b1 = b[1].as_array().ok_or("proof.pi_b[1] missing")?;
    if b0.len() < 2 || b1.len() < 2 {
        return Err("proof.pi_b coordinates incomplete".into());
    }
    // SnarkJS verification-key and proof JSON use the same Fq2 coefficient order.
    let b_x = Fq2::new(parse_fq(&read(&b0[0])?)?, parse_fq(&read(&b0[1])?)?);
    let b_y = Fq2::new(parse_fq(&read(&b1[0])?)?, parse_fq(&read(&b1[1])?)?);
    Ok(Proof {
        a: g1(a)?,
        b: checked_g2(b_x, b_y)?,
        c: g1(c)?,
    })
}

pub fn parse_snarkjs_verification_key(value: &Value) -> Result<VerifyingKey<Bn254>, String> {
    if value.get("protocol").and_then(Value::as_str) != Some("groth16")
        || value.get("curve").and_then(Value::as_str) != Some("bn128")
    {
        return Err("verification key must be Groth16 over bn128".into());
    }
    let read_coord = |v: &Value| -> Result<String, String> {
        v.as_str()
            .map(str::to_owned)
            .or_else(|| v.as_number().map(ToString::to_string))
            .ok_or_else(|| "verification key coordinate missing".to_owned())
    };
    let g1 = |name: &str| -> Result<G1Affine, String> {
        let point = value
            .get(name)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("verification key {name} missing"))?;
        if point.len() < 2 {
            return Err(format!("verification key {name} incomplete"));
        }
        checked_g1(
            parse_fq(&read_coord(&point[0])?)?,
            parse_fq(&read_coord(&point[1])?)?,
        )
    };
    let g2 = |name: &str| -> Result<G2Affine, String> {
        let point = value
            .get(name)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("verification key {name} missing"))?;
        if point.len() < 2 {
            return Err(format!("verification key {name} incomplete"));
        }
        let x = point[0]
            .as_array()
            .ok_or_else(|| format!("verification key {name} x missing"))?;
        let y = point[1]
            .as_array()
            .ok_or_else(|| format!("verification key {name} y missing"))?;
        if x.len() < 2 || y.len() < 2 {
            return Err(format!("verification key {name} Fq2 coordinate incomplete"));
        }
        checked_g2(
            Fq2::new(
                parse_fq(&read_coord(&x[0])?)?,
                parse_fq(&read_coord(&x[1])?)?,
            ),
            Fq2::new(
                parse_fq(&read_coord(&y[0])?)?,
                parse_fq(&read_coord(&y[1])?)?,
            ),
        )
    };
    let ic_json = value
        .get("IC")
        .and_then(Value::as_array)
        .ok_or("verification key IC missing")?;
    let mut gamma_abc_g1 = Vec::with_capacity(ic_json.len());
    for point in ic_json {
        let point = point
            .as_array()
            .ok_or("verification key IC point malformed")?;
        if point.len() < 2 {
            return Err("verification key IC point incomplete".into());
        }
        gamma_abc_g1.push(checked_g1(
            parse_fq(&read_coord(&point[0])?)?,
            parse_fq(&read_coord(&point[1])?)?,
        )?);
    }
    if gamma_abc_g1.len() != PUBLIC_SIGNAL_COUNT + 1 {
        return Err("verification key IC count does not encode 37 public signals".into());
    }
    Ok(VerifyingKey {
        alpha_g1: g1("vk_alpha_1")?,
        beta_g2: g2("vk_beta_2")?,
        gamma_g2: g2("vk_gamma_2")?,
        delta_g2: g2("vk_delta_2")?,
        gamma_abc_g1,
    })
}

fn snarkjs_proof(proof: &Proof<Bn254>) -> SnarkJsProof {
    let g1 = |point: &G1Affine| {
        [
            point.x.into_bigint().to_string(),
            point.y.into_bigint().to_string(),
            "1".into(),
        ]
    };
    SnarkJsProof {
        pi_a: g1(&proof.a),
        pi_b: [
            [
                proof.b.x.c0.into_bigint().to_string(),
                proof.b.x.c1.into_bigint().to_string(),
            ],
            [
                proof.b.y.c0.into_bigint().to_string(),
                proof.b.y.c1.into_bigint().to_string(),
            ],
            ["1".into(), "0".into()],
        ],
        pi_c: g1(&proof.c),
        protocol: "groth16".into(),
        curve: "bn128".into(),
    }
}

fn validate_witness(witness: &BallotWitness) -> Result<(), String> {
    if witness.path_elements.len() != REGISTRY_DEPTH || witness.path_indices.len() != REGISTRY_DEPTH
    {
        return Err("ballot witness must contain a depth-10 registry path".into());
    }
    if witness.randomness.len() != WEIGHT_WIDTH {
        return Err("ballot witness must contain exactly eight encryption scalars".into());
    }
    let identity = parse_subgroup_scalar(&witness.identity_secret, "identitySecret")?;
    if identity.is_zero() {
        return Err("identitySecret must be nonzero".into());
    }
    let weight = parse_fr(&witness.weight, "weight")?;
    if weight.into_bigint() > Fr::from(255u64).into_bigint() {
        return Err("weight must fit uint8".into());
    }
    let vote = parse_fr(&witness.vote, "vote")?;
    if vote != Fr::ZERO && vote != Fr::ONE {
        return Err("vote must be a bit".into());
    }
    for path in &witness.path_elements {
        let _ = parse_fr(path, "path element")?;
    }
    if witness.path_indices.iter().any(|index| *index > 1) {
        return Err("registry path indices must be bits".into());
    }
    for randomness in &witness.randomness {
        let random = parse_subgroup_scalar(randomness, "encryption randomness")?;
        if random.is_zero() {
            return Err("encryption randomness must be nonzero".into());
        }
    }
    let _ = parse_fr(&witness.root, "registry root")?;
    let _ = parse_fr(&witness.poll_id, "pollId")?;
    ValidatedPoint::from_decimal(&witness.committee_key[0], &witness.committee_key[1])
        .map_err(|error| format!("committee public key is invalid: {error}"))?;
    Ok(())
}

fn random_subgroup_scalar(rng: &mut impl RngCore) -> Fr {
    let order =
        BigUint::from_str(SUBGROUP_ORDER_DECIMAL).expect("BabyJub subgroup order is decimal");
    let space = BigUint::from(1u8) << 256usize;
    let limit = &space - (&space % &order);
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let candidate = BigUint::from_bytes_be(&bytes);
        if candidate >= limit {
            continue;
        }
        let scalar = candidate % &order;
        if scalar != BigUint::from(0u8) {
            return Fr::from_be_bytes_mod_order(&scalar.to_bytes_be());
        }
    }
}

fn push(inputs: &mut HashMap<String, Vec<BigInt>>, name: &str, value: &str) -> Result<(), String> {
    let parsed =
        BigInt::from_str(value).map_err(|_| format!("{name} must be a decimal integer"))?;
    if parsed.sign() == num_bigint::Sign::Minus {
        return Err(format!("{name} cannot be negative"));
    }
    inputs.entry(name.to_owned()).or_default().push(parsed);
    Ok(())
}

fn parse_fr(value: &str, name: &str) -> Result<Fr, String> {
    parse_canonical_field::<Fr>(value, name)
}

fn parse_subgroup_scalar(value: &str, name: &str) -> Result<Fr, String> {
    let parsed = BigUint::from_str(value)
        .map_err(|_| format!("{name} is not an unsigned decimal integer"))?;
    let order = BigUint::from_str(SUBGROUP_ORDER_DECIMAL)
        .map_err(|_| "invalid BabyJub subgroup-order constant")?;
    if parsed >= order {
        return Err(format!("{name} must be below the BabyJub subgroup order"));
    }
    Ok(Fr::from_be_bytes_mod_order(&parsed.to_bytes_be()))
}

fn parse_fq(value: &str) -> Result<Fq, String> {
    parse_canonical_field::<Fq>(value, "proof coordinate")
        .map_err(|_| "proof coordinate is not a canonical BN254 base-field element".to_owned())
}

fn parse_canonical_field<F: PrimeField>(value: &str, name: &str) -> Result<F, String> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!(
            "{name} must be a canonical unsigned decimal integer"
        ));
    }
    let integer = BigUint::from_str(value)
        .map_err(|_| format!("{name} is not an unsigned decimal integer"))?;
    let modulus = BigUint::from_bytes_le(&F::MODULUS.to_bytes_le());
    if integer >= modulus {
        return Err(format!("{name} is outside the field"));
    }
    Ok(F::from_be_bytes_mod_order(&integer.to_bytes_be()))
}

fn checked_g1(x: Fq, y: Fq) -> Result<G1Affine, String> {
    let point = G1Affine::new_unchecked(x, y);
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err("Groth16 G1 point is not in the correct subgroup".into());
    }
    Ok(point)
}

fn checked_g2(x: Fq2, y: Fq2) -> Result<G2Affine, String> {
    let point = G2Affine::new_unchecked(x, y);
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err("Groth16 G2 point is not in the correct subgroup".into());
    }
    Ok(point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgy_crypto::{BASE8_X_DECIMAL, BASE8_Y_DECIMAL};

    #[test]
    fn rejects_malformed_ballot_witness_before_wasm_execution() {
        let witness = BallotWitness {
            identity_secret: "1".into(),
            weight: "256".into(),
            vote: "0".into(),
            path_elements: vec!["0".into(); REGISTRY_DEPTH],
            path_indices: vec![0; REGISTRY_DEPTH],
            randomness: vec!["1".into(); WEIGHT_WIDTH],
            root: "0".into(),
            poll_id: "1".into(),
            committee_key: [BASE8_X_DECIMAL.into(), BASE8_Y_DECIMAL.into()],
        };
        assert!(validate_witness(&witness).unwrap_err().contains("uint8"));
    }

    #[test]
    fn rejects_noncanonical_and_out_of_range_public_scalars() {
        assert!(parse_fr("01", "test").is_err());
        assert!(
            parse_fr(
                "21888242871839275222246405745257275088548364400416034343698204186575808495617",
                "test"
            )
            .is_err()
        );
        assert!(parse_fr("0", "test").is_ok());
    }

    #[test]
    fn parses_the_frozen_snarkjs_proof_coordinate_order() {
        let value = serde_json::json!({
            "pi_a":["1","2","1"],
            "pi_b":[["3","4"],["5","6"],["1","0"]],
            "pi_c":["7","8","1"],
            "protocol":"groth16","curve":"bn128"
        });
        let error = parse_snarkjs_proof(&value).unwrap_err();
        assert!(error.contains("correct subgroup"));
    }

    #[test]
    fn rejects_wrong_proof_system_and_truncated_points() {
        let wrong_protocol = serde_json::json!({
            "pi_a":["1","2","1"],
            "pi_b":[["3","4"],["5","6"],["1","0"]],
            "pi_c":["7","8","1"],
            "protocol":"plonk","curve":"bn128"
        });
        assert!(
            parse_snarkjs_proof(&wrong_protocol)
                .unwrap_err()
                .contains("Groth16")
        );

        let truncated = serde_json::json!({
            "pi_a":["1"],
            "pi_b":[["3","4"],["5","6"]],
            "pi_c":["7","8"],
            "protocol":"groth16","curve":"bn128"
        });
        assert!(parse_snarkjs_proof(&truncated).is_err());
    }
}
