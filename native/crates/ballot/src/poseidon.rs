//! Circomlib-compatible Poseidon over BN254 Fr for one- and two-input hashes.
//!
//! The round constants are extracted from the repository's pinned circomlibjs
//! reference package (`src/poseidon_constants.json`); the permutation follows
//! its unoptimized reference implementation. Keeping only t=2 and t=3 covers
//! the ballot's identity commitment, registry leaves/nodes and nullifier.

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, PrimeField};
use num_bigint::BigUint;
use serde::Deserialize;
use std::sync::OnceLock;

#[derive(Deserialize)]
struct ConstantDocument {
    #[serde(rename = "C")]
    c: Vec<Vec<String>>,
    #[serde(rename = "M")]
    m: Vec<Vec<Vec<String>>>,
}

struct PoseidonParameters {
    constants: Vec<Fr>,
    matrix: Vec<Vec<Fr>>,
}

static PARAMETERS: OnceLock<Vec<PoseidonParameters>> = OnceLock::new();

fn parameters() -> &'static [PoseidonParameters] {
    PARAMETERS.get_or_init(|| {
        let document: ConstantDocument =
            serde_json::from_str(include_str!("../data/poseidon_t2_t3.json"))
                .expect("bundled Circomlib Poseidon constants must parse");
        document
            .c
            .into_iter()
            .zip(document.m)
            .map(|(constants, matrix)| PoseidonParameters {
                constants: constants.iter().map(|value| constant(value)).collect(),
                matrix: matrix
                    .iter()
                    .map(|row| row.iter().map(|value| constant(value)).collect())
                    .collect(),
            })
            .collect()
    })
}

fn constant(value: &str) -> Fr {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let integer = BigUint::parse_bytes(value.as_bytes(), 16)
        .expect("Poseidon constants must be hexadecimal integers");
    Fr::from_be_bytes_mod_order(&integer.to_bytes_be())
}

/// Compute Circomlib's Poseidon hash for one or two BN254 scalar-field inputs.
pub fn hash(inputs: &[Fr]) -> Result<Fr, &'static str> {
    if !(1..=2).contains(&inputs.len()) {
        return Err("ballot Poseidon supports exactly one or two inputs");
    }
    let index = inputs.len() - 1;
    let t = inputs.len() + 1;
    let rounds_partial = [56usize, 57][index];
    let rounds_full = 8usize;
    let params = &parameters()[index];
    if params.constants.len() != (rounds_full + rounds_partial) * t
        || params.matrix.len() != t
        || params.matrix.iter().any(|row| row.len() != t)
    {
        return Err("bundled Circomlib Poseidon parameters have invalid dimensions");
    }

    let mut state = Vec::with_capacity(t);
    state.push(Fr::ZERO);
    state.extend_from_slice(inputs);
    for round in 0..rounds_full + rounds_partial {
        for (index, value) in state.iter_mut().enumerate() {
            *value += params.constants[round * t + index];
        }
        if round < rounds_full / 2 || round >= rounds_full / 2 + rounds_partial {
            for value in &mut state {
                *value = pow5(*value);
            }
        } else {
            state[0] = pow5(state[0]);
        }
        let mut mixed = vec![Fr::ZERO; t];
        for i in 0..t {
            for j in 0..t {
                mixed[i] += params.matrix[i][j] * state[j];
            }
        }
        state = mixed;
    }
    Ok(state[0])
}

fn pow5(value: Fr) -> Fr {
    let square = value.square();
    square.square() * value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_circomlib_poseidon_pair_vector() {
        let digest = hash(&[Fr::from(1u64), Fr::from(2u64)]).unwrap();
        assert_eq!(
            digest.into_bigint().to_string(),
            "7853200120776062878684798364095072458815029376092732009249414926327459813530"
        );
    }

    #[test]
    fn rejects_unsupported_arity() {
        assert!(hash(&[]).is_err());
        assert!(hash(&[Fr::ONE, Fr::ONE, Fr::ONE]).is_err());
    }
}
