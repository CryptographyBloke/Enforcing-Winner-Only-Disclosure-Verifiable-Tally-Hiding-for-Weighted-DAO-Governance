//! Rust-native witness generation, Groth16 proving, verification and ballot parsing.

use cgy_crypto::{FIELD_PRIME_DECIMAL, ValidatedPoint};
use serde::Serialize;

pub mod poseidon;
pub mod proving;

pub const PUBLIC_SIGNAL_COUNT: usize = 37;
pub const ENCRYPTED_WEIGHT_BITS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Ciphertext {
    pub r: PointCoordinates,
    pub s: PointCoordinates,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PointCoordinates {
    pub x: String,
    pub y: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdmittedBallotSignals {
    pub nullifier: String,
    pub ciphertexts: [Ciphertext; ENCRYPTED_WEIGHT_BITS],
    pub registry_root: String,
    pub poll_id: String,
    pub committee_key: PointCoordinates,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BallotSignalError {
    WrongSignalCount,
    NoncanonicalScalar,
    InvalidPoint,
}

impl std::fmt::Display for BallotSignalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for BallotSignalError {}

impl AdmittedBallotSignals {
    pub fn parse(signals: &[String]) -> Result<Self, BallotSignalError> {
        if signals.len() != PUBLIC_SIGNAL_COUNT {
            return Err(BallotSignalError::WrongSignalCount);
        }
        for scalar in [&signals[0], &signals[33], &signals[34]] {
            validate_decimal(scalar)?;
        }
        let mut ciphertexts = Vec::with_capacity(ENCRYPTED_WEIGHT_BITS);
        for bit in 0..ENCRYPTED_WEIGHT_BITS {
            let offset = 1 + bit * 4;
            let r = point(&signals[offset], &signals[offset + 1])?;
            let s = point(&signals[offset + 2], &signals[offset + 3])?;
            ciphertexts.push(Ciphertext { r, s });
        }
        let ciphertexts: [Ciphertext; ENCRYPTED_WEIGHT_BITS] = ciphertexts
            .try_into()
            .map_err(|_| BallotSignalError::WrongSignalCount)?;
        let committee_key = point(&signals[35], &signals[36])?;
        Ok(Self {
            nullifier: signals[0].clone(),
            ciphertexts,
            registry_root: signals[33].clone(),
            poll_id: signals[34].clone(),
            committee_key,
        })
    }
}

fn validate_decimal(value: &str) -> Result<(), BallotSignalError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(BallotSignalError::NoncanonicalScalar);
    }
    if value.len() > FIELD_PRIME_DECIMAL.len()
        || (value.len() == FIELD_PRIME_DECIMAL.len() && value >= FIELD_PRIME_DECIMAL)
    {
        return Err(BallotSignalError::NoncanonicalScalar);
    }
    Ok(())
}

fn point(x: &str, y: &str) -> Result<PointCoordinates, BallotSignalError> {
    ValidatedPoint::from_decimal(x, y).map_err(|_| BallotSignalError::InvalidPoint)?;
    Ok(PointCoordinates {
        x: x.to_owned(),
        y: y.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgy_crypto::{BASE8_X_DECIMAL, BASE8_Y_DECIMAL};

    #[test]
    fn parses_exact_frozen_public_signal_layout() {
        let mut signals = vec!["0".to_owned(); PUBLIC_SIGNAL_COUNT];
        for bit in 0..ENCRYPTED_WEIGHT_BITS {
            let offset = 1 + bit * 4;
            signals[offset] = BASE8_X_DECIMAL.into();
            signals[offset + 1] = BASE8_Y_DECIMAL.into();
            signals[offset + 2] = BASE8_X_DECIMAL.into();
            signals[offset + 3] = BASE8_Y_DECIMAL.into();
        }
        signals[35] = BASE8_X_DECIMAL.into();
        signals[36] = BASE8_Y_DECIMAL.into();
        let parsed = AdmittedBallotSignals::parse(&signals).unwrap();
        assert_eq!(parsed.ciphertexts.len(), 8);
        assert_eq!(parsed.committee_key.x, BASE8_X_DECIMAL);
    }

    #[test]
    fn rejects_wrong_layout_and_invalid_points() {
        assert_eq!(
            AdmittedBallotSignals::parse(&vec!["0".into(); 36]),
            Err(BallotSignalError::WrongSignalCount)
        );
        let mut signals = vec!["0".to_owned(); PUBLIC_SIGNAL_COUNT];
        signals[1] = "1".into();
        assert_eq!(
            AdmittedBallotSignals::parse(&signals),
            Err(BallotSignalError::InvalidPoint)
        );
    }
}
