//! Native arithmetic for the frozen CGY BabyJub profile.
//!
//! External points remain exact circomlib affine `(x,y)` coordinates. Validated
//! points are converted once to arkworks projective form for group operations
//! and normalized only at the serialization boundary.

use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, Zero};
use std::{fmt, str::FromStr, sync::OnceLock};
use taceo_ark_babyjubjub::{EdwardsAffine, EdwardsProjective, Fq, Fr};

pub mod gate;

pub const FIELD_BYTES: usize = 32;
pub const POINT_BYTES: usize = FIELD_BYTES * 2;
pub const FIELD_PRIME_DECIMAL: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";
pub const SUBGROUP_ORDER_DECIMAL: &str =
    "2736030358979909402780800718157159386076813972158567259200215660948447373041";
pub const BASE8_X_DECIMAL: &str =
    "5299619240641551281634865583518297030282874472190772894086521144482721001553";
pub const BASE8_Y_DECIMAL: &str =
    "16950150798460657717958625567821834550301663161624707787222815936182638968203";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointError {
    NonCanonicalCoordinate,
    InvalidEncodingLength,
    NotOnCurve,
    NotInPrimeSubgroup,
}

impl fmt::Display for PointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for PointError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedPoint(EdwardsProjective);

impl ValidatedPoint {
    pub fn identity() -> Self {
        Self(EdwardsProjective::zero())
    }

    pub fn base8() -> Self {
        static BASE8_POINT: OnceLock<ValidatedPoint> = OnceLock::new();
        BASE8_POINT.get_or_init(|| {
            Self::from_decimal(BASE8_X_DECIMAL, BASE8_Y_DECIMAL)
                .expect("the frozen Base8 constant must validate")
        }).clone()
    }

    pub fn from_decimal(x: &str, y: &str) -> Result<Self, PointError> {
        let x = parse_canonical_field(x)?;
        let y = parse_canonical_field(y)?;
        Self::from_affine(EdwardsAffine::new_unchecked(x, y))
    }

    pub fn decode_affine_le64(input: &[u8]) -> Result<Self, PointError> {
        if input.len() != POINT_BYTES {
            return Err(PointError::InvalidEncodingLength);
        }
        let x = Fq::from_le_bytes_mod_order(&input[..FIELD_BYTES]);
        let y = Fq::from_le_bytes_mod_order(&input[FIELD_BYTES..]);
        if fixed_le_bytes(&x) != input[..FIELD_BYTES]
            || fixed_le_bytes(&y) != input[FIELD_BYTES..]
        {
            return Err(PointError::NonCanonicalCoordinate);
        }
        Self::from_affine(EdwardsAffine::new_unchecked(x, y))
    }

    fn from_affine(affine: EdwardsAffine) -> Result<Self, PointError> {
        if !affine.is_on_curve() {
            return Err(PointError::NotOnCurve);
        }
        if !affine.is_in_correct_subgroup_assuming_on_curve() {
            return Err(PointError::NotInPrimeSubgroup);
        }
        Ok(Self(affine.into_group()))
    }

    pub fn add(&self, other: &Self) -> Self {
        Self(self.0 + other.0)
    }

    pub fn negate(&self) -> Self {
        Self(-self.0)
    }

    pub fn scalar_mul_decimal(&self, scalar: &str) -> Result<Self, PointError> {
        let scalar = parse_canonical_scalar(scalar)?;
        Ok(self.scalar_mul_fr(scalar))
    }

    pub(crate) fn scalar_mul_fr(&self, scalar: Fr) -> Self {
        Self(self.0.mul_bigint(scalar.into_bigint()))
    }

    pub(crate) fn from_fq(x: Fq, y: Fq) -> Result<Self, PointError> {
        Self::from_affine(EdwardsAffine::new_unchecked(x, y))
    }

    pub fn affine_decimal(&self) -> (String, String) {
        let affine = self.0.into_affine();
        (affine.x.to_string(), affine.y.to_string())
    }

    pub fn encode_affine_le64(&self) -> [u8; POINT_BYTES] {
        let affine = self.0.into_affine();
        let mut output = [0_u8; POINT_BYTES];
        output[..FIELD_BYTES].copy_from_slice(&fixed_le_bytes(&affine.x));
        output[FIELD_BYTES..].copy_from_slice(&fixed_le_bytes(&affine.y));
        output
    }
}

fn parse_canonical_field(value: &str) -> Result<Fq, PointError> {
    if !is_canonical_decimal_below(value, FIELD_PRIME_DECIMAL) {
        return Err(PointError::NonCanonicalCoordinate);
    }
    Fq::from_str(value).map_err(|_| PointError::NonCanonicalCoordinate)
}

fn parse_canonical_scalar(value: &str) -> Result<Fr, PointError> {
    if !is_canonical_decimal_below(value, SUBGROUP_ORDER_DECIMAL) {
        return Err(PointError::NonCanonicalCoordinate);
    }
    Fr::from_str(value).map_err(|_| PointError::NonCanonicalCoordinate)
}

fn is_canonical_decimal_below(value: &str, modulus: &str) -> bool {
    !value.is_empty()
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value.len() < modulus.len() || (value.len() == modulus.len() && value < modulus))
}

fn fixed_le_bytes<F: PrimeField>(value: &F) -> [u8; FIELD_BYTES] {
    let bytes = value.into_bigint().to_bytes_le();
    let mut output = [0_u8; FIELD_BYTES];
    output[..bytes.len()].copy_from_slice(&bytes);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_moduli_and_base8_are_exact() {
        assert_eq!(Fq::MODULUS.to_string(), FIELD_PRIME_DECIMAL);
        assert_eq!(Fr::MODULUS.to_string(), SUBGROUP_ORDER_DECIMAL);
        assert_eq!(
            ValidatedPoint::base8().affine_decimal(),
            (BASE8_X_DECIMAL.to_owned(), BASE8_Y_DECIMAL.to_owned())
        );
    }

    #[test]
    fn rejects_noncanonical_external_coordinates_and_lengths() {
        assert_eq!(
            ValidatedPoint::from_decimal("00", "1"),
            Err(PointError::NonCanonicalCoordinate)
        );
        assert_eq!(
            ValidatedPoint::from_decimal(FIELD_PRIME_DECIMAL, "1"),
            Err(PointError::NonCanonicalCoordinate)
        );
        assert_eq!(
            ValidatedPoint::decode_affine_le64(&[0_u8; POINT_BYTES - 1]),
            Err(PointError::InvalidEncodingLength)
        );
    }
}
