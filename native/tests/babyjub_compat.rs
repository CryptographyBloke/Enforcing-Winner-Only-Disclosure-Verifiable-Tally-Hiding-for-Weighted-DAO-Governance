use cgy_native::{
    FIELD_PRIME_DECIMAL, SUBGROUP_ORDER_DECIMAL, ValidatedPoint,
};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../testdata/babyjub_compat_vectors.json"))
        .expect("compatibility fixture must be valid JSON")
}

fn point(data: &Value, name: &str) -> ValidatedPoint {
    let value = &data["points"][name];
    let decoded = ValidatedPoint::from_decimal(
        value["x"].as_str().expect("x must be decimal"),
        value["y"].as_str().expect("y must be decimal"),
    )
    .expect("fixture point must validate");
    assert_eq!(
        hex::encode(decoded.encode_affine_le64()),
        value["le64"].as_str().expect("encoding must be hex"),
        "{name} external encoding differs from JS"
    );
    decoded
}

fn assert_point(data: &Value, name: &str, actual: &ValidatedPoint) {
    let expected = &data["points"][name];
    assert_eq!(
        actual.affine_decimal(),
        (
            expected["x"].as_str().unwrap().to_owned(),
            expected["y"].as_str().unwrap().to_owned(),
        ),
        "{name} affine coordinates differ from JS"
    );
    assert_eq!(
        hex::encode(actual.encode_affine_le64()),
        expected["le64"].as_str().unwrap(),
        "{name} external encoding differs from JS"
    );
}

#[test]
fn exact_external_points_round_trip() {
    let data = fixture();
    assert_eq!(data["fieldPrime"].as_str().unwrap(), FIELD_PRIME_DECIMAL);
    assert_eq!(data["subgroupOrder"].as_str().unwrap(), SUBGROUP_ORDER_DECIMAL);
    for name in [
        "identity",
        "base8",
        "twoBase8",
        "randomBase8",
        "committeeH",
        "sampleCiphertextR",
        "sampleCiphertextS",
        "sampleHtilde",
    ] {
        let native = point(&data, name);
        let encoded = native.encode_affine_le64();
        let decoded = ValidatedPoint::decode_affine_le64(&encoded).unwrap();
        assert_point(&data, name, &decoded);
    }
}

#[test]
fn native_projective_operations_match_js_affine_results() {
    let data = fixture();
    let base8 = point(&data, "base8");
    let committee_h = point(&data, "committeeH");
    let sample_r = point(&data, "sampleCiphertextR");
    let sample_s = point(&data, "sampleCiphertextS");
    let scalar = data["randomScalar"].as_str().unwrap();

    assert_point(&data, "identity", &ValidatedPoint::identity());
    assert_point(&data, "twoBase8", &base8.add(&base8));
    assert_point(
        &data,
        "randomBase8",
        &base8.scalar_mul_decimal(scalar).unwrap(),
    );
    assert_point(&data, "sampleAddition", &sample_r.add(&sample_s));
    assert_point(&data, "sampleNegation", &sample_r.negate());
    assert_point(
        &data,
        "sampleScalarMultiplication",
        &committee_h.scalar_mul_decimal(scalar).unwrap(),
    );
}
