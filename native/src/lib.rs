//! Compatibility facade retained for existing tools while the Rust workspace
//! is split into focused cryptography and protocol crates.

pub use cgy_crypto::{
    BASE8_X_DECIMAL, BASE8_Y_DECIMAL, FIELD_BYTES, FIELD_PRIME_DECIMAL, POINT_BYTES,
    SUBGROUP_ORDER_DECIMAL, ValidatedPoint,
};

pub use cgy_protocol::gate;
