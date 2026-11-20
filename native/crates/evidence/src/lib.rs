//! Public-safe artifact manifests and hashes for new local/network runs.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactHash {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunManifest {
    pub schema: String,
    pub run_id: String,
    pub source_commit: String,
    pub mode: String,
    pub experiment_size: usize,
    pub gate_count: usize,
    pub scheduled_depth: usize,
    pub public_replay: String,
    pub oracle_comparison: String,
    pub artifacts: Vec<ArtifactHash>,
}

#[derive(Debug)]
pub enum EvidenceError {
    PrivatePath,
    Io(std::io::Error),
}
impl std::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for EvidenceError {}

pub fn public_artifact_allowed(path: &Path) -> bool {
    let value = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let parts = value.split('/').collect::<Vec<_>>();
    if parts.iter().any(|part| {
        matches!(
            *part,
            "private" | "oracle" | "secrets" | "trustee-private" | "runs-private"
        )
    }) {
        return false;
    }
    let name = parts.last().copied().unwrap_or("");
    if [
        ".wtns",
        ".ptau",
        ".zkey",
        ".pem",
        ".key",
        ".seed",
        ".mnemonic",
        ".wallet",
        ".keystore",
        ".private.json",
    ]
    .iter()
    .any(|suffix| name.ends_with(suffix))
    {
        return false;
    }
    [
        "witness",
        "secret_share",
        "private_key",
        "private-key",
        "trustee-config",
        "trustee_config",
        "authseed",
        "auth_seed",
        "deployer_key",
        "cleartext_oracle",
        "oracle_inputs",
        "plaintext_votes",
        "share.json",
    ]
    .iter()
    .all(|needle| !value.contains(needle))
}

pub fn hash_public_file(root: &Path, path: &Path) -> Result<ArtifactHash, EvidenceError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| EvidenceError::PrivatePath)?;
    if !public_artifact_allowed(relative) {
        return Err(EvidenceError::PrivatePath);
    }
    let mut file = File::open(path).map_err(EvidenceError::Io)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut bytes = 0u64;
    loop {
        let read = file.read(&mut buffer).map_err(EvidenceError::Io)?;
        if read == 0 {
            break;
        }
        bytes += read as u64;
        hasher.update(&buffer[..read]);
    }
    let digest = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(ArtifactHash {
        path: relative.to_string_lossy().replace('\\', "/"),
        sha256: digest,
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_export_filter_rejects_sensitive_runtime_paths() {
        for path in [
            "private/share.json",
            "oracle/inputs.json",
            "proof.wtns",
            "keys/deployer.pem",
            "plaintext_votes.json",
            "trustee-1.private.json",
            "trustee_config.json",
            "authSeedHex.json",
        ] {
            assert!(
                !public_artifact_allowed(Path::new(path)),
                "must exclude {path}"
            );
        }
        assert!(public_artifact_allowed(Path::new("public/manifest.json")));
    }
}
