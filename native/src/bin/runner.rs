use cgy_chain::ReadOnlyRpc;
use cgy_native::gate::run_gate_request;
use cgy_network::TrusteeAuthenticator;
use serde_json::json;
use std::{
    env,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Component, Path},
    process::{Command, Stdio},
};

fn main() {
    if let Err(error) = run() {
        eprintln!("RUST_RUNNER_ERROR={error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str) {
        Some("local-gate") => {
            let request = if args.len() == 3 { serde_json::from_slice(&fs::read(&args[2])?)? } else {
                let mut bytes = Vec::new(); std::io::stdin().read_to_end(&mut bytes)?; serde_json::from_slice(&bytes)?
            };
            let result = run_gate_request(&request).map_err(std::io::Error::other)?;
            println!("{}", serde_json::to_string(&serde_json::json!({"gate":result.value,"generationMs":result.generation_ms,"verificationMs":result.verification_ms}))?);
        }
        Some("chain-preflight") if args.len() == 4 && args[2] == "--rpc" => {
            let rpc = ReadOnlyRpc::new(args[3].clone())?;
            let chain_id = rpc.chain_id()?;
            println!("{}", serde_json::json!({"readOnly":true,"chainId":chain_id}));
        }
        Some("distributed") if args.len() == 4 && args[2] == "--plan" => {
            let coordinator = sibling_executable("coordinator")?;
            let status = Command::new(coordinator).args(["--plan", &args[3]]).stdin(Stdio::inherit()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).status()?;
            if !status.success() { return Err(format!("Rust distributed coordinator exited with {status}").into()); }
        }
        Some("test-dealer") if args.len() == 4 && args[2] == "--output" => provision_test_dealer(Path::new(&args[3]))?,
        _ => return Err("usage: runner local-gate [request.json] | runner distributed --plan <public-plan.json> | runner test-dealer --output runs-private/<run-id> | runner chain-preflight --rpc <endpoint>".into()),
    }
    Ok(())
}

fn provision_test_dealer(relative_output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut components = relative_output.components();
    if relative_output.is_absolute()
        || relative_output
            .components()
            .any(|part| matches!(part, Component::ParentDir))
        || components.next() != Some(Component::Normal(std::ffi::OsStr::new("runs-private")))
    {
        return Err("test-only dealer output must be a new runs-private/<run-id> directory".into());
    }
    let executable = env::current_exe()?;
    let repo_root = executable
        .ancestors()
        .nth(4)
        .ok_or("could not find repository root from runner binary")?;
    let run_root = repo_root.join(relative_output);
    if run_root.exists() {
        return Err("dealer output directory already exists".into());
    }
    let private_root = run_root.join("private");
    let public_root = run_root.join("public");
    fs::create_dir_all(&private_root)?;
    fs::create_dir_all(&public_root)?;

    let dealer =
        cgy_native::gate::create_test_only_reference_dealer().map_err(std::io::Error::other)?;
    let public_setup = dealer
        .get("publicSetup")
        .cloned()
        .ok_or("dealer did not return a public setup")?;
    let shares = dealer
        .get("secretShares")
        .and_then(serde_json::Value::as_array)
        .ok_or("dealer did not return five shares")?;
    if shares.len() != 5 {
        return Err("test dealer did not create five trustee shares".into());
    }
    let setup_path = public_root.join("public_setup.json");
    write_new_json(&setup_path, &public_setup)?;
    if public_setup
        .get("setupHash")
        .and_then(serde_json::Value::as_str)
        .is_none()
    {
        return Err("public setup hash missing".into());
    }

    for (index, share) in shares.iter().enumerate() {
        let trustee_id = index + 1;
        let (authenticator, seed) = TrusteeAuthenticator::generate();
        let trustee_dir = private_root.join(format!("trustee-{trustee_id}"));
        fs::create_dir(&trustee_dir)?;
        let config = json!({
            "trusteeId":trustee_id,
            "secretShare":share,
            "authSeedHex":hex(&seed),
            "publicKeyHex":authenticator.public_key_hex(),
            "setup":public_setup.clone(),
        });
        let private_config_path = trustee_dir.join("trustee-config.json");
        write_new_json(&private_config_path, &config)?;
        set_private_permissions(&private_config_path)?;
    }

    let public_setup_hash = cgy_evidence::hash_public_file(&public_root, &setup_path)?;
    let manifest = json!({
        "schema":"winner-only-disclosure/rust-test-dealer/v1",
        "provisioning":"TEST_ONLY_CSPRNG_DEALER_NOT_DKG",
        "trustees":5,
        "polynomialDegree":4,
        "finalThreshold":5,
        "publicSetup":public_setup_hash,
        "privateTrusteeDirectories":5,
    });
    write_new_json(&public_root.join("dealer-manifest.json"), &manifest)?;
    println!("RUST_TEST_DEALER=READY trustees=5 degree=4 threshold=5");
    println!("PUBLIC={}", public_root.display());
    println!("PRIVATE=separate trustee directories under runs-private");
    Ok(())
}

fn write_new_json(
    path: &Path,
    value: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn hex(value: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(TABLE[(byte >> 4) as usize] as char);
        output.push(TABLE[(byte & 15) as usize] as char);
    }
    output
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

fn sibling_executable(name: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let mut path = env::current_exe()?;
    path.set_file_name(if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    });
    if !path.is_file() {
        return Err(format!("required sibling binary is missing: {}", path.display()).into());
    }
    Ok(path)
}
