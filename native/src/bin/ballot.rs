use cgy_ballot::proving::{
    BallotProfile, BallotProver, parse_snarkjs_proof, parse_snarkjs_verification_key,
    prove_fresh_profile, verify_snarkjs_proof,
};
use cgy_ballot::{AdmittedBallotSignals, PUBLIC_SIGNAL_COUNT};
use serde::Deserialize;
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProveConfig {
    wasm_path: PathBuf,
    r1cs_path: PathBuf,
    zkey_path: PathBuf,
    verification_key_path: PathBuf,
    count: usize,
    votes: Vec<u8>,
    weights: Vec<u8>,
    poll_id: String,
    committee_key: [String; 2],
    output_path: PathBuf,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("BALLOT_ERROR={error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("prove") => {
            let config_path = match (args.next().as_deref(), args.next()) {
                (Some("--config"), Some(path)) if args.next().is_none() => PathBuf::from(path),
                _ => return Err("usage: ballot prove --config <private-input-config.json>".into()),
            };
            prove(&config_path)
        }
        Some("verify") => {
            let (bundle, vkey) = match (args.next().as_deref(), args.next(), args.next().as_deref(), args.next(), args.next()) {
                (Some("--bundle"), Some(bundle), Some("--vkey"), Some(vkey), None) => (PathBuf::from(bundle), PathBuf::from(vkey)),
                _ => return Err("usage: ballot verify --bundle <public-ballots.json> --vkey <verification_key.json>".into()),
            };
            verify(&bundle, &vkey)
        }
        Some("check-vkey") => {
            let path = match (args.next().as_deref(), args.next(), args.next()) {
                (Some("--vkey"), Some(path), None) => PathBuf::from(path),
                _ => return Err("usage: ballot check-vkey --vkey <verification_key.json>".into()),
            };
            check_vkey(&path)
        }
        _ => Err(
            "usage: ballot prove --config <json> | ballot verify --bundle <json> --vkey <json>"
                .into(),
        ),
    }
}

fn prove(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let wall_started = Instant::now();
    let config: ProveConfig = serde_json::from_reader(File::open(path)?)?;
    if config.count == 0
        || config.count != config.votes.len()
        || config.count != config.weights.len()
    {
        return Err("count, votes and weights must have the same nonzero length".into());
    }
    let mut prover = BallotProver::new(&config.wasm_path, &config.r1cs_path, &config.zkey_path)
        .map_err(io::Error::other)?;
    let profile = prove_fresh_profile(
        &mut prover,
        config.count,
        &config.votes,
        &config.weights,
        &config.poll_id,
        config.committee_key,
    )
    .map_err(io::Error::other)?;
    let verification_key: Value =
        serde_json::from_reader(File::open(&config.verification_key_path)?)?;
    let verification_key =
        parse_snarkjs_verification_key(&verification_key).map_err(io::Error::other)?;
    verify_profile(&profile, &verification_key)?;

    let parent = config
        .output_path
        .parent()
        .ok_or("output path must have a parent directory")?;
    fs::create_dir_all(parent)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&config.output_path)?;
    serde_json::to_writer_pretty(&mut output, &profile)?;
    output.write_all(b"\n")?;
    output.flush()?;
    let sum_ms = |select: fn(&cgy_ballot::proving::BallotProof) -> f64| {
        profile.ballots.iter().map(select).sum::<f64>()
    };
    println!("RUST_BALLOT_PROVING=PASS");
    println!("BALLOTS={}", profile.ballots.len());
    println!("PUBLIC_SIGNALS_PER_BALLOT={PUBLIC_SIGNAL_COUNT}");
    println!("RUST_VKEY_COMPATIBILITY=PASS");
    println!(
        "WITNESS_GENERATION_MS={:.3}",
        sum_ms(|ballot| ballot.witness_ms)
    );
    println!(
        "GROTH16_PROVING_MS={:.3}",
        sum_ms(|ballot| ballot.proving_ms)
    );
    println!(
        "GROTH16_VERIFICATION_MS={:.3}",
        sum_ms(|ballot| ballot.verification_ms)
    );
    println!(
        "BALLOT_PIPELINE_MS={:.3}",
        sum_ms(|ballot| ballot.ballot_pipeline_ms)
    );
    println!(
        "COMMAND_WALL_MS={:.3}",
        wall_started.elapsed().as_secs_f64() * 1000.0
    );
    println!("PUBLIC_BUNDLE={}", config.output_path.display());
    Ok(())
}

fn verify(bundle_path: &PathBuf, vkey_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let profile: BallotProfile = serde_json::from_reader(File::open(bundle_path)?)?;
    let vkey_json: Value = serde_json::from_reader(File::open(vkey_path)?)?;
    let vkey = parse_snarkjs_verification_key(&vkey_json).map_err(io::Error::other)?;
    verify_profile(&profile, &vkey)?;
    println!("RUST_BALLOT_REPLAY=PASS");
    println!("BALLOTS={}", profile.ballots.len());
    println!("PUBLIC_SIGNALS_PER_BALLOT={PUBLIC_SIGNAL_COUNT}");
    Ok(())
}

fn check_vkey(vkey_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let value: Value = serde_json::from_reader(File::open(vkey_path)?)?;
    let vkey = parse_snarkjs_verification_key(&value).map_err(io::Error::other)?;
    println!("RUST_SNARKJS_VKEY_PARSE=PASS");
    println!("PUBLIC_SIGNALS={}", vkey.gamma_abc_g1.len() - 1);
    Ok(())
}

fn verify_profile(
    profile: &BallotProfile,
    vkey: &ark_groth16::VerifyingKey<ark_bn254::Bn254>,
) -> io::Result<()> {
    for (index, ballot) in profile.ballots.iter().enumerate() {
        if ballot.public_signals.len() != PUBLIC_SIGNAL_COUNT {
            return Err(io::Error::other(format!(
                "ballot {index} has an invalid public signal count"
            )));
        }
        AdmittedBallotSignals::parse(&ballot.public_signals)
            .map_err(|error| io::Error::other(format!("ballot {index} signals: {error}")))?;
        if ballot.public_signals[33] != profile.registry_root
            || ballot.public_signals[34] != profile.poll_id
            || ballot.public_signals[35] != profile.public_key[0]
            || ballot.public_signals[36] != profile.public_key[1]
        {
            return Err(io::Error::other(format!(
                "ballot {index} public context mismatch"
            )));
        }
        let proof_json = serde_json::to_value(&ballot.proof)?;
        let proof = parse_snarkjs_proof(&proof_json).map_err(io::Error::other)?;
        if !verify_snarkjs_proof(vkey, &proof, &ballot.public_signals).map_err(io::Error::other)? {
            return Err(io::Error::other(format!(
                "ballot {index} Groth16 proof rejected"
            )));
        }
    }
    Ok(())
}
