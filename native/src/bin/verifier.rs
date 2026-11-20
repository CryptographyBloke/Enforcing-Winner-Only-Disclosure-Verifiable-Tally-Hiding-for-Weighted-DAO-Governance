use cgy_native::gate::{verify_dag_request, verify_gate_json};
use cgy_network::{BoardServiceConfig, replay_event_log};
use serde_json::Value;
use std::{env, fs, io::Read};

fn main() {
    if let Err(error) = run() {
        eprintln!("RUST_VERIFIER_ERROR={error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str) {
        Some("gate") if args.len() == 3 => {
            let value: Value = serde_json::from_slice(&fs::read(&args[2])?)?;
            verify_gate_json(value.get("gate").unwrap_or(&value)).map_err(std::io::Error::other)?;
            println!("RUST_GATE_REPLAY=PASS");
        }
        Some("dag") => {
            let mut bytes = Vec::new();
            std::io::stdin().read_to_end(&mut bytes)?;
            let value: Value = serde_json::from_slice(&bytes)?;
            let result = verify_dag_request(&value).map_err(std::io::Error::other)?;
            println!("{}", serde_json::to_string(&result)?);
        }
        Some("board") if args.len() == 3 => {
            let config: BoardServiceConfig = serde_json::from_slice(&fs::read(&args[2])?)?;
            let phases = replay_event_log(&config)?;
            println!("RUST_BOARD_REPLAY=PASS phases={}", phases.len());
        }
        _ => return Err("usage: verifier gate <single-gate.json> | verifier dag < request.json | verifier board <board-config.json>".into()),
    }
    Ok(())
}
