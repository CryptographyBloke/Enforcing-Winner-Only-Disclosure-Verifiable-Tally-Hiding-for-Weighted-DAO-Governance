use cgy_native::gate::{
    distributed_public_message, distributed_trustee_init, distributed_trustee_phase,
    normalize_distributed_proof_context,
};
use cgy_network::{BoardSlot, PhaseSpec, TrusteeAuthenticator, read_phase_tcp, submit_tcp};
use serde_json::{Value, json};
use std::{
    env, fs,
    io::{self, BufRead, Write},
    net::SocketAddr,
    path::PathBuf,
    time::Instant,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("RUST_TRUSTEE_ERROR={error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 3 || args[1] != "--config" {
        return Err("usage: trustee --config <trustee-private-config.json>".into());
    }
    let config_path = PathBuf::from(&args[2]);
    let config: Value = serde_json::from_slice(&fs::read(config_path)?)?;
    let trustee_id = config
        .get("trusteeId")
        .and_then(Value::as_u64)
        .ok_or("trusteeId missing")? as u32;
    let secret_share = config
        .get("secretShare")
        .and_then(Value::as_str)
        .ok_or("trustee secretShare missing")?;
    let setup = config.get("setup").cloned().ok_or("public setup missing")?;
    let worker = distributed_trustee_init(
        &json!({"trusteeId":trustee_id,"secretShare":secret_share,"setup":setup}),
    )
    .map_err(io::Error::other)?;
    let seed = decode_hex32(
        config
            .get("authSeedHex")
            .and_then(Value::as_str)
            .ok_or("authentication seed missing")?,
    )?;
    let authenticator = TrusteeAuthenticator::from_seed(seed);
    if let Some(expected) = config.get("publicKeyHex").and_then(Value::as_str) {
        if authenticator.public_key_hex() != expected {
            return Err("authentication seed does not match trustee public key".into());
        }
    }
    let configured_board_address = config
        .get("boardAddress")
        .and_then(Value::as_str)
        .map(str::parse::<SocketAddr>)
        .transpose()?;
    println!(
        "{}",
        json!({"type":"READY","trusteeId":trustee_id,"pid":std::process::id()})
    );
    io::stdout().flush()?;

    for line in io::stdin().lock().lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let task: Value = serde_json::from_str(&line)?;
        match task.get("type").and_then(Value::as_str) {
            Some("STOP") => {
                println!("{{\"type\":\"STOPPED\",\"trusteeId\":{trustee_id}}}");
                io::stdout().flush()?;
                break;
            }
            Some("TASK") => {
                let board_address: SocketAddr = task
                    .get("boardAddress")
                    .and_then(Value::as_str)
                    .ok_or("task boardAddress missing")?
                    .parse()?;
                if configured_board_address.is_some_and(|configured| configured != board_address) {
                    return Err("task boardAddress differs from trustee configuration".into());
                }
                let task_id = task.get("taskId").cloned().unwrap_or(Value::Null);
                let phase = task
                    .get("phase")
                    .and_then(Value::as_str)
                    .ok_or("phase missing")?;
                let context = task.get("context").ok_or("context missing")?;
                let slot: BoardSlot =
                    serde_json::from_value(task.get("slot").cloned().ok_or("slot missing")?)?;
                if slot.trustee_id != trustee_id || slot.phase != phase {
                    return Err("task slot is assigned to another trustee or phase".into());
                }
                if context
                    .get("trusteeId")
                    .and_then(Value::as_u64)
                    .is_some_and(|id| id != trustee_id as u64)
                {
                    return Err("task context trustee mismatch".into());
                }
                let required = task
                    .get("requiredPhases")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for value in required {
                    let predecessor: PhaseSpec = serde_json::from_value(value)?;
                    if read_phase_tcp(board_address, &predecessor)?.is_none() {
                        return Err("required predecessor phase is not sealed on the board".into());
                    }
                }
                let started = Instant::now();
                let result =
                    distributed_trustee_phase(&worker, phase, context).map_err(io::Error::other)?;
                let payload = distributed_public_message(phase, context, &result)
                    .map_err(io::Error::other)?;
                let proof_context =
                    normalize_distributed_proof_context(context).map_err(io::Error::other)?;
                let signed = authenticator.sign(slot, payload)?;
                let board_response = submit_tcp(board_address, &signed, &proof_context)?;
                if board_response.get("type").and_then(Value::as_str) == Some("ERROR") {
                    return Err("board rejected trustee contribution".into());
                }
                println!(
                    "{}",
                    json!({"type":"TASK_DONE","taskId":task_id,"trusteeId":trustee_id,"phase":phase,"result":result,"submission":signed,"boardResponse":board_response,"trusteeComputeMs":started.elapsed().as_secs_f64()*1000.0})
                );
                io::stdout().flush()?;
            }
            _ => return Err("unknown trustee command".into()),
        }
    }
    Ok(())
}

fn decode_hex32(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if value.len() != 64 {
        return Err("authentication seed must be 32-byte hex".into());
    }
    let mut bytes = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Ok(bytes)
}
fn digit(value: u8) -> Result<u8, Box<dyn std::error::Error>> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("authentication seed is not canonical lowercase hex".into()),
    }
}
