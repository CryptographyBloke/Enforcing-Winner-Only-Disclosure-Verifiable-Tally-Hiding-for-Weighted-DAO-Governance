use cgy_network::{BoardServiceConfig, serve};
use std::{env, fs};

fn main() {
    if let Err(error) = run() {
        eprintln!("RUST_BOARD_ERROR={error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 3 || args[1] != "--config" {
        return Err("usage: board --config <public-board-config.json>".into());
    }
    let config: BoardServiceConfig = serde_json::from_slice(&fs::read(&args[2])?)?;
    serve(config)?;
    Ok(())
}
