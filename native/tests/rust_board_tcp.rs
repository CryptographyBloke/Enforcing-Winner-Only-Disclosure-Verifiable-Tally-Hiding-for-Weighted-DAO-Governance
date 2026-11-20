use cgy_network::{BoardServiceConfig, PhaseSpec, TrusteeAuthenticator, TrusteePublicKey};
use serde_json::Value;
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

fn launch(config_path: &PathBuf) -> (Child, SocketAddr) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_board"))
        .args(["--config", config_path.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let address = line
        .trim()
        .strip_prefix("RUST_BOARD_LISTENING=")
        .unwrap()
        .parse()
        .unwrap();
    (child, address)
}

fn request(address: SocketAddr, body: &str) -> Value {
    let mut stream = TcpStream::connect(address).unwrap();
    stream.write_all(body.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

#[test]
fn rust_board_accepts_tcp_health_and_recovers_its_durable_configuration() {
    let setup: Value =
        serde_json::from_str(include_str!("../testdata/rust_single_gate.json")).unwrap();
    let public_setup = setup.get("setup").unwrap().clone();
    let setup_hash = public_setup
        .get("setupHash")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let signing = TrusteeAuthenticator::from_seed([7u8; 32]);
    let execution_id = "08".repeat(32);
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let log_path = std::env::temp_dir().join(format!(
        "cgy-rust-board-{}-{unique}.jsonl",
        std::process::id()
    ));
    let config_path = std::env::temp_dir().join(format!(
        "cgy-rust-board-{}-{unique}.json",
        std::process::id()
    ));
    let config = BoardServiceConfig {
        bind: "127.0.0.1:0".into(),
        setup_hash,
        execution_id,
        trustees: vec![TrusteePublicKey {
            trustee_id: 1,
            public_key_hex: signing.public_key_hex(),
        }],
        phase_plan: vec![PhaseSpec {
            gate_id: 1,
            invocation: 0,
            phase: "MASKING_01".into(),
            trustee_ids: vec![1],
        }],
        public_setup,
        event_log_path: log_path.clone(),
        max_frame_bytes: 1024 * 1024,
        max_payload_bytes: 512 * 1024,
    };
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();

    for _ in 0..2 {
        let (mut board, address) = launch(&config_path);
        let pong = request(address, r#"{"type":"PING"}"#);
        assert_eq!(pong.get("type").and_then(Value::as_str), Some("PONG"));
        let status = request(address, r#"{"type":"STATUS"}"#);
        assert_eq!(status.get("complete").and_then(Value::as_bool), Some(false));
        board.kill().unwrap();
        let _ = board.wait();
    }
    assert!(
        fs::read_to_string(&log_path)
            .unwrap()
            .starts_with("{\"type\":\"CONFIG\"")
    );
    let _ = fs::remove_file(config_path);
    let _ = fs::remove_file(log_path);
}
