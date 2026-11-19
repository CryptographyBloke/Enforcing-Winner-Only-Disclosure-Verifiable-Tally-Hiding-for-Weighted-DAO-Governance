use cgy_native::gate::{run_gate, verify_gate_json};
use rayon::prelude::*;
use std::{env, fs, io::{BufWriter, Write}};
use serde_json::Value;

fn main() {
    let mut args = env::args();
    let _program = args.next();
    let mode = args.next();
    if mode.as_deref() == Some("--verify") {
        let path = args.next().expect("--verify requires a JSON path");
        let bytes = fs::read(path).expect("read transcript");
        let value: Value = serde_json::from_slice(&bytes).expect("parse transcript JSON");
        verify_gate_json(value.get("gate").unwrap_or(&value)).expect("gate verification failed");
        println!("RUST_VERIFIES_JS_GATE=PASS");
        return;
    }
    if mode.as_deref() == Some("--gate-stdin") {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut bytes).expect("read gate request");
        let request: Value = serde_json::from_slice(&bytes).expect("parse gate request");
        let run = cgy_native::gate::run_gate_request(&request).expect("native gate request failed");
        println!("{}", serde_json::json!({
            "gate": run.value,
            "generationMs": run.generation_ms,
            "verificationMs": run.verification_ms,
        }));
        return;
    }
    if mode.as_deref() == Some("--verify-stdin") {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut bytes).expect("read gate transcript");
        let value: Value = serde_json::from_slice(&bytes).expect("parse gate transcript");
        verify_gate_json(value.get("gate").unwrap_or(&value)).expect("gate verification failed");
        println!("RUST_VERIFIES_GATE=PASS");
        return;
    }
    if mode.as_deref() == Some("--verify-batch-stdin") {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut bytes).expect("read gate transcript batch");
        let values: Vec<Value> = serde_json::from_slice(&bytes).expect("parse gate transcript batch");
        for value in &values {
            let gate = value.get("record").or_else(|| value.get("gate")).unwrap_or(value);
            cgy_native::gate::verify_gate_json(gate).expect("gate batch verification failed");
        }
        println!("{}", serde_json::json!({"verified": values.len()}));
        return;
    }
    if mode.as_deref() == Some("--gate-batch-stdin") {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut bytes).expect("read gate batch");
        let requests: Vec<Value> = serde_json::from_slice(&bytes).expect("parse gate batch");
        let runs: Vec<Value> = requests.par_iter()
            .map(|request| {
                let run = cgy_native::gate::run_gate_request(request).expect("native gate batch request failed");
                serde_json::json!({
                    "gate": run.value,
                    "generationMs": run.generation_ms,
                    "verificationMs": run.verification_ms,
                })
            })
            .collect();
        println!("{}", serde_json::to_string(&runs).expect("serialize gate batch"));
        return;
    }
    if mode.as_deref() == Some("--dag-stdin") {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut bytes).expect("read weighted DAG request");
        let request: Value = serde_json::from_slice(&bytes).expect("parse weighted DAG request");
        let result = cgy_native::gate::run_dag_request(&request).expect("native weighted DAG failed");
        println!("{}", serde_json::to_string(&result).expect("serialize weighted DAG result"));
        return;
    }
    if mode.as_deref() == Some("--dag-file-stdin") {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut bytes).expect("read streamed weighted DAG request");
        let request: Value = serde_json::from_slice(&bytes).expect("parse streamed weighted DAG request");
        let output_path = request.get("transcriptPath").and_then(Value::as_str).expect("streamed DAG transcriptPath missing");
        let result = cgy_native::gate::run_dag_request(&request).expect("native streamed weighted DAG failed");
        let mut writer = BufWriter::new(fs::File::create(output_path).expect("create streamed DAG transcript"));
        if let Some(gates) = result.get("gates").and_then(Value::as_array) {
            for gate in gates {
                serde_json::to_writer(&mut writer, gate).expect("serialize streamed DAG gate");
                writer.write_all(b"\n").expect("write streamed DAG gate newline");
            }
        } else {
            panic!("native streamed DAG result has no gates");
        }
        writer.flush().expect("flush streamed DAG transcript");
        let mut summary = result;
        summary.as_object_mut().expect("streamed DAG result object").remove("gates");
        println!("{}", serde_json::to_string(&summary).expect("serialize streamed DAG summary"));
        return;
    }
    if mode.as_deref() == Some("--verify-dag-stdin") {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut bytes).expect("read public DAG transcript");
        let request: Value = serde_json::from_slice(&bytes).expect("parse public DAG transcript");
        let result = cgy_native::gate::verify_dag_request(&request).expect("native public DAG verification failed");
        println!("{}", serde_json::to_string(&result).expect("serialize public DAG verification"));
        return;
    }
    if mode.as_deref() == Some("--verify-dag-file-stdin") {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut bytes).expect("read public streamed DAG request");
        let request: Value = serde_json::from_slice(&bytes).expect("parse public streamed DAG request");
        let result = cgy_native::gate::verify_dag_file_request(&request).expect("native streamed public DAG verification failed");
        println!("{}", serde_json::to_string(&result).expect("serialize streamed DAG verification"));
        return;
    }
    let run = run_gate();
    println!("{}", serde_json::json!({
        "gate": run.value,
        "generationMs": run.generation_ms,
        "verificationMs": run.verification_ms,
    }));
}
