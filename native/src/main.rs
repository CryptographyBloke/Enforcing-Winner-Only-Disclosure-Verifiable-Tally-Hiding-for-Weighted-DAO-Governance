use cgy_native::gate::{run_gate, verify_gate_json};
use rayon::prelude::*;
use std::{env, fs, io::{BufRead, BufWriter, Write}};
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
    if mode.as_deref() == Some("--public-proof-worker-stdin") {
        let stdin = std::io::stdin();
        let mut worker = None;
        for line in stdin.lock().lines() {
            let line = match line { Ok(line) => line, Err(error) => { println!("{{\"type\":\"ERROR\",\"message\":{}}}", serde_json::to_string(&error.to_string()).unwrap()); break; } };
            let request: Value = match serde_json::from_str(&line) {
                Ok(request) => request,
                Err(error) => { println!("{{\"type\":\"ERROR\",\"message\":{}}}", serde_json::to_string(&error.to_string()).unwrap()); let _ = std::io::stdout().flush(); break; }
            };
            match request.get("type").and_then(Value::as_str) {
                Some("INIT") => match cgy_native::gate::distributed_public_verifier_init(&request) {
                    Ok(initialized) => {
                        worker = Some(initialized);
                        println!("{}", serde_json::json!({"type":"READY", "pid":std::process::id()}));
                    }
                    Err(error) => println!("{}", serde_json::json!({"type":"ERROR", "message":error})),
                },
                Some("VERIFY") => {
                    let result: Result<(), String> = (|| {
                        let worker = worker.as_ref().ok_or_else(|| "public verifier has not been initialized".to_owned())?;
                        cgy_native::gate::verify_distributed_live_payload(worker, &request)
                    })();
                    match result {
                        Ok(()) => println!("{}", serde_json::json!({"type":"RESULT", "requestId":request.get("requestId"), "valid":true})),
                        Err(error) => println!("{}", serde_json::json!({"type":"ERROR", "requestId":request.get("requestId"), "message":error})),
                    }
                }
                Some("STOP") => { println!("{}", serde_json::json!({"type":"STOPPED"})); let _ = std::io::stdout().flush(); break; }
                _ => { println!("{}", serde_json::json!({"type":"ERROR", "message":"unknown public verifier request"})); let _ = std::io::stdout().flush(); break; }
            }
            let _ = std::io::stdout().flush();
        }
        return;
    }
    if mode.as_deref() == Some("--trustee-worker-stdin") {
        let stdin = std::io::stdin();
        let mut worker = None;
        for line in stdin.lock().lines() {
            let line = match line { Ok(line) => line, Err(error) => { println!("{{\"type\":\"ERROR\",\"message\":{}}}", serde_json::to_string(&error.to_string()).unwrap()); break; } };
            let request: Value = match serde_json::from_str(&line) {
                Ok(request) => request,
                Err(error) => { println!("{{\"type\":\"ERROR\",\"message\":{}}}", serde_json::to_string(&error.to_string()).unwrap()); let _ = std::io::stdout().flush(); break; }
            };
            match request.get("type").and_then(Value::as_str) {
                Some("INIT") => {
                    match cgy_native::gate::distributed_trustee_init(&request) {
                        Ok(initialized) => {
                            let trustee_id = request.get("trusteeId").and_then(Value::as_u64).unwrap_or(0);
                            worker = Some(initialized);
                            println!("{}", serde_json::json!({"type":"READY", "trusteeId":trustee_id, "pid":std::process::id()}));
                        }
                        Err(error) => println!("{}", serde_json::json!({"type":"ERROR", "message":error})),
                    }
                    let _ = std::io::stdout().flush();
                }
                Some("TASK") => {
                    let result: Result<Value, String> = (|| {
                        let worker = worker.as_ref().ok_or_else(|| "native trustee has not been initialized".to_owned())?;
                        let phase = request.get("phase").and_then(Value::as_str).ok_or_else(|| "trustee phase missing".to_owned())?;
                        let context = request.get("context").ok_or_else(|| "trustee phase context missing".to_owned())?;
                        cgy_native::gate::distributed_trustee_phase(worker, phase, context)
                    })();
                    match result {
                        Ok(result) => println!("{}", serde_json::json!({"type":"RESULT", "taskId":request.get("taskId"), "result":result})),
                        Err(error) => println!("{}", serde_json::json!({"type":"ERROR", "taskId":request.get("taskId"), "message":error})),
                    }
                    let _ = std::io::stdout().flush();
                }
                Some("STOP") => { println!("{{\"type\":\"STOPPED\"}}"); let _ = std::io::stdout().flush(); break; }
                _ => { println!("{{\"type\":\"ERROR\",\"message\":\"unknown trustee worker request\"}}"); let _ = std::io::stdout().flush(); break; }
            }
        }
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
