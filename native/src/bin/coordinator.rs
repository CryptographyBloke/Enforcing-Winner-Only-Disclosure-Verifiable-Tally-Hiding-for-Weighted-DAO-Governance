use cgy_network::{BoardSlot, PhaseSpec, read_phase_tcp};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    env, fs,
    io::{BufRead, BufReader, BufWriter, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Plan {
    board_address: SocketAddr,
    trustees: Vec<TrusteeProcessSpec>,
    phases: Vec<PhaseWork>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrusteeProcessSpec {
    trustee_id: u32,
    config_path: PathBuf,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PhaseWork {
    phase: PhaseSpec,
    tasks: Vec<TrusteeTask>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrusteeTask {
    trustee_id: u32,
    slot: BoardSlot,
    context: Value,
    #[serde(default)]
    required_phases: Vec<PhaseSpec>,
}

struct TrusteeProcess {
    child: Child,
    input: BufWriter<ChildStdin>,
    output: BufReader<ChildStdout>,
}
impl Drop for TrusteeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("RUST_COORDINATOR_ERROR={error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 3 || args[1] != "--plan" {
        return Err("usage: coordinator --plan <public-execution-plan.json>".into());
    }
    let plan_path = PathBuf::from(&args[2]);
    let plan: Plan = serde_json::from_slice(&fs::read(&plan_path)?)?;
    let base = plan_path.parent().unwrap_or(Path::new("."));
    let trustee_exe = sibling_executable("trustee")?;
    let mut trustees = BTreeMap::new();
    for spec in &plan.trustees {
        if trustees.contains_key(&spec.trustee_id) {
            return Err("duplicate trustee process id".into());
        }
        let config_path = if spec.config_path.is_absolute() {
            spec.config_path.clone()
        } else {
            base.join(&spec.config_path)
        };
        let mut child = Command::new(&trustee_exe)
            .arg("--config")
            .arg(config_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let input = BufWriter::new(child.stdin.take().ok_or("trustee stdin unavailable")?);
        let mut output = BufReader::new(child.stdout.take().ok_or("trustee stdout unavailable")?);
        let ready = read_response(&mut output)?;
        if ready.get("type").and_then(Value::as_str) != Some("READY")
            || ready.get("trusteeId").and_then(Value::as_u64) != Some(spec.trustee_id as u64)
        {
            return Err("trustee process did not report the configured identity".into());
        }
        trustees.insert(
            spec.trustee_id,
            TrusteeProcess {
                child,
                input,
                output,
            },
        );
    }
    if trustees.keys().copied().collect::<Vec<_>>() != (1..=5).collect::<Vec<_>>() {
        return Err("distributed coordinator requires five separately configured trustees".into());
    }

    for (phase_index, phase_work) in plan.phases.iter().enumerate() {
        let mut by_id = BTreeMap::new();
        for task in &phase_work.tasks {
            if task.trustee_id != task.slot.trustee_id
                || task.slot.gate_id != phase_work.phase.gate_id
                || task.slot.invocation != phase_work.phase.invocation
                || task.slot.phase != phase_work.phase.phase
            {
                return Err("task slot does not match its scheduled phase".into());
            }
            if by_id.insert(task.trustee_id, task).is_some() {
                return Err("duplicate trustee task in a phase".into());
            }
        }
        let actual = by_id.keys().copied().collect::<Vec<_>>();
        if actual != phase_work.phase.trustee_ids {
            return Err("scheduled contributors differ from the phase trustee set".into());
        }

        for (trustee_id, task) in &by_id {
            let process = trustees
                .get_mut(trustee_id)
                .ok_or("phase references an unavailable trustee")?;
            let request = json!({"type":"TASK","taskId":phase_index,"boardAddress":plan.board_address,"phase":phase_work.phase.phase,"slot":task.slot,"context":task.context,"requiredPhases":task.required_phases});
            serde_json::to_writer(&mut process.input, &request)?;
            process.input.write_all(b"\n")?;
            process.input.flush()?;
        }
        for trustee_id in &actual {
            let process = trustees
                .get_mut(trustee_id)
                .ok_or("phase references an unavailable trustee")?;
            let response = read_response(&mut process.output)?;
            if response.get("type").and_then(Value::as_str) != Some("TASK_DONE") {
                return Err(
                    format!("trustee {trustee_id} did not complete its scheduled task").into(),
                );
            }
            if response
                .get("boardResponse")
                .and_then(|v| v.get("type"))
                .and_then(Value::as_str)
                != Some("RESULT")
            {
                return Err(format!("board rejected trustee {trustee_id} contribution").into());
            }
        }
        let sealed = read_phase_tcp(plan.board_address, &phase_work.phase)?
            .ok_or("board phase did not seal")?;
        let sealed_ids = sealed
            .submissions
            .iter()
            .map(|entry| entry.slot.trustee_id)
            .collect::<Vec<_>>();
        if sealed_ids != actual {
            return Err("sealed board contributor order differs from the scheduled set".into());
        }
        println!(
            "{}",
            json!({"type":"PHASE_VERIFIED","index":phase_index,"gateId":phase_work.phase.gate_id,"invocation":phase_work.phase.invocation,"phase":phase_work.phase.phase,"trustees":sealed_ids,"submissionCount":sealed.submissions.len()})
        );
    }
    for process in trustees.values_mut() {
        process.input.write_all(b"{\"type\":\"STOP\"}\n")?;
        process.input.flush()?;
    }
    for (trustee_id, process) in &mut trustees {
        let stopped = read_response(&mut process.output)?;
        if stopped.get("type").and_then(Value::as_str) != Some("STOPPED") {
            return Err(format!("trustee {trustee_id} did not stop cleanly").into());
        }
        let status = process.child.wait()?;
        if !status.success() {
            return Err(format!("trustee {trustee_id} exited with {status}").into());
        }
    }
    println!("RUST_COORDINATOR_PHASES=PASS count={}", plan.phases.len());
    Ok(())
}

fn read_response(reader: &mut BufReader<ChildStdout>) -> Result<Value, Box<dyn std::error::Error>> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Err("trustee process closed its output".into());
    }
    Ok(serde_json::from_str(&line)?)
}

fn sibling_executable(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
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
