//! Canonical trustee-message authentication and sequential common-view board.
//! The state machine is a trusted sequencer, not Byzantine reliable broadcast.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

const BOARD_DOMAIN: &[u8] = b"-CGY-TOOLBOX-FULL-V1/CANONICAL-ATOMIC-BOARD/V1";
const SLOT_DOMAIN: &[u8] = b"-CGY-TOOLBOX-FULL-V1/BROADCAST-SLOT/V1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoardSlot {
    pub protocol_version: String,
    pub setup_hash: String,
    pub execution_id: String,
    pub gate_id: u64,
    pub invocation: u64,
    pub phase: String,
    pub trustee_id: u32,
}

impl BoardSlot {
    pub fn new(
        setup_hash: [u8; 32],
        execution_id: [u8; 32],
        gate_id: u64,
        invocation: u64,
        phase: impl Into<String>,
        trustee_id: u32,
    ) -> Self {
        Self {
            protocol_version: cgy_protocol::gate::PROTOCOL_VERSION.to_owned(),
            setup_hash: hex(&setup_hash),
            execution_id: hex(&execution_id),
            gate_id,
            invocation,
            phase: phase.into(),
            trustee_id,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, BoardError> {
        if self.protocol_version != cgy_protocol::gate::PROTOCOL_VERSION {
            return Err(BoardError::ProtocolVersion);
        }
        if self.trustee_id == 0 {
            return Err(BoardError::TrusteeIdentity);
        }
        if self.phase.is_empty()
            || !self
                .phase
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            || !self.phase.as_bytes()[0].is_ascii_uppercase()
        {
            return Err(BoardError::NoncanonicalPhase);
        }
        let setup = parse_hex32(&self.setup_hash)?;
        let execution = parse_hex32(&self.execution_id)?;
        let mut output = Vec::with_capacity(128);
        lp(&mut output, SLOT_DOMAIN)?;
        lp(&mut output, self.protocol_version.as_bytes())?;
        output.extend_from_slice(&setup);
        output.extend_from_slice(&execution);
        output.extend_from_slice(&self.gate_id.to_be_bytes());
        output.extend_from_slice(&self.invocation.to_be_bytes());
        lp(&mut output, self.phase.as_bytes())?;
        output.extend_from_slice(&self.trustee_id.to_be_bytes());
        Ok(output)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhaseSpec {
    pub gate_id: u64,
    pub invocation: u64,
    pub phase: String,
    pub trustee_ids: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedSubmission {
    pub slot: BoardSlot,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

pub struct TrusteeAuthenticator(SigningKey);

impl TrusteeAuthenticator {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }
    pub fn generate() -> (Self, [u8; 32]) {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        (Self::from_seed(seed), seed)
    }
    pub fn public_key_hex(&self) -> String {
        hex(&self.0.verifying_key().to_bytes())
    }
    pub fn sign(&self, slot: BoardSlot, payload: Vec<u8>) -> Result<SignedSubmission, BoardError> {
        sign_submission(&self.0, slot, payload)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedPhase {
    pub phase: PhaseSpec,
    pub submissions: Vec<SignedSubmission>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubmitResult {
    Accepted,
    Idempotent,
    Sealed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BoardError {
    ProtocolVersion,
    NoncanonicalHex,
    NoncanonicalPhase,
    TrusteeIdentity,
    WrongSession,
    UnknownTrustee,
    InvalidSignature,
    OutOfOrder,
    ConflictingDuplicate,
    InvalidPhasePlan,
    InvalidProof,
    PayloadTooLarge,
    Io,
    FrameTooLarge,
}

impl std::fmt::Display for BoardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for BoardError {}

#[derive(Clone)]
pub struct BoardState {
    setup_hash: String,
    execution_id: String,
    keys: HashMap<u32, VerifyingKey>,
    plan: Vec<PhaseSpec>,
    next_phase: usize,
    pending: BTreeMap<u32, SignedSubmission>,
    sealed: Vec<SealedPhase>,
    max_payload_bytes: usize,
}

impl BoardState {
    pub fn new(
        setup_hash: [u8; 32],
        execution_id: [u8; 32],
        keys: impl IntoIterator<Item = (u32, [u8; 32])>,
        plan: Vec<PhaseSpec>,
        max_payload_bytes: usize,
    ) -> Result<Self, BoardError> {
        if plan.is_empty() || max_payload_bytes == 0 {
            return Err(BoardError::InvalidPhasePlan);
        }
        let mut public_keys = HashMap::new();
        for (id, bytes) in keys {
            if id == 0
                || public_keys
                    .insert(
                        id,
                        VerifyingKey::from_bytes(&bytes).map_err(|_| BoardError::UnknownTrustee)?,
                    )
                    .is_some()
            {
                return Err(BoardError::UnknownTrustee);
            }
        }
        if public_keys.is_empty()
            || plan.iter().any(|p| {
                p.phase.is_empty()
                    || p.trustee_ids.is_empty()
                    || p.trustee_ids.iter().any(|id| !public_keys.contains_key(id))
            })
        {
            return Err(BoardError::InvalidPhasePlan);
        }
        Ok(Self {
            setup_hash: hex(&setup_hash),
            execution_id: hex(&execution_id),
            keys: public_keys,
            plan,
            next_phase: 0,
            pending: BTreeMap::new(),
            sealed: Vec::new(),
            max_payload_bytes,
        })
    }

    pub fn submit(&mut self, submission: SignedSubmission) -> Result<SubmitResult, BoardError> {
        if submission.payload.len() > self.max_payload_bytes {
            return Err(BoardError::PayloadTooLarge);
        }
        let slot = &submission.slot;
        if slot.setup_hash != self.setup_hash || slot.execution_id != self.execution_id {
            return Err(BoardError::WrongSession);
        }
        let position = self
            .plan
            .iter()
            .position(|phase| {
                phase.gate_id == slot.gate_id
                    && phase.invocation == slot.invocation
                    && phase.phase == slot.phase
            })
            .ok_or(BoardError::OutOfOrder)?;
        if !self.plan[position].trustee_ids.contains(&slot.trustee_id) {
            return Err(BoardError::TrusteeIdentity);
        }
        let key = self
            .keys
            .get(&slot.trustee_id)
            .ok_or(BoardError::UnknownTrustee)?;
        let signature = Signature::from_slice(&submission.signature)
            .map_err(|_| BoardError::InvalidSignature)?;
        let mut signed = slot.encode()?;
        let payload_len =
            u32::try_from(submission.payload.len()).map_err(|_| BoardError::PayloadTooLarge)?;
        signed.extend_from_slice(&payload_len.to_be_bytes());
        signed.extend_from_slice(&submission.payload);
        key.verify(&signed, &signature)
            .map_err(|_| BoardError::InvalidSignature)?;

        if position < self.next_phase {
            let existing = self.sealed[position]
                .submissions
                .iter()
                .find(|entry| entry.slot.trustee_id == slot.trustee_id)
                .ok_or(BoardError::OutOfOrder)?;
            return if existing == &submission {
                Ok(SubmitResult::Idempotent)
            } else {
                Err(BoardError::ConflictingDuplicate)
            };
        }
        if position != self.next_phase {
            return Err(BoardError::OutOfOrder);
        }
        if let Some(existing) = self.pending.get(&slot.trustee_id) {
            return if existing == &submission {
                Ok(SubmitResult::Idempotent)
            } else {
                Err(BoardError::ConflictingDuplicate)
            };
        }
        self.pending.insert(slot.trustee_id, submission);
        if self.pending.len() != self.plan[self.next_phase].trustee_ids.len() {
            return Ok(SubmitResult::Accepted);
        }
        let phase = self.plan[self.next_phase].clone();
        let submissions = std::mem::take(&mut self.pending).into_values().collect();
        self.sealed.push(SealedPhase { phase, submissions });
        self.next_phase += 1;
        Ok(SubmitResult::Sealed)
    }

    pub fn read_phase(&self, phase: &PhaseSpec) -> Option<&SealedPhase> {
        self.sealed.iter().find(|sealed| &sealed.phase == phase)
    }

    pub fn is_complete(&self) -> bool {
        self.next_phase == self.plan.len()
    }
    pub fn sealed_phases(&self) -> &[SealedPhase] {
        &self.sealed
    }
    pub fn phase_count(&self) -> usize {
        self.plan.len()
    }
    pub fn current_phase(&self) -> Option<&PhaseSpec> {
        self.plan.get(self.next_phase)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrusteePublicKey {
    pub trustee_id: u32,
    pub public_key_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoardServiceConfig {
    pub bind: String,
    pub setup_hash: String,
    pub execution_id: String,
    pub trustees: Vec<TrusteePublicKey>,
    pub phase_plan: Vec<PhaseSpec>,
    pub public_setup: serde_json::Value,
    pub event_log_path: PathBuf,
    #[serde(default = "default_max_frame")]
    pub max_frame_bytes: usize,
    #[serde(default = "default_payload_limit")]
    pub max_payload_bytes: usize,
}

fn default_max_frame() -> usize {
    8 * 1024 * 1024
}
fn default_payload_limit() -> usize {
    4 * 1024 * 1024
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BoardRequest {
    #[serde(rename = "type")]
    request_type: String,
    #[serde(default)]
    submission: Option<SignedSubmission>,
    #[serde(default)]
    phase: Option<PhaseSpec>,
    #[serde(default)]
    proof_context: Option<serde_json::Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BoardResponse {
    #[serde(rename = "type")]
    response_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phase: Option<SealedPhase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    complete: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

struct BoardServiceState {
    board: BoardState,
    verifier: cgy_protocol::gate::DistributedPublicVerifier,
    log: BufWriter<File>,
}

/// Start the authenticated sequential TCP board and durably append every new
/// accepted message. The board is a trusted sequencer for the experiment.
pub fn serve(config: BoardServiceConfig) -> Result<(), BoardError> {
    let setup = parse_hex32(&config.setup_hash)?;
    let execution = parse_hex32(&config.execution_id)?;
    let keys = config
        .trustees
        .iter()
        .map(|entry| Ok((entry.trustee_id, parse_hex32(&entry.public_key_hex)?)))
        .collect::<Result<Vec<_>, BoardError>>()?;
    let mut board = BoardState::new(
        setup,
        execution,
        keys,
        config.phase_plan.clone(),
        config.max_payload_bytes,
    )?;
    let verifier = cgy_protocol::gate::distributed_public_verifier_init(
        &serde_json::json!({"setup":config.public_setup}),
    )
    .map_err(|_| BoardError::InvalidPhasePlan)?;
    let config_digest = digest_config(&config)?;
    if let Some(parent) = config.event_log_path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| BoardError::Io)?;
    }
    let existing = config.event_log_path.exists();
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(&config.event_log_path)
        .map_err(|_| BoardError::Io)?;
    if existing {
        let reader =
            BufReader::new(File::open(&config.event_log_path).map_err(|_| BoardError::Io)?);
        let mut lines = reader.lines();
        let header = lines
            .next()
            .ok_or(BoardError::InvalidPhasePlan)?
            .map_err(|_| BoardError::Io)?;
        let header: serde_json::Value =
            serde_json::from_str(&header).map_err(|_| BoardError::InvalidPhasePlan)?;
        if header.get("type").and_then(|v| v.as_str()) != Some("CONFIG")
            || header.get("digest").and_then(|v| v.as_str()) != Some(&config_digest)
        {
            return Err(BoardError::WrongSession);
        }
        for line in lines {
            let value = line.map_err(|_| BoardError::Io)?;
            let event: serde_json::Value =
                serde_json::from_str(&value).map_err(|_| BoardError::InvalidPhasePlan)?;
            let submission: SignedSubmission = serde_json::from_value(
                event
                    .get("submission")
                    .cloned()
                    .ok_or(BoardError::InvalidPhasePlan)?,
            )
            .map_err(|_| BoardError::InvalidPhasePlan)?;
            let proof_context = event
                .get("proofContext")
                .cloned()
                .ok_or(BoardError::InvalidPhasePlan)?;
            verify_public_proof(&verifier, &submission, &proof_context)?;
            board.submit(submission)?;
        }
    }
    let mut log = BufWriter::new(file);
    if !existing {
        serde_json::to_writer(
            &mut log,
            &serde_json::json!({"type":"CONFIG", "digest":config_digest}),
        )
        .map_err(|_| BoardError::Io)?;
        log.write_all(b"\n")
            .and_then(|_| log.flush())
            .and_then(|_| log.get_ref().sync_all())
            .map_err(|_| BoardError::Io)?;
    }
    let listener = TcpListener::bind(&config.bind).map_err(|_| BoardError::Io)?;
    let address = listener.local_addr().map_err(|_| BoardError::Io)?;
    println!("RUST_BOARD_LISTENING={address}");
    let state = Arc::new(Mutex::new(BoardServiceState {
        board,
        verifier,
        log,
    }));
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let state = Arc::clone(&state);
                let max_frame = config.max_frame_bytes;
                thread::spawn(move || {
                    let _ = handle_connection(stream, state, max_frame);
                });
            }
            Err(_) => return Err(BoardError::Io),
        }
    }
    Ok(())
}

/// Independently replay the durable board log, checking every trustee
/// signature, phase dependency, and live CGY proof before returning the seal.
pub fn replay_event_log(config: &BoardServiceConfig) -> Result<Vec<SealedPhase>, BoardError> {
    let setup = parse_hex32(&config.setup_hash)?;
    let execution = parse_hex32(&config.execution_id)?;
    let keys = config
        .trustees
        .iter()
        .map(|entry| Ok((entry.trustee_id, parse_hex32(&entry.public_key_hex)?)))
        .collect::<Result<Vec<_>, BoardError>>()?;
    let mut board = BoardState::new(
        setup,
        execution,
        keys,
        config.phase_plan.clone(),
        config.max_payload_bytes,
    )?;
    let verifier = cgy_protocol::gate::distributed_public_verifier_init(
        &serde_json::json!({"setup":config.public_setup.clone()}),
    )
    .map_err(|_| BoardError::InvalidPhasePlan)?;
    let reader = BufReader::new(File::open(&config.event_log_path).map_err(|_| BoardError::Io)?);
    let mut lines = reader.lines();
    let header = lines
        .next()
        .ok_or(BoardError::InvalidPhasePlan)?
        .map_err(|_| BoardError::Io)?;
    let header: serde_json::Value =
        serde_json::from_str(&header).map_err(|_| BoardError::InvalidPhasePlan)?;
    let digest = digest_config(config)?;
    if header.get("type").and_then(|v| v.as_str()) != Some("CONFIG")
        || header.get("digest").and_then(|v| v.as_str()) != Some(digest.as_str())
    {
        return Err(BoardError::WrongSession);
    }
    for line in lines {
        let value: serde_json::Value = serde_json::from_str(&line.map_err(|_| BoardError::Io)?)
            .map_err(|_| BoardError::InvalidPhasePlan)?;
        if value.get("type").and_then(|v| v.as_str()) != Some("SUBMIT") {
            return Err(BoardError::InvalidPhasePlan);
        }
        let submission: SignedSubmission = serde_json::from_value(
            value
                .get("submission")
                .cloned()
                .ok_or(BoardError::InvalidPhasePlan)?,
        )
        .map_err(|_| BoardError::InvalidPhasePlan)?;
        let context = value
            .get("proofContext")
            .ok_or(BoardError::InvalidPhasePlan)?;
        let mut next = board.clone();
        let result = next.submit(submission.clone())?;
        if result == SubmitResult::Idempotent {
            return Err(BoardError::ConflictingDuplicate);
        }
        verify_public_proof(&verifier, &submission, context)?;
        board = next;
    }
    if !board.is_complete() {
        return Err(BoardError::InvalidPhasePlan);
    }
    Ok(board.sealed_phases().to_vec())
}

fn handle_connection(
    mut stream: TcpStream,
    state: Arc<Mutex<BoardServiceState>>,
    max_frame: usize,
) -> Result<(), BoardError> {
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .map_err(|_| BoardError::Io)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(120)))
        .map_err(|_| BoardError::Io)?;
    let mut reader = BufReader::new(stream.try_clone().map_err(|_| BoardError::Io)?);
    loop {
        let mut line = Vec::new();
        let read = (&mut reader)
            .take((max_frame + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|_| BoardError::Io)?;
        if read == 0 {
            return Ok(());
        }
        if line.len() > max_frame || !line.ends_with(b"\n") {
            return Err(BoardError::FrameTooLarge);
        }
        let request: BoardRequest =
            serde_json::from_slice(&line).map_err(|_| BoardError::InvalidPhasePlan)?;
        let response = match request.request_type.as_str() {
            "PING" => BoardResponse {
                response_type: "PONG",
                result: None,
                phase: None,
                complete: None,
                error: None,
            },
            "SUBMIT" => {
                let submission = request.submission.ok_or(BoardError::InvalidPhasePlan)?;
                let proof_context = request.proof_context.ok_or(BoardError::InvalidPhasePlan)?;
                let mut guard = state.lock().map_err(|_| BoardError::Io)?;
                let mut next = guard.board.clone();
                match next.submit(submission.clone()) {
                    Ok(result) => {
                        if result == SubmitResult::Idempotent {
                            BoardResponse {
                                response_type: "RESULT",
                                result: Some("IDEMPOTENT"),
                                phase: None,
                                complete: Some(guard.board.is_complete()),
                                error: None,
                            }
                        } else if let Err(error) =
                            verify_public_proof(&guard.verifier, &submission, &proof_context)
                        {
                            BoardResponse {
                                response_type: "ERROR",
                                result: None,
                                phase: None,
                                complete: None,
                                error: Some(error.to_string()),
                            }
                        } else {
                            serde_json::to_writer(&mut guard.log, &serde_json::json!({"type":"SUBMIT", "submission":submission, "proofContext":proof_context})).map_err(|_| BoardError::Io)?;
                            guard
                                .log
                                .write_all(b"\n")
                                .and_then(|_| guard.log.flush())
                                .and_then(|_| guard.log.get_ref().sync_all())
                                .map_err(|_| BoardError::Io)?;
                            guard.board = next;
                            let name = if result == SubmitResult::Accepted {
                                "ACCEPTED"
                            } else {
                                "SEALED"
                            };
                            BoardResponse {
                                response_type: "RESULT",
                                result: Some(name),
                                phase: guard.board.sealed_phases().last().cloned(),
                                complete: Some(guard.board.is_complete()),
                                error: None,
                            }
                        }
                    }
                    Err(error) => BoardResponse {
                        response_type: "ERROR",
                        result: None,
                        phase: None,
                        complete: None,
                        error: Some(error.to_string()),
                    },
                }
            }
            "READ_PHASE" => {
                let phase = request.phase.ok_or(BoardError::InvalidPhasePlan)?;
                let guard = state.lock().map_err(|_| BoardError::Io)?;
                BoardResponse {
                    response_type: "RESULT",
                    result: None,
                    phase: guard.board.read_phase(&phase).cloned(),
                    complete: Some(guard.board.is_complete()),
                    error: None,
                }
            }
            "STATUS" => {
                let guard = state.lock().map_err(|_| BoardError::Io)?;
                BoardResponse {
                    response_type: "RESULT",
                    result: None,
                    phase: None,
                    complete: Some(guard.board.is_complete()),
                    error: None,
                }
            }
            _ => BoardResponse {
                response_type: "ERROR",
                result: None,
                phase: None,
                complete: None,
                error: Some("unknown request type".into()),
            },
        };
        serde_json::to_writer(&mut stream, &response).map_err(|_| BoardError::Io)?;
        stream.write_all(b"\n").map_err(|_| BoardError::Io)?;
    }
}

pub fn submit_tcp(
    address: SocketAddr,
    submission: &SignedSubmission,
    proof_context: &serde_json::Value,
) -> Result<serde_json::Value, BoardError> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(10))
        .map_err(|_| BoardError::Io)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .map_err(|_| BoardError::Io)?;
    serde_json::to_writer(&mut stream, &serde_json::json!({"type":"SUBMIT", "submission":submission, "proofContext":proof_context})).map_err(|_| BoardError::Io)?;
    stream.write_all(b"\n").map_err(|_| BoardError::Io)?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|_| BoardError::Io)?;
    let response: serde_json::Value =
        serde_json::from_str(&line).map_err(|_| BoardError::InvalidPhasePlan)?;
    if response.get("type").and_then(|value| value.as_str()) == Some("ERROR") {
        return Err(BoardError::InvalidSignature);
    }
    Ok(response)
}

pub fn read_phase_tcp(
    address: SocketAddr,
    phase: &PhaseSpec,
) -> Result<Option<SealedPhase>, BoardError> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(10))
        .map_err(|_| BoardError::Io)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .map_err(|_| BoardError::Io)?;
    serde_json::to_writer(
        &mut stream,
        &serde_json::json!({"type":"READ_PHASE", "phase":phase}),
    )
    .map_err(|_| BoardError::Io)?;
    stream.write_all(b"\n").map_err(|_| BoardError::Io)?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|_| BoardError::Io)?;
    let response: serde_json::Value =
        serde_json::from_str(&line).map_err(|_| BoardError::InvalidPhasePlan)?;
    if response.get("type").and_then(|value| value.as_str()) == Some("ERROR") {
        return Err(BoardError::OutOfOrder);
    }
    response
        .get("phase")
        .filter(|value| !value.is_null())
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| BoardError::InvalidPhasePlan)
}

fn verify_public_proof(
    verifier: &cgy_protocol::gate::DistributedPublicVerifier,
    submission: &SignedSubmission,
    context: &serde_json::Value,
) -> Result<(), BoardError> {
    let request = serde_json::json!({"phase":submission.slot.phase,"trusteeId":submission.slot.trustee_id,"context":context,"payloadHex":hex(&submission.payload)});
    cgy_protocol::gate::verify_distributed_live_payload(verifier, &request)
        .map_err(|_| BoardError::InvalidProof)
}

pub fn payload_hash(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}
pub fn board_domain() -> &'static [u8] {
    BOARD_DOMAIN
}

fn lp(output: &mut Vec<u8>, value: &[u8]) -> Result<(), BoardError> {
    let len = u32::try_from(value.len()).map_err(|_| BoardError::PayloadTooLarge)?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}
fn parse_hex32(value: &str) -> Result<[u8; 32], BoardError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BoardError::NoncanonicalHex);
    }
    let bytes = decode_hex(value).ok_or(BoardError::NoncanonicalHex)?;
    bytes.try_into().map_err(|_| BoardError::NoncanonicalHex)
}
fn decode_hex(value: &str) -> Option<Vec<u8>> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Some((hex_digit(pair[0])? << 4) | hex_digit(pair[1])?))
        .collect()
}
fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}
fn hex(value: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(value.len() * 2);
    for byte in value {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 15) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture() -> (BoardState, SigningKey, BoardSlot, PhaseSpec) {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let public = signing.verifying_key().to_bytes();
        let phase = PhaseSpec {
            gate_id: 1,
            invocation: 0,
            phase: "MASKING".into(),
            trustee_ids: vec![1],
        };
        let state =
            BoardState::new([1; 32], [2; 32], [(1, public)], vec![phase.clone()], 1024).unwrap();
        let slot = BoardSlot::new([1; 32], [2; 32], 1, 0, "MASKING", 1);
        (state, signing, slot, phase)
    }

    fn sign(signing: &SigningKey, slot: BoardSlot, payload: &[u8]) -> SignedSubmission {
        let mut message = slot.encode().unwrap();
        message.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        message.extend_from_slice(payload);
        SignedSubmission {
            slot,
            payload: payload.to_vec(),
            signature: signing.sign(&message).to_bytes().to_vec(),
        }
    }

    #[test]
    fn accepts_and_seals_a_signed_phase_and_allows_exact_retry() {
        let (mut state, signing, slot, phase) = fixture();
        let submission = sign(&signing, slot, b"public contribution");
        assert_eq!(state.submit(submission.clone()), Ok(SubmitResult::Sealed));
        assert_eq!(state.submit(submission), Ok(SubmitResult::Idempotent));
        assert!(state.is_complete());
        assert_eq!(state.read_phase(&phase).unwrap().submissions.len(), 1);
    }

    #[test]
    fn rejects_invalid_signature_and_conflicting_retry() {
        let (mut state, signing, slot, _) = fixture();
        let mut bad = sign(&signing, slot.clone(), b"payload");
        bad.signature[0] ^= 1;
        assert_eq!(state.submit(bad), Err(BoardError::InvalidSignature));
        let first = sign(&signing, slot.clone(), b"payload");
        assert_eq!(state.submit(first), Ok(SubmitResult::Sealed));
        let conflict = sign(&signing, slot, b"other payload");
        assert_eq!(
            state.submit(conflict),
            Err(BoardError::ConflictingDuplicate)
        );
    }

    #[test]
    fn rejects_out_of_order_and_wrong_identity() {
        let (mut state, signing, slot, _) = fixture();
        let mut stale = slot.clone();
        stale.phase = "RERANDOMIZATION".into();
        assert_eq!(
            state.submit(sign(&signing, stale, b"payload")),
            Err(BoardError::OutOfOrder)
        );
        let mut unknown = slot;
        unknown.trustee_id = 2;
        assert_eq!(
            state.submit(sign(&signing, unknown, b"payload")),
            Err(BoardError::TrusteeIdentity)
        );
    }

    #[test]
    fn matches_the_frozen_javascript_slot_encoding_and_ed25519_signature() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/js_signed_slot.json")).unwrap();
        let slot: BoardSlot = serde_json::from_value(vector["slot"].clone()).unwrap();
        let payload = decode_hex(vector["payloadHex"].as_str().unwrap()).unwrap();
        let public_key = parse_hex32(vector["publicKeyRawHex"].as_str().unwrap()).unwrap();
        let signature = decode_hex(vector["signatureHex"].as_str().unwrap()).unwrap();
        let mut message = slot.encode().unwrap();
        message.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        message.extend_from_slice(&payload);
        assert_eq!(hex(&message), vector["signedMessageHex"].as_str().unwrap());
        let rust_signature = sign_submission(
            &SigningKey::from_bytes(&[7u8; 32]),
            slot.clone(),
            payload.clone(),
        )
        .unwrap();
        assert_eq!(rust_signature.signature, signature);
        let phase = PhaseSpec {
            gate_id: slot.gate_id,
            invocation: slot.invocation,
            phase: slot.phase.clone(),
            trustee_ids: vec![slot.trustee_id],
        };
        let mut state =
            BoardState::new([1; 32], [2; 32], [(1, public_key)], vec![phase], 1024).unwrap();
        assert_eq!(
            state.submit(SignedSubmission {
                slot,
                payload,
                signature
            }),
            Ok(SubmitResult::Sealed)
        );
    }
}

pub fn sign_submission(
    signing_key: &SigningKey,
    slot: BoardSlot,
    payload: Vec<u8>,
) -> Result<SignedSubmission, BoardError> {
    let mut message = slot.encode()?;
    let len = u32::try_from(payload.len()).map_err(|_| BoardError::PayloadTooLarge)?;
    message.extend_from_slice(&len.to_be_bytes());
    message.extend_from_slice(&payload);
    Ok(SignedSubmission {
        slot,
        payload,
        signature: signing_key.sign(&message).to_bytes().to_vec(),
    })
}

fn digest_config(config: &BoardServiceConfig) -> Result<String, BoardError> {
    let public = serde_json::json!({"setupHash":config.setup_hash,"executionId":config.execution_id,"trustees":config.trustees,"phasePlan":config.phase_plan,"publicSetup":config.public_setup,"maxPayloadBytes":config.max_payload_bytes});
    let bytes = serde_json::to_vec(&public).map_err(|_| BoardError::InvalidPhasePlan)?;
    Ok(hex(&Sha256::digest(bytes)))
}
