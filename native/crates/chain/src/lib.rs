//! Read-only Ethereum JSON-RPC access. Transaction submission methods are
//! intentionally absent from the public API.

use serde_json::{Value, json};
use std::time::Duration;

#[derive(Clone)]
pub struct ReadOnlyRpc {
    endpoint: String,
    agent: ureq::Agent,
}

#[derive(Debug)]
pub enum RpcError {
    InvalidEndpoint,
    Http,
    InvalidResponse,
    Rpc(String),
    ForbiddenMethod,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for RpcError {}

impl ReadOnlyRpc {
    pub fn new(endpoint: impl Into<String>) -> Result<Self, RpcError> {
        let endpoint = endpoint.into();
        if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
            return Err(RpcError::InvalidEndpoint);
        }
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5))
            .timeout_read(Duration::from_secs(20))
            .timeout_write(Duration::from_secs(20))
            .build();
        Ok(Self { endpoint, agent })
    }

    pub fn chain_id(&self) -> Result<u64, RpcError> {
        let value = self.call("eth_chainId", json!([]))?;
        let text = value.as_str().ok_or(RpcError::InvalidResponse)?;
        u64::from_str_radix(
            text.strip_prefix("0x").ok_or(RpcError::InvalidResponse)?,
            16,
        )
        .map_err(|_| RpcError::InvalidResponse)
    }

    pub fn transaction_receipt(&self, tx_hash: &str) -> Result<Option<Value>, RpcError> {
        self.call("eth_getTransactionReceipt", json!([tx_hash]))
            .map(|value| if value.is_null() { None } else { Some(value) })
    }

    pub fn logs(&self, filter: Value) -> Result<Vec<Value>, RpcError> {
        self.call("eth_getLogs", json!([filter]))?
            .as_array()
            .cloned()
            .ok_or(RpcError::InvalidResponse)
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        if !matches!(
            method,
            "eth_chainId"
                | "eth_getTransactionReceipt"
                | "eth_getLogs"
                | "eth_call"
                | "eth_blockNumber"
                | "eth_getCode"
        ) {
            return Err(RpcError::ForbiddenMethod);
        }
        let response = self
            .agent
            .post(&self.endpoint)
            .send_json(json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .map_err(|_| RpcError::Http)?;
        let body: Value = response
            .into_json()
            .map_err(|_| RpcError::InvalidResponse)?;
        if let Some(error) = body.get("error") {
            return Err(RpcError::Rpc(error.to_string()));
        }
        body.get("result").cloned().ok_or(RpcError::InvalidResponse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rpc_client_has_no_transaction_submission_method_allowlist() {
        let client = ReadOnlyRpc::new("http://127.0.0.1:8545").unwrap();
        assert!(matches!(
            client.call("eth_sendRawTransaction", json!(["0x00"])),
            Err(RpcError::ForbiddenMethod)
        ));
        assert!(matches!(
            ReadOnlyRpc::new("file:///etc/passwd"),
            Err(RpcError::InvalidEndpoint)
        ));
    }
}
