//! The test prover server protocol: one request per connection, each message a
//! 4-byte little-endian length followed by that many bytes of JSON.

use std::{
    io::{self, Read, Write},
    path::PathBuf,
};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zolana_gnark_ffi_prover::ProofInputMap;

/// Upper bound on a message, so a corrupt length prefix cannot exhaust memory.
pub const MAX_MESSAGE_LEN: usize = 64 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProveRequest {
    pub circuit: String,
    pub inputs: ProofInputMap,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProveResponse {
    pub proof: Option<Vec<u8>>,
    pub error: Option<String>,
}

/// The server socket of this clone, scoped by `ZOLANA_PORT_OFFSET` like every
/// other localnet service so parallel clones do not share a server.
pub fn socket_path() -> PathBuf {
    let offset = std::env::var("ZOLANA_PORT_OFFSET").unwrap_or_else(|_| "0".to_string());
    std::env::temp_dir().join(format!("zolana-squads-prover-{offset}.sock"))
}

pub fn pid_path() -> PathBuf {
    socket_path().with_extension("pid")
}

pub fn log_path() -> PathBuf {
    socket_path().with_extension("log")
}

pub fn write_message<T: Serialize>(stream: &mut impl Write, message: &T) -> io::Result<()> {
    let json = serde_json::to_vec(message)?;
    let len = u32::try_from(json.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message too large"))?;
    stream.write_all(&len.to_le_bytes())?;
    stream.write_all(&json)
}

pub fn read_message<T: DeserializeOwned>(stream: &mut impl Read) -> io::Result<T> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = usize::try_from(u32::from_le_bytes(len))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "message too large"))?;
    if len > MAX_MESSAGE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message of {len} bytes exceeds {MAX_MESSAGE_LEN}"),
        ));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    Ok(serde_json::from_slice(&body)?)
}
