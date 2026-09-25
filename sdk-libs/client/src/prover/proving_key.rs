//! The proving key each prove request must be served with.
//!
//! The prover reports the sha256 of the proving key file behind every proof
//! (`provingKeySha256`). The expected digest is the one generated next to the
//! verifying key the program verifies with, so a prover running a stale or
//! foreign key set fails here, before a transaction is built, instead of
//! on-chain.

use serde::Deserialize;
use zolana_interface::{
    verifying_keys::{
        Bsb22Commitment, CircuitId, RingP256ProofData, PROVING_KEY_SHA256S as TRANSACT_KEYS,
    },
    N_PUBLIC_SLOTS,
};
use zolana_tree::nullifier_tree::verify::verifying_keys::PROVING_KEY_SHA256S as ADDRESS_APPEND_KEYS;

use crate::ClientError;

/// One key in the prover's `GET /proving-keys` response.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProverKeyStatus {
    pub name: String,
    /// The sha256 the prover's proving-keys.lock pins; `None` for a key the
    /// lockfile does not know.
    pub expected_sha256: Option<String>,
    /// The sha256 of the bytes the prover loaded; `None` until loaded.
    pub loaded_sha256: Option<String>,
    pub available: bool,
}

/// The prover's `GET /proving-keys` response.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct ProverKeys {
    /// The prover's proving-key version (its lockfile prefix).
    pub prefix: String,
    pub keys: Vec<ProverKeyStatus>,
}

/// How one proving key this client knows stands on the prover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvingKeyCheck {
    pub name: &'static str,
    /// Whether the prover lists the key at all.
    pub served: bool,
    pub available: bool,
    pub loaded: bool,
}

/// A prover's proving keys, every one matching this client's verifying keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvingKeyReport {
    pub prefix: String,
    pub keys: Vec<ProvingKeyCheck>,
}

impl ProverKeys {
    /// Compare with every proving key this client knows. An expected or
    /// loaded digest that differs from the verifying key's pin is an error
    /// naming every such key. A key the prover does not serve or cannot load
    /// is only reported: provers may serve a subset.
    pub fn check(&self) -> Result<ProvingKeyReport, ClientError> {
        let mut mismatches = Vec::new();
        let mut keys = Vec::new();
        for (name, pinned) in known_proving_keys() {
            let Some(status) = self.keys.iter().find(|status| status.name == name) else {
                keys.push(ProvingKeyCheck {
                    name,
                    served: false,
                    available: false,
                    loaded: false,
                });
                continue;
            };
            for (kind, digest) in [
                ("expected", &status.expected_sha256),
                ("loaded", &status.loaded_sha256),
            ] {
                let Some(digest) = digest else { continue };
                let reported = parse_sha256_hex(digest).ok_or_else(|| {
                    ClientError::ProverServer(format!(
                        "/proving-keys reports a malformed {kind} sha256 for {name}"
                    ))
                })?;
                if reported != pinned {
                    mismatches.push(format!(
                        "{name} {kind} {digest}, verifying key pins {}",
                        hex(&pinned)
                    ));
                }
            }
            keys.push(ProvingKeyCheck {
                name,
                served: true,
                available: status.available,
                loaded: status.loaded_sha256.is_some(),
            });
        }
        if !mismatches.is_empty() {
            return Err(ClientError::ProverProvingKeysMismatch { mismatches });
        }
        Ok(ProvingKeyReport {
            prefix: self.prefix.clone(),
            keys,
        })
    }
}

/// The proving key a proof must come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedProvingKey {
    /// Key file name, as proving-keys.lock and the prover's `/proving-keys`
    /// name it.
    pub name: String,
    /// The sha256 the matching verifying key pins.
    pub sha256: [u8; 32],
}

/// Every proving key this client can check: the interface crate's transact
/// and merge keys and the nullifier tree's address-append keys, by file name.
pub fn known_proving_keys() -> impl Iterator<Item = (&'static str, [u8; 32])> {
    TRANSACT_KEYS.iter().chain(ADDRESS_APPEND_KEYS).copied()
}

impl ExpectedProvingKey {
    /// A transfer circuit. The digest comes from [`CircuitId::proving_key_sha256`],
    /// the table the on-chain verifier picks its verifying key from.
    fn transfer(
        file_prefix: &str,
        n_inputs: usize,
        n_outputs: usize,
        circuit: impl FnOnce(u8, u8, u8) -> CircuitId,
    ) -> Result<Self, ClientError> {
        let shape_err = || ClientError::UnsupportedShape {
            n_in: n_inputs,
            n_out: n_outputs,
        };
        let n_in = u8::try_from(n_inputs).map_err(|_| shape_err())?;
        let n_out = u8::try_from(n_outputs).map_err(|_| shape_err())?;
        let slots = u8::try_from(N_PUBLIC_SLOTS).map_err(|_| shape_err())?;
        let sha256 = *circuit(n_in, n_out, slots)
            .proving_key_sha256()
            .ok_or_else(shape_err)?;
        Ok(Self {
            name: format!("{file_prefix}_{n_inputs}_{n_outputs}.key"),
            sha256,
        })
    }

    pub(crate) fn transfer_confidential(
        n_inputs: usize,
        n_outputs: usize,
    ) -> Result<Self, ClientError> {
        Self::transfer(
            "transfer_confidential",
            n_inputs,
            n_outputs,
            CircuitId::ConfidentialEddsa,
        )
    }

    pub(crate) fn transfer_ring(n_inputs: usize, n_outputs: usize) -> Result<Self, ClientError> {
        Self::transfer("transfer_ring", n_inputs, n_outputs, CircuitId::RingEddsa)
    }

    pub(crate) fn transfer_ring_authority(
        n_inputs: usize,
        n_outputs: usize,
    ) -> Result<Self, ClientError> {
        Self::transfer(
            "transfer_ring_authority",
            n_inputs,
            n_outputs,
            CircuitId::RingAuthority,
        )
    }

    pub(crate) fn transfer_p256_ring(
        n_inputs: usize,
        n_outputs: usize,
    ) -> Result<Self, ClientError> {
        // The proof data does not select the key; only rail and shape do.
        let proof_data = RingP256ProofData {
            bsb22_commitment: Bsb22Commitment {
                commitment: [0; 32],
                commitment_pok: [0; 32],
            },
            default_owner_tag: None,
        };
        Self::transfer(
            "transfer_p256_ring",
            n_inputs,
            n_outputs,
            |n_in, n_out, slots| CircuitId::RingP256(n_in, n_out, slots, proof_data),
        )
    }

    /// A merge circuit. Merges always have one output, as in the prover's
    /// `merge_<inputs>_1.key` naming.
    fn merge_circuit(file_prefix: &str, n_inputs: usize) -> Result<Self, ClientError> {
        let name = format!("{file_prefix}_{n_inputs}_1.key");
        let sha256 = lookup(TRANSACT_KEYS, &name).ok_or(ClientError::UnsupportedShape {
            n_in: n_inputs,
            n_out: 1,
        })?;
        Ok(Self { name, sha256 })
    }

    pub(crate) fn merge(n_inputs: usize) -> Result<Self, ClientError> {
        Self::merge_circuit("merge", n_inputs)
    }

    pub(crate) fn merge_ring(n_inputs: usize) -> Result<Self, ClientError> {
        Self::merge_circuit("merge_ring", n_inputs)
    }

    pub(crate) fn batch_address_append(
        tree_height: u32,
        batch_size: u32,
    ) -> Result<Self, ClientError> {
        let name = format!("batch_address-append_{tree_height}_{batch_size}.key");
        let sha256 = lookup(ADDRESS_APPEND_KEYS, &name).ok_or(
            ClientError::UnsupportedAddressAppendShape {
                tree_height,
                batch_size,
            },
        )?;
        Ok(Self { name, sha256 })
    }

    /// Compare the digest a prover reported for a proof with this key.
    pub(crate) fn check(&self, reported: Option<[u8; 32]>) -> Result<(), ClientError> {
        match reported {
            None => Err(ClientError::MissingProvingKeySha256 {
                key: self.name.clone(),
            }),
            Some(reported) if reported == self.sha256 => Ok(()),
            Some(reported) => Err(ClientError::ProvingKeyMismatch {
                key: self.name.clone(),
                expected: hex(&self.sha256),
                reported: hex(&reported),
            }),
        }
    }
}

fn lookup(table: &[(&str, [u8; 32])], name: &str) -> Option<[u8; 32]> {
    table
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, sha256)| *sha256)
}

pub(crate) fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a prover-reported sha256: exactly 64 lowercase hex digits.
pub(crate) fn parse_sha256_hex(value: &str) -> Option<[u8; 32]> {
    let digits = value.as_bytes();
    if digits.len() != 64
        || !digits
            .iter()
            .all(|d| d.is_ascii_digit() || (b'a'..=b'f').contains(d))
    {
        return None;
    }
    let mut out = [0u8; 32];
    let (pairs, _) = digits.as_chunks::<2>();
    for (byte, pair) in out.iter_mut().zip(pairs) {
        let pair = core::str::from_utf8(pair).ok()?;
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}
