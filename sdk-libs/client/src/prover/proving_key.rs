//! The proving key each prove request must be served with.
//!
//! The prover reports the sha256 of the proving key file behind every proof
//! (`provingKeySha256`). The expected digest is the one generated next to the
//! verifying key the program verifies with, so a prover running a stale or
//! foreign key set fails here, before a transaction is built, instead of
//! on-chain.

use serde::Deserialize;
use spr_interface::{
    verifying_keys::{
        AnonymousRingEddsaProofData, Bsb22Commitment, CircuitId, EddsaProofData,
        PROVING_KEY_SHA256S as TRANSACT_KEYS,
    },
    N_PUBLIC_SLOTS,
};
use spr_tree::nullifier_tree::verify::verifying_keys::PROVING_KEY_SHA256S as ADDRESS_APPEND_KEYS;

use crate::ClientError;

/// Serialization of one downloadable proving-key artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProvingKeyFormat {
    Gnark,
    Zopro,
}

/// The checksum and size apply to the bytes downloaded from this URL.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct ProvingKeyArtifact {
    pub format: ProvingKeyFormat,
    pub sha256: String,
    pub size: u64,
    pub url: String,
}

/// A manifest-backed key and its published downloads.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct ProverKeyStatus {
    pub name: String,
    pub artifacts: Vec<ProvingKeyArtifact>,
}

/// The prover's `GET /proving-keys` response.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct ProverKeys {
    pub keys: Vec<ProverKeyStatus>,
}

/// A key in the checked download catalog.
pub type ProvingKeyCheck = ProverKeyStatus;

/// A download catalog whose gnark digests match every client-known key listed.
/// Keys absent from the catalog remain absent; this does not describe routing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvingKeyReport {
    pub keys: Vec<ProvingKeyCheck>,
}

impl ProverKeys {
    /// Validate the catalog and compare gnark hashes with the verifying-key pins.
    /// A missing key is permitted, but every listed key needs one gnark artifact.
    pub fn check(&self) -> Result<ProvingKeyReport, ClientError> {
        let invalid = || ClientError::ProverServer("invalid /proving-keys catalog".into());
        let mut names = std::collections::HashSet::new();
        let mut mismatches = Vec::new();
        for status in &self.keys {
            if !names.insert(&status.name)
                || status.name.len() <= 4
                || !status.name.ends_with(".key")
                || !status
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
                || status.name.contains("..")
            {
                return Err(invalid());
            }
            let mut gnark = None;
            let mut zopro = false;
            for artifact in &status.artifacts {
                let digest = parse_sha256_hex(&artifact.sha256).ok_or_else(invalid)?;
                let url = url::Url::parse(&artifact.url).map_err(|_| invalid())?;
                if artifact.size == 0
                    || artifact.size > 9_007_199_254_740_991
                    || !matches!(url.scheme(), "https" | "http")
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.fragment().is_some()
                {
                    return Err(invalid());
                }
                match artifact.format {
                    ProvingKeyFormat::Gnark => {
                        if gnark.replace(digest).is_some() {
                            return Err(invalid());
                        }
                    }
                    ProvingKeyFormat::Zopro => {
                        if zopro {
                            return Err(invalid());
                        }
                        zopro = true;
                    }
                }
            }
            let gnark = gnark.ok_or_else(invalid)?;
            if let Some((_, pinned)) = known_proving_keys().find(|(name, _)| *name == status.name) {
                if gnark != pinned {
                    mismatches.push(format!(
                        "{} gnark {}, verifying key pins {}",
                        status.name,
                        hex(&gnark),
                        hex(&pinned)
                    ));
                }
            }
        }
        if !mismatches.is_empty() {
            return Err(ClientError::ProverProvingKeysMismatch { mismatches });
        }
        Ok(ProvingKeyReport {
            keys: self.keys.clone(),
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
    /// The path of this key's proofs, `/prove/<key>`, `<key>` being the file
    /// name without `.key`. A gateway routes and prices on the path alone, so
    /// it can send each key, and each key's status polls, to its own prover
    /// pool at its own price.
    pub(crate) fn prove_path(&self) -> String {
        let name = self.name.strip_suffix(".key").unwrap_or(&self.name);
        format!("{}/{name}", super::PROVE_PATH)
    }

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
            CircuitId::ConfidentialSigner,
        )
    }

    pub(crate) fn transfer_ring(n_inputs: usize, n_outputs: usize) -> Result<Self, ClientError> {
        Self::transfer(
            "transfer_ring",
            n_inputs,
            n_outputs,
            CircuitId::ConfidentialRingEddsa,
        )
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

    pub(crate) fn transfer_anonymous_ring_eddsa(
        n_inputs: usize,
        n_outputs: usize,
    ) -> Result<Self, ClientError> {
        // The proof data does not select the key; only rail and shape do.
        let proof_data = AnonymousRingEddsaProofData {
            bsb22_commitment: Bsb22Commitment {
                commitment: [0; 32],
                commitment_pok: [0; 32],
            },
            default_owner_tag: None,
        };
        Self::transfer(
            "transfer_eddsa_ring",
            n_inputs,
            n_outputs,
            |n_in, n_out, slots| CircuitId::AnonymousRingEddsa(n_in, n_out, slots, proof_data),
        )
    }

    pub(crate) fn transfer_confidential_eddsa(
        n_inputs: usize,
        n_outputs: usize,
    ) -> Result<Self, ClientError> {
        // The proof data does not select the key; only rail and shape do.
        let proof_data = EddsaProofData {
            bsb22_commitment: Bsb22Commitment {
                commitment: [0; 32],
                commitment_pok: [0; 32],
            },
            owner_pk: [0; 32],
        };
        Self::transfer(
            "transfer_confidential_eddsa",
            n_inputs,
            n_outputs,
            |n_in, n_out, slots| CircuitId::ConfidentialEddsa(n_in, n_out, slots, proof_data),
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

    /// Its proofs carry only public tree data.
    pub(crate) fn is_address_append(&self) -> bool {
        lookup(ADDRESS_APPEND_KEYS, &self.name) == Some(self.sha256)
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
