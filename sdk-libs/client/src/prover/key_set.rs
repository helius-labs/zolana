//! Proving keys a client takes at runtime from an attested prover.
//!
//! The prover's `/proving-keys` catalog lists each key's downloads. Its
//! `runtime` block adds the verifying key of every confidential signer and
//! merge circuit, so a client follows a key rotation without a new build.
//! The enclave image embeds that block, and only an encrypted answer from a
//! prover attesting to the client's TEE policy yields a [`ProvingKeySet`].

use std::collections::BTreeMap;

use groth16_solana::groth16::Groth16Verifyingkey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spr_interface::PROGRAM_ID_PUBKEY;

use super::{
    endpoint::ProverEndpoint,
    known_proving_keys,
    proving_key::{hex, parse_sha256_hex},
    verify::{confidential_verifying_key, merge_verifying_key, StatementVerification},
    ExpectedProvingKey, ProverKeyStatus, ProvingKeyArtifact, ProvingKeyFormat,
};
use crate::{ClientError, Proof};

/// The proof-input contract of the confidential signer and merge circuits.
/// A release that changes a witness field, a public input or a solver
/// feature the runtime needs changes this, and clients built before it refuse
/// its keys.
pub const PROVING_KEY_ABI: &str = "spr-confidential-v1";

/// The `runtime` block of the prover's `/proving-keys` catalog.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeKeyMetadata {
    pub abi: String,
    pub program_id: String,
    pub verifying_keys: BTreeMap<String, RuntimeVerifyingKey>,
}

/// One circuit's verifying key: uncompressed BN254 points in the on-chain
/// verifier's big-endian encoding, as lowercase hex.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeVerifyingKey {
    /// The gnark proving key this verifying key belongs to.
    pub proving_key_sha256: String,
    pub alpha_g1: String,
    pub beta_g2: String,
    pub gamma_g2: String,
    pub delta_g2: String,
    pub ic: [String; 2],
}

impl RuntimeKeyMetadata {
    /// The metadata of the verifying keys this crate was built with. Release
    /// tooling writes it into the prover image
    /// (`cargo run -q -p xtask -- runtime-proving-keys`).
    pub fn compiled() -> Self {
        let verifying_keys = runtime_names()
            .map(|(name, sha256)| {
                let key = compiled_verifying_key(name).expect("a runtime circuit has a verifier");
                assert_eq!(key.nr_pubinputs, 1, "{name} has one public input");
                assert_eq!(key.vk_ic.len(), 2, "{name} has one public input");
                assert!(key.vk_commitment.is_none(), "{name} has no commitment");
                let key = RuntimeVerifyingKey {
                    proving_key_sha256: hex(&sha256),
                    alpha_g1: hex::encode(key.vk_alpha_g1),
                    beta_g2: hex::encode(key.vk_beta_g2),
                    gamma_g2: hex::encode(key.vk_gamma_g2),
                    delta_g2: hex::encode(key.vk_delta_g2),
                    ic: [hex::encode(key.vk_ic[0]), hex::encode(key.vk_ic[1])],
                };
                (name.to_owned(), key)
            })
            .collect();
        Self {
            abi: PROVING_KEY_ABI.into(),
            program_id: PROGRAM_ID_PUBKEY.to_string(),
            verifying_keys,
        }
    }
}

/// The keys of one protocol release, taken from an attested prover. A client
/// holds one set for its lifetime, so a rotation never mixes releases within
/// a proof.
#[derive(Clone, Debug)]
pub struct ProvingKeySet {
    keys: BTreeMap<String, Key>,
    cache_key: String,
}

#[derive(Clone, Debug)]
struct Key {
    sha256: [u8; 32],
    alpha: [u8; 64],
    beta: [u8; 128],
    gamma: [u8; 128],
    delta: [u8; 128],
    ic: [[u8; 64]; 2],
    /// The zopro conversion's download.
    artifact: ProvingKeyArtifact,
}

impl ProvingKeySet {
    /// Parse the decrypted `/proving-keys` answer of an attested prover.
    /// The set covers every confidential signer and merge circuit this crate
    /// knows; entries for other circuits are ignored.
    pub(crate) fn from_attested_response(json: &str) -> Result<Self, ClientError> {
        #[derive(Deserialize)]
        struct Catalog {
            keys: Vec<ProverKeyStatus>,
            runtime: Option<RuntimeKeyMetadata>,
        }
        let catalog: Catalog = serde_json::from_str(json).map_err(|_| invalid("malformed"))?;
        let runtime = catalog.runtime.ok_or_else(|| invalid("runtime_missing"))?;
        if runtime.abi != PROVING_KEY_ABI || runtime.program_id != PROGRAM_ID_PUBKEY.to_string() {
            return Err(invalid("incompatible"));
        }
        let mut keys = BTreeMap::new();
        for (name, _) in runtime_names() {
            let verifier = runtime
                .verifying_keys
                .get(name)
                .ok_or_else(|| invalid("incompatible"))?;
            let entry = only(catalog.keys.iter().filter(|key| key.name == name))?;
            let gnark = only(
                entry
                    .artifacts
                    .iter()
                    .filter(|artifact| artifact.format == ProvingKeyFormat::Gnark),
            )?;
            let zopro = only(
                entry
                    .artifacts
                    .iter()
                    .filter(|artifact| artifact.format == ProvingKeyFormat::Zopro),
            )?;
            if gnark.sha256 != verifier.proving_key_sha256 {
                return Err(invalid("source_mismatch"));
            }
            check_download(zopro)?;
            keys.insert(
                name.to_owned(),
                Key {
                    sha256: fixed(&verifier.proving_key_sha256)?,
                    alpha: fixed(&verifier.alpha_g1)?,
                    beta: fixed(&verifier.beta_g2)?,
                    gamma: fixed(&verifier.gamma_g2)?,
                    delta: fixed(&verifier.delta_g2)?,
                    ic: [fixed(&verifier.ic[0])?, fixed(&verifier.ic[1])?],
                    artifact: zopro.clone(),
                },
            );
        }
        let identities: Vec<_> = keys
            .iter()
            .map(|(name, key)| {
                (
                    name,
                    hex(&key.sha256),
                    &key.artifact.sha256,
                    key.artifact.size,
                )
            })
            .collect();
        let identities = serde_json::to_vec(&identities).expect("key identities serialize");
        let cache_key = hex::encode(Sha256::digest(identities));
        Ok(Self { keys, cache_key })
    }

    /// Names the files of this set: the sha256 of its keys' names, gnark
    /// digests and zopro downloads, as 64 lowercase hex digits.
    pub fn cache_key(&self) -> &str {
        &self.cache_key
    }

    /// Each key with its zopro download, by name.
    pub fn keys(&self) -> impl Iterator<Item = (ExpectedProvingKey, &ProvingKeyArtifact)> {
        self.keys.iter().map(|(name, key)| {
            (
                ExpectedProvingKey {
                    name: name.clone(),
                    sha256: key.sha256,
                },
                &key.artifact,
            )
        })
    }

    /// The gnark digest of key `name`, if the set holds it.
    pub(crate) fn sha256(&self, name: &str) -> Option<[u8; 32]> {
        self.keys.get(name).map(|key| key.sha256)
    }

    /// The key of this set a proof for `key` must come from. A circuit
    /// outside the set fails: its compiled pin may belong to another release.
    pub fn expected(&self, key: &ExpectedProvingKey) -> Result<ExpectedProvingKey, ClientError> {
        let found = self
            .keys
            .get(&key.name)
            .ok_or_else(|| invalid("unsupported_circuit"))?;
        Ok(ExpectedProvingKey {
            name: key.name.clone(),
            sha256: found.sha256,
        })
    }

    /// Verify `proof` of key `name` against this set's verifying key.
    pub fn verify(
        &self,
        name: &str,
        public_input_hash: [u8; 32],
        proof: &Proof,
    ) -> Result<(), ClientError> {
        let key = self
            .keys
            .get(name)
            .ok_or_else(|| invalid("unsupported_circuit"))?;
        let verifying_key = Groth16Verifyingkey {
            nr_pubinputs: 1,
            vk_alpha_g1: key.alpha,
            vk_beta_g2: key.beta,
            vk_gamma_g2: key.gamma,
            vk_delta_g2: key.delta,
            vk_ic: &key.ic,
            vk_commitment: None,
        };
        StatementVerification {
            verifying_key: &verifying_key,
            public_input_hash,
        }
        .verify(proof)
    }
}

/// The confidential signer and merge keys, which the runtime set replaces.
fn runtime_names() -> impl Iterator<Item = (&'static str, [u8; 32])> {
    known_proving_keys().filter(|(name, _)| compiled_verifying_key(name).is_some())
}

fn compiled_verifying_key(name: &str) -> Option<&'static Groth16Verifyingkey<'static>> {
    let stem = name.strip_suffix(".key")?;
    if let Some(shape) = stem.strip_prefix("transfer_confidential_") {
        let (inputs, outputs) = shape.split_once('_')?;
        let (inputs, outputs) = (inputs.parse().ok()?, outputs.parse().ok()?);
        return confidential_verifying_key(inputs, outputs).ok();
    }
    let inputs = stem.strip_prefix("merge_")?.strip_suffix("_1")?;
    merge_verifying_key(inputs.parse().ok()?).ok()
}

fn only<'a, T>(mut items: impl Iterator<Item = &'a T>) -> Result<&'a T, ClientError> {
    match (items.next(), items.next()) {
        (Some(item), None) => Ok(item),
        _ => Err(invalid("malformed")),
    }
}

/// A download the client fetches and checks against `sha256` and `size`.
fn check_download(artifact: &ProvingKeyArtifact) -> Result<(), ClientError> {
    parse_sha256_hex(&artifact.sha256).ok_or_else(|| invalid("malformed"))?;
    let url = url::Url::parse(&artifact.url).map_err(|_| invalid("malformed"))?;
    let transport = url.scheme() == "https"
        || (url.scheme() == "http" && ProverEndpoint::parse(&artifact.url).is_loopback());
    if artifact.size == 0
        || artifact.size > u64::from(u32::MAX)
        || !transport
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid("malformed"));
    }
    Ok(())
}

/// `N` bytes as exactly `2 * N` lowercase hex digits.
fn fixed<const N: usize>(value: &str) -> Result<[u8; N], ClientError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(invalid("malformed"));
    }
    let mut out = [0; N];
    hex::decode_to_slice(value, &mut out).map_err(|_| invalid("malformed"))?;
    Ok(out)
}

fn invalid(reason: &'static str) -> ClientError {
    ClientError::ProvingKeySet(reason)
}

#[cfg(test)]
mod tests;
