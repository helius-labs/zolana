use std::{fs, str::FromStr, time::Instant};

use rand::rngs::OsRng;
use zolana_groth16_gnark::{parse_transfer_key, proof_json, prove, verify, Assignment};
use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::{ShieldedAddress, ShieldedKeypair, SigningKey};
use zolana_transaction::{
    instructions::{transact::ConfidentialTransfer, types::SppProofInputUtxo},
    Address, AssetRegistry, Data, Utxo, SOL_MINT,
};

#[derive(Debug, Clone)]
pub struct ProvingKeyInfo {
    pub inputs: u32,
    pub outputs: u32,
    pub requires_p256: bool,
    pub wires: u64,
    pub public_wires: u64,
    pub domain_size: u64,
    pub constraint_system_offset: u64,
}

#[derive(Debug, Clone)]
pub struct LocalProofResult {
    pub proof_json: String,
    pub verified: bool,
    pub inputs: u32,
    pub outputs: u32,
    pub key_load_ms: u64,
    pub proof_ms: u64,
    pub total_ms: u64,
}

#[derive(Debug, Clone)]
pub struct TransferDraftRequest {
    pub sender_seed: Vec<u8>,
    pub recipient: String,
    pub input_lamports: u64,
    pub transfer_lamports: u64,
}

#[derive(Debug, Clone)]
pub struct TransferDraftOutput {
    pub owner: String,
    pub lamports: u64,
    pub is_change: bool,
    pub is_dummy: bool,
    pub commitment_hex: String,
}

#[derive(Debug, Clone)]
pub struct TransferDraft {
    pub sender: String,
    pub recipient: String,
    pub input_lamports: u64,
    pub transfer_lamports: u64,
    pub change_lamports: u64,
    pub shape: String,
    pub first_nullifier_hex: String,
    pub external_data_hash_hex: String,
    pub outputs: Vec<TransferDraftOutput>,
}

pub fn sdk_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

pub fn poseidon_hash(inputs: Vec<Vec<u8>>) -> Result<Vec<u8>, String> {
    if inputs.is_empty() || inputs.len() > 12 {
        return Err("Poseidon expects between 1 and 12 field elements".to_string());
    }
    if let Some((index, input)) = inputs
        .iter()
        .enumerate()
        .find(|(_, input)| input.len() != 32)
    {
        return Err(format!(
            "Poseidon input {index} has {} bytes, expected 32",
            input.len()
        ));
    }
    let refs = inputs.iter().map(Vec::as_slice).collect::<Vec<_>>();
    Poseidon::hashv(&refs)
        .map(|hash| hash.to_vec())
        .map_err(|error| error.to_string())
}

pub fn inspect_proving_key(path: String) -> Result<ProvingKeyInfo, String> {
    let bytes = fs::read(&path).map_err(|error| format!("read {path}: {error}"))?;
    let key = parse_transfer_key(&bytes).map_err(|error| error.to_string())?;
    Ok(key_info(&key))
}

pub fn prove_assignment(
    proving_key_path: String,
    assignment_path: String,
) -> Result<LocalProofResult, String> {
    let total_started = Instant::now();
    let key_started = Instant::now();
    let key_bytes =
        fs::read(&proving_key_path).map_err(|error| format!("read {proving_key_path}: {error}"))?;
    let key = parse_transfer_key(&key_bytes).map_err(|error| error.to_string())?;
    let key_load_ms = elapsed_ms(key_started);

    let assignment_bytes =
        fs::read(&assignment_path).map_err(|error| format!("read {assignment_path}: {error}"))?;
    let assignment = Assignment::from_blob(&assignment_bytes).map_err(|error| error.to_string())?;
    let proof_started = Instant::now();
    let proof = prove(&key.pk, &assignment, &mut OsRng).map_err(|error| error.to_string())?;
    let proof_ms = elapsed_ms(proof_started);
    let public_inputs = &assignment.wires[1..assignment.nb_public];
    let verified = verify(&key.vk, &proof, public_inputs);

    Ok(LocalProofResult {
        proof_json: proof_json(&proof),
        verified,
        inputs: key.header.n_inputs,
        outputs: key.header.n_outputs,
        key_load_ms,
        proof_ms,
        total_ms: elapsed_ms(total_started),
    })
}

pub fn shielded_address(seed: Vec<u8>) -> Result<String, String> {
    keypair_from_seed(&seed)?
        .shielded_address()
        .map(|address| address.to_string())
        .map_err(|error| error.to_string())
}

pub fn prepare_transfer(request: TransferDraftRequest) -> Result<TransferDraft, String> {
    if request.input_lamports == 0 {
        return Err("input_lamports must be greater than zero".to_string());
    }
    if request.transfer_lamports == 0 {
        return Err("transfer_lamports must be greater than zero".to_string());
    }
    if request.transfer_lamports > request.input_lamports {
        return Err("transfer_lamports exceeds the input balance".to_string());
    }

    let sender = keypair_from_seed(&request.sender_seed)?;
    let sender_address = sender
        .shielded_address()
        .map_err(|error| error.to_string())?;
    let recipient =
        ShieldedAddress::from_str(&request.recipient).map_err(|error| error.to_string())?;
    let payer = Address::new_from_array(
        sender
            .signing_pubkey()
            .as_ed25519()
            .map_err(|error| error.to_string())?,
    );
    let mut blinding = [0u8; 32];
    blinding[1..].copy_from_slice(&request.sender_seed[1..]);
    let input = SppProofInputUtxo::new(
        Utxo {
            owner: sender.signing_pubkey(),
            asset: SOL_MINT,
            amount: request.input_lamports,
            blinding,
            ring_program_id: None,
            data: Data::default(),
        },
        &sender,
    );
    let mut transfer =
        ConfidentialTransfer::new(sender_address, vec![input], payer).with_compact_change();
    transfer
        .send(&recipient, SOL_MINT, request.transfer_lamports)
        .map_err(|error| error.to_string())?;
    let proof_inputs = transfer
        .sign(&sender, &AssetRegistry::default())
        .map_err(|error| error.to_string())?;
    let shape = proof_inputs
        .check_shape()
        .map_err(|error| error.to_string())?;
    let first_nullifier = proof_inputs.input_utxos[0]
        .nullifier()
        .map_err(|error| error.to_string())?;
    let external_data_hash = proof_inputs
        .external_data
        .hash()
        .map_err(|error| error.to_string())?;
    let sender_text = sender_address.to_string();
    let outputs = proof_inputs
        .output_utxos
        .iter()
        .map(|output| {
            let owner = output
                .owner_address
                .map(|address| address.to_string())
                .unwrap_or_default();
            let commitment = output.hash().map_err(|error| error.to_string())?;
            Ok(TransferDraftOutput {
                is_change: output.owner_address == Some(sender_address),
                is_dummy: output.is_dummy(),
                owner,
                lamports: output.amount,
                commitment_hex: hex(&commitment),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(TransferDraft {
        sender: sender_text,
        recipient: recipient.to_string(),
        input_lamports: request.input_lamports,
        transfer_lamports: request.transfer_lamports,
        change_lamports: request.input_lamports - request.transfer_lamports,
        shape: format!("{}→{}", shape.n_inputs(), shape.n_outputs()),
        first_nullifier_hex: hex(&first_nullifier),
        external_data_hash_hex: hex(&external_data_hash),
        outputs,
    })
}

fn key_info(key: &zolana_groth16_gnark::TransferKey) -> ProvingKeyInfo {
    ProvingKeyInfo {
        inputs: key.header.n_inputs,
        outputs: key.header.n_outputs,
        requires_p256: key.header.requires_p256,
        wires: key.pk.nb_wires as u64,
        public_wires: key.pk.nb_public() as u64,
        domain_size: key.pk.domain.cardinality,
        constraint_system_offset: key.constraint_system_offset as u64,
    }
}

fn keypair_from_seed(seed: &[u8]) -> Result<ShieldedKeypair, String> {
    let bytes: [u8; 32] = seed
        .try_into()
        .map_err(|_| format!("seed has {} bytes, expected 32", seed.len()))?;
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&bytes))
        .map_err(|error| error.to_string())
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepares_compact_partial_transfer() {
        let recipient = shielded_address(vec![8; 32]).unwrap();
        let draft = prepare_transfer(TransferDraftRequest {
            sender_seed: vec![7; 32],
            recipient,
            input_lamports: 10,
            transfer_lamports: 4,
        })
        .unwrap();

        assert_eq!(draft.shape, "1→2");
        assert_eq!(draft.change_lamports, 6);
        assert_eq!(draft.outputs.len(), 2);
        assert!(draft.outputs[0].is_change);
        assert!(!draft.outputs[1].is_change);
    }

    #[test]
    fn poseidon_binding_validates_inputs() {
        assert!(poseidon_hash(vec![]).is_err());
        assert!(poseidon_hash(vec![vec![0; 31]]).is_err());
        assert_eq!(poseidon_hash(vec![vec![0; 32]]).unwrap().len(), 32);
    }

    #[test]
    #[ignore = "requires local proving fixtures"]
    fn proves_and_verifies_staged_assignment() {
        let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let result = prove_assignment(
            repository
                .join("prover/server/proving-keys/transfer_confidential_2_3.key")
                .display()
                .to_string(),
            repository
                .join("target/assignment-2x3.bin")
                .display()
                .to_string(),
        )
        .unwrap();

        assert!(result.verified);
        assert_eq!((result.inputs, result.outputs), (2, 3));
    }
}
