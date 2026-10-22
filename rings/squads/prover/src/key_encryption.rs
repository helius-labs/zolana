use std::collections::HashMap;

use zolana_gnark_ffi_prover::{decimal, ProofInputMap};

use crate::{prove, CircuitId, Error, Result, SquadsProof};

/// Supported recovery-plus-auditor recipient key counts.
pub const KEY_ENCRYPTION_SUPPORTED_KEYS: [usize; 3] = [1, 2, 3];

/// The key encryption witness. Secrets are raw 32-byte X25519 keys,
/// clamped during key agreement; recipients are tagged keys `0x04 || u`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEncryptionProofInputs {
    pub old_state_hash: [u8; 32],
    pub viewing_secret_key: [u8; 32],
    pub ephemeral_secret_key: [u8; 32],
    pub nullifier_secret: [u8; 32],
    pub recipient_keys: Vec<[u8; 33]>,
    pub public_input_hash: [u8; 32],
}

impl KeyEncryptionProofInputs {
    pub fn circuit(&self) -> Result<CircuitId> {
        match self.recipient_keys.len() {
            1 => Ok(CircuitId::KeyEncryption1),
            2 => Ok(CircuitId::KeyEncryption2),
            3 => Ok(CircuitId::KeyEncryption3),
            count => Err(Error::UnsupportedKeyCount(count)),
        }
    }

    fn witness(&self) -> ProofInputMap {
        let mut map = HashMap::new();
        let scalars: [(&str, &[u8; 32]); 3] = [
            ("OldStateHash", &self.old_state_hash),
            ("NullifierSecret", &self.nullifier_secret),
            ("PublicInputHash", &self.public_input_hash),
        ];
        for (key, value) in scalars {
            map.insert(key.to_string(), vec![decimal(value)]);
        }
        map.insert(
            "ViewingSecretKey".to_string(),
            self.viewing_secret_key.iter().map(u8::to_string).collect(),
        );
        map.insert(
            "EphemeralSecretKey".to_string(),
            self.ephemeral_secret_key
                .iter()
                .map(u8::to_string)
                .collect(),
        );
        for (index, pubkey) in self.recipient_keys.iter().enumerate() {
            map.insert(
                format!("RecipientKeys_{index}_Pubkey"),
                pubkey.iter().map(u8::to_string).collect(),
            );
        }
        map
    }

    pub fn prove(&self) -> Result<SquadsProof> {
        prove(self.circuit()?, &self.witness())
    }
}
