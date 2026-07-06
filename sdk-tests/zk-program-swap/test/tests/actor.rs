use anyhow::Result;
use solana_keypair::Keypair;
use zolana_keypair::{ShieldedKeypair, ViewingKey};
use zolana_transaction::Utxo;

/// One participant. Its shielded (SPP) identity is the ed25519 derivation of a
/// Solana `Keypair`, so the same Solana key can sign the SPP eddsa spend at
/// SPP `eddsa_signer_index` 0 while owning the confidential UTXOs.
pub(crate) struct Actor {
    pub(crate) solana_keypair: Keypair,
    pub(crate) shielded_keypair: ShieldedKeypair,
    pub(crate) spendable: Vec<Utxo>,
}

impl Actor {
    pub(crate) fn new() -> Result<Self> {
        let solana_keypair = Keypair::new();
        let seed: [u8; 32] = solana_keypair.to_bytes()[..32]
            .try_into()
            .expect("ed25519 seed is the first 32 bytes");
        let shielded_keypair = ShieldedKeypair::from_ed25519(&seed, ViewingKey::new())?;
        Ok(Self {
            solana_keypair,
            shielded_keypair,
            spendable: Vec::new(),
        })
    }
}
