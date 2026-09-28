//! Deterministic wallets and spent UTXOs for the protocol-flow fixtures,
//! built the way `tests/scenarios/shared.rs` builds them, with fixed
//! blindings so every native value and pinned count is reproducible.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use solana_address::Address;
use solana_signature::Signature;
use zk_program_sdk::circuit::Field;
use zolana_keypair::{ShieldedAddress, ShieldedKeypair, SigningKey};
use zolana_transaction::{utxo::Utxo, Data, DataRecord, Mint, WalletUtxo};

pub const TREE_ID: u16 = 3;
pub const USDC: Mint = Mint::new(Address::new_from_array([4u8; 32]), 4);
pub const ACCOUNT: Address = Address::new_from_array([8u8; 32]);
pub const PAYER: Address = Address::new_from_array([9u8; 32]);
pub const SEED: [u8; 32] = blinding(0x5e);

pub const SENDER: u8 = 5;
pub const RECIPIENT: u8 = 6;
pub const STRANGER: u8 = 7;

pub fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).expect("keypair")
}

pub fn address(seed: u8) -> ShieldedAddress {
    keypair(seed).shielded_address().expect("shielded address")
}

pub const fn blinding(seed: u8) -> [u8; 32] {
    let mut bytes = [seed; 32];
    bytes[0] = 0;
    bytes
}

pub fn field_of(bytes: &[u8; 32]) -> Field {
    Field::from(Fr::from_be_bytes_mod_order(bytes))
}

#[derive(Clone, Debug)]
pub struct Spent {
    pub owner: u8,
    pub mint: Mint,
    pub amount: u64,
    pub state: Option<Vec<u8>>,
    pub data_hash: [u8; 32],
    pub ring: Option<([u8; 32], Address)>,
    pub tree_id: u16,
    pub latest_tree_id: Option<u16>,
    pub leaf_index: u64,
}

impl Spent {
    pub fn token(owner: u8, mint: Mint, amount: u64, leaf_index: u64) -> Self {
        Self {
            owner,
            mint,
            amount,
            state: None,
            data_hash: [0u8; 32],
            ring: None,
            tree_id: TREE_ID,
            latest_tree_id: None,
            leaf_index,
        }
    }

    pub fn with_ring(mut self, ring_data_hash: [u8; 32], ring_program_id: Address) -> Self {
        self.ring = Some((ring_data_hash, ring_program_id));
        self
    }

    pub fn with_state(mut self, state: Vec<u8>, data_hash: [u8; 32]) -> Self {
        self.state = Some(state);
        self.data_hash = data_hash;
        self
    }

    pub fn with_latest_tree_id(mut self, latest_tree_id: Option<u16>) -> Self {
        self.latest_tree_id = latest_tree_id;
        self
    }

    pub fn wallet_utxo(&self) -> WalletUtxo {
        let owner = keypair(self.owner);
        let address = owner.shielded_address().expect("owner address");
        let utxo = Utxo {
            owner: owner.signing_pubkey(),
            asset: self.mint,
            amount: self.amount,
            blinding: blinding(u8::try_from(self.leaf_index + 1).expect("small leaf index")),
            ring_program_id: self.ring.map(|(_, program_id)| program_id),
            data: self.state.clone().map_or_else(Data::default, |state| {
                Data::new(vec![DataRecord::UtxoData(state)])
            }),
        };
        let ring_data_hash = self.ring.map(|(data_hash, _)| data_hash);
        let utxo_hash = utxo
            .hash(
                &address.nullifier_pubkey,
                &self.data_hash,
                &ring_data_hash.unwrap_or_default(),
                self.tree_id,
            )
            .expect("utxo hash");
        WalletUtxo {
            nullifier: owner
                .nullifier(&utxo_hash, &utxo.blinding)
                .expect("nullifier"),
            tx_viewing_key: None,
            utxo,
            nullifier_pubkey: address.nullifier_pubkey,
            utxo_hash,
            data_hash: self.state.as_ref().map(|_| self.data_hash),
            ring_data_hash,
            tree_id: self.tree_id,
            leaf_index: self.leaf_index,
            latest_tree_id: self.latest_tree_id,
            slot: 0,
            tx_signature: Signature::default(),
            slot_index: 0,
        }
    }
}

pub fn token_input(owner: u8, mint: Mint, amount: u64, leaf_index: u64) -> WalletUtxo {
    Spent::token(owner, mint, amount, leaf_index).wallet_utxo()
}

pub fn dummy() -> WalletUtxo {
    crate::protocol::utxo::vectors::dummy(blinding(0xd0), TREE_ID)
}
