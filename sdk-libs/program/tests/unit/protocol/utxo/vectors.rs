use solana_address::Address;
use solana_signature::Signature;
use zolana_program::circuit::Field;
use zolana_transaction::{
    utxo::{ProofInputUtxo, SppProofInputUtxo, Utxo},
    Data, Mint, WalletUtxo,
};

use crate::{
    harness::{
        field::{be_bytes, MODULUS_MINUS_1},
        fixture::Named,
    },
    protocol::{
        asset::vectors::{field_of, USDC},
        owner::keys::{self, Key},
    },
};

pub const TREE_ID: u16 = 3;

#[derive(Clone)]
pub struct Preimage {
    pub name: &'static str,
    pub key: Key,
    pub mint: Mint,
    pub amount: u64,
    pub blinding: [u8; 32],
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
    pub ring_program_id: Option<Address>,
    pub tree_id: u16,
    pub latest_tree_id: Option<u16>,
}

impl std::fmt::Debug for Preimage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Preimage")
            .field("owner", &self.key.address.signing_pubkey)
            .field("mint", &self.mint)
            .field("amount", &self.amount)
            .field("blinding", &self.blinding)
            .field("data_hash", &self.data_hash)
            .field("ring_data_hash", &self.ring_data_hash)
            .field("ring_program_id", &self.ring_program_id)
            .field("tree_id", &self.tree_id)
            .finish()
    }
}

impl Named for Preimage {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl Preimage {
    pub fn utxo(&self) -> Utxo {
        Utxo {
            owner: self.key.address.signing_pubkey,
            asset: self.mint,
            amount: self.amount,
            blinding: self.blinding,
            ring_program_id: self.ring_program_id,
            data: Data::default(),
        }
    }

    pub fn native_hash(&self) -> [u8; 32] {
        self.utxo()
            .hash(
                &self.key.address.nullifier_pubkey,
                &self.data_hash.unwrap_or_default(),
                &self.ring_data_hash.unwrap_or_default(),
                self.tree_id,
            )
            .expect("native utxo hash")
    }

    pub fn native_nullifier(&self) -> [u8; 32] {
        self.utxo()
            .nullifier(&self.native_hash(), &self.key.nullifier_key)
            .expect("native nullifier")
    }

    pub fn hash(&self) -> Field {
        field_of(&self.native_hash())
    }

    pub fn wallet(&self) -> WalletUtxo {
        WalletUtxo {
            utxo: self.utxo(),
            nullifier_pubkey: self.key.address.nullifier_pubkey,
            utxo_hash: self.native_hash(),
            nullifier: self.native_nullifier(),
            tx_viewing_key: None,
            data_hash: self.data_hash,
            ring_data_hash: self.ring_data_hash,
            tree_id: self.tree_id,
            leaf_index: 0,
            latest_tree_id: self.latest_tree_id,
            slot: 0,
            tx_signature: Signature::default(),
            slot_index: 0,
        }
    }

    pub fn fields(&self) -> ProofInputUtxo {
        ProofInputUtxo::try_from(&SppProofInputUtxo::from(&self.wallet()))
            .expect("proof input fields")
    }
}

pub fn blinding(seed: u8) -> [u8; 32] {
    let mut bytes = [seed; 32];
    bytes[0] = 0;
    bytes
}

fn token(name: &'static str, key: Key, mint: Mint, amount: u64) -> Preimage {
    Preimage {
        name,
        key,
        mint,
        amount,
        blinding: blinding(9),
        data_hash: None,
        ring_data_hash: None,
        ring_program_id: None,
        tree_id: TREE_ID,
        latest_tree_id: None,
    }
}

pub fn preimages() -> Vec<Preimage> {
    vec![
        token("ed25519 SOL token of 1", keys::ed25519(7), Mint::SOL, 1),
        token("p256 USDC token of 2^64 - 1", keys::p256(7), USDC, u64::MAX),
        token("pda SOL token of 0", keys::pda(7), Mint::SOL, 0),
        Preimage {
            data_hash: Some(blinding(21)),
            ring_data_hash: Some(blinding(22)),
            ring_program_id: Some(Address::new_from_array([23u8; 32])),
            ..token("ed25519 data utxo in a ring", keys::ed25519(42), USDC, 500)
        },
        Preimage {
            tree_id: u16::MAX,
            latest_tree_id: Some(4),
            ..token(
                "p256 token in tree 2^16 - 1 reporting tree 4",
                keys::p256(42),
                Mint::SOL,
                3,
            )
        },
        Preimage {
            blinding: be_bytes(MODULUS_MINUS_1),
            data_hash: Some(be_bytes(MODULUS_MINUS_1)),
            ..token(
                "pda data utxo with p - 1 blinding and data hash",
                keys::pda(42),
                USDC,
                9,
            )
        },
    ]
}

pub fn dummy(blinding: [u8; 32], tree_id: u16) -> WalletUtxo {
    let dummy = SppProofInputUtxo::dummy_with_blinding(blinding, tree_id).expect("dummy input");
    WalletUtxo {
        utxo: dummy.utxo,
        nullifier_pubkey: dummy.nullifier_pubkey,
        utxo_hash: dummy.utxo_hash,
        nullifier: dummy.nullifier,
        tx_viewing_key: None,
        data_hash: dummy.data_hash,
        ring_data_hash: dummy.ring_data_hash,
        tree_id: dummy.tree_id,
        leaf_index: dummy.leaf_index,
        latest_tree_id: None,
        slot: 0,
        tx_signature: Signature::default(),
        slot_index: 0,
    }
}
