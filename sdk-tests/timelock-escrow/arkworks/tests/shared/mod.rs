use timelock_escrow_arkworks::client;
use timelock_escrow_program::instructions::escrow::slot;
use zolana_keypair::{random_blinding, ShieldedKeypair, SigningKey};
use zolana_transaction::{
    utxo::{SppProofInputUtxo, Utxo},
    Data, Mint,
};

pub const TREE_ID: u16 = 3;

pub fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).expect("keypair")
}

pub fn token_input(owner: &ShieldedKeypair, amount: u64, leaf_index: u64) -> SppProofInputUtxo {
    let address = owner.shielded_address().expect("owner address");
    let utxo = Utxo {
        owner: owner.signing_pubkey(),
        asset: Mint::SOL,
        amount,
        blinding: random_blinding(),
        ring_program_id: None,
        data: Data::default(),
    };
    let utxo_hash = utxo
        .hash(&address.nullifier_pubkey, &[0u8; 32], &[0u8; 32], TREE_ID)
        .expect("utxo hash");
    let nullifier = owner
        .nullifier(&utxo_hash, &utxo.blinding)
        .expect("nullifier");
    SppProofInputUtxo {
        utxo,
        nullifier_pubkey: address.nullifier_pubkey,
        utxo_hash,
        nullifier,
        data_hash: None,
        ring_data_hash: None,
        tree_id: TREE_ID,
        leaf_index,
        cache_slot: None,
    }
}

pub fn escrow_utxo(creator: &ShieldedKeypair, amount: u64, unlock: u64) -> SppProofInputUtxo {
    let address = creator.shielded_address().expect("creator address");
    let escrow = client::Escrow {
        creator: address,
        token_utxos_asset_a: [
            token_input(creator, amount, 0),
            SppProofInputUtxo::dummy(TREE_ID).expect("dummy input"),
        ],
        amount,
        unlock,
        payer: address.solana_address().expect("payer"),
        output_tree_id: TREE_ID,
    }
    .build(creator)
    .expect("escrow transaction");
    let output = escrow
        .transaction
        .spp_proof_inputs
        .output_utxos
        .get(slot::ESCROW)
        .expect("escrow output");
    client::escrow_input(output, TREE_ID, 2).expect("escrow input")
}
