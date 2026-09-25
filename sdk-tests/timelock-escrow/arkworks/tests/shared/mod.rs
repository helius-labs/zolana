use solana_signature::Signature;
use timelock_escrow_arkworks::{
    escrow_input, Escrow, EscrowPrivateInputs, EscrowPublicInputs, ESCROW_TOKEN_INPUTS,
};
use timelock_escrow_program::instructions::escrow::slot;
use timelock_escrow_sdk::escrow_authority;
use zk_program_sdk::{TxContext, ZkProgram};
use zolana_keypair::{random_blinding, ShieldedKeypair, SigningKey};
use zolana_transaction::{utxo::Utxo, Data, Mint, WalletUtxo};

pub const TREE_ID: u16 = 3;

pub fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).expect("keypair")
}

pub fn token_input(owner: &ShieldedKeypair, amount: u64, leaf_index: u64) -> WalletUtxo {
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
    WalletUtxo {
        nullifier: owner
            .nullifier(&utxo_hash, &utxo.blinding)
            .expect("nullifier"),
        utxo,
        nullifier_pubkey: address.nullifier_pubkey,
        utxo_hash,
        data_hash: None,
        ring_data_hash: None,
        tree_id: TREE_ID,
        leaf_index,
        latest_tree_id: None,
        slot: 0,
        tx_signature: Signature::default(),
        slot_index: 0,
    }
}

pub fn token_inputs<const N: usize>(inputs: [WalletUtxo; N]) -> [WalletUtxo; ESCROW_TOKEN_INPUTS] {
    let mut inputs = inputs.into_iter();
    std::array::from_fn(|_| {
        inputs
            .next()
            .unwrap_or_else(|| WalletUtxo::dummy(TREE_ID).expect("dummy"))
    })
}

pub fn escrow_utxo(creator: &ShieldedKeypair, amount: u64, unlock: u64) -> WalletUtxo {
    let address = creator.shielded_address().expect("creator address");
    let funding = token_input(creator, amount, 0);
    let spp_proof_inputs = Escrow {
        private: EscrowPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: token_inputs([funding]),
            unlock,
            amount,
        },
        public: EscrowPublicInputs {
            escrow_owner: escrow_authority()
                .address(address.viewing_pubkey)
                .expect("escrow owner"),
        },
    }
    .create_proof_inputs_and_encrypt(creator, address.solana_address().expect("payer"), u64::MAX)
    .expect("escrow transaction");
    let output = spp_proof_inputs
        .output_utxos
        .get(slot::ESCROW)
        .expect("escrow output");
    escrow_input(output, spp_proof_inputs.output_tree_id, 2).expect("escrow input")
}
