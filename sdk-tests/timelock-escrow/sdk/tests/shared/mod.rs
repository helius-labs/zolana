use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::Groth16Verifier,
    vk::gnark::{parse_gnark_vk_bytes, Groth16VerifyingkeyOwned},
};
use timelock_escrow_prover::{CircuitId, TimelockProof, PROVER};
use timelock_escrow_sdk::{
    escrow_authority,
    instructions::escrow::{EscrowProofInputParams, EscrowTransaction},
    state::{Funding, FundingUtxo},
    zk_program::NewProgramUtxo,
};
use zolana_keypair::{random_blinding, ShieldedKeypair, SigningKey};
use zolana_transaction::Mint;

pub const TREE_ID: u16 = 3;
pub const FUNDING: u64 = 1_000;
pub const UNLOCK: u64 = 1_700_000_000;

pub fn creator() -> ShieldedKeypair {
    keypair(5)
}

pub fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).expect("keypair")
}

pub fn funding(creator: &ShieldedKeypair, amount: u64) -> FundingUtxo {
    let creator_address = creator.shielded_address().expect("creator address");
    NewProgramUtxo::new(
        escrow_authority(),
        Funding {
            creator: creator_address,
        },
        Mint::SOL,
        amount,
        creator_address.viewing_pubkey,
    )
    .created(random_blinding(), TREE_ID)
}

pub fn escrow_params(
    creator: &ShieldedKeypair,
    funding: FundingUtxo,
    amount: u64,
) -> EscrowProofInputParams {
    EscrowProofInputParams {
        creator: creator.shielded_address().expect("creator address"),
        funding,
        funding_leaf_index: 0,
        amount,
        unlock_timestamp: UNLOCK,
        output_tree_id: TREE_ID,
    }
}

pub fn escrow(creator: &ShieldedKeypair, funding: FundingUtxo, amount: u64) -> EscrowTransaction {
    escrow_params(creator, funding, amount)
        .build(creator)
        .expect("escrow transaction")
}

pub fn ensure_keys(circuit: CircuitId) {
    let dir = PROVER.keys_dir(circuit);
    if !dir.join("pk.bin").exists() || !dir.join("vk.bin").exists() {
        PROVER
            .setup_insecure_test_keys(circuit, &dir)
            .expect("setup failed");
    }
}

pub fn generated_vk(circuit: CircuitId) -> Groth16VerifyingkeyOwned {
    let bytes = std::fs::read(PROVER.keys_dir(circuit).join("vk.bin")).expect("read vk.bin");
    parse_gnark_vk_bytes(&bytes).expect("parse vk.bin")
}

pub fn verifies(
    vk: &Groth16VerifyingkeyOwned,
    proof: &TimelockProof,
    public_input: [u8; 32],
) -> bool {
    let (Ok(a), Ok(b), Ok(c)) = (
        decompress_g1(&proof.proof_a),
        decompress_g2(&proof.proof_b),
        decompress_g1(&proof.proof_c),
    ) else {
        return false;
    };
    let public_inputs = [public_input];
    let borrowed = vk.as_borrowed();
    Groth16Verifier::new(&a, &b, &c, &public_inputs, &borrowed)
        .map(|mut verifier| verifier.verify().is_ok())
        .unwrap_or(false)
}
