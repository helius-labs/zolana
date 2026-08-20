use dynamic_swap_program::{
    error::DynamicSwapError,
    instructions::{
        verifier::Groth16ProofBytes,
        withdraw_liquidity::{process_withdraw_liquidity_ix, WithdrawLiquidityIxData},
    },
    state::{discriminator::PAIR, Pair},
};
use pinocchio::{error::ProgramError, Address};
use zolana_account_checks::account_info::test_account_info::get_account_view;
use zolana_interface::{
    instruction::instruction_data::transact::{TransactIxData, TransactProof},
    verifying_keys::CircuitId,
};

fn dummy_transact() -> TransactIxData {
    TransactIxData {
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [0u8; 32],
        circuit: CircuitId::ConfidentialEddsa(1, 2, 0),
        tx_viewing_pk: [2u8; 33],
        salt: [0u8; 16],
        proof: TransactProof::zeroed(),
        inputs: vec![],
        interface_transfers: vec![],
        data_hash: None,
        ring_data_hash: None,
        outputs: vec![],
        messages: vec![],
    }
}

#[test]
fn zero_withdrawal_is_rejected_before_proof_verification() {
    let authority = [7u8; 32];
    let pair_address = [8u8; 32];
    let pair = Pair {
        discriminator: PAIR,
        bump: 0,
        _pad: [0u8; 6],
        authority: Address::new_from_array(authority),
        source_asset_id: 1,
        destination_asset_id: 2,
        price: 1,
        expiry_slots: 1,
        max_order_size: 1,
        available_liquidity: 1,
        open_reservations: 0,
        source_asset: [1u8; 32],
        destination_asset: [2u8; 32],
        maker_receipt_owner_hash: [3u8; 32],
        maker_encryption_pubkey: [2u8; 33],
        _pad2: [0u8; 7],
    };
    let mut accounts = vec![
        get_account_view(authority, [0u8; 32], true, true, false, vec![]),
        get_account_view(
            pair_address,
            dynamic_swap_program::ID.to_bytes(),
            false,
            true,
            false,
            bytemuck::bytes_of(&pair).to_vec(),
        ),
    ];
    let data = wincode::serialize(&WithdrawLiquidityIxData {
        proof: Groth16ProofBytes {
            proof_a: [0u8; 32],
            proof_b: [0u8; 64],
            proof_c: [0u8; 32],
        },
        amount: 0,
        transact: dummy_transact(),
    })
    .expect("serialize withdrawal data");

    assert_eq!(
        process_withdraw_liquidity_ix(&mut accounts, &data),
        Err(ProgramError::Custom(
            DynamicSwapError::InvalidWithdrawalAmount as u32
        ))
    );
}
