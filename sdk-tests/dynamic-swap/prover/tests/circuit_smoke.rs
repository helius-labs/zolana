use dynamic_swap_program::instructions::{
    create_escrow::EscrowOpenPublicInput, deposit_liquidity::PoolUpdatePublicInput,
    refund_expired::RefundPublicInput, settle::SettlePublicInput, shared::u64_right_align,
};
use dynamic_swap_prover::{
    EscrowOpenProofInputs, EscrowRefundProofInputs, EscrowSettleProofInputs, PoolUpdateProofInputs,
    ProofInputUtxo,
};
use solana_address::Address;
use zolana_hasher::{Hasher, Poseidon};
use zolana_transaction::instructions::transact::PrivateTxHash;

fn fe(value: u64) -> [u8; 32] {
    u64_right_align(value)
}

fn note(owner: [u8; 32], asset: &Address, amount: u64, blinding: u64) -> ProofInputUtxo {
    ProofInputUtxo::new(owner, asset, amount, &fe(blinding)).unwrap()
}

fn private_tx(
    inputs: &[ProofInputUtxo],
    outputs: &[ProofInputUtxo],
    external_data_hash: &[u8; 32],
) -> [u8; 32] {
    let input_hashes = inputs
        .iter()
        .map(|utxo| utxo.hash().unwrap())
        .collect::<Vec<_>>();
    let output_hashes = outputs
        .iter()
        .map(|utxo| utxo.hash().unwrap())
        .collect::<Vec<_>>();
    PrivateTxHash::new(&input_hashes, &output_hashes, external_data_hash)
        .hash()
        .unwrap()
}

fn order_data_hash(
    recipient: &[u8; 32],
    max_price: u64,
    created_at: u64,
    expires_at: u64,
    execution_price: u64,
    quote_version: u64,
) -> [u8; 32] {
    Poseidon::hashv(&[
        recipient,
        &fe(max_price),
        &fe(created_at),
        &fe(expires_at),
        &fe(execution_price),
        &fe(quote_version),
    ])
    .unwrap()
}

#[test]
fn all_four_circuits_accept_the_new_flow() {
    let source_asset = Address::new_from_array([21; 32]);
    let destination_asset = Address::new_from_array([22; 32]);
    let source_owner = fe(31);
    let escrow_owner = fe(32);
    let pool_owner = fe(33);
    let recipient_owner = fe(34);
    let authority_owner = fe(35);
    let external_data_hash = fe(41);
    let created_at = 1_700_000_000;
    let expires_at = created_at + 600;
    let execution_price = 1;
    let max_price = 1;
    let quote_version = 1;

    let source_in = note(source_owner, &source_asset, 1, 51);
    let order_data_hash = order_data_hash(
        &recipient_owner,
        max_price,
        created_at,
        expires_at,
        execution_price,
        quote_version,
    );
    let order_out = note(escrow_owner, &source_asset, 1, 52).with_data_hash(order_data_hash);
    let open_private_tx = private_tx(
        std::slice::from_ref(&source_in),
        std::slice::from_ref(&order_out),
        &external_data_hash,
    );
    let open_public_hash = EscrowOpenPublicInput {
        private_tx_hash: &open_private_tx,
        created_at_unix_ts: created_at as i64,
        expires_at_unix_ts: expires_at as i64,
        execution_price,
        quote_version,
        max_order_size: 1,
        escrow_authority_owner_hash: &escrow_owner,
        source_asset: &source_in.asset,
    }
    .hash()
    .unwrap();
    EscrowOpenProofInputs {
        public_input_hash: open_public_hash,
        private_tx_hash: open_private_tx,
        created_at,
        expires_at,
        execution_price,
        quote_version,
        max_order_size: 1,
        escrow_authority_owner_hash: escrow_owner,
        source_asset: source_in.asset,
        order_amount: 1,
        max_price,
        recipient_owner_hash: recipient_owner,
        source_in,
        order_out: order_out.clone(),
        external_data_hash,
    }
    .prove()
    .expect("escrow_open proof");

    let pool_in = note(pool_owner, &destination_asset, 1_000, 61);
    let auth_in = note(authority_owner, &destination_asset, 100, 62);
    let pool_topup_out = note(pool_owner, &destination_asset, 1_100, 63);
    let auth_change = note(authority_owner, &destination_asset, 0, 64);
    let pool_update_private_tx = private_tx(
        &[pool_in.clone(), auth_in.clone()],
        &[pool_topup_out.clone(), auth_change.clone()],
        &external_data_hash,
    );
    let pool_update_public_hash = PoolUpdatePublicInput {
        private_tx_hash: &pool_update_private_tx,
        pool_in_hash: &pool_in.hash().unwrap(),
        destination_asset: &pool_in.asset,
        reserved_liability: 0,
        slot_value: 1,
        available_slots: 1_100,
        refresh_capacity: true,
    }
    .hash()
    .unwrap();
    let pool_update_inputs = PoolUpdateProofInputs {
        public_input_hash: pool_update_public_hash,
        private_tx_hash: pool_update_private_tx,
        pool_in_hash: pool_in.hash().unwrap(),
        destination_asset: pool_in.asset,
        reserved_liability: 0,
        slot_value: 1,
        available_slots: 1_100,
        refresh_capacity: true,
        pool_in,
        auth_in,
        pool_out: pool_topup_out,
        auth_out: auth_change,
        external_data_hash,
    };
    pool_update_inputs.prove().expect("pool_update proof");

    let wrong_destination_asset = fe(99);
    let wrong_destination_public_hash = PoolUpdatePublicInput {
        private_tx_hash: &pool_update_inputs.private_tx_hash,
        pool_in_hash: &pool_update_inputs.pool_in_hash,
        destination_asset: &wrong_destination_asset,
        reserved_liability: pool_update_inputs.reserved_liability,
        slot_value: pool_update_inputs.slot_value,
        available_slots: pool_update_inputs.available_slots,
        refresh_capacity: pool_update_inputs.refresh_capacity,
    }
    .hash()
    .unwrap();
    let mut wrong_asset_inputs = pool_update_inputs.clone();
    wrong_asset_inputs.public_input_hash = wrong_destination_public_hash;
    wrong_asset_inputs.destination_asset = wrong_destination_asset;
    assert!(
        wrong_asset_inputs.prove().is_err(),
        "pool_update accepted liquidity in the wrong asset"
    );

    let settle_pool_in = note(pool_owner, &destination_asset, 1_000, 71);
    let recipient_out = note(recipient_owner, &destination_asset, 1, 72);
    let settle_pool_out = note(pool_owner, &destination_asset, 999, 73);
    let authority_out = note(authority_owner, &source_asset, 1, 74);
    let settle_private_tx = private_tx(
        &[order_out.clone(), settle_pool_in.clone()],
        &[
            recipient_out.clone(),
            settle_pool_out.clone(),
            authority_out.clone(),
        ],
        &external_data_hash,
    );
    let settle_public_hash = SettlePublicInput {
        private_tx_hash: &settle_private_tx,
        execution_price,
        quote_version,
        order_in_hash: &order_out.hash().unwrap(),
        pool_in_hash: &settle_pool_in.hash().unwrap(),
        authority_owner_hash: &authority_owner,
        destination_asset: &settle_pool_in.asset,
        remaining_reserved_liability: 0,
        slot_value: 1,
        available_slots: 999,
        refresh_capacity: true,
    }
    .hash()
    .unwrap();
    EscrowSettleProofInputs {
        public_input_hash: settle_public_hash,
        private_tx_hash: settle_private_tx,
        execution_price,
        quote_version,
        order_in_hash: order_out.hash().unwrap(),
        pool_in_hash: settle_pool_in.hash().unwrap(),
        authority_owner_hash: authority_owner,
        destination_asset: settle_pool_in.asset,
        remaining_reserved_liability: 0,
        slot_value: 1,
        available_slots: 999,
        refresh_capacity: true,
        order_amount: 1,
        max_price,
        recipient_owner_hash: recipient_owner,
        created_at,
        expires_at,
        order_in: order_out.clone(),
        pool_in: settle_pool_in,
        recipient_out,
        pool_out: settle_pool_out,
        authority_out,
        external_data_hash,
    }
    .prove()
    .expect("escrow_settle proof");

    let refund_out = note(recipient_owner, &source_asset, 1, 81);
    let refund_private_tx = private_tx(
        std::slice::from_ref(&order_out),
        std::slice::from_ref(&refund_out),
        &external_data_hash,
    );
    let refund_public_hash = RefundPublicInput {
        private_tx_hash: &refund_private_tx,
        execution_price,
        quote_version,
        order_in_hash: &order_out.hash().unwrap(),
    }
    .hash()
    .unwrap();
    EscrowRefundProofInputs {
        public_input_hash: refund_public_hash,
        private_tx_hash: refund_private_tx,
        execution_price,
        quote_version,
        order_in_hash: order_out.hash().unwrap(),
        max_price,
        recipient_owner_hash: recipient_owner,
        created_at,
        expires_at,
        order_in: order_out,
        recipient_out: refund_out,
        external_data_hash,
    }
    .prove()
    .expect("escrow_refund proof");
}
