mod shared;

use anyhow::{anyhow, Result};
use dynamic_swap_program::state::Pair;
use dynamic_swap_sdk::{
    instructions::{create_pair::CreatePair, update_price::UpdatePrice},
    pair_pda,
};
use shared::{
    escrow_authority_identity, setup, DESTINATION_ASSET_ID, MIN_ORDER_AMOUNT, PRICE_TOLERANCE,
    SOURCE_ASSET_ID,
};
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_transaction::instructions::transact::spp_proof_inputs::asset_field;

const INITIAL_PRICE: u64 = 100;
const EXPIRY_SLOTS: u64 = 777;
const MAX_ORDER_SIZE: u64 = 1_000_000;

// Creates a unidirectional pair then updates its price, asserting the pair
// account ends up in the expected state. The pool starts empty:
// `available_liquidity` and `open_reservations` are zero until the maker deposits.
#[test]
fn create_pair_then_update_price() -> Result<()> {
    let env = setup()?;
    let authority_solana = &env.authority.keypair;

    // create_pair: derive the pair PDA and register the source/destination
    // asset pair at `INITIAL_PRICE` with the maker's settle window, reservation
    // size, receipt destination, and encryption pubkey.
    let pair = pair_pda(
        &authority_solana.pubkey(),
        SOURCE_ASSET_ID,
        DESTINATION_ASSET_ID,
    );
    let source_asset = asset_field(&env.spl_mint).map_err(|e| anyhow!("source asset: {e:?}"))?;
    let destination_asset =
        asset_field(&env.dest_mint).map_err(|e| anyhow!("destination asset: {e:?}"))?;
    let maker_encryption_pubkey = *escrow_authority_identity(&env.authority.keypair, &pair)?
        .viewing_pubkey()
        .as_bytes();
    let maker_receipt_owner_hash = env.authority.owner_hash()?;
    let create_pair_ix = CreatePair {
        payer: authority_solana.pubkey(),
        pair,
        price: INITIAL_PRICE,
        source_asset_id: SOURCE_ASSET_ID,
        destination_asset_id: DESTINATION_ASSET_ID,
        expiry_slots: EXPIRY_SLOTS,
        max_order_size: MAX_ORDER_SIZE,
        price_tolerance: PRICE_TOLERANCE,
        min_order_amount: MIN_ORDER_AMOUNT,
        source_asset,
        destination_asset,
        maker_receipt_owner_hash,
        maker_encryption_pubkey,
    }
    .instruction()
    .map_err(|e| anyhow!("create_pair instruction: {e:?}"))?;
    env.client
        .rpc()
        .create_and_send_transaction(
            &[create_pair_ix],
            authority_solana.pubkey(),
            &[&authority_solana],
        )
        .map_err(|e| anyhow!("send create_pair: {e:?}"))?;

    let pair_account = env
        .client
        .rpc()
        .get_account(pair)
        .map_err(|e| anyhow!("get pair account: {e:?}"))?
        .ok_or_else(|| anyhow!("pair account not found"))?;
    let pair_state: &Pair = bytemuck::from_bytes(&pair_account.data);

    let pair_bump = solana_pubkey::Pubkey::find_program_address(
        &[
            Pair::SEED_PREFIX,
            authority_solana.pubkey().as_ref(),
            &SOURCE_ASSET_ID.to_le_bytes(),
            &DESTINATION_ASSET_ID.to_le_bytes(),
        ],
        &dynamic_swap_program::ID,
    )
    .1;
    let expected = Pair {
        discriminator: dynamic_swap_program::state::discriminator::PAIR,
        bump: pair_bump,
        _pad: [0u8; 6],
        authority: authority_solana.pubkey(),
        source_asset_id: SOURCE_ASSET_ID,
        destination_asset_id: DESTINATION_ASSET_ID,
        price: INITIAL_PRICE,
        expiry_slots: EXPIRY_SLOTS,
        max_order_size: MAX_ORDER_SIZE,
        price_tolerance: PRICE_TOLERANCE,
        min_order_amount: MIN_ORDER_AMOUNT,
        available_liquidity: 0,
        open_reservations: 0,
        source_asset,
        destination_asset,
        maker_receipt_owner_hash,
        maker_encryption_pubkey,
        _pad2: [0u8; 7],
    };
    assert_eq!(*pair_state, expected);

    // Only the pair authority may update the price; any other actor is out of
    // scope here (the negative binary exercises the signer check).
    let new_price = INITIAL_PRICE * 3;
    let update_price_ix = UpdatePrice {
        authority: authority_solana.pubkey(),
        pair,
        price: new_price,
    }
    .instruction()
    .map_err(|e| anyhow!("update_price instruction: {e:?}"))?;
    env.client
        .rpc()
        .create_and_send_transaction(
            &[update_price_ix],
            authority_solana.pubkey(),
            &[&authority_solana],
        )
        .map_err(|e| anyhow!("send update_price: {e:?}"))?;

    let pair_account = env
        .client
        .rpc()
        .get_account(pair)
        .map_err(|e| anyhow!("get pair account after update: {e:?}"))?
        .ok_or_else(|| anyhow!("pair account not found after update"))?;
    let pair_state: &Pair = bytemuck::from_bytes(&pair_account.data);
    assert_eq!(pair_state.price, new_price);

    Ok(())
}
