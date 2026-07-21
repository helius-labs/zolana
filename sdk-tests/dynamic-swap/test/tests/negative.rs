mod shared;

use anyhow::{anyhow, Result};
use dynamic_swap_sdk::{
    instructions::{create_pair::CreatePair, update_price::UpdatePrice},
    pair_pda,
};
use shared::{setup, TestEnv, DESTINATION_ASSET_ID, SOURCE_ASSET_ID};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_transaction::{instructions::transact::spp_proof_inputs::asset_field, SOL_MINT};

const PRICE: u64 = 5;

const INVALID_PRICE: u32 = 9016;
const UNAUTHORIZED: u32 = 9012;

// A custom program error surfaces in the RPC error two ways: the structured
// `InstructionError::Custom(<decimal>)` and the program-log line `custom program
// error: 0x<hex>`. Match both of those *delimited* forms only -- a bare decimal
// would spuriously match compute-unit counts or lamport amounts elsewhere in the
// error text.
fn assert_custom_error(context: &str, err: &anyhow::Error, code: u32) {
    let text = format!("{err:?}");
    let structured = format!("Custom({code})");
    let hex = format!("0x{code:x}");
    assert!(
        text.contains(&structured) || text.contains(&hex),
        "{context}: expected custom error {code} ({structured} / {hex}) in: {text}"
    );
}

// Derives the pair PDA and sends `create_pair` at `price`. There is no shared
// pool: the maker funds each escrow on demand, so this creates only the pair
// account. Returns the pair PDA (or the RPC error, which the price-0 case
// asserts on).
fn create_pair(env: &TestEnv, authority_solana: &Keypair, price: u64) -> Result<Pubkey> {
    let pair = pair_pda(
        &authority_solana.pubkey(),
        SOURCE_ASSET_ID,
        DESTINATION_ASSET_ID,
    );
    let authority_owner_hash = env
        .authority
        .owner_hash()
        .map_err(|e| anyhow!("authority owner hash: {e:?}"))?;
    let source_asset = asset_field(&env.spl_mint).map_err(|e| anyhow!("source asset: {e:?}"))?;
    let destination_asset =
        asset_field(&SOL_MINT).map_err(|e| anyhow!("destination asset: {e:?}"))?;
    let create_pair_ix = CreatePair {
        payer: authority_solana.pubkey(),
        pair,
        price,
        source_asset_id: SOURCE_ASSET_ID,
        destination_asset_id: DESTINATION_ASSET_ID,
        authority_owner_hash,
        source_asset,
        destination_asset,
    }
    .instruction()
    .map_err(|e| anyhow!("create_pair instruction: {e:?}"))?;
    env.client
        .rpc()
        .create_and_send_transaction(
            &[create_pair_ix],
            authority_solana.pubkey(),
            &[authority_solana],
        )
        .map_err(|e| anyhow!("send create_pair: {e:?}"))?;
    Ok(pair)
}

// Proof-free access-control and validation rejections, all under one validator
// (kept in a single `#[test]` because each `setup()` boots its own localnet on
// fixed ports, so multiple tests in one binary would race for them):
//   - create_pair with price 0            -> InvalidPrice
//   - update_price to 0                    -> InvalidPrice
//   - update_price by a non-authority      -> Unauthorized
#[test]
fn zero_price_and_authority_checks() -> Result<()> {
    let env = setup()?;
    let authority_solana = env.authority.solana_keypair()?;

    // create_pair rejects a zero price (create_escrow could not stamp a nonzero
    // execution_price, so escrows on the pair could never settle).
    let err = create_pair(&env, &authority_solana, 0)
        .err()
        .ok_or_else(|| anyhow!("create_pair with price 0 must fail"))?;
    assert_custom_error("create_pair zero price", &err, INVALID_PRICE);

    // A valid pair for the remaining update_price checks.
    let pair = create_pair(&env, &authority_solana, PRICE)?;

    // update_price rejects a zero price for the same reason.
    let zero_ix = UpdatePrice {
        authority: authority_solana.pubkey(),
        pair,
        price: 0,
    }
    .instruction()
    .map_err(|e| anyhow!("update_price instruction: {e:?}"))?;
    let err = env
        .client
        .rpc()
        .create_and_send_transaction(&[zero_ix], authority_solana.pubkey(), &[&authority_solana])
        .err()
        .ok_or_else(|| anyhow!("update_price to 0 must fail"))?;
    assert_custom_error("update_price zero", &anyhow!("{err:?}"), INVALID_PRICE);

    // A non-authority signer cannot move the price: `authority_solana` pays the
    // fee, the intruder signs as the claimed authority but is not the pair's
    // stored authority.
    let intruder = Keypair::new();
    let intruder_ix = UpdatePrice {
        authority: intruder.pubkey(),
        pair,
        price: PRICE + 1,
    }
    .instruction()
    .map_err(|e| anyhow!("update_price instruction: {e:?}"))?;
    let err = env
        .client
        .rpc()
        .create_and_send_transaction(
            &[intruder_ix],
            authority_solana.pubkey(),
            &[&authority_solana, &intruder],
        )
        .err()
        .ok_or_else(|| anyhow!("non-authority update_price must fail"))?;
    assert_custom_error(
        "non-authority update_price",
        &anyhow!("{err:?}"),
        UNAUTHORIZED,
    );

    Ok(())
}
