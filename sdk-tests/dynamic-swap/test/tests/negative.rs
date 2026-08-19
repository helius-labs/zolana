mod shared;

use anyhow::{anyhow, Result};
use dynamic_swap_sdk::{
    escrow_pda,
    Groth16ProofBytes,
    instructions::{
        create_escrow::CreateEscrow, create_pair::CreatePair, update_price::UpdatePrice,
    },
    pair_pda,
};
use shared::{escrow_authority_identity, setup, TestEnv, DESTINATION_ASSET_ID, SOURCE_ASSET_ID};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_interface::{
    instruction::instruction_data::transact::{TransactIxData, TransactProof},
    verifying_keys::CircuitId,
};
use zolana_transaction::{instructions::transact::spp_proof_inputs::asset_field, SOL_MINT};

const PRICE: u64 = 5;
const EXPIRY_SLOTS: u64 = 100_000;

const INVALID_PRICE: u32 = 9016;
const UNAUTHORIZED: u32 = 9012;
const MAX_PRICE_EXCEEDED: u32 = 9019;
const INVALID_ENCRYPTION_PUBKEY: u32 = 9020;
const INVALID_EXPIRY: u32 = 9021;

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

// Derives the pair PDA and sends `create_pair`. There is no shared pool:
// liquidity arrives at settle time, so this creates only the pair account.
// Returns the pair PDA (or the RPC error, which the rejection cases assert on).
fn create_pair(
    env: &TestEnv,
    authority_solana: &dyn Signer,
    price: u64,
    expiry_slots: u64,
    maker_encryption_pubkey: [u8; 33],
) -> Result<Pubkey> {
    let pair = pair_pda(
        &authority_solana.pubkey(),
        SOURCE_ASSET_ID,
        DESTINATION_ASSET_ID,
    );
    let source_asset = asset_field(&env.spl_mint).map_err(|e| anyhow!("source asset: {e:?}"))?;
    let destination_asset =
        asset_field(&SOL_MINT).map_err(|e| anyhow!("destination asset: {e:?}"))?;
    let create_pair_ix = CreatePair {
        payer: authority_solana.pubkey(),
        pair,
        price,
        source_asset_id: SOURCE_ASSET_ID,
        destination_asset_id: DESTINATION_ASSET_ID,
        expiry_slots,
        source_asset,
        destination_asset,
        maker_encryption_pubkey,
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

/// A wincode-deserializable transact payload for gates that reject before proof
/// verification touches it.
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

// Proof-free access-control and validation rejections, all under one validator
// (kept in a single `#[test]` because each `setup()` boots its own localnet on
// fixed ports, so multiple tests in one binary would race for them):
//   - create_pair with price 0                    -> InvalidPrice
//   - create_pair with expiry_slots 0             -> InvalidExpiry
//   - create_pair with a non-SEC1 encryption key  -> InvalidEncryptionPubkey
//   - update_price to 0                           -> InvalidPrice
//   - update_price by a non-authority             -> Unauthorized
//   - create_escrow with max_price < pair.price   -> MaxPriceExceeded
#[test]
fn zero_price_and_authority_checks() -> Result<()> {
    let env = setup()?;
    let authority_solana = &env.authority.keypair;
    let user_solana = &env.user.keypair;

    let pair = pair_pda(
        &authority_solana.pubkey(),
        SOURCE_ASSET_ID,
        DESTINATION_ASSET_ID,
    );
    let maker_encryption_pubkey = *escrow_authority_identity(&env.authority.keypair, &pair)?
        .viewing_pubkey()
        .as_bytes();

    // create_pair rejects a zero price (create_escrow could not write a nonzero
    // execution_price, so escrows on the pair could never settle).
    let err = create_pair(
        &env,
        &authority_solana,
        0,
        EXPIRY_SLOTS,
        maker_encryption_pubkey,
    )
    .err()
    .ok_or_else(|| anyhow!("create_pair with price 0 must fail"))?;
    assert_custom_error("create_pair zero price", &err, INVALID_PRICE);

    // create_pair rejects a zero settle window (every escrow would be
    // immediately cancellable and unsettleable).
    let err = create_pair(&env, &authority_solana, PRICE, 0, maker_encryption_pubkey)
        .err()
        .ok_or_else(|| anyhow!("create_pair with expiry 0 must fail"))?;
    assert_custom_error("create_pair zero expiry", &err, INVALID_EXPIRY);

    // create_pair rejects an encryption pubkey that is not a SEC1-compressed
    // P256 point (order UTXO handoffs would be undecryptable).
    let mut bad_encryption_pubkey = maker_encryption_pubkey;
    bad_encryption_pubkey[0] = 0x04;
    let err = create_pair(
        &env,
        &authority_solana,
        PRICE,
        EXPIRY_SLOTS,
        bad_encryption_pubkey,
    )
    .err()
    .ok_or_else(|| anyhow!("create_pair with a bad encryption pubkey must fail"))?;
    assert_custom_error(
        "create_pair bad encryption pubkey",
        &err,
        INVALID_ENCRYPTION_PUBKEY,
    );

    // A valid pair for the remaining checks.
    let pair = create_pair(
        &env,
        &authority_solana,
        PRICE,
        EXPIRY_SLOTS,
        maker_encryption_pubkey,
    )?;

    // update_price rejects a zero price for the same reason as create_pair.
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

    // create_escrow rejects a max_price below the pair's current price. The gate
    // runs before proof verification, so a garbage proof and an empty transact
    // payload reach it.
    let escrow_ix = CreateEscrow {
        taker: user_solana.pubkey(),
        pair,
        escrow: escrow_pda(&[0u8; 32]),
        tree: Pubkey::new_unique(),
        proof: Groth16ProofBytes {
            proof_a: [0u8; 32],
            proof_b: [0u8; 64],
            proof_c: [0u8; 32],
        },
        max_price: PRICE - 1,
        transact: dummy_transact(),
    }
    .instruction()
    .map_err(|e| anyhow!("create_escrow instruction: {e:?}"))?;
    let err = env
        .client
        .rpc()
        .create_and_send_transaction(&[escrow_ix], user_solana.pubkey(), &[&user_solana])
        .err()
        .ok_or_else(|| anyhow!("create_escrow above max_price must fail"))?;
    assert_custom_error(
        "create_escrow above max_price",
        &anyhow!("{err:?}"),
        MAX_PRICE_EXCEEDED,
    );

    Ok(())
}
