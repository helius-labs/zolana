mod shared;

use anyhow::{anyhow, bail, Result};
use dynamic_swap_program::{
    instructions::{create_escrow::EscrowOpenProof, settle::SettleProof},
    state::{Escrow, Pair},
};
use dynamic_swap_sdk::{
    discovery::{discover_escrow_note, DiscoveredEscrow},
    escrow_authority_pda, escrow_pda,
    instructions::{
        create_escrow::{CreateEscrow, EscrowOpenProofInputParams},
        create_pair::CreatePair,
        settle::{
            derive_settle_output_blinding, Settle, SettleProofInputParams,
            MAKER_COUNTER_BLINDING_DOMAIN, MAKER_SOURCE_BLINDING_DOMAIN, RECIPIENT_BLINDING_DOMAIN,
        },
    },
    pair_pda,
    prover::DynamicSwapProverClient,
    shared_address::SharedShieldedAddress,
    state::{EscrowTerms, EscrowUtxo, Reservation},
};
use shared::{
    get_slot_with_retry, send_v0_with_lookup_table, setup, DESTINATION_ASSET_ID, SOURCE_ASSET_ID,
    USER_SPL_SHIELD,
};
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_interface::instruction::Transact;
use zolana_keypair::random_blinding;
use zolana_transaction::{
    instructions::transact::{
        encrypt_transaction_data, get_transaction_viewing_key, spp_proof_inputs::asset_field,
        ExternalData, SppProofInputs, SppProofOutputUtxo,
    },
    instructions::types::SppProofInputUtxo,
    utxo::Utxo,
    Data, SOL_MINT,
};
use zolana_wallet::{resolve_registered_address, Deposit, DepositParams};

const PRICE: u64 = 10;
const MAX_PRICE: u64 = 3;
const ORDER_AMOUNT: u64 = 100_000_000;

// The escrow is priced at creation with execution_price = PRICE; a max_price
// below it is what drives the refund branch. Enforced at compile time so the
// setup can never silently drift into the settle branch.
const _: () = assert!(MAX_PRICE < PRICE);

// create_escrow prices the order at creation, so an order whose max_price is
// below the pair's current price is committed already underwater: the escrow's
// execution_price (the pair price) exceeds max_price. settle then hits the
// refund outcome of the SAME escrow_settle circuit used for settlement -- the
// escrowed source asset returns to `recipient` and the escrow closes.
#[test]
fn create_escrow_underwater_then_refund() -> Result<()> {
    let env = setup()?;
    let authority_solana = env.authority.solana_keypair()?;
    let user_solana = env.user.solana_keypair()?;

    // 1. create_pair: register the SPL(source)->SOL(destination) pair at PRICE.
    let pair = pair_pda(
        &authority_solana.pubkey(),
        SOURCE_ASSET_ID,
        DESTINATION_ASSET_ID,
    );
    {
        let authority_owner_hash = env.authority.owner_hash()?;
        let source_asset =
            asset_field(&env.spl_mint).map_err(|e| anyhow!("source asset: {e:?}"))?;
        let destination_asset =
            asset_field(&SOL_MINT).map_err(|e| anyhow!("destination asset: {e:?}"))?;
        let create_pair_ix = CreatePair {
            payer: authority_solana.pubkey(),
            pair,
            price: PRICE,
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
                &[&authority_solana],
            )
            .map_err(|e| anyhow!("send create_pair: {e:?}"))?;
    }

    let recipient_owner_hash = env
        .user
        .owner_hash()
        .map_err(|e| anyhow!("user owner hash: {e:?}"))?;

    // 2. create_escrow with max_price below the pair's current price: the order
    // is committed at execution_price = PRICE > MAX_PRICE, which resolves as a
    // refund. First split the user's funding UTXO into an exact-`ORDER_AMOUNT`
    // UTXO; the remainder is left unspent. The split does not depend on
    // `created_at`, so it happens once, up front.
    let source_utxo = {
        let source_utxo = Utxo {
            owner: env.user.keypair.signing_pubkey(),
            asset: env.spl_mint,
            amount: USER_SPL_SHIELD,
            blinding: env.user_spl_blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        let source_in = SppProofInputUtxo::new(source_utxo, &env.user.keypair);
        let remainder_amount = USER_SPL_SHIELD
            .checked_sub(ORDER_AMOUNT)
            .ok_or_else(|| anyhow!("order_amount exceeds the user's funding UTXO"))?;
        let user_address = env.user.address()?;
        let split_out = SppProofOutputUtxo::new(env.spl_mint, ORDER_AMOUNT, user_address)
            .map_err(|e| anyhow!("split_out: {e:?}"))?;
        let split_blinding = split_out.blinding;
        let remainder_out = SppProofOutputUtxo::new(env.spl_mint, remainder_amount, user_address)
            .map_err(|e| anyhow!("remainder_out: {e:?}"))?;

        let input_utxos = vec![source_in];
        let viewing_key = get_transaction_viewing_key(&env.user.keypair, &input_utxos)
            .map_err(|e| anyhow!("transaction viewing key: {e:?}"))?;
        let encoded =
            encrypt_transaction_data(&[split_out, remainder_out], &env.assets, &viewing_key)
                .map_err(|e| anyhow!("encode outputs: {e:?}"))?;
        let external_data = ExternalData::new(
            *viewing_key.pubkey().as_bytes(),
            encoded.salt,
            encoded.outputs,
            encoded.resolved_owner_tags,
            vec![],
        );
        let spp_proof_inputs = SppProofInputs::new(
            input_utxos,
            encoded.output_utxos,
            external_data,
            user_solana.pubkey(),
        );
        let split_transact = env
            .client
            .indexer()
            .prove_transact(env.tree, spp_proof_inputs)
            .map_err(|e| anyhow!("prove_transact: {e:?}"))?;

        let split_ix = Transact {
            payer: user_solana.pubkey(),
            tree: env.tree,
            withdrawal: None,
            data: split_transact,
        }
        .instruction();
        env.client
            .rpc()
            .create_and_send_transaction(&[split_ix], user_solana.pubkey(), &[&user_solana])
            .map_err(|e| anyhow!("send split transact: {e:?}"))?;

        Utxo {
            owner: env.user.keypair.signing_pubkey(),
            asset: env.spl_mint,
            amount: ORDER_AMOUNT,
            blinding: split_blinding,
            zone_program_id: None,
            data: Data::default(),
        }
    };

    // The maker funds the reservation on demand: a fresh deposit of exactly
    // `reserved` (= order_amount * max_price) of SOL, spent by `escrow_open`.
    let reserved = ORDER_AMOUNT
        .checked_mul(MAX_PRICE)
        .ok_or_else(|| anyhow!("order_amount * max_price overflows"))?;
    let maker_funding = {
        let authority_address = env.authority.address()?;
        let deposit = Deposit::new(DepositParams {
            recipient: &authority_address,
            asset: SOL_MINT,
            amount: reserved,
            spl_token_account: None,
            memo: None,
        })
        .map_err(|e| anyhow!("maker funding deposit: {e:?}"))?;
        deposit
            .send(
                env.client.rpc(),
                &authority_solana,
                env.tree,
                &authority_solana,
            )
            .map_err(|e| anyhow!("send maker funding deposit: {e:?}"))?;
        Utxo {
            owner: env.authority.keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount: reserved,
            blinding: deposit.data.blinding,
            zone_program_id: None,
            data: Data::default(),
        }
    };

    let escrow = {
        // create_escrow's proof commits to a `created_at` slot the on-chain
        // processor tolerance-checks against `Clock::get()?.slot`
        // (CREATED_AT_SLOT_TOLERANCE). Read the current slot and use it as-is: it
        // is always <= the landing slot, and the tolerance window absorbs the
        // proving + landing latency, so the landing slot is never estimated.
        let created_at = get_slot_with_retry(env.client.rpc().client())?;
        let order_amount = ORDER_AMOUNT;
        let max_price = MAX_PRICE;
        let prover = DynamicSwapProverClient::new();

        // Both parties derive the same viewing key from their registered viewing
        // pubkeys; the order UTXO's note is encrypted to it so either can rebuild
        // the escrow on settle. The reservation blinding rides in that note, so
        // it is chosen up front and fed into the order output.
        let escrow_owner = SharedShieldedAddress::from_key_exchange(
            &env.authority.keypair.viewing_key,
            &env.user.keypair.viewing_pubkey(),
            escrow_authority_pda(&pair),
        )?;
        let reservation_blinding = random_blinding();

        let source_in = SppProofInputUtxo::new(source_utxo.clone(), &env.user.keypair);
        let maker_funding_in =
            SppProofInputUtxo::new(maker_funding.clone(), &env.authority.keypair);

        let escrow_terms = EscrowTerms {
            recipient_owner_hash,
            max_price,
        };
        let escrow_utxo = EscrowUtxo {
            terms: escrow_terms,
            created_at,
            asset: env.spl_mint,
            order_amount,
            blinding: random_blinding(),
        };
        let order_out = escrow_utxo
            .output_utxo(&escrow_owner, &reservation_blinding)
            .map_err(|e| anyhow!("order_out: {e:?}"))?;
        let order_utxo_hash = order_out
            .hash()
            .map_err(|e| anyhow!("order_utxo hash: {e:?}"))?;

        let reserved = order_amount
            .checked_mul(max_price)
            .ok_or_else(|| anyhow!("order_amount * max_price overflows"))?;
        let reservation = Reservation {
            asset: SOL_MINT,
            amount: reserved,
            blinding: reservation_blinding,
        };
        let reservation_out = reservation
            .output_utxo(&escrow_owner, order_utxo_hash)
            .map_err(|e| anyhow!("reservation_out: {e:?}"))?;

        let maker_change_amount = maker_funding
            .amount
            .checked_sub(reserved)
            .ok_or_else(|| anyhow!("reservation exceeds the maker funding amount"))?;
        let authority_address = env.authority.address()?;
        let maker_change =
            SppProofOutputUtxo::new(SOL_MINT, maker_change_amount, authority_address)
                .map_err(|e| anyhow!("maker_change: {e:?}"))?;

        // Output order (order, reservation, maker_change) matches the program's own
        // output indices and the circuit.
        let input_utxos = vec![source_in.clone(), maker_funding_in.clone()];
        let viewing_key = get_transaction_viewing_key(&env.user.keypair, &input_utxos)
            .map_err(|e| anyhow!("transaction viewing key: {e:?}"))?;
        let encoded = encrypt_transaction_data(
            &[
                order_out.clone(),
                reservation_out.clone(),
                maker_change.clone(),
            ],
            &env.assets,
            &viewing_key,
        )
        .map_err(|e| anyhow!("encode outputs: {e:?}"))?;
        // reservation_out (index 1) is spent only by the program later (settle),
        // rebuilt from the order note's reservation blinding, so its ciphertext
        // is dropped to keep the transaction under Solana's size limit.
        const RESERVATION_OUTPUT_INDEX: usize = 1;
        let mut outputs = encoded.outputs;
        outputs
            .get_mut(RESERVATION_OUTPUT_INDEX)
            .ok_or_else(|| anyhow!("reservation output index out of range"))?
            .data = None;
        let external_data = ExternalData::new(
            *viewing_key.pubkey().as_bytes(),
            encoded.salt,
            outputs,
            encoded.resolved_owner_tags,
            vec![],
        );
        let external_data_hash = external_data
            .hash()
            .map_err(|e| anyhow!("external data hash: {e:?}"))?;
        let spp_proof_inputs = SppProofInputs::new(
            input_utxos,
            encoded.output_utxos,
            external_data,
            authority_solana.pubkey(),
        );
        let transact = env
            .client
            .indexer()
            .prove_transact(env.tree, spp_proof_inputs)
            .map_err(|e| anyhow!("prove_transact: {e:?}"))?;

        let escrow_authority_owner_hash = escrow_owner
            .shielded_address()?
            .owner_hash()
            .map_err(|e| anyhow!("escrow authority owner hash: {e:?}"))?;
        let source_asset =
            asset_field(&env.spl_mint).map_err(|e| anyhow!("source asset: {e:?}"))?;
        let destination_asset =
            asset_field(&SOL_MINT).map_err(|e| anyhow!("destination asset: {e:?}"))?;
        let proof_inputs = EscrowOpenProofInputParams {
            source_in,
            maker_funding: maker_funding_in,
            order_out,
            reservation_out,
            maker_change,
            max_price,
            escrow_authority_owner_hash,
            source_asset,
            destination_asset,
            created_at,
            order_amount,
            external_data_hash,
        }
        .to_proof_inputs()
        .map_err(|e| anyhow!("escrow_open proof inputs: {e:?}"))?;
        let order_proof = prover
            .prove_escrow_open(&proof_inputs)
            .map_err(|e| anyhow!("prove escrow_open: {e:?}"))?;

        let escrow = escrow_pda(&user_solana.pubkey());
        let ix = CreateEscrow {
            authority: authority_solana.pubkey(),
            owner: user_solana.pubkey(),
            pair,
            escrow,
            tree: env.tree,
            proof: EscrowOpenProof {
                proof_a: order_proof.proof_a,
                proof_b: order_proof.proof_b,
                proof_c: order_proof.proof_c,
            },
            created_at,
            transact,
        }
        .instruction()
        .map_err(|e| anyhow!("create_escrow instruction: {e:?}"))?;

        send_v0_with_lookup_table(env.client.rpc(), &authority_solana, &[&user_solana], ix)
            .map_err(|e| anyhow!("send create_escrow: {e:?}"))?;

        escrow
    };

    // The escrow is committed at the pair's price (PRICE), above its own
    // max_price (MAX_PRICE): already underwater.
    let escrow_account = env
        .client
        .rpc()
        .get_account(escrow)
        .map_err(|e| anyhow!("get escrow account: {e:?}"))?
        .ok_or_else(|| anyhow!("escrow account not found"))?;
    let escrow_state: Escrow = *bytemuck::from_bytes::<Escrow>(&escrow_account.data);
    assert_eq!(escrow_state.execution_price, PRICE);

    // 3. settle with execution_price (PRICE) > max_price (MAX_PRICE) -> refund
    // branch of the same escrow_settle circuit. Refund payout (distinct from
    // settle): the recipient gets the full order amount back in the SOURCE asset
    // (SPL), not the destination asset; the maker is credited the whole
    // reservation (`order_amount * max_price`) in the destination asset (SOL);
    // the maker's source leg is a zero-amount placeholder so the on-chain shape
    // never differs between outcomes.
    let (recipient_out_hash, maker_counter_hash, maker_source_hash) = {
        let prover = DynamicSwapProverClient::new();

        // Recover everything settle needs purely from chain + registry + indexer,
        // isolated in its own scope so the settlement math below can only use
        // recovered values -- never create-time state or test-env conveniences.
        let (escrow_owner, recipient, discovered, source_asset) = {
            let recipient = resolve_registered_address(env.client.rpc(), user_solana.pubkey())
                .map_err(|e| anyhow!("resolve recipient: {e:?}"))?
                .address;
            let escrow_owner = SharedShieldedAddress::from_key_exchange(
                &env.authority.keypair.viewing_key,
                &recipient.viewing_pubkey,
                escrow_authority_pda(&pair),
            )?;
            let discovered = discover_escrow_note(env.client.indexer(), &escrow_owner)?;
            // The scan matches the shared authority tag alone, so pin the
            // discovered order UTXO to the escrow account being settled.
            if discovered.order_utxo_hash != escrow_state.escrow_utxo_hash {
                bail!("discovered order utxo does not match the on-chain escrow account");
            }
            // The pair stores the source asset as an id + a hashed field element,
            // not the mint; resolve the mint from that id via the asset registry.
            let source_asset = {
                let pair_account = env
                    .client
                    .rpc()
                    .get_account(pair)
                    .map_err(|e| anyhow!("get pair account: {e:?}"))?
                    .ok_or_else(|| anyhow!("pair account not found"))?;
                let source_asset_id =
                    bytemuck::from_bytes::<Pair>(&pair_account.data).source_asset_id;
                env.assets
                    .resolve(source_asset_id)
                    .map_err(|e| anyhow!("resolve source asset: {e:?}"))?
            };
            (escrow_owner, recipient, discovered, source_asset)
        };
        let recipient_owner_hash = recipient
            .owner_hash()
            .map_err(|e| anyhow!("recipient owner hash: {e:?}"))?;
        let execution_price = escrow_state.execution_price;
        let created_at = escrow_state.created_at;
        let DiscoveredEscrow {
            order_utxo_hash,
            order_amount,
            order_blinding,
            max_price,
            reservation_blinding,
        } = discovered;

        let escrow_utxo = EscrowUtxo {
            terms: EscrowTerms {
                recipient_owner_hash,
                max_price,
            },
            created_at,
            asset: source_asset,
            order_amount,
            blinding: order_blinding,
        };
        let order_in = escrow_utxo
            .to_input_utxo(&escrow_owner)
            .map_err(|e| anyhow!("order_in: {e:?}"))?;
        let reserved = order_amount
            .checked_mul(max_price)
            .ok_or_else(|| anyhow!("order_amount * max_price overflows"))?;
        let reservation = Reservation {
            asset: SOL_MINT,
            amount: reserved,
            blinding: reservation_blinding,
        };
        let reservation_in = reservation
            .to_input_utxo(&escrow_owner, order_utxo_hash)
            .map_err(|e| anyhow!("reservation_in: {e:?}"))?;

        // The reconstructed inputs must hash back to the leaves create_escrow
        // committed on-chain: this pins the registry owner hash and the decrypted
        // note against the commitment before we spend them.
        if order_in
            .hash()
            .map_err(|e| anyhow!("order_in hash: {e:?}"))?
            != escrow_state.escrow_utxo_hash
        {
            bail!("reconstructed order utxo does not match the committed escrow leaf");
        }
        if reservation_in
            .hash()
            .map_err(|e| anyhow!("reservation_in hash: {e:?}"))?
            != escrow_state.reservation_utxo_hash
        {
            bail!("reconstructed reservation utxo does not match the committed escrow leaf");
        }

        // execution_price > max_price -> refund: recipient gets the full source
        // amount back (SPL); the maker is credited the whole reservation (SOL);
        // the maker's source leg is a zero-amount placeholder.
        let (recipient_asset, recipient_amount, maker_counter_amount, maker_source_amount) =
            (source_asset, order_amount, reserved, 0);

        let mut recipient_out =
            SppProofOutputUtxo::new(recipient_asset, recipient_amount, recipient)
                .map_err(|e| anyhow!("recipient_out: {e:?}"))?;
        let authority_address = env.authority.address()?;
        let mut maker_counter =
            SppProofOutputUtxo::new(SOL_MINT, maker_counter_amount, authority_address)
                .map_err(|e| anyhow!("maker_counter: {e:?}"))?;
        let mut maker_source =
            SppProofOutputUtxo::new(source_asset, maker_source_amount, authority_address)
                .map_err(|e| anyhow!("maker_source: {e:?}"))?;

        // The circuit fixes each output blinding to a derivation over both input
        // blindings, so the same value must be used here (this output feeds both
        // the SPP transaction and the escrow_settle proof below).
        recipient_out.blinding = derive_settle_output_blinding(
            &order_blinding,
            &reservation_blinding,
            RECIPIENT_BLINDING_DOMAIN,
        )
        .map_err(|e| anyhow!("recipient_out blinding: {e:?}"))?;
        maker_counter.blinding = derive_settle_output_blinding(
            &order_blinding,
            &reservation_blinding,
            MAKER_COUNTER_BLINDING_DOMAIN,
        )
        .map_err(|e| anyhow!("maker_counter blinding: {e:?}"))?;
        maker_source.blinding = derive_settle_output_blinding(
            &order_blinding,
            &reservation_blinding,
            MAKER_SOURCE_BLINDING_DOMAIN,
        )
        .map_err(|e| anyhow!("maker_source blinding: {e:?}"))?;

        let recipient_out_hash = recipient_out
            .hash()
            .map_err(|e| anyhow!("recipient_out hash: {e:?}"))?;
        let maker_counter_hash = maker_counter
            .hash()
            .map_err(|e| anyhow!("maker_counter hash: {e:?}"))?;
        let maker_source_hash = maker_source
            .hash()
            .map_err(|e| anyhow!("maker_source hash: {e:?}"))?;

        // maker_counter (output index 1) returns to the maker and is tracked
        // off-chain, so its ciphertext is dropped to keep the transaction under
        // Solana's size limit.
        const MAKER_COUNTER_INDEX: usize = 1;
        let input_utxos = vec![order_in.clone(), reservation_in.clone()];
        let viewing_key = get_transaction_viewing_key(&env.authority.keypair, &input_utxos)
            .map_err(|e| anyhow!("transaction viewing key: {e:?}"))?;
        let encoded = encrypt_transaction_data(
            &[
                recipient_out.clone(),
                maker_counter.clone(),
                maker_source.clone(),
            ],
            &env.assets,
            &viewing_key,
        )
        .map_err(|e| anyhow!("encode outputs: {e:?}"))?;
        let mut outputs = encoded.outputs;
        outputs
            .get_mut(MAKER_COUNTER_INDEX)
            .ok_or_else(|| anyhow!("maker_counter output index out of range"))?
            .data = None;
        let external_data = ExternalData::new(
            *viewing_key.pubkey().as_bytes(),
            encoded.salt,
            outputs,
            encoded.resolved_owner_tags,
            vec![],
        );
        let external_data_hash = external_data
            .hash()
            .map_err(|e| anyhow!("external data hash: {e:?}"))?;
        let spp_proof_inputs = SppProofInputs::new(
            input_utxos,
            encoded.output_utxos,
            external_data,
            authority_solana.pubkey(),
        );
        let transact = env
            .client
            .indexer()
            .prove_transact(env.tree, spp_proof_inputs)
            .map_err(|e| anyhow!("prove_transact: {e:?}"))?;

        let authority_owner_hash = env
            .authority
            .owner_hash()
            .map_err(|e| anyhow!("authority owner hash: {e:?}"))?;
        let proof_inputs = SettleProofInputParams {
            order_in,
            reservation_in,
            recipient_out,
            maker_counter,
            maker_source,
            execution_price,
            max_price,
            created_at,
            order_amount,
            escrow_utxo_hash: order_utxo_hash,
            reservation_utxo_hash: escrow_state.reservation_utxo_hash,
            recipient_owner_hash,
            authority_owner_hash,
            external_data_hash,
        }
        .to_proof_inputs()
        .map_err(|e| anyhow!("settle proof inputs: {e:?}"))?;
        let order_proof = prover
            .prove_escrow_settle(&proof_inputs)
            .map_err(|e| anyhow!("prove escrow_settle: {e:?}"))?;

        let settle_ix = Settle {
            caller: authority_solana.pubkey(),
            pair,
            escrow,
            rent_recipient: user_solana.pubkey(),
            tree: env.tree,
            proof: SettleProof {
                proof_a: order_proof.proof_a,
                proof_b: order_proof.proof_b,
                proof_c: order_proof.proof_c,
            },
            transact,
        }
        .instruction()
        .map_err(|e| anyhow!("settle instruction: {e:?}"))?;
        send_v0_with_lookup_table(env.client.rpc(), &authority_solana, &[], settle_ix)
            .map_err(|e| anyhow!("send settle: {e:?}"))?;

        (recipient_out_hash, maker_counter_hash, maker_source_hash)
    };

    // All three refund legs landed as real UTXOs in the pool tree. The
    // asset/amount shapes above are bound into these commitments, so inclusion
    // pins the exact refund payout the program produced.
    let leaves = vec![recipient_out_hash, maker_counter_hash, maker_source_hash];
    let response = env
        .client
        .indexer()
        .get_merkle_proofs(env.tree, leaves.clone(), None)
        .map_err(|e| anyhow!("get merkle proofs: {e:?}"))?;
    if response.proofs.len() != leaves.len() {
        bail!(
            "expected {} indexed refund output leaves, indexer returned {}",
            leaves.len(),
            response.proofs.len()
        );
    }

    // Refund closes the escrow account.
    assert!(
        env.client
            .rpc()
            .get_account(escrow)
            .map_err(|e| anyhow!("get escrow account after settle: {e:?}"))?
            .is_none(),
        "escrow account must be closed after refund"
    );

    Ok(())
}
