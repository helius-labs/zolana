mod shared;

use anyhow::{anyhow, bail, Result};
use dynamic_swap_program::state::{Escrow, Pair};
use dynamic_swap_sdk::{
    discovery::{discover_escrow_note, DiscoveredEscrow},
    escrow_pda,
    Groth16ProofBytes,
    instructions::{
        create_escrow::{CreateEscrow, EscrowOpenProofInputParams},
        settle::{
            derive_output_blinding, Settle, SettleProofInputParams, FUNDER_CHANGE_BLINDING_DOMAIN,
            FUNDER_RECEIPT_BLINDING_DOMAIN, RECIPIENT_BLINDING_DOMAIN,
        },
    },
    prover::DynamicSwapProverClient,
    state::{escrow_authority_address, EscrowUtxo},
};
use shared::{escrow_authority_identity, send_v0_with_lookup_table, setup_with_pair};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_keypair::random_blinding;
use zolana_transaction::{
    instructions::transact::{
        encrypt_transaction_data, get_transaction_viewing_key, spp_proof_inputs::asset_field,
        ExternalData, SppProofInputs, SppProofOutputUtxo,
    },
    instructions::types::SppProofInputUtxo,
    Data, Filter, Utxo, Wallet, SOL_MINT,
};
use zolana_wallet::{resolve_registered_address, sync_wallet, Deposit, DepositParams};

const PRICE: u64 = 5;
const ORDER_AMOUNT: u64 = 100_000_000;
/// Wide enough that the settle proof (~14s of in-process proving) always lands
/// inside the window; the cancel flow uses its own small window.
const EXPIRY_SLOTS: u64 = 100_000;

// Full happy path: create_pair -> create_escrow (taker-only: the taker escrows
// the source asset, priced at creation, with its own change output) -> settle
// (the maker funds the payout at fill time from its own shielded note) -> the
// escrow account closes and all legs land as real UTXOs.
//
// Flow:
//   1. setup_with_pair (in setup): register the SPL(source)->SOL(destination)
//      pair at PRICE with the maker encryption pubkey and EXPIRY_SLOTS.
//   2. create_escrow: the taker spends its funding UTXO directly (IN1_OUT2:
//      order UTXO under the escrow-authority PDA + taker change), prices the
//      order at creation (execution_price := pair.price, gated by max_price),
//      and opens the escrow account. The order slot's ciphertext is encrypted
//      to the maker encryption pubkey (the handoff). Taker signs alone.
//   3. settle: the maker recovers the order UTXO data purely from Solana, the
//      registry, and the indexer, deposits destination-asset liquidity to its
//      OWN shielded address, and spends order + funding -> recipient paid
//      `order_amount * execution_price` SOL, funder change, funder receipt
//      (the full escrowed SPL). Maker signs alone.
//   4. Assert all three settle legs are indexed as real UTXOs, the escrow
//      account closed, and the taker's change note is wallet-discoverable.
#[test]
fn create_pair_escrow_and_settle() -> Result<()> {
    // 1. setup_with_pair: register the SPL(source)->SOL(destination) pair.
    let (env, pair) = setup_with_pair(PRICE, EXPIRY_SLOTS)?;
    let authority_solana = &env.authority.keypair;
    let user_solana = &env.user.keypair;

    let recipient_owner_hash = env
        .user
        .owner_hash()
        .map_err(|e| anyhow!("user owner hash: {e:?}"))?;
    // create_escrow: the escrow account key and its state are all that cross into
    // settle -- everything else settle needs is fetched fresh there.
    let (escrow, escrow_state) = {
        // 2. create_escrow. Discover the taker's funding UTXO the way a real
        // wallet would: sync from Photon and pick a spendable note of the source
        // asset large enough to cover the order; the circuit's change output
        // returns the remainder, so no pre-split is needed.
        let mut user_wallet = Wallet::new(env.user.address()?, env.assets.clone())
            .map_err(|e| anyhow!("user wallet: {e:?}"))?;
        sync_wallet(&mut user_wallet, &env.user.keypair, env.client.indexer())
            .map_err(|e| anyhow!("sync user wallet: {e:?}"))?;
        let funding_utxo = user_wallet
            .balance(env.spl_mint, Some(Filter::MinAmount(ORDER_AMOUNT)))
            .map_err(|e| anyhow!("user balance: {e:?}"))?
            .utxos
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("no spendable utxo of {} >= {ORDER_AMOUNT}", env.spl_mint))?;

        // The taker builds the order owner from public data alone: the pair
        // account's maker encryption pubkey plus the hardcoded zero-secret
        // nullifier pubkey.
        let maker_encryption_pubkey = {
            let pair_account = env
                .client
                .rpc()
                .get_account(pair)
                .map_err(|e| anyhow!("get pair account: {e:?}"))?
                .ok_or_else(|| anyhow!("pair account not found"))?;
            bytemuck::from_bytes::<Pair>(&pair_account.data).maker_encryption_pubkey
        };
        let escrow_authority = escrow_authority_address(&pair, &maker_encryption_pubkey)
            .map_err(|e| anyhow!("escrow authority address: {e:?}"))?;

        let order_amount = ORDER_AMOUNT;
        let prover = DynamicSwapProverClient::new();

        let source_in = SppProofInputUtxo::new(funding_utxo.clone(), &env.user.keypair);

        let escrow_utxo = EscrowUtxo {
            recipient_owner_hash,
            asset: env.spl_mint,
            order_amount,
            blinding: random_blinding(),
        };
        let order_out = escrow_utxo
            .output_utxo(&escrow_authority)
            .map_err(|e| anyhow!("order_out: {e:?}"))?;
        let order_utxo_hash = order_out
            .hash()
            .map_err(|e| anyhow!("order_utxo hash: {e:?}"))?;

        let change_amount = funding_utxo
            .amount
            .checked_sub(order_amount)
            .ok_or_else(|| anyhow!("order_amount exceeds the taker's funding UTXO"))?;
        let taker_change =
            SppProofOutputUtxo::new(env.spl_mint, change_amount, env.user.address()?)
                .map_err(|e| anyhow!("taker_change: {e:?}"))?;

        // Output order (order, taker_change) matches the program's own output
        // index and the circuit. Both ciphertexts are kept: the order slot is
        // the maker handoff, the change slot is the taker's own note.
        let input_utxos = vec![source_in.clone()];
        let viewing_key = get_transaction_viewing_key(&env.user.keypair, &input_utxos)
            .map_err(|e| anyhow!("transaction viewing key: {e:?}"))?;
        let encoded = encrypt_transaction_data(
            &[order_out.clone(), taker_change.clone()],
            &env.assets,
            &viewing_key,
        )
        .map_err(|e| anyhow!("encode outputs: {e:?}"))?;
        let external_data = ExternalData::new(
            *viewing_key.pubkey().as_bytes(),
            encoded.salt,
            encoded.outputs,
            encoded.resolved_owner_tags,
            vec![],
        );
        let external_data_hash = external_data
            .hash()
            .map_err(|e| anyhow!("external data hash: {e:?}"))?;
        // The escrow authority owns the data-bearing order output but spends no
        // input, so it must be declared as the extra owner signer (the program's
        // CPI flips its account); the circuit requires a data-carrying output's
        // owner in the authorized signer set.
        let spp_proof_inputs = SppProofInputs::new(
            input_utxos,
            encoded.output_utxos,
            external_data,
            user_solana.pubkey(),
        )
        .with_owner_signer(
            escrow_authority
                .solana_address()
                .map_err(|e| anyhow!("escrow authority solana address: {e:?}"))?,
        );
        let transact = env
            .client
            .indexer()
            .prove_transact(env.tree, spp_proof_inputs)
            .map_err(|e| anyhow!("prove_transact: {e:?}"))?;

        let escrow_authority_owner_hash = escrow_authority
            .owner_hash()
            .map_err(|e| anyhow!("escrow authority owner hash: {e:?}"))?;
        let source_asset =
            asset_field(&env.spl_mint).map_err(|e| anyhow!("source asset: {e:?}"))?;
        let proof_inputs = EscrowOpenProofInputParams {
            source_in,
            order_out,
            taker_change,
            escrow_authority_owner_hash,
            source_asset,
            order_amount,
            external_data_hash,
        }
        .to_proof_inputs()
        .map_err(|e| anyhow!("escrow_open proof inputs: {e:?}"))?;
        let order_proof = prover
            .prove_escrow_open(&proof_inputs)
            .map_err(|e| anyhow!("prove escrow_open: {e:?}"))?;

        let escrow = escrow_pda(&order_utxo_hash);
        let ix = CreateEscrow {
            taker: user_solana.pubkey(),
            pair,
            escrow,
            tree: env.tree,
            proof: Groth16ProofBytes {
                proof_a: order_proof.proof_a,
                proof_b: order_proof.proof_b,
                proof_c: order_proof.proof_c,
            },
            max_price: PRICE,
            transact,
        }
        .instruction()
        .map_err(|e| anyhow!("create_escrow instruction: {e:?}"))?;

        // The taker signs alone and pays fees + escrow rent. Dropping the maker
        // legs brought create_escrow back under Solana's 1232-byte packet limit
        // (1162-byte legacy tx, see BENCHMARK.md), so no lookup table is needed.
        let compute = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        env.client
            .rpc()
            .create_and_send_transaction(&[compute, ix], user_solana.pubkey(), &[&user_solana])
            .map_err(|e| anyhow!("send create_escrow: {e:?}"))?;

        // The taker's change landed as a wallet-discoverable note (its
        // ciphertext carries the taker's own view tag, distinct from the order
        // slot's escrow-authority tag).
        sync_wallet(&mut user_wallet, &env.user.keypair, env.client.indexer())
            .map_err(|e| anyhow!("resync user wallet: {e:?}"))?;
        user_wallet
            .balance(env.spl_mint, None)
            .map_err(|e| anyhow!("user balance after escrow: {e:?}"))?
            .utxos
            .into_iter()
            .find(|utxo| utxo.amount == change_amount)
            .ok_or_else(|| anyhow!("taker change note not discovered after create_escrow"))?;

        // create_escrow prices the order at creation and stores the order leaf
        // as the PDA seed; `created_at` is program-stamped from the Clock, so it
        // is the one field read back rather than predicted.
        let escrow_account = env
            .client
            .rpc()
            .get_account(escrow)
            .map_err(|e| anyhow!("get escrow account: {e:?}"))?
            .ok_or_else(|| anyhow!("escrow account not found"))?;
        let escrow_state: Escrow = *bytemuck::from_bytes::<Escrow>(&escrow_account.data);
        let escrow_bump = solana_pubkey::Pubkey::find_program_address(
            &[Escrow::SEED_PREFIX, &order_utxo_hash],
            &dynamic_swap_program::ID,
        )
        .1;
        let expected = Escrow {
            discriminator: dynamic_swap_program::state::discriminator::ESCROW,
            bump: escrow_bump,
            _pad: [0u8; 6],
            pair,
            order_utxo_hash,
            owner: user_solana.pubkey(),
            created_at: escrow_state.created_at,
            execution_price: PRICE,
        };
        assert_eq!(escrow_state, expected);

        (escrow, escrow_state)
    };

    // 3. settle: the maker funds the payout at fill time. The recipient is paid
    // `order_amount * execution_price` of the destination asset (SOL); the
    // funder receives its change and the full escrowed source amount (SPL).
    let (recipient_out_hash, funder_change_hash, funder_receipt_hash) = {
        let prover = DynamicSwapProverClient::new();

        // Recover everything settle needs purely from Solana, the registry, and
        // the indexer, isolated in its own scope so the settlement math below can
        // only use recovered values, not create-time state or test-env
        // conveniences.
        let (escrow_owner, recipient, discovered, source_asset) = {
            let recipient = resolve_registered_address(env.client.rpc(), user_solana.pubkey())
                .map_err(|e| anyhow!("resolve recipient: {e:?}"))?
                .address;
            let escrow_owner = escrow_authority_identity(&env.authority.keypair, &pair)?;
            // The scan is keyed by the committed order leaf from the escrow
            // account being settled, so the result is pinned to this escrow.
            let discovered = discover_escrow_note(
                env.client.indexer(),
                &escrow_owner,
                &escrow_state.order_utxo_hash,
            )?;
            // The registry-resolved recipient must be the one the order's data
            // hash commits -- the settle proof re-opens exactly that owner-hash.
            if recipient
                .owner_hash()
                .map_err(|e| anyhow!("recipient owner hash: {e:?}"))?
                != discovered.recipient_owner_hash
            {
                bail!("registered recipient does not match the order's committed recipient");
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
        let execution_price = escrow_state.execution_price;
        let order_utxo_hash = escrow_state.order_utxo_hash;
        let DiscoveredEscrow {
            order_amount,
            order_blinding,
            recipient_owner_hash,
        } = discovered;

        let owed = order_amount
            .checked_mul(execution_price)
            .ok_or_else(|| anyhow!("order_amount * execution_price overflows"))?;

        // The maker deposits destination-asset liquidity to its OWN shielded
        // address -- an ordinary wallet note, entering escrow machinery only at
        // this fill.
        let funding_amount = shared::AUTHORITY_SOL_SHIELD;
        let maker_funding = {
            let authority_address = env.authority.address()?;
            let deposit = Deposit::new(DepositParams {
                recipient: &authority_address,
                asset: SOL_MINT,
                amount: funding_amount,
                spl_token_account: None,
                spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
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
                owner: authority_address.signing_pubkey,
                asset: SOL_MINT,
                amount: funding_amount,
                blinding: deposit.deposit.blinding,
                ring_program_id: None,
                data: Data::default(),
            }
        };
        let funding_blinding = maker_funding.blinding;

        let escrow_utxo = EscrowUtxo {
            recipient_owner_hash,
            asset: source_asset,
            order_amount,
            blinding: order_blinding,
        };
        let order_in = escrow_utxo
            .to_input_utxo(
                &escrow_owner
                    .shielded_address()
                    .map_err(|e| anyhow!("escrow authority address: {e:?}"))?,
            )
            .map_err(|e| anyhow!("order_in: {e:?}"))?;
        // The reconstructed input must hash back to the leaf create_escrow
        // committed on Solana: this pins the decrypted order UTXO data against
        // the commitment before we spend it.
        if order_in
            .hash()
            .map_err(|e| anyhow!("order_in hash: {e:?}"))?
            != escrow_state.order_utxo_hash
        {
            bail!("reconstructed order utxo does not match the committed escrow leaf");
        }
        let maker_funding_in = SppProofInputUtxo::new(maker_funding, &env.authority.keypair);

        let change_amount = funding_amount
            .checked_sub(owed)
            .ok_or_else(|| anyhow!("owed exceeds the maker funding amount"))?;

        let mut recipient_out = SppProofOutputUtxo::new(SOL_MINT, owed, recipient)
            .map_err(|e| anyhow!("recipient_out: {e:?}"))?;
        let authority_address = env.authority.address()?;
        let mut funder_change =
            SppProofOutputUtxo::new(SOL_MINT, change_amount, authority_address)
                .map_err(|e| anyhow!("funder_change: {e:?}"))?;
        let mut funder_receipt =
            SppProofOutputUtxo::new(source_asset, order_amount, authority_address)
                .map_err(|e| anyhow!("funder_receipt: {e:?}"))?;

        // The circuit fixes each output blinding to a derivation over one input
        // blinding: the recipient's from the order blinding (the taker
        // precomputed this note at creation), the funder's from the funding
        // blinding it picked.
        recipient_out.blinding = derive_output_blinding(&order_blinding, RECIPIENT_BLINDING_DOMAIN)
            .map_err(|e| anyhow!("recipient_out blinding: {e:?}"))?;
        funder_change.blinding =
            derive_output_blinding(&funding_blinding, FUNDER_CHANGE_BLINDING_DOMAIN)
                .map_err(|e| anyhow!("funder_change blinding: {e:?}"))?;
        funder_receipt.blinding =
            derive_output_blinding(&funding_blinding, FUNDER_RECEIPT_BLINDING_DOMAIN)
                .map_err(|e| anyhow!("funder_receipt blinding: {e:?}"))?;

        let recipient_out_hash = recipient_out
            .hash()
            .map_err(|e| anyhow!("recipient_out hash: {e:?}"))?;
        let funder_change_hash = funder_change
            .hash()
            .map_err(|e| anyhow!("funder_change hash: {e:?}"))?;
        let funder_receipt_hash = funder_receipt
            .hash()
            .map_err(|e| anyhow!("funder_receipt hash: {e:?}"))?;

        // funder_change (output index 1) returns to the funder and its blinding
        // is derivable from the funding note, so its ciphertext is dropped to
        // keep the transaction under Solana's size limit.
        const FUNDER_CHANGE_INDEX: usize = 1;
        let input_utxos = vec![order_in.clone(), maker_funding_in.clone()];
        let viewing_key = get_transaction_viewing_key(&env.authority.keypair, &input_utxos)
            .map_err(|e| anyhow!("transaction viewing key: {e:?}"))?;
        let encoded = encrypt_transaction_data(
            &[
                recipient_out.clone(),
                funder_change.clone(),
                funder_receipt.clone(),
            ],
            &env.assets,
            &viewing_key,
        )
        .map_err(|e| anyhow!("encode outputs: {e:?}"))?;
        let mut outputs = encoded.outputs;
        outputs
            .get_mut(FUNDER_CHANGE_INDEX)
            .ok_or_else(|| anyhow!("funder_change output index out of range"))?
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

        let destination_asset =
            asset_field(&SOL_MINT).map_err(|e| anyhow!("destination asset: {e:?}"))?;
        let proof_inputs = SettleProofInputParams {
            order_in,
            maker_funding: maker_funding_in,
            recipient_out,
            funder_change,
            funder_receipt,
            execution_price,
            order_amount,
            order_utxo_hash,
            destination_asset,
            external_data_hash,
        }
        .to_proof_inputs()
        .map_err(|e| anyhow!("settle proof inputs: {e:?}"))?;
        let order_proof = prover
            .prove_escrow_settle(&proof_inputs)
            .map_err(|e| anyhow!("prove escrow_settle: {e:?}"))?;

        let settle_ix = Settle {
            funder: authority_solana.pubkey(),
            pair,
            escrow,
            rent_recipient: user_solana.pubkey(),
            tree: env.tree,
            proof: Groth16ProofBytes {
                proof_a: order_proof.proof_a,
                proof_b: order_proof.proof_b,
                proof_c: order_proof.proof_c,
            },
            transact,
        }
        .instruction()
        .map_err(|e| anyhow!("settle instruction: {e:?}"))?;
        // The funder signs alone: its outer signature authorizes the funding
        // input, the program's CPI signs for the order input.
        send_v0_with_lookup_table(env.client.rpc(), &authority_solana, &[], settle_ix)
            .map_err(|e| anyhow!("send settle: {e:?}"))?;

        (recipient_out_hash, funder_change_hash, funder_receipt_hash)
    };

    // Settle payout (encoded in the leaf hashes asserted below): recipient paid
    // `order_amount * execution_price` of SOL; funder change is the unspent
    // funding; funder receipt is the full escrowed SPL. A wrong asset or amount
    // would hash differently and fail the tree inclusion check.
    let leaves = vec![recipient_out_hash, funder_change_hash, funder_receipt_hash];
    let response = env
        .client
        .indexer()
        .get_merkle_proofs(env.tree, leaves.clone(), None)
        .map_err(|e| anyhow!("get merkle proofs: {e:?}"))?;
    if response.proofs.len() != leaves.len() {
        bail!(
            "expected {} indexed settle output leaves, indexer returned {}",
            leaves.len(),
            response.proofs.len()
        );
    }

    // Settlement closes the escrow account.
    assert!(
        env.client
            .rpc()
            .get_account(escrow)
            .map_err(|e| anyhow!("get escrow account after settle: {e:?}"))?
            .is_none(),
        "escrow account must be closed after settlement"
    );

    Ok(())
}
