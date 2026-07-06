use solana_address::Address;
use swap_sdk::{
    escrow_authority_pda,
    instructions::create_swap::EscrowCreate,
    order::{marker_output, Escrow, OrderTerms, SOL_ASSET_ID},
};
use zolana_keypair::{hash::hash_field, ShieldedKeypair, ViewingKey};
use zolana_transaction::{
    instructions::{transact::Transaction as TxBuilder, types::SpendUtxo},
    utxo::{Blinding, Utxo},
    AssetRegistry, Data, SOL_MINT,
};

const SENDER_SLOT_SHARED_INDEX: usize = 0;

fn sample_terms(maker_owner_hash: [u8; 32]) -> OrderTerms {
    let mut taker_pk_fe = [0u8; 32];
    taker_pk_fe[31] = 123;
    let mut maker_viewing_pk = [0u8; 33];
    maker_viewing_pk[0] = 2;
    OrderTerms {
        source_asset_id: SOL_ASSET_ID,
        source_amount: 1_000,
        destination_asset_id: 2,
        destination_mint: Address::new_from_array([7u8; 32]),
        destination_amount: 250,
        maker_owner_hash,
        maker_viewing_pk,
        expiry: 1_700_000_000,
        taker_pk_fe,
        fill_mode: swap_prover::FILL_MODE_DERIVED,
    }
}

fn maker_keypair() -> ShieldedKeypair {
    let mut seed = [0u8; 32];
    seed[0] = 0;
    seed[31] = 5;
    ShieldedKeypair::from_ed25519(&seed, ViewingKey::new()).expect("maker keypair")
}

fn taker_keypair() -> ShieldedKeypair {
    let mut seed = [0u8; 32];
    seed[31] = 13;
    ShieldedKeypair::from_ed25519(&seed, ViewingKey::new()).expect("taker keypair")
}

fn maker_input(keypair: &ShieldedKeypair, amount: u64) -> SpendUtxo {
    let mut blinding: Blinding = [0u8; 31];
    blinding[30] = 9;
    let utxo = Utxo {
        owner: keypair.signing_pubkey(),
        asset: SOL_MINT,
        amount,
        blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    SpendUtxo::from_keypair(utxo, keypair)
}

fn prover_output_owner_pk_hashes(
    signed: &zolana_transaction::instructions::transact::SignedTransaction,
) -> Vec<[u8; 32]> {
    signed
        .outputs
        .iter()
        .map(|output| match &output.owner_address {
            Some(address) => address
                .signing_pubkey
                .owner_pk_field()
                .expect("owner pk field"),
            None => hash_field(&output.owner_tag.unwrap_or([0u8; 32])).expect("hash field"),
        })
        .collect()
}

fn onchain_output_owner_pk_hashes(
    signed: &zolana_transaction::instructions::transact::SignedTransaction,
) -> Vec<[u8; 32]> {
    let n_outputs = signed.outputs.len();
    let n_ciphertexts = signed.external_data.output_ciphertexts.len();
    let sender_slots = n_outputs.saturating_sub(n_ciphertexts.saturating_sub(1));
    (0..n_outputs)
        .map(|i| {
            let idx = if i < sender_slots {
                SENDER_SLOT_SHARED_INDEX
            } else {
                1 + i - sender_slots
            };
            let view_tag = signed
                .external_data
                .output_ciphertexts
                .get(idx)
                .expect("ciphertext slot")
                .view_tag;
            hash_field(&view_tag).expect("hash field")
        })
        .collect()
}

#[test]
fn create_change_first_owner_tag_mapping_matches() {
    let maker = maker_keypair();
    let taker = taker_keypair();
    let taker_address = taker.shielded_address().expect("taker address");

    let mut maker_owner_hash = [0u8; 32];
    maker_owner_hash[31] = 99;
    let terms = sample_terms(maker_owner_hash);

    let mut escrow_blinding: Blinding = [0u8; 31];
    escrow_blinding[30] = 7;
    let escrow = Escrow {
        terms: terms.clone(),
        blinding: escrow_blinding,
        source_mint: SOL_MINT,
    }
    .output(taker_address.viewing_pubkey)
    .expect("escrow output");
    let marker = marker_output(taker_address);

    let assets = AssetRegistry::default();
    let payer = Address::new_from_array(maker.signing_pubkey().hash().expect("hash"));
    let input = maker_input(&maker, terms.source_amount);
    let signed = EscrowCreate {
        tx: TxBuilder::new(
            maker.shielded_address().expect("maker address"),
            vec![input],
            payer,
        ),
        escrow,
        marker,
    }
    .sign(&maker, &assets)
    .expect("sign escrow create");

    let prover = prover_output_owner_pk_hashes(&signed);
    let onchain = onchain_output_owner_pk_hashes(&signed);

    let escrow_tag = hash_field(&escrow_authority_pda().to_bytes()).expect("escrow owner pk field");
    let maker_tag = maker
        .signing_pubkey()
        .owner_pk_field()
        .expect("maker owner pk field");
    let marker_tag = taker
        .signing_pubkey()
        .owner_pk_field()
        .expect("taker owner pk field");

    assert_eq!(
        prover,
        vec![maker_tag, escrow_tag, marker_tag],
        "the prover commits output_owner_pk_hashes in SPP output order [change (sender), escrow (recipient), marker (recipient)]"
    );
    assert_eq!(
        onchain,
        vec![maker_tag, escrow_tag, marker_tag],
        "the SPP owner_view_tag mapping assigns the sender bundle tag to output slot 0 (change), the escrow recipient ciphertext tag to slot 1, and the marker recipient ciphertext tag to slot 2"
    );
    assert_eq!(
        prover, onchain,
        "change-first (2,3) layout: prover and program-side output_owner_pk_hashes agree, so the confidential public input matches and the SPP transact proof verifies"
    );
}
