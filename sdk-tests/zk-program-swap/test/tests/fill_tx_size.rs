use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{v0, AddressLookupTableAccount, Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::{versioned::VersionedTransaction, Transaction};
use swap_sdk::{
    escrow_authority_pda,
    instructions::fill::{fill, EscrowFill, FillIxData, FillSharedInputs},
    order::{Escrow, OrderTerms, SOL_ASSET_ID},
    FillProof,
};
use zolana_client::Transaction as TxBuilder;
use zolana_interface::{
    instruction::instruction_data::transact::{
        InputUtxo, OutputCiphertext, TransactIxData, TransactProof,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{random_blinding, ShieldedKeypair};
use zolana_transaction::{
    instructions::types::SpendUtxo, utxo::Utxo, AssetRegistry, Data, SOL_MINT,
};

const FILL_TX_LIMIT: usize = 1232;

fn fe(byte: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = byte;
    out
}

fn sample_terms(
    taker_pk_fe: [u8; 32],
    maker_owner_hash: [u8; 32],
    maker_viewing_pk: [u8; 33],
) -> OrderTerms {
    OrderTerms {
        source_asset_id: SOL_ASSET_ID,
        source_amount: 1_000,
        destination_asset_id: SOL_ASSET_ID,
        destination_mint: SOL_MINT,
        destination_amount: 250,
        maker_owner_hash,
        maker_viewing_pk,
        expiry: 1_700_000_000,
        taker_pk_fe,
        fill_mode: swap_prover::FILL_MODE_DERIVED,
    }
}

fn build_fill_transact() -> (TransactIxData, FillProof) {
    let assets = AssetRegistry::default();

    let maker = ShieldedKeypair::from_seed_ed25519(&fe(0x51)).expect("maker keypair");
    let maker_recipient = maker.shielded_address().expect("maker address");
    let taker = ShieldedKeypair::from_seed_ed25519(&fe(0x4d)).expect("taker keypair");
    let taker_recipient = taker.shielded_address().expect("taker address");
    let taker_address = taker.owner_hash().expect("taker owner hash");

    let taker_pk_fe = taker
        .signing_pubkey()
        .owner_pk_field()
        .expect("taker pk_fe");
    let terms = sample_terms(
        taker_pk_fe,
        maker.owner_hash().expect("maker owner hash"),
        *maker.viewing_pubkey().as_bytes(),
    );

    let escrow_blinding = {
        let mut b = [0u8; 31];
        b[30] = 7;
        b
    };
    let taker_in_blinding = random_blinding();
    let source_output_blinding = random_blinding();

    let fill_shared_inputs = FillSharedInputs {
        terms: terms.clone(),
        escrow_blinding,
        taker_address,
        taker_in_blinding,
        source_output_blinding,
        external_data_hash: [0u8; 32],
        maker_recipient,
        taker_recipient,
    };
    let source_output = fill_shared_inputs.source_output(SOL_MINT);
    let destination_output = fill_shared_inputs
        .destination_output(SOL_MINT)
        .expect("destination output");

    let escrow_input = Escrow {
        terms: terms.clone(),
        blinding: escrow_blinding,
        source_mint: SOL_MINT,
    }
    .spend()
    .expect("escrow spend");
    let taker_utxo = Utxo {
        owner: taker.signing_pubkey(),
        asset: SOL_MINT,
        amount: terms.destination_amount,
        blinding: taker_in_blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let taker_spend = SpendUtxo::from_keypair(taker_utxo, &taker);

    let payer_address = Address::new_from_array([9u8; 32]);
    let signed = EscrowFill {
        tx: TxBuilder::new(
            taker_recipient,
            vec![escrow_input, taker_spend],
            payer_address,
        )
        .with_expiry(terms.expiry),
        source_output,
        destination_output,
    }
    .sign(&taker, &assets)
    .expect("escrow fill sign");

    let external_data = &signed.external_data;
    let output_ciphertexts: Vec<OutputCiphertext> = external_data
        .output_ciphertexts
        .iter()
        .map(|c| OutputCiphertext {
            view_tag: c.view_tag,
            data: c.data.clone(),
        })
        .collect();

    let inputs: Vec<InputUtxo> = (0..signed.shape.n_inputs)
        .map(|i| InputUtxo {
            nullifier_hash: fe(i as u8 + 1),
            nullifier_tree_root_index: 0,
            utxo_tree_root_index: 0,
            tree_index: 0,
            eddsa_signer_index: if i == 0 { 2 } else { 0 },
        })
        .collect();

    let transact = TransactIxData {
        proof: TransactProof::zeroed_eddsa(),
        expiry_unix_ts: external_data.expiry_unix_ts,
        relayer_fee: external_data.relayer_fee,
        private_tx_hash: [1u8; 32],
        p256_signing_pk_field: None,
        inputs,
        public_sol_amount: external_data.public_sol_amount,
        public_spl_amount: external_data.public_spl_amount,
        data_hash: external_data.data_hash,
        zone_data_hash: external_data.zone_data_hash,
        tx_viewing_pk: external_data.tx_viewing_pk,
        salt: external_data.salt,
        output_utxo_hashes: external_data.output_utxo_hashes.clone(),
        output_ciphertexts,
    };

    let fill_proof = FillProof {
        proof_a: [0u8; 32],
        proof_b: [0u8; 64],
        proof_c: [0u8; 32],
    };
    (transact, fill_proof)
}

fn fill_instruction(transact: TransactIxData, fill_proof: FillProof) -> (Instruction, Pubkey) {
    let taker_solana_keypair = Keypair::new();
    let tree = Pubkey::new_from_array([3u8; 32]);
    let spp_accounts = vec![
        AccountMeta::new(taker_solana_keypair.pubkey(), true),
        AccountMeta::new(tree, false),
        AccountMeta::new_readonly(escrow_authority_pda(), false),
        AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
    ];
    let ix = fill(
        taker_solana_keypair.pubkey(),
        spp_accounts,
        fill_proof,
        transact,
    );
    (ix, taker_solana_keypair.pubkey())
}

fn v0_alt_size(ix: &Instruction, payer: &Pubkey, alt: &AddressLookupTableAccount) -> usize {
    let compute = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let msg = v0::Message::try_compile(
        payer,
        &[compute, ix.clone()],
        std::slice::from_ref(alt),
        Default::default(),
    )
    .expect("compile v0 message");
    let versioned = VersionedMessage::V0(msg);
    let signature_count = versioned.header().num_required_signatures as usize;
    let tx = VersionedTransaction {
        signatures: vec![Default::default(); signature_count],
        message: versioned,
    };
    bincode::serialize(&tx).expect("serialize v0").len()
}

fn legacy_size(ix: &Instruction, payer: &Pubkey, n_signers: usize) -> usize {
    let compute = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let message = Message::new(&[compute, ix.clone()], Some(payer));
    let tx = Transaction::new_unsigned(message);
    let serialized = bincode::serialize(&tx).expect("serialize legacy");
    serialized.len() + n_signers.saturating_sub(1) * 64
}

#[test]
fn fill_tx_fits_under_1232_with_alt() {
    let (transact, fill_proof) = build_fill_transact();

    let n_ciphertexts = transact.output_ciphertexts.len();
    let ix_data_len = FillIxData {
        proof: fill_proof,
        transact: transact.clone(),
    }
    .serialize()
    .len();

    let (ix, payer) = fill_instruction(transact, fill_proof);
    let n_accounts = ix.accounts.len();

    let mut signer_keys: Vec<Pubkey> = ix
        .accounts
        .iter()
        .filter(|m| m.is_signer)
        .map(|m| m.pubkey)
        .collect();
    signer_keys.sort();
    signer_keys.dedup();
    let n_signers = signer_keys.len();
    assert_eq!(n_signers, 1, "fill carries exactly one transaction signer");
    let legacy = legacy_size(&ix, &payer, n_signers);

    let alt = AddressLookupTableAccount {
        key: Address::new_from_array([250u8; 32]),
        addresses: ix
            .accounts
            .iter()
            .filter(|m| !m.is_signer)
            .map(|m| Address::new_from_array(m.pubkey.to_bytes()))
            .chain(std::iter::once(Address::new_from_array(
                ix.program_id.to_bytes(),
            )))
            .collect(),
    };
    let v0 = v0_alt_size(&ix, &payer, &alt);

    println!("=== swap derived fill transaction size ===");
    println!("output ciphertext slots           : {n_ciphertexts}");
    println!("swap fill instruction data (FillIxData): {ix_data_len} B");
    println!("instruction accounts              : {n_accounts}");
    println!("legacy transaction size           : {legacy} B");
    println!("v0 + ALT transaction size         : {v0} B  (limit {FILL_TX_LIMIT})");

    assert!(
        v0 < FILL_TX_LIMIT,
        "fill v0+ALT tx must fit under {FILL_TX_LIMIT} bytes, got {v0}"
    );
}
