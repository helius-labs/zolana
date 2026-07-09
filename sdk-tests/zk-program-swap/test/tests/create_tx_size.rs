use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{v0, AddressLookupTableAccount, Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::{versioned::VersionedTransaction, Transaction};
use swap_sdk::{
    instructions::create_swap::{create_swap, CreateSwapIxData, EscrowCreate},
    order::{marker_output_utxo, Escrow, OrderTerms, SOL_ASSET_ID},
    CreateProof,
};
use zolana_client::Transaction as TxBuilder;
use zolana_interface::{
    instruction::instruction_data::transact::{
        InputUtxo, OutputCiphertext, TransactIxData, TransactProof,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{
    instructions::types::SpendUtxo, utxo::Utxo, AssetRegistry, Data, SOL_MINT,
};

const TX_LIMIT: usize = 1232;

fn fe(byte: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = byte;
    out
}

fn build_create_transact() -> (TransactIxData, CreateProof, [u8; 65]) {
    let assets = AssetRegistry::default();

    let maker = ShieldedKeypair::from_seed_ed25519(&fe(0x51)).expect("maker keypair");
    let maker_owner_hash = maker.owner_hash().expect("maker owner hash");
    let maker_viewing_pk = *maker.viewing_pubkey().as_bytes();
    let mut maker_address = [0u8; 65];
    maker_address[0..32].copy_from_slice(&maker_owner_hash);
    maker_address[32..65].copy_from_slice(&maker_viewing_pk);
    let taker = ShieldedKeypair::from_seed_ed25519(&fe(0x4d)).expect("taker keypair");
    let taker_recipient = taker.shielded_address().expect("taker address");

    let terms = OrderTerms {
        source_asset_id: SOL_ASSET_ID,
        source_amount: 400_000_000,
        destination_asset_id: SOL_ASSET_ID,
        destination_mint: SOL_MINT,
        destination_amount: 250_000_000,
        destination: maker.shielded_address().expect("maker address"),
        taker: Address::new_from_array(taker.signing_pubkey().as_ed25519().expect("taker pubkey")),
        expiry: 1_700_000_000,
        fill_mode: swap_prover::FILL_MODE_DERIVED,
    };

    let escrow_blinding = {
        let mut b = [0u8; 31];
        b[30] = 7;
        b
    };
    let escrow = Escrow {
        terms: terms.clone(),
        blinding: escrow_blinding,
        source_mint: SOL_MINT,
    }
    .output_utxo(taker_recipient.viewing_pubkey)
    .expect("escrow output");
    let marker = marker_output_utxo(taker_recipient);

    let source_utxo = Utxo {
        owner: maker.signing_pubkey(),
        asset: SOL_MINT,
        amount: 1_000_000_000,
        blinding: fe(0x33)[1..].try_into().expect("blinding"),
        zone_program_id: None,
        data: Data::default(),
    };
    let source_spend = SpendUtxo::from_keypair(source_utxo, &maker);

    let payer_address = Address::new_from_array([9u8; 32]);
    let signed = EscrowCreate {
        tx: TxBuilder::new(
            maker.shielded_address().expect("maker address"),
            vec![source_spend],
            payer_address,
        ),
        escrow,
        marker,
        payer: Pubkey::new_from_array([9u8; 32]),
    }
    .sign(&maker, &assets)
    .expect("escrow create sign");

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
            eddsa_signer_index: 0,
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

    let create_proof = CreateProof {
        proof_a: [0u8; 32],
        proof_b: [0u8; 64],
        proof_c: [0u8; 32],
    };
    (transact, create_proof, maker_address)
}

fn create_instruction(
    transact: TransactIxData,
    create_proof: CreateProof,
    maker_address: [u8; 65],
) -> (Instruction, Pubkey) {
    let maker_solana = Keypair::new();
    let tree = Pubkey::new_from_array([3u8; 32]);
    let spp_accounts = vec![
        AccountMeta::new(maker_solana.pubkey(), true),
        AccountMeta::new(tree, false),
        AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
    ];
    let ix = create_swap(
        maker_solana.pubkey(),
        spp_accounts,
        create_proof,
        SOL_ASSET_ID,
        maker_address,
        transact,
    );
    (ix, maker_solana.pubkey())
}

fn legacy_size(ix: &Instruction, payer: &Pubkey, n_signers: usize) -> usize {
    let compute = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let message = Message::new(&[compute, ix.clone()], Some(payer));
    let tx = Transaction::new_unsigned(message);
    let serialized = bincode::serialize(&tx).expect("serialize legacy");
    serialized.len() + n_signers.saturating_sub(1) * 64
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

#[test]
fn create_tx_size_breakdown() {
    let (transact, create_proof, maker_address) = build_create_transact();

    let n_ciphertexts = transact.output_ciphertexts.len();
    let slot_lens: Vec<usize> = transact
        .output_ciphertexts
        .iter()
        .map(|c| c.data.len())
        .collect();
    let transact_len = transact.serialize().expect("serialize transact").len();
    let ix_data_len = CreateSwapIxData {
        proof: create_proof,
        source_asset_id: SOL_ASSET_ID,
        maker_address,
        transact: transact.clone(),
    }
    .serialize()
    .len();

    let (ix, payer) = create_instruction(transact, create_proof, maker_address);
    let ix_total_data = ix.data.len();
    let n_accounts = ix.accounts.len();
    let legacy = legacy_size(&ix, &payer, 1);

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

    println!("=== swap create transaction size ===");
    println!("output ciphertext slots           : {n_ciphertexts}");
    for (i, len) in slot_lens.iter().enumerate() {
        println!("  slot {i} data: {len} B");
    }
    println!("transact (wincode)                : {transact_len} B");
    println!("swap create instruction data (CreateSwapIxData): {ix_data_len} B");
    println!("swap create instruction data (with 1-byte tag): {ix_total_data} B");
    println!("instruction accounts              : {n_accounts}");
    println!("legacy transaction size           : {legacy} B  (limit {TX_LIMIT})");
    println!("v0 + ALT transaction size         : {v0} B  (limit {TX_LIMIT})");

    assert!(
        v0 < TX_LIMIT,
        "create v0+ALT tx must fit under {TX_LIMIT} bytes, got {v0}"
    );
}
