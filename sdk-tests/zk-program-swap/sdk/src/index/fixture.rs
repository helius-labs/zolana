use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use swap_prover::TAKE_MODE_DERIVED;
use zolana_keypair::{constants::BLINDING_LEN, P256Pubkey, ShieldedAddress, ShieldedKeypair};
use zolana_transaction::{
    instructions::{
        transact::{
            encrypt_transaction_data, get_transaction_viewing_key, ExternalData, OutputContext,
            OutputSlot, SppProofInputs, SppProofOutputUtxo,
        },
        types::SppProofInputUtxo,
    },
    utxo::Utxo,
    AssetRegistry, Data, ShieldedTransaction, Wallet, SOL_ASSET_ID, SOL_MINT,
};

use crate::{
    instructions::make::OrderMarker,
    shared::input_sum,
    state::{OrderTerms, OrderUtxo},
};

pub(crate) struct OrderFixture {
    pub(crate) tx: ShieldedTransaction,
    pub(crate) wallet: Wallet,
    pub(crate) maker_wallet: Wallet,
    pub(crate) taker_keypair: ShieldedKeypair,
    pub(crate) maker_keypair: ShieldedKeypair,
    pub(crate) order_utxo: OrderUtxo,
    pub(crate) maker_address: ShieldedAddress,
    pub(crate) maker_pubkey: Pubkey,
}

fn shielded_transaction(proof_inputs: &SppProofInputs) -> ShieldedTransaction {
    let external = &proof_inputs.external_data;
    let output_slots = external
        .outputs
        .iter()
        .zip(external.resolved_owner_tags.iter())
        .enumerate()
        .map(|(index, (output, view_tag))| OutputSlot {
            view_tag: *view_tag,
            output_context: OutputContext {
                hash: output.utxo_hash,
                tree: Address::default(),
                leaf_index: index as u64,
            },
            payload: output.data.clone().unwrap_or_default(),
        })
        .collect();
    let nullifiers = proof_inputs
        .input_utxo_hashes()
        .expect("input commitments")
        .iter()
        .map(|commitment| commitment.nullifier)
        .collect();
    ShieldedTransaction {
        slot: 0,
        tx_signature: Signature::default(),
        tx_viewing_pk: P256Pubkey::from_bytes(external.tx_viewing_pk).ok(),
        salt: Some(external.salt),
        output_slots,
        messages: external.messages.clone(),
        nullifiers,
        proofless: false,
    }
}

pub(crate) fn order_fixture() -> OrderFixture {
    let maker_keypair = ShieldedKeypair::from_solana_keypair(&Keypair::new_from_array([7u8; 32]))
        .expect("maker keypair");
    let taker_keypair = ShieldedKeypair::from_solana_keypair(&Keypair::new_from_array([13u8; 32]))
        .expect("taker keypair");
    let maker_address = maker_keypair.shielded_address().expect("maker address");
    let taker_address = taker_keypair.shielded_address().expect("taker address");
    let source_mint = Address::new_from_array([9u8; 32]);
    let mut registry = AssetRegistry::default();
    registry.insert(2, source_mint).expect("register mint");

    let terms = OrderTerms {
        destination_mint: SOL_MINT,
        destination_amount: 250_000,
        destination: maker_address,
        taker: taker_address
            .solana_address()
            .expect("taker solana address"),
        expiry: 2_000_000_000,
        take_mode: TAKE_MODE_DERIVED,
    };
    let order_utxo = OrderUtxo {
        terms,
        blinding: [11u8; BLINDING_LEN],
        source_mint,
        source_amount: 400_000,
        destination_asset_id: SOL_ASSET_ID,
    };
    let order_output_utxo = order_utxo
        .output_utxo(taker_address.viewing_pubkey)
        .expect("order output");
    let maker_pubkey = Pubkey::new_from_array(
        *maker_address
            .solana_address()
            .expect("maker solana address")
            .as_array(),
    );

    let input_utxo = Utxo {
        owner: maker_keypair.signing_pubkey(),
        asset: source_mint,
        amount: 1_000_000,
        blinding: [5u8; BLINDING_LEN],
        zone_program_id: None,
        data: Data::default(),
    };
    let spend = SppProofInputUtxo::new(input_utxo, &maker_keypair);
    let input_utxos = vec![spend, SppProofInputUtxo::new_dummy()];

    let order_utxo_hash = order_output_utxo.hash().expect("order output hash");
    let change_amount =
        u64::try_from(input_sum(&input_utxos, &source_mint) - i128::from(order_output_utxo.amount))
            .expect("change amount");
    let change =
        SppProofOutputUtxo::new(source_mint, change_amount, maker_address).expect("change output");
    let marker_message = OrderMarker {
        order_utxo_hash,
        maker_pubkey,
        taker_address,
    }
    .message()
    .expect("marker message");
    let transaction_viewing_key =
        get_transaction_viewing_key(&maker_keypair, &input_utxos).expect("transaction viewing key");

    let encoded = encrypt_transaction_data(
        &[change, order_output_utxo],
        &registry,
        &transaction_viewing_key,
    )
    .expect("encode slots");

    let external_data = ExternalData::new(
        *transaction_viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![marker_message],
    );
    let spp_proof_inputs = SppProofInputs::new(
        input_utxos,
        encoded.output_utxos,
        external_data,
        Address::default(),
    );

    OrderFixture {
        tx: shielded_transaction(&spp_proof_inputs),
        wallet: Wallet::new(taker_address, registry.clone()).expect("taker wallet"),
        maker_wallet: Wallet::new(maker_address, registry).expect("maker wallet"),
        taker_keypair,
        maker_keypair,
        order_utxo,
        maker_address,
        maker_pubkey,
    }
}
