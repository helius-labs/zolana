use std::path::{Path, PathBuf};
use serde_json::{json, Value};
use solana_signature::Signature;
use wasm_test_program::{escrow_authority, Escrow, EscrowPrivateInputs, EscrowPublicInputs, EscrowTerms,
    Withdraw, WithdrawPrivateInputs, WithdrawPublicInputs, ESCROW_OUTPUT_SLOT};
use zolana_keypair::{ShieldedKeypair, SigningKey};
use zolana_program::{InputRecords, ProgramTransaction, from_bytes, wasm};
use zolana_transaction::{utxo::Utxo, Data, Mint, WalletUtxo};

const TREE_ID: u16 = 3;
const UNLOCK: u64 = 1_700_000_000;

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).expect("keypair")
}

fn token_input(owner: &ShieldedKeypair, amount: u64, leaf_index: u64, blinding: u8) -> WalletUtxo {
    let address = owner.shielded_address().expect("owner address");
    let utxo = Utxo {
        owner: owner.signing_pubkey(),
        asset: Mint::SOL,
        amount,
        blinding: [blinding; 32],
        ring_program_id: None,
        data: Data::default(),
    };
    let utxo_hash = utxo
        .hash(&address.nullifier_pubkey, &[0u8; 32], &[0u8; 32], TREE_ID)
        .expect("utxo hash");
    WalletUtxo {
        nullifier: owner
            .nullifier(&utxo_hash, &utxo.blinding)
            .expect("nullifier"),
        tx_viewing_key: None,
        utxo,
        nullifier_pubkey: address.nullifier_pubkey,
        utxo_hash,
        data_hash: None,
        ring_data_hash: None,
        tree_id: TREE_ID,
        leaf_index,
        latest_tree_id: Some(TREE_ID),
        slot: 0,
        tx_signature: Signature::default(),
        slot_index: 0,
    }
}

fn directory() -> PathBuf { Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures") }

fn output(name: &str, inputs: Value, records: Value, tx: ProgramTransaction, keys: &ShieldedKeypair) -> Value {
    let sender = keys.shielded_address().unwrap();
    let artifact = Path::new(env!("CARGO_TARGET_TMPDIR")).parent().unwrap().join("zk/zolana-program-wasm-test-program").join(name);
    let mut hashes = serde_json::Map::new();
    for file in ["circuit.xbc", "pk.bin", "vk.bin"] {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(artifact.join(file)).expect("compile browser fixture circuits and keys first");
        hashes.insert(file.to_string(), Value::String(format!("{:x}", Sha256::digest(bytes))));
    }
    let transaction = serde_json::to_value(wasm::ProgramTransaction::try_from(&tx).unwrap()).unwrap();
    let external = tx.finalized.clone().encrypt_with_keys(keys).unwrap().external_data;
    json!({ "inputs": inputs, "records": records, "sender": sender.to_bytes().to_vec(),
        "payer": sender.solana_address().unwrap().to_string(), "transaction": transaction,
        "encrypted": { "utxoHashes": external.outputs.iter().map(|output| output.utxo_hash.to_vec()).collect::<Vec<_>>() },
        "circuit": name, "hashes": hashes })
}

fn fixtures() -> (Value, Value) {
    let creator = keypair(5);
    let sender = creator.shielded_address().unwrap();
    let payer = sender.solana_address().unwrap();
    let authority = escrow_authority();
    let receiver = authority.address(sender.viewing_pubkey).unwrap();
    let wallets = vec![token_input(&creator, 600, 0, 11), token_input(&creator, 400, 1, 12)];
    let mut records = InputRecords::new();
    let program = Escrow {
        private: EscrowPrivateInputs { tx_context: InputRecords::context(&[21; 32], None).unwrap(),
            token_utxos_asset_a: records.utxos(&wallets).unwrap(), unlock: UNLOCK, amount: 250 },
        public: EscrowPublicInputs { escrow_owner: records.address(&receiver).unwrap() },
    };
    let inputs = zolana_program::xark::client::to_json(&program).unwrap();
    let tx = records.create_program_transaction(&program, program.execute().unwrap(), &sender, payer).unwrap();
    let mut spent = authority.input(&tx.finalized.output_utxos()[ESCROW_OUTPUT_SLOT], tx.finalized.output_tree_id(), 2).unwrap();
    spent.latest_tree_id = Some(TREE_ID);
    let terms = <EscrowTerms as borsh::BorshDeserialize>::try_from_slice(tx.finalized.output_utxos()[ESCROW_OUTPUT_SLOT].data.utxo_data().unwrap()).unwrap();
    let escrow = output("escrow", inputs, json!({"inputs": wallets, "addresses": [receiver.to_bytes().to_vec()], "mints": []}), tx, &creator);
    let mut records = InputRecords::new();
    records.address(&sender).unwrap();
    let program = Withdraw {
        private: WithdrawPrivateInputs { tx_context: InputRecords::context(&[22; 32], None).unwrap(), escrow: records.utxo(&spent).unwrap(), terms },
        public: WithdrawPublicInputs { unlock: UNLOCK, owner_identity: from_bytes(&zolana_hasher::primitives::solana_owner_identity(payer.as_array()).unwrap()).unwrap() },
    };
    let inputs = zolana_program::xark::client::to_json(&program).unwrap();
    let tx = records.create_program_transaction(&program, program.execute().unwrap(), &sender, payer).unwrap();
    let withdraw = output("withdraw", inputs, json!({"inputs": [spent], "addresses": [sender.to_bytes().to_vec()], "mints": []}), tx, &creator);
    (escrow, withdraw)
}

#[test]
fn native_transactions_match_committed_browser_fixtures() {
    let (escrow, withdraw) = fixtures();
    for (name, actual) in [("escrow", escrow), ("withdraw", withdraw)] {
        let expected: Value = serde_json::from_slice(&std::fs::read(directory().join(format!("{name}.json"))).unwrap()).unwrap();
        assert_eq!(actual, expected, "{name} native transaction and proof inputs");
    }
}

#[test]
#[ignore = "regenerates synthetic browser fixtures"]
fn write_wasm_fixtures() {
    let (escrow, withdraw) = fixtures();
    std::fs::create_dir_all(directory()).unwrap();
    for (name, value) in [("escrow", escrow), ("withdraw", withdraw)] {
        std::fs::write(directory().join(format!("{name}.json")), serde_json::to_string_pretty(&value).unwrap()+"\n").unwrap();
    }
}
