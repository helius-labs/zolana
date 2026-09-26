use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solana_signature::Signature;
use timelock_escrow_arkworks::{
    escrow_authority, escrow_input, Escrow, EscrowPrivateInputs, EscrowPublicInputs, EscrowTerms,
    Withdraw, WithdrawPrivateInputs, WithdrawPublicInputs,
};
use timelock_escrow_program::instructions::escrow::slot;
use zk_program_sdk::{wasm, Groth16Prover, Owner, TxContext, ZkProgram};
use zolana_hasher::primitives::solana_owner_identity;
use zolana_interface::instruction::instruction_data::transact::OwnerTag;
use zolana_keypair::{ShieldedAddress, ShieldedKeypair, SigningKey};
use zolana_transaction::{
    utxo::{SppProofInputUtxo, Utxo},
    Data, Mint, WalletUtxo,
};

#[cfg(feature = "snarkjs")]
#[allow(dead_code)]
mod ceremony;

const TREE_ID: u16 = 3;
const UNLOCK: u64 = 1_700_000_000;

struct Fixture<P> {
    name: &'static str,
    program: P,
    keypair: ShieldedKeypair,
}

impl<P: ZkProgram + Serialize> Fixture<P> {
    fn sender(&self) -> ShieldedAddress {
        self.keypair.shielded_address().expect("sender address")
    }

    fn json(&self, prover: &Groth16Prover<P>) -> Value {
        let sender = self.sender();
        let payer = sender.solana_address().expect("payer");
        let transaction = self
            .program
            .create_program_transaction(&sender, payer)
            .expect("program transaction");
        let proof_inputs = transaction.proof_inputs.to_bytes().expect("proof inputs");
        let mut wire = serde_json::to_value(
            wasm::ProgramTransaction::try_from(&transaction).expect("wasm transaction"),
        )
        .expect("transaction json");
        if let Some(object) = wire.as_object_mut() {
            object.remove("proofInputs");
        }
        let external_data = transaction
            .finalized
            .clone()
            .encrypt(&self.keypair)
            .expect("encrypted transaction")
            .external_data;
        json!({
            "inputs": serde_json::to_value(&self.program).expect("inputs json"),
            "sender": sender.to_bytes().to_vec(),
            "payer": payer.to_string(),
            "transaction": wire,
            "proofInputsSha256": hex::encode(Sha256::digest(&proof_inputs)),
            "verifyingKey": prover.keys().gnark_verifying_key().expect("verifying key"),
            "encrypted": {
                "utxoHashes": external_data
                    .outputs
                    .iter()
                    .map(|output| output.utxo_hash.to_vec())
                    .collect::<Vec<_>>(),
                "ownerTags": external_data
                    .outputs
                    .iter()
                    .map(|output| match output.owner_tag {
                        OwnerTag::Inline(value) => json!({ "kind": "inline", "value": value.to_vec() }),
                        OwnerTag::Account(index) => json!({ "kind": "account", "index": index }),
                    })
                    .collect::<Vec<_>>(),
                "resolvedOwnerTags": external_data
                    .resolved_owner_tags
                    .iter()
                    .map(|tag| tag.to_vec())
                    .collect::<Vec<_>>(),
                "interfaceTransfers": serde_json::to_value(&external_data.interface_transfers)
                    .expect("transfers json"),
            },
        })
    }
}

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
        utxo,
        nullifier_pubkey: address.nullifier_pubkey,
        utxo_hash,
        data_hash: None,
        ring_data_hash: None,
        tree_id: TREE_ID,
        leaf_index,
        latest_tree_id: None,
        slot: 0,
        tx_signature: Signature::default(),
        slot_index: 0,
    }
}

fn dummy_input(blinding: u8) -> WalletUtxo {
    let dummy = SppProofInputUtxo::dummy_with_blinding([blinding; 32], TREE_ID).expect("dummy");
    WalletUtxo {
        utxo: dummy.utxo,
        nullifier_pubkey: dummy.nullifier_pubkey,
        utxo_hash: dummy.utxo_hash,
        nullifier: dummy.nullifier,
        data_hash: dummy.data_hash,
        ring_data_hash: dummy.ring_data_hash,
        tree_id: dummy.tree_id,
        leaf_index: dummy.leaf_index,
        latest_tree_id: None,
        slot: 0,
        tx_signature: Signature::default(),
        slot_index: 0,
    }
}

fn escrow() -> Fixture<Escrow> {
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    Fixture {
        name: "escrow",
        program: Escrow {
            private: EscrowPrivateInputs {
                tx_context: TxContext::new().with_blinding_seed([21; 32]),
                token_utxos_asset_a: [
                    token_input(&creator, 600, 0, 11),
                    token_input(&creator, 400, 1, 12),
                    dummy_input(13),
                    dummy_input(14),
                    dummy_input(15),
                ],
                unlock: UNLOCK,
                amount: 250,
            },
            public: EscrowPublicInputs {
                escrow_owner: escrow_authority()
                    .address(address.viewing_pubkey)
                    .expect("escrow owner"),
            },
        },
        keypair: creator,
    }
}

fn withdraw() -> Fixture<Withdraw> {
    let escrow = escrow();
    let address = escrow.sender();
    let finalized = escrow
        .program
        .create_finalized_transaction(&address, address.solana_address().expect("payer"))
        .expect("escrow transaction");
    let escrow_utxo = escrow_input(
        finalized
            .output_utxos()
            .get(slot::ESCROW)
            .expect("escrow output"),
        finalized.output_tree_id(),
        2,
    )
    .expect("escrow input");
    Fixture {
        name: "withdraw",
        program: Withdraw {
            private: WithdrawPrivateInputs {
                tx_context: TxContext::new().with_blinding_seed([22; 32]),
                escrow: escrow_utxo,
                terms: EscrowTerms {
                    creator: Owner::try_from(&address).expect("creator owner"),
                    unlock: UNLOCK,
                },
            },
            public: WithdrawPublicInputs {
                unlock: UNLOCK,
                owner_identity: solana_owner_identity(
                    address.solana_address().expect("creator").as_array(),
                )
                .expect("owner identity"),
            },
        },
        keypair: escrow.keypair,
    }
}

fn committed_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../wasm/tests/fixtures")
}

fn keys_dir() -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR"))
        .parent()
        .expect("target directory")
        .join("escrow-wasm-fixtures")
}

fn committed(name: &str) -> Value {
    let path = committed_dir().join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "{} is missing: run just regen-escrow-wasm-fixtures",
            path.display()
        )
    });
    serde_json::from_str(&text).expect("fixture json")
}

fn write<P: ZkProgram + Serialize>(fixture: &Fixture<P>) {
    let prover = Groth16Prover::<P>::new_with_test_setup().expect("seeded setup");
    std::fs::create_dir_all(keys_dir()).expect("keys directory");
    prover
        .keys()
        .save(&keys_dir().join(format!("{}.pk", fixture.name)))
        .expect("proving key");
    std::fs::write(
        keys_dir().join(format!("{}.wtns", fixture.name)),
        fixture.program.export_assignment().expect("proof inputs"),
    )
    .expect("wtns");
    std::fs::create_dir_all(committed_dir()).expect("fixtures directory");
    std::fs::write(
        committed_dir().join(format!("{}.json", fixture.name)),
        serde_json::to_string_pretty(&fixture.json(&prover)).expect("fixture text") + "\n",
    )
    .expect("fixture");
    #[cfg(feature = "snarkjs")]
    write_zkey::<P>(fixture.name);
}

#[cfg(feature = "snarkjs")]
fn write_zkey<P: ZkProgram>(name: &str) {
    use zk_program_sdk::Groth16Keys;

    let ceremony = ceremony::ceremony::<P>(name);
    let zkey = keys_dir().join(format!("{name}.zkey"));
    std::fs::copy(ceremony.final_zkey(), &zkey).expect("zkey");
    std::fs::copy(
        ceremony.verification_key(),
        keys_dir().join(format!("{name}.vkey.json")),
    )
    .expect("snarkjs verification key");
    let keys = Groth16Keys::load_zkey::<P>(&zkey).expect("zkey keys");
    std::fs::write(
        keys_dir().join(format!("{name}.zkey.vk")),
        keys.gnark_verifying_key().expect("zkey verifying key"),
    )
    .expect("zkey verifying key file");
}

#[test]
#[ignore = "regenerates the escrow wasm fixtures: just regen-escrow-wasm-fixtures"]
fn write_wasm_fixtures() {
    write(&escrow());
    write(&withdraw());
}

#[test]
fn committed_wasm_fixtures_match_the_native_path() {
    let escrow = escrow();
    let withdraw = withdraw();
    let escrow_prover = Groth16Prover::<Escrow>::new_with_test_setup().expect("escrow setup");
    let withdraw_prover = Groth16Prover::<Withdraw>::new_with_test_setup().expect("withdraw setup");

    assert_eq!(
        (escrow.json(&escrow_prover), withdraw.json(&withdraw_prover)),
        (committed("escrow"), committed("withdraw"))
    );
}
