//! Vectors shared with `sdk-libs/ts/test/ring-list-write.test.ts`.

use zolana_client::{PublicInputs, PublicTransfers};
use zolana_hasher::primitives::{right_align, solana_owner_identity};
use zolana_interface::{
    instruction::instruction_data::transact::{OwnerTag, TransactOutput},
    tree_slot::TreeSlot,
    INPUT_TREES,
};
use zolana_ring_policy::{entry_nullifier, EntryState, ListEntry, ListId, ListNamespace, Member};
use zolana_transaction::{
    instructions::transact::{ExternalData, PrivateTxHash},
    utxo::{
        derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
    },
};

const RECORDS_PDA: [u8; 32] = [0x11; 32];
const RECIPIENT_TAG: [u8; 32] = [0xa1; 32];
const PAYER: [u8; 32] = [0x01; 32];
const STATE_ROOT: [u8; 32] = [0x06; 32];
const NULLIFIER_ROOT: [u8; 32] = [0x07; 32];
const TREE_ID: u16 = 3;
const BLINDING_SEED: [u8; 32] = [0x08; 32];

const EXTERNAL_HASH: &str = "00ef014f5c68fff05cd62415182ac9e7db2456eebca778b39a14cdac540d0173";
const CLAIM_PRIVATE_TX_HASH: &str =
    "1224a99757d2c68fcacc59845bc8adf7689a879b0d5fccd451deea5ea5779a7b";
const CLAIM_PUBLIC_INPUT_HASH: &str =
    "0c36fee57941a1f35389036e8b7037d66d6cd0ef6466b633c30ccf84b4652a51";
const SPEND_PRIVATE_TX_HASH: &str =
    "16f3de48d03c896f8e726afe1f9a9f26f10237542b9a6ecdfb94929e2e860719";
const SPEND_PUBLIC_INPUT_HASH: &str =
    "130fe7107f0bfcf8411d769abcd08a238dbb104049980f8833153a204908eb37";
const CLAIM_BLINDING: &str = "078e398422043456dc67a4c39f57ab507670ab3d1024746d47a2e93c7a46c344";
const SPEND_BLINDING: &str = "018be3ee8af2454b58a964be7d94a0b752f31e5a85f4a0c80b4d25213d44b256";

struct Transition {
    entry: ListEntry,
    external: [u8; 32],
    private_tx: [u8; 32],
    public_input: [u8; 32],
}

/// The namespace and member of the Go policy circuit fixture.
fn transition(spent: Option<ListEntry>) -> Transition {
    let owner = ListNamespace::new(&RECORDS_PDA).expect("owner");
    let member = Member::owner_tag(&RECIPIENT_TAG).expect("member");
    let address = owner
        .address(ListId::Allow, &member, TREE_ID)
        .expect("address");
    let (input_hash, address_nullifier, nullifier) = match spent {
        None => ([0u8; 32], Some(address), address),
        Some(spent) => {
            let spent_hash = spent
                .utxo_hash(&owner, &address, TREE_ID)
                .expect("spent hash");
            let nullifier = entry_nullifier(&spent_hash, &spent.blinding()).expect("nullifier");
            (spent_hash, None, nullifier)
        }
    };
    let blinding = derive_transact_output_blinding(
        &nullifier,
        &derive_output_blinding_seed(&nullifier, &BLINDING_SEED).expect("output seed"),
        0,
    )
    .expect("blinding");
    let private_tx_blinding =
        derive_private_tx_blinding(&nullifier, &BLINDING_SEED).expect("private tx blinding");
    let entry = ListEntry {
        list_id: ListId::Allow,
        member,
        state: EntryState::Active,
        version: spent.map_or(0, |spent| spent.version + 1),
        content_hash: [0u8; 32],
        blinding,
    };
    let output_hash = entry
        .utxo_hash(&owner, &address, TREE_ID)
        .expect("output hash");
    let external = ExternalData::new(
        [0u8; 33],
        [0u8; 16],
        vec![TransactOutput {
            utxo_hash: output_hash,
            owner_tag: OwnerTag::Inline(RECORDS_PDA),
            data: Some(entry.to_output_data().to_vec()),
        }],
        vec![RECORDS_PDA],
        Vec::new(),
    )
    .hash()
    .expect("external hash");
    let address_nullifiers = address_nullifier.map(|nullifier| [nullifier]);
    let private_tx = PrivateTxHash {
        input_hashes: &[input_hash],
        output_hashes: &[output_hash],
        address_nullifiers: address_nullifiers.as_ref().map(|slice| slice.as_slice()),
        external_data_hash: &external,
        blinding: &private_tx_blinding,
    }
    .hash()
    .expect("private tx hash");
    let namespace_hash = solana_owner_identity(&RECORDS_PDA).expect("namespace");
    let payer_hash = solana_owner_identity(&PAYER).expect("payer");
    let mut tree_slots = [TreeSlot::ZERO; INPUT_TREES];
    tree_slots[0] = TreeSlot::new(TREE_ID, STATE_ROOT, NULLIFIER_ROOT);
    let public_input = PublicInputs {
        nullifiers: &[nullifier],
        output_hashes: &[output_hash],
        tree_slots: &tree_slots,
        output_tree_id: TREE_ID,
        private_tx: &private_tx,
        external_data_hash: &external,
        public_transfers: &PublicTransfers::default(),
        ring_program_id: &[0u8; 32],
        allow_dummy_inputs: &right_align(&1u64.to_be_bytes()),
        signer_pk_hashes: &[payer_hash, namespace_hash],
        output_owner_pk_hashes: Some(&[namespace_hash]),
    }
    .hash()
    .expect("public input hash");
    Transition {
        entry,
        external,
        private_tx,
        public_input,
    }
}

#[test]
fn a_claim_hashes_to_the_typescript_vector() {
    let claim = transition(None);
    assert_eq!(
        hex::encode(claim.entry.blinding),
        CLAIM_BLINDING,
        "blinding"
    );
    assert_eq!(hex::encode(claim.external), EXTERNAL_HASH, "external");
    assert_eq!(
        hex::encode(claim.private_tx),
        CLAIM_PRIVATE_TX_HASH,
        "private"
    );
    assert_eq!(
        hex::encode(claim.public_input),
        CLAIM_PUBLIC_INPUT_HASH,
        "public"
    );
}

#[test]
fn a_spend_hashes_to_the_typescript_vector() {
    let spend = transition(Some(transition(None).entry));
    assert_eq!(
        hex::encode(spend.entry.blinding),
        SPEND_BLINDING,
        "blinding"
    );
    assert_eq!(
        hex::encode(spend.private_tx),
        SPEND_PRIVATE_TX_HASH,
        "private"
    );
    assert_eq!(
        hex::encode(spend.public_input),
        SPEND_PUBLIC_INPUT_HASH,
        "public"
    );
}
