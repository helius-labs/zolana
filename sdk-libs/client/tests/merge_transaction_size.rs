#[path = "common/input.rs"]
mod input_fixture;
#[path = "test_indexer.rs"]
mod test_indexer;

use input_fixture::wallet_utxo;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_message::v1::MAX_TRANSACTION_SIZE;
use solana_pubkey::Pubkey;
use test_indexer::TestIndexer;
use zolana_client::{
    transaction_size, CompressedCommitments, ComputeBudgetConfig, MergeProver, ProofCompressed,
    Rpc, TransactionSize,
};
use zolana_keypair::{random_blinding, ShieldedKeypair, SigningKey};
use zolana_program::instruction::{MergeRing, MergeTransact};
use zolana_transaction::{
    instructions::merge::{
        merge_circuit_width, MergeTransaction, MAX_MERGE_INPUTS, MERGE_DEFAULT_INPUT_COUNT,
    },
    Data, Mint, Utxo,
};

const TREE_ID: u16 = 0;

fn ring_program() -> Address {
    Address::new_from_array([9u8; 32])
}

fn zeroed_proof(commitment: Option<CompressedCommitments>) -> ProofCompressed {
    ProofCompressed {
        a: [0; 32],
        b: [0; 128],
        c: [0; 32],
        commitment,
    }
}

fn output_ring_data_hash() -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[31] = 0xd2;
    hash
}

struct BuiltMerge {
    instruction: Instruction,
    circuit_slots: usize,
    compact_slots: usize,
    sent_nullifiers: usize,
}

impl BuiltMerge {
    fn size(&self) -> TransactionSize {
        let payer = self
            .instruction
            .accounts
            .iter()
            .find(|account| account.is_signer)
            .expect("fee payer")
            .pubkey;
        transaction_size(
            &payer,
            std::slice::from_ref(&self.instruction),
            ComputeBudgetConfig::new(1_400_000),
        )
        .expect("measure merge transaction")
    }
}

fn build_merge(real_inputs: usize, ring: Option<Address>) -> BuiltMerge {
    let sender = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7u8; 32]))
        .expect("eddsa sender keypair");
    let owner = sender.signing_pubkey();
    let nullifier_pk = sender.nullifier_key.pubkey().expect("nullifier pk");
    let mut indexer = TestIndexer::new();
    let inputs = (0..real_inputs)
        .map(|index| {
            let ring_data_hash = ring.map(|_| {
                let mut hash = [0u8; 32];
                hash[31] = u8::try_from(index + 1).expect("merge input count fits u8");
                hash
            });
            let utxo = Utxo {
                owner,
                asset: Mint::SOL,
                amount: 100,
                blinding: random_blinding(),
                ring_program_id: ring,
                data: Data::default(),
            };
            let utxo_hash = utxo
                .hash(
                    &nullifier_pk,
                    &[0u8; 32],
                    &ring_data_hash.unwrap_or_default(),
                    TREE_ID,
                )
                .expect("utxo hash");
            let leaf_index = indexer.add_utxo(utxo_hash);
            wallet_utxo(
                utxo,
                &sender.nullifier_key,
                TREE_ID,
                leaf_index,
                None,
                ring_data_hash,
            )
        })
        .collect();
    let merge = match ring {
        Some(ring) => MergeTransaction::new_with_ring(inputs, ring, Some(output_ring_data_hash())),
        None => MergeTransaction::new(inputs),
    }
    .expect("build merge");
    let prepared = merge.encrypt(&sender).expect("encrypt merge");
    let circuit_slots = prepared.input_utxos.len();
    let compact_slots = prepared
        .input_utxos
        .iter()
        .filter(|input| input.is_compact())
        .count();
    let commitments = prepared.input_utxo_hashes().expect("input commitments");
    let proofs = indexer
        .get_input_merkle_proofs(&commitments, None)
        .expect("merkle proofs");
    let dummy_nullifier_proofs = prepared
        .dummy_nullifiers()
        .into_iter()
        .map(|nullifier| indexer.dummy_nullifier_proof(nullifier))
        .collect();
    let result = MergeProver {
        transaction: prepared,
        nullifier_key: sender.nullifier_key.clone(),
        proofs,
        dummy_nullifier_proofs,
        cache: None,
    }
    .build()
    .expect("build merge witness");
    let tree = zolana_interface::pda::tree(TREE_ID);
    let payer = Pubkey::new_unique();
    let (instruction, sent_nullifiers) = match ring {
        Some(ring) => {
            let data = result
                .ring_instruction_data(zeroed_proof(None))
                .expect("merge-ring instruction data");
            let sent_nullifiers = data.merge.nullifiers.len();
            let instruction = MergeRing {
                input_tree: tree,
                output_tree: tree,
                ring_program_id: ring,
                payer,
                output_ring_data_hash: data.output_ring_data_hash,
                data: data.merge,
                cache: None,
            }
            .instruction();
            (instruction, sent_nullifiers)
        }
        None => {
            let data = result
                .instruction_data(zeroed_proof(Some(CompressedCommitments {
                    commitment: [0; 32],
                    commitment_pok: [0; 32],
                })))
                .expect("merge instruction data");
            let sent_nullifiers = data.body.nullifiers.len();
            let instruction = MergeTransact {
                input_tree: tree,
                output_tree: tree,
                payer,
                user_record: Pubkey::new_unique(),
                data,
                cache: None,
            }
            .instruction();
            (instruction, sent_nullifiers)
        }
    };
    BuiltMerge {
        instruction,
        circuit_slots,
        compact_slots,
        sent_nullifiers,
    }
}

fn assert_compact(merge: &BuiltMerge, real_inputs: usize) {
    let width = merge_circuit_width(real_inputs).expect("supported merge width");
    assert_eq!(
        (
            merge.circuit_slots,
            merge.compact_slots,
            merge.sent_nullifiers
        ),
        (width, width - real_inputs, real_inputs,),
        "{real_inputs} real inputs"
    );
}

#[test]
fn wide_ring_merges_pad_with_compact_slots_and_fit_a_v1_transaction() {
    for real_inputs in MERGE_DEFAULT_INPUT_COUNT + 1..MAX_MERGE_INPUTS {
        let merge = build_merge(real_inputs, Some(ring_program()));
        assert_compact(&merge, real_inputs);
        let size = merge.size();
        assert!(
            size.fits() && size.bytes <= MAX_TRANSACTION_SIZE,
            "ring merge of {real_inputs} real inputs is {size:?}"
        );
    }
}

#[test]
fn a_ring_merge_of_every_slot_misses_the_byte_ceiling() {
    let merge = build_merge(MAX_MERGE_INPUTS, Some(ring_program()));
    assert_compact(&merge, MAX_MERGE_INPUTS);
    assert!(merge.size().bytes > MAX_TRANSACTION_SIZE);
}

#[test]
fn a_plain_merge_of_every_slot_misses_the_byte_ceiling() {
    let merge = build_merge(MAX_MERGE_INPUTS, None);
    assert_compact(&merge, MAX_MERGE_INPUTS);
    assert!(merge.size().bytes > MAX_TRANSACTION_SIZE);
}

#[test]
fn a_plain_merge_two_slots_short_of_the_widest_shape_is_the_widest_that_fits() {
    let widest = build_merge(MAX_MERGE_INPUTS - 2, None);
    assert_compact(&widest, MAX_MERGE_INPUTS - 2);
    let size = widest.size();
    assert!(
        size.fits(),
        "plain merge of {} real inputs is {size:?}",
        MAX_MERGE_INPUTS - 2
    );
    let one_more = build_merge(MAX_MERGE_INPUTS - 1, None);
    assert!(one_more.size().bytes > MAX_TRANSACTION_SIZE);
}
