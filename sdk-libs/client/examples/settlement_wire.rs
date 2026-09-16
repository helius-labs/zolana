use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::{Keypair, Signer};
use solana_pubkey::Pubkey;
use wincode::{containers, len::FixIntLen, SchemaWrite};
use zolana_client::{compile_message, sign_transaction, transaction_size, ComputeBudgetConfig};
use zolana_interface::instruction::{TransactOutput, TreeContext};
use zolana_keypair::{ShieldedKeypair, ViewingKey};
use zolana_transaction::{
    instructions::transact::slots::encrypt_transaction_data, AssetRegistry, SppProofOutputUtxo,
    SOL_MINT,
};

// A proposed wire format, not an instruction accepted by the deployed program.
#[derive(SchemaWrite)]
struct Spend<const WIDTH: usize, const PROOF_BYTES: usize> {
    tag: u8,
    expiry_unix_ts: u64,
    max_forester_fee: u64,
    tree_context: TreeContext,
    tx_viewing_pk: [u8; 33],
    salt: [u8; 16],
    private_tx_hash: [u8; 32],
    #[wincode(with = "containers::Vec<[u8; PROOF_BYTES], FixIntLen<u8>>")]
    proofs: Vec<[u8; PROOF_BYTES]>,
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    value_commitments: Vec<[u8; 32]>,
    #[wincode(with = "containers::Vec<[u8; WIDTH], FixIntLen<u16>>")]
    nullifiers: Vec<[u8; WIDTH]>,
    #[wincode(with = "containers::Vec<TransactOutput, FixIntLen<u8>>")]
    outputs: Vec<TransactOutput>,
}

fn measure<const WIDTH: usize, const PROOF_BYTES: usize>(
    inputs: usize,
    proofs: usize,
    memo_bytes: usize,
) {
    let owner = Keypair::new();
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    let viewing_key = ViewingKey::new();
    let outputs = [144, 0]
        .into_iter()
        .enumerate()
        .map(|(index, amount)| SppProofOutputUtxo {
            asset: SOL_MINT,
            amount,
            blinding: [index as u8 + 1; 32],
            owner_address: Some(recipient.shielded_address().unwrap()),
            data: if memo_bytes == 0 {
                Default::default()
            } else {
                zolana_transaction::Data::new(vec![zolana_transaction::DataRecord::Memo(vec![
                    0;
                    memo_bytes
                ])])
            },
            ..Default::default()
        })
        .collect::<Vec<_>>();
    let encrypted =
        encrypt_transaction_data(&outputs, &AssetRegistry::default(), &viewing_key, 0).unwrap();
    let ciphertext_bytes: usize = encrypted
        .outputs
        .iter()
        .map(|output| output.data.as_ref().unwrap().len())
        .sum();
    let spend = Spend {
        tag: u8::MAX,
        expiry_unix_ts: u64::MAX,
        max_forester_fee: 0,
        tree_context: TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        },
        tx_viewing_pk: *viewing_key.pubkey().as_bytes(),
        salt: encrypted.salt,
        private_tx_hash: [0; 32],
        proofs: vec![[0; PROOF_BYTES]; proofs],
        value_commitments: vec![[0; 32]; if proofs == 1 { 0 } else { inputs.div_ceil(36) }],
        nullifiers: vec![[0; WIDTH]; inputs],
        outputs: encrypted.outputs,
    };
    let program = Pubkey::new_unique();
    let instruction = Instruction {
        program_id: program,
        accounts: vec![
            AccountMeta::new(owner.pubkey(), true),
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(program, false),
        ],
        data: wincode::serialize(&spend).unwrap(),
    };
    let payload_bytes = instruction.data.len();
    let budget = ComputeBudgetConfig::new(1_400_000)
        .with_compute_unit_price(1_000)
        .with_heap_size(256 * 1024);
    let instructions = [instruction];
    let measured = transaction_size(&owner.pubkey(), &instructions, budget).unwrap();
    let transaction = sign_transaction(
        compile_message(&owner.pubkey(), &instructions, Hash::default(), budget).unwrap(),
        &[&owner],
    )
    .unwrap();
    assert_eq!(
        measured.bytes,
        wincode::serialize(&transaction).unwrap().len()
    );
    println!(
        "inputs={inputs} nullifier_bits={} proofs={proofs} proof_bytes={PROOF_BYTES} outputs=2 memo_bytes_per_output={memo_bytes} ciphertext_bytes={ciphertext_bytes} payload_bytes={payload_bytes} wire_bytes={} accounts={} fits={}",
        WIDTH * 8, measured.bytes, measured.addresses, measured.fits()
    );
}

fn main() {
    use solana_bn254::compression::prelude::{
        alt_bn128_g2_compress_be, alt_bn128_g2_decompress_be,
    };
    let point = zolana_interface::verifying_keys::merge_36_1::VERIFYINGKEY.vk_beta_g2;
    let compressed = alt_bn128_g2_compress_be(&point).unwrap();
    assert_eq!(alt_bn128_g2_decompress_be(&compressed).unwrap(), point);
    println!("g2_compression_roundtrip=true raw_bytes=128 compressed_bytes=64");
    for inputs in [36, 144, 512] {
        for proofs in [1, 5, 9] {
            measure::<32, 192>(inputs, proofs, 0);
            measure::<16, 192>(inputs, proofs, 0);
        }
    }
    measure::<20, 192>(144, 1, 0);
    measure::<22, 192>(144, 1, 0);
    measure::<23, 192>(144, 1, 0);
    measure::<24, 192>(144, 1, 0);
    measure::<16, 192>(144, 1, 256);
    measure::<16, 128>(144, 5, 0);
}
