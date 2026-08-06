//! Drives the permissionless registry-init step machine end to end through
//! the shimmed prepared-operand syscalls and pins the resulting account
//! bytes. Needs `just build-programs-vk-registry` first.

use litesvm::LiteSVM;
use solana_instruction::Instruction;
use solana_instruction_error::InstructionError;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;
use vk_registry_test::with_prepared_syscalls;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{builders::InitVkRegistry, tag},
    verifying_keys::{
        catalog::VK_CATALOG,
        registry::VK_REGISTRY_SPECS,
        registry_spec::{
            vk_registry_account_len, vk_registry_blob_offset, vk_registry_gt_offset,
            vk_registry_source_offset, VK_REGISTRY_BLOB_BYTES, VK_REGISTRY_GT_BYTES,
        },
    },
    SHIELDED_POOL_PROGRAM_ID,
};

fn registry_program_path() -> std::path::PathBuf {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    workspace.join("target/deploy-vk-registry/shielded_pool_program.so")
}

fn boot() -> (LiteSVM, Keypair) {
    let path = registry_program_path();
    assert!(
        path.exists(),
        "missing {}; run `just build-programs-vk-registry` first",
        path.display()
    );
    let mut svm = with_prepared_syscalls(LiteSVM::new());
    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    svm.add_program(program_id, &std::fs::read(&path).unwrap())
        .unwrap();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 20_000_000_000).unwrap();
    (svm, payer)
}

fn run_init(svm: &mut LiteSVM, payer: &Keypair, vk_index: u8) {
    let builder = InitVkRegistry {
        payer: payer.pubkey(),
        vk_index,
    };
    for step in 0..builder.transaction_count() {
        let message = Message::new(&[builder.instruction()], Some(&payer.pubkey()));
        let tx = Transaction::new(&[payer], message, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        assert!(result.is_ok(), "init step {step} failed: {result:?}");
        svm.expire_blockhash();
    }
}

fn catalog_index(name: &str) -> u8 {
    VK_CATALOG
        .iter()
        .position(|(entry, _)| *entry == name)
        .unwrap() as u8
}

fn assert_finalized_registry(svm: &LiteSVM, vk_index: u8) {
    let spec = &VK_REGISTRY_SPECS[vk_index as usize];
    let (_, vk) = &VK_CATALOG[vk_index as usize];
    let account = svm
        .get_account(&Pubkey::new_from_array(spec.address))
        .expect("registry account exists");
    assert_eq!(account.owner.to_bytes(), SHIELDED_POOL_PROGRAM_ID);
    let g2_count = spec.g2_count as usize;
    assert_eq!(account.data.len(), vk_registry_account_len(g2_count));

    // The header is discriminator 2, layout 1, backend 5, count, finalized, bump.
    assert_eq!(&account.data[..6], &[2, 1, 5, spec.g2_count, 1, spec.bump],);

    // Every entry stores its canonical source followed by a framed blob.
    let mut sources = vec![vk.vk_beta_g2, vk.vk_gamma_g2, vk.vk_delta_g2];
    if let Some(commitment) = vk.vk_commitment {
        sources.push(commitment.g2);
        sources.push(commitment.g_sigma_neg_g2);
    }
    assert_eq!(sources.len(), g2_count);
    for (index, source) in sources.iter().enumerate() {
        let source_offset = vk_registry_source_offset(index);
        assert_eq!(&account.data[source_offset..source_offset + 128], source);
        let blob_offset = vk_registry_blob_offset(index);
        assert_eq!(
            &account.data[blob_offset..blob_offset + 8],
            b"BPG2\x01\x01\x05\x00",
        );
        assert!(
            account.data[blob_offset + 8..blob_offset + VK_REGISTRY_BLOB_BYTES]
                .iter()
                .any(|byte| *byte != 0),
        );
    }

    let gt_offset = vk_registry_gt_offset(g2_count);
    assert!(
        account.data[gt_offset..gt_offset + VK_REGISTRY_GT_BYTES]
            .iter()
            .any(|byte| *byte != 0),
        "GT target must be written"
    );
}

/// The custom error code a rejected transaction carries.
#[track_caller]
fn assert_rejected_with(svm: &mut LiteSVM, instruction: Instruction, payer: &Keypair, code: u32) {
    let message = Message::new(&[instruction], Some(&payer.pubkey()));
    let tx = Transaction::new(&[payer], message, svm.latest_blockhash());
    let error = svm.send_transaction(tx).expect_err("must be rejected");
    assert_eq!(
        error.err,
        TransactionError::InstructionError(0, InstructionError::Custom(code))
    );
}

#[test]
fn init_flow_finalizes_a_3_g2_registry() {
    let (mut svm, payer) = boot();
    let vk_index = catalog_index("transfer_confidential_1_1");
    run_init(&mut svm, &payer, vk_index);
    assert_finalized_registry(&svm, vk_index);

    // Re-running any step against a finalized registry fails closed. Contents
    // are trustworthy because no write path survives `finalized`.
    let builder = InitVkRegistry {
        payer: payer.pubkey(),
        vk_index,
    };
    assert_rejected_with(
        &mut svm,
        builder.instruction(),
        &payer,
        ShieldedPoolError::VkRegistryAlreadyInitialized as u32,
    );
}

/// The index reaches the program from instruction data, so it is bounds
/// checked against the catalogue rather than subscripted.
#[test]
fn init_rejects_a_vk_index_past_the_catalog() {
    let (mut svm, payer) = boot();
    let mut instruction = InitVkRegistry {
        payer: payer.pubkey(),
        vk_index: 0,
    }
    .instruction();
    instruction.data = vec![tag::INIT_VK_REGISTRY, u8::MAX];
    assert_rejected_with(
        &mut svm,
        instruction,
        &payer,
        ShieldedPoolError::InvalidVkRegistryIndex as u32,
    );
}

/// A registry that exists but has not been finalized carries no prepared
/// blobs, so the verified path must refuse it rather than read zeros.
#[test]
fn a_registry_short_of_finalize_is_not_ready() {
    let (mut svm, payer) = boot();
    let vk_index = catalog_index("transfer_confidential_1_1");
    let builder = InitVkRegistry {
        payer: payer.pubkey(),
        vk_index,
    };
    // Create and grow, but stop before the finalize step.
    for _ in 0..builder.transaction_count() - 1 {
        let message = Message::new(&[builder.instruction()], Some(&payer.pubkey()));
        let tx = Transaction::new(&[&payer], message, svm.latest_blockhash());
        svm.send_transaction(tx).expect("init step");
        svm.expire_blockhash();
    }

    let spec = &VK_REGISTRY_SPECS[vk_index as usize];
    let account = svm
        .get_account(&Pubkey::new_from_array(spec.address))
        .expect("registry account exists");
    assert_eq!(
        account.data.len(),
        vk_registry_account_len(spec.g2_count as usize)
    );
    assert_eq!(account.data[4], 0, "the finalized flag must still be clear");
}

#[test]
fn init_flow_finalizes_a_5_g2_bsb22_registry() {
    let (mut svm, payer) = boot();
    let vk_index = catalog_index("transfer_p256_ring_1_1");
    run_init(&mut svm, &payer, vk_index);
    assert_finalized_registry(&svm, vk_index);
}

#[test]
fn init_rejects_a_mismatched_registry_account() {
    let (mut svm, payer) = boot();
    let vk_index = catalog_index("transfer_confidential_1_1");
    let other_index = catalog_index("transfer_confidential_1_2");
    // The account for one VK cannot be created through another VK's index.
    // The address is a commitment to the keyset.
    let mut instruction = InitVkRegistry {
        payer: payer.pubkey(),
        vk_index,
    }
    .instruction();
    instruction.accounts[1].pubkey =
        Pubkey::new_from_array(VK_REGISTRY_SPECS[other_index as usize].address);
    let message = Message::new(&[instruction], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], message, svm.latest_blockhash());
    assert!(svm.send_transaction(tx).is_err());
}
