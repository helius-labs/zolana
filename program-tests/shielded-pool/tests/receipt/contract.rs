//! Nullifier receipt contract tests without real proofs: lifecycle, upload
//! ordering, sponsor and tree binding, and every receipt check a
//! receipt-backed merge performs before it reaches proof verification.

use shielded_pool_tests::support::{fixtures::Pool, merge::write_user_record};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_signer::Signer;
use zolana_account_checks::AccountError;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::merge_transact::{MergeProof, MergeTransactIxData},
        CloseReceipt, CreateReceipt, CreateReceiptData, MergeTransact, UploadReceipt,
        UploadReceiptData, VerifyReceipt, VerifyReceiptData,
    },
    pda,
    state::{
        discriminator::RECEIPT,
        receipt::{receipt_account_size, receipt_nullifiers, ReceiptHeader},
    },
};
use zolana_program_test::{Rejection, ZolanaProgramTest};
use zolana_test_utils::transact::fe;

const CAPACITY: u16 = 8;

fn create(payer: Address, tree: Address, nonce: u64, capacity: u16) -> (Address, Instruction) {
    let builder = CreateReceipt {
        payer,
        tree,
        data: CreateReceiptData { nonce, capacity },
    };
    (builder.receipt(), builder.instruction())
}

fn upload(
    sponsor: Address,
    receipt: Address,
    offset: u16,
    nullifiers: Vec<[u8; 32]>,
) -> Instruction {
    UploadReceipt {
        sponsor,
        receipt,
        data: UploadReceiptData { offset, nullifiers },
    }
    .instruction()
}

fn verify(receipt: Address, tree: Address, count: u16) -> Instruction {
    VerifyReceipt {
        receipt,
        tree,
        data: VerifyReceiptData {
            nullifier_tree_root_index: 0,
            count,
            proof: MergeProof::zeroed(),
            commitment: [0; 32],
            commitment_pok: [0; 32],
        },
    }
    .instruction()
}

fn header(rpc: &ZolanaProgramTest, receipt: &Address) -> ReceiptHeader {
    let data = rpc.account_data(receipt).expect("receipt data");
    *bytemuck::from_bytes(&data[..ReceiptHeader::SIZE])
}

fn slots(rpc: &ZolanaProgramTest, receipt: &Address) -> Vec<[u8; 32]> {
    receipt_nullifiers(&rpc.account_data(receipt).expect("receipt data")).to_vec()
}

/// Mark a receipt verified at `root` without a proof, to test the merge-side
/// checks in isolation.
fn force_verified(rpc: &mut ZolanaProgramTest, receipt: Address, count: u16, root: [u8; 32]) {
    let mut account = rpc.svm.get_account(&receipt).expect("receipt account");
    let head: &mut ReceiptHeader =
        bytemuck::from_bytes_mut(&mut account.data[..ReceiptHeader::SIZE]);
    head.verified = 1;
    head.count = count.to_le_bytes();
    head.nullifier_root = root;
    rpc.svm
        .set_account(receipt, account)
        .expect("store receipt");
}

fn nullifier_root(rpc: &ZolanaProgramTest, tree: &Address) -> [u8; 32] {
    let mut data = rpc.account_data(tree).expect("tree data");
    let account =
        zolana_tree::TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    account.get_nullifier_tree_root(0).expect("nullifier root")
}

fn send(rpc: &mut ZolanaProgramTest, ix: Instruction, what: &str) {
    rpc.svm.expire_blockhash();
    rpc.create_and_send_default_payer_transaction(&[ix], &[])
        .expect(what);
}

fn reject(rpc: &mut ZolanaProgramTest, ix: Instruction, error: ShieldedPoolError) {
    reject_code(rpc, ix, error as u32);
}

fn reject_code(rpc: &mut ZolanaProgramTest, ix: Instruction, code: u32) {
    rpc.svm.expire_blockhash();
    let actual = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("must reject");
    Rejection::custom(code).assert_litesvm(actual);
}

#[test]
fn lifecycle_create_upload_close() {
    let Pool {
        mut rpc,
        tree,
        authority,
        ..
    } = Pool::initialized();
    let payer = rpc.payer.pubkey();
    let (receipt, create_ix) = create(payer, tree, 1, CAPACITY);
    send(&mut rpc, create_ix.clone(), "create a receipt");
    let head = header(&rpc, &receipt);
    assert_eq!(head.discriminator, RECEIPT);
    assert_eq!(
        (head.capacity(), head.count(), head.filled(), head.verified),
        (CAPACITY, 0, 0, 0)
    );
    assert_eq!(head.tree, tree.to_bytes());
    assert_eq!(head.rent_sponsor, payer.to_bytes());
    assert_eq!(
        rpc.account_data(&receipt).expect("receipt").len(),
        receipt_account_size(CAPACITY)
    );

    send(&mut rpc, create_ix, "an identical create is a no-op");
    // Same PDA (sponsor, nonce), different tree.
    let other_tree = rpc.create_tree(&authority).expect("second tree");
    let (_, other) = create(payer, other_tree, 1, CAPACITY);
    reject(&mut rpc, other, ShieldedPoolError::ReceiptConfigMismatch);
    let (_, unsupported) = create(payer, tree, 2, 7);
    reject(
        &mut rpc,
        unsupported,
        ShieldedPoolError::UnsupportedReceiptCapacity,
    );

    send(
        &mut rpc,
        upload(payer, receipt, 0, (1..=3).map(fe).collect()),
        "upload the first slice",
    );
    reject(
        &mut rpc,
        upload(payer, receipt, 0, vec![fe(4)]),
        ShieldedPoolError::ReceiptUploadOutOfOrder,
    );
    reject(
        &mut rpc,
        upload(payer, receipt, 3, (4..=9).map(fe).collect()),
        ShieldedPoolError::ReceiptUploadOutOfOrder,
    );
    reject(
        &mut rpc,
        upload(payer, receipt, 3, vec![[0; 32]]),
        ShieldedPoolError::NonCanonicalReceiptNullifier,
    );
    reject(
        &mut rpc,
        upload(payer, receipt, 3, vec![[0xff; 32]]),
        ShieldedPoolError::NonCanonicalReceiptNullifier,
    );
    send(
        &mut rpc,
        upload(payer, receipt, 3, (4..=8).map(fe).collect()),
        "fill the receipt",
    );
    assert_eq!(header(&rpc, &receipt).filled(), 8);
    assert_eq!(slots(&rpc, &receipt), (1..=8).map(fe).collect::<Vec<_>>());

    // Verification without a valid proof stops at the pairing check, after
    // every structural check passed; the receipt stays unverified.
    reject(
        &mut rpc,
        verify(receipt, tree, 7),
        ShieldedPoolError::ReceiptIncomplete,
    );
    // Zero points decompress (infinity); the pairing check rejects them.
    reject(
        &mut rpc,
        verify(receipt, tree, 8),
        ShieldedPoolError::TransactProofVerificationFailed,
    );
    assert_eq!(header(&rpc, &receipt).verified, 0);

    let before = rpc.svm.get_account(&payer).expect("payer").lamports;
    let rent = rpc.svm.get_account(&receipt).expect("receipt").lamports;
    send(
        &mut rpc,
        CloseReceipt {
            sponsor: payer,
            receipt,
        }
        .instruction(),
        "close the receipt",
    );
    assert!(rpc
        .svm
        .get_account(&receipt)
        .is_none_or(|account| account.lamports == 0));
    assert_eq!(
        rpc.svm.get_account(&payer).expect("payer").lamports,
        before + rent - 5_000
    );
}

/// A 512-slot receipt exceeds the per-transaction data growth cap: the first
/// create allocates 10 KiB, the second grows it to full size and tops up rent.
#[test]
fn wide_receipt_grows_across_creates() {
    let Pool { mut rpc, tree, .. } = Pool::initialized();
    let payer = rpc.payer.pubkey();
    let (receipt, create_ix) = create(payer, tree, 1, 512);
    send(&mut rpc, create_ix.clone(), "first create");
    assert_eq!(rpc.account_data(&receipt).expect("receipt").len(), 10_240);
    assert_eq!(header(&rpc, &receipt).capacity(), 512);
    reject(
        &mut rpc,
        upload(payer, receipt, 0, vec![fe(1)]),
        ShieldedPoolError::InvalidReceipt,
    );

    send(
        &mut rpc,
        create_ix.clone(),
        "second create grows the account",
    );
    let account = rpc.svm.get_account(&receipt).expect("receipt");
    assert_eq!(account.data.len(), receipt_account_size(512));
    assert!(
        account.lamports
            >= rpc
                .svm
                .minimum_balance_for_rent_exemption(account.data.len()),
        "grown receipt is rent exempt"
    );
    assert!(receipt_nullifiers(&account.data)
        .iter()
        .all(|slot| *slot == [0; 32]));
    send(&mut rpc, create_ix, "a full receipt is a no-op");
    send(&mut rpc, upload(payer, receipt, 0, vec![fe(1)]), "upload");
    assert_eq!(header(&rpc, &receipt).filled(), 1);
}

#[test]
fn only_the_sponsor_uploads_and_closes() {
    let Pool { mut rpc, tree, .. } = Pool::initialized();
    let payer = rpc.payer.pubkey();
    let (receipt, create_ix) = create(payer, tree, 3, CAPACITY);
    send(&mut rpc, create_ix, "create");
    let stranger = solana_keypair::Keypair::new();
    rpc.airdrop(&stranger.pubkey(), 1_000_000_000)
        .expect("fund");
    for (ix, error) in [
        (
            upload(stranger.pubkey(), receipt, 0, vec![fe(1)]),
            ShieldedPoolError::InvalidReceiptSponsor,
        ),
        (
            CloseReceipt {
                sponsor: stranger.pubkey(),
                receipt,
            }
            .instruction(),
            ShieldedPoolError::InvalidReceiptSponsor,
        ),
    ] {
        rpc.svm.expire_blockhash();
        let actual = rpc
            .create_and_send_default_payer_transaction(&[ix], &[&stranger])
            .expect_err("must reject");
        Rejection::custom(error as u32).assert_litesvm(actual);
    }
}

#[test]
fn a_verified_receipt_is_frozen() {
    let Pool { mut rpc, tree, .. } = Pool::initialized();
    let payer = rpc.payer.pubkey();
    let (receipt, create_ix) = create(payer, tree, 4, CAPACITY);
    send(&mut rpc, create_ix, "create");
    send(
        &mut rpc,
        upload(payer, receipt, 0, (1..=8).map(fe).collect()),
        "fill",
    );
    force_verified(&mut rpc, receipt, 8, [9; 32]);
    reject(
        &mut rpc,
        upload(payer, receipt, 8, vec![fe(1)]),
        ShieldedPoolError::ReceiptAlreadyVerified,
    );
    reject(
        &mut rpc,
        verify(receipt, tree, 8),
        ShieldedPoolError::ReceiptAlreadyVerified,
    );
}

/// Every receipt check the merge makes before proof verification, each with
/// unchanged tree state.
#[test]
fn receipt_backed_merge_checks_the_receipt_before_the_proof() {
    for case in [
        "unverified",
        "slice",
        "offset",
        "root",
        "tree",
        "p256",
        "missing account",
        "zero proof",
    ] {
        let Pool {
            mut rpc,
            tree,
            authority,
            ..
        } = Pool::initialized();
        let owner = rpc.payer.pubkey();
        let p256 = case == "p256";
        let record = write_user_record(&mut rpc, owner, p256.then_some([2; 33]), true);
        let nullifiers: Vec<[u8; 32]> = (1..=8).map(fe).collect();
        let receipt_tree = if case == "tree" {
            rpc.create_tree(&authority).expect("second tree")
        } else {
            tree
        };
        let (receipt, create_ix) = create(owner, receipt_tree, 5, CAPACITY);
        send(&mut rpc, create_ix, "create");
        let uploaded = if case == "slice" {
            let mut altered = nullifiers.clone();
            altered[3] = fe(99);
            altered
        } else {
            nullifiers.clone()
        };
        send(&mut rpc, upload(owner, receipt, 0, uploaded), "fill");
        let root = if case == "root" {
            [7; 32]
        } else {
            nullifier_root(&rpc, &tree)
        };
        if case != "unverified" {
            force_verified(&mut rpc, receipt, 8, root);
        }
        let code = match case {
            "unverified" => ShieldedPoolError::ReceiptNotVerified as u32,
            "slice" | "offset" => ShieldedPoolError::ReceiptSliceMismatch as u32,
            "root" => ShieldedPoolError::ReceiptRootMismatch as u32,
            "tree" => ShieldedPoolError::ReceiptTreeMismatch as u32,
            "p256" => ShieldedPoolError::ReceiptUnsupportedOwner as u32,
            "missing account" => u32::from(AccountError::NotEnoughAccountKeys),
            _ => ShieldedPoolError::TransactProofVerificationFailed as u32,
        };
        let data = MergeTransactIxData {
            cache_slot: None,
            receipt_offset: Some(if case == "offset" { 1 } else { 0 }),
            expiry_unix_ts: u64::MAX,
            proof: MergeProof::zeroed(),
            output_utxo_hash: fe(9),
            eddsa_owner: !p256,
            private_tx_hash: [0; 32],
            nullifiers,
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        };
        let ix = MergeTransact {
            input_tree: tree,
            output_tree: tree,
            payer: owner,
            user_record: record,
            data,
            cache: None,
            receipt: (case != "missing account").then_some(receipt),
        }
        .instruction();
        let before = rpc.account_data(&tree).expect("tree data");
        reject_code(&mut rpc, ix, code);
        assert_eq!(
            rpc.account_data(&tree).expect("tree data"),
            before,
            "{case}"
        );
    }
}

#[test]
fn receipt_pda_derives_from_sponsor_and_nonce() {
    let sponsor = Address::new_unique();
    let (a, _) = pda::receipt(&sponsor, 1);
    let (b, _) = pda::receipt(&sponsor, 2);
    let (c, _) = pda::receipt(&Address::new_unique(), 1);
    assert_ne!(a, b);
    assert_ne!(a, c);
}
