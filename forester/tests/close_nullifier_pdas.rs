use anyhow::anyhow;
use forester::close_nullifier_pdas::{
    collect_queued_pages, plan_batches, retain_open_accounts, CloseNullifierPdasBatch,
    ForesterSmartAccount, LEGACY_TRANSACTION_SIZE_LIMIT,
};
use solana_account::Account;
use solana_pubkey::Pubkey;
use zolana_api::{Hash, NullifierQueueElement, PAGE_LIMIT};
use zolana_interface::{instruction::CloseNullifierPdas, pda, NULLIFIER_PDA_SIZE};
use zolana_smart_account_client::SMART_ACCOUNT_PROGRAM_ID;

fn forester() -> ForesterSmartAccount {
    ForesterSmartAccount {
        settings: Pubkey::new_unique(),
        account_index: 0,
        member: Pubkey::new_unique(),
    }
}

fn nullifier(seq: u64) -> [u8; 32] {
    let mut value = [0u8; 32];
    value[24..].copy_from_slice(&seq.to_be_bytes());
    value
}

fn element(seq: u64) -> NullifierQueueElement {
    NullifierQueueElement {
        seq,
        value: Hash(nullifier(seq)),
    }
}

#[test]
fn plan_fills_each_transaction_up_to_the_legacy_size_limit() {
    let tree = Pubkey::new_unique();
    let forester = forester();
    let nullifiers: Vec<[u8; 32]> = (0..100).map(nullifier).collect();

    let batches = plan_batches(tree, forester, &nullifiers).unwrap();
    let nullifier_pdas_per_transaction = batches.first().unwrap().nullifiers.len();

    for batch in &batches {
        assert!(!batch.nullifiers.is_empty());
        assert!(batch.serialized_size().unwrap() <= LEGACY_TRANSACTION_SIZE_LIMIT);
    }
    for pair in batches.windows(2) {
        let [full, next] = pair else {
            unreachable!("windows(2) yields pairs")
        };
        let mut overfilled = full.nullifiers.clone();
        overfilled.extend(next.nullifiers.first().copied());
        let overfilled = CloseNullifierPdasBatch {
            tree,
            forester,
            nullifiers: overfilled,
        };
        assert!(overfilled.serialized_size().unwrap() > LEGACY_TRANSACTION_SIZE_LIMIT);
        assert_eq!(full.nullifiers.len(), nullifier_pdas_per_transaction);
    }

    let replanned: Vec<[u8; 32]> = batches
        .iter()
        .flat_map(|batch| batch.nullifiers.iter().copied())
        .collect();
    assert_eq!(replanned, nullifiers);
    assert_eq!(
        batches.len(),
        100_usize.div_ceil(nullifier_pdas_per_transaction)
    );
}

#[test]
fn plan_of_nothing_is_empty() {
    let batches = plan_batches(Pubkey::new_unique(), forester(), &[]).unwrap();
    assert!(batches.is_empty());
}

#[test]
fn batch_instruction_matches_the_interface_builder() {
    let tree = Pubkey::new_unique();
    let forester = forester();
    let nullifiers: Vec<[u8; 32]> = (0..40).map(nullifier).collect();

    let batches = plan_batches(tree, forester, &nullifiers).unwrap();

    assert!(batches.len() > 1);
    for batch in &batches {
        let expected = CloseNullifierPdas {
            authority: forester.vault(),
            tree,
            reimbursement_recipient: forester.member,
            nullifiers: batch.nullifiers.clone(),
        }
        .instruction();
        assert_eq!(batch.inner_instruction(), expected);
        assert_eq!(
            expected
                .accounts
                .first()
                .map(|meta| (meta.pubkey, meta.is_signer)),
            Some((forester.vault(), true))
        );
        assert_eq!(
            expected
                .accounts
                .get(3)
                .map(|meta| (meta.pubkey, meta.is_writable)),
            Some((forester.member, true))
        );

        let execute = batch.instruction();
        assert_eq!(execute.program_id, SMART_ACCOUNT_PROGRAM_ID);
        assert_eq!(
            execute.accounts.first().map(|meta| meta.pubkey),
            Some(forester.settings)
        );
        assert!(execute
            .accounts
            .iter()
            .any(|meta| meta.pubkey == forester.member && meta.is_signer));
        assert!(!execute
            .accounts
            .iter()
            .any(|meta| meta.pubkey == forester.vault() && meta.is_signer));

        let message = batch.message();
        assert_eq!(message.account_keys.first(), Some(&forester.member));
        assert_eq!(message.header.num_required_signatures, 1);
        assert_eq!(message.instructions.len(), 1);
    }
}

#[test]
fn retain_open_accounts_requires_program_owner_and_nullifier_pda_size() {
    let nullifiers: Vec<[u8; 32]> = (0..5).map(nullifier).collect();
    let accounts = vec![
        Some(Account {
            owner: pda::shielded_pool_program_id(),
            data: vec![0; NULLIFIER_PDA_SIZE],
            ..Account::default()
        }),
        None,
        Some(Account {
            owner: Pubkey::default(),
            data: vec![0; NULLIFIER_PDA_SIZE],
            ..Account::default()
        }),
        Some(Account {
            owner: pda::shielded_pool_program_id(),
            data: vec![0; NULLIFIER_PDA_SIZE - 1],
            ..Account::default()
        }),
        Some(Account {
            lamports: 890_880,
            owner: Pubkey::default(),
            ..Account::default()
        }),
    ];

    let open = retain_open_accounts(&nullifiers, &accounts).unwrap();
    assert_eq!(open, vec![nullifier(0)]);

    let short = vec![Some(Account::default())];
    assert!(retain_open_accounts(&nullifiers, &short).is_err());
}

#[test]
fn queued_pages_stop_at_the_watermark() {
    let start = 3u64;
    let end = PAGE_LIMIT + 10;
    let mut requests = Vec::new();

    let elements = collect_queued_pages(start, end, |start_seq, limit| {
        requests.push((start_seq, limit));
        Ok((start_seq..start_seq + limit).map(element).collect())
    })
    .unwrap();

    assert_eq!(requests, vec![(3, PAGE_LIMIT), (PAGE_LIMIT + 3, 7)]);
    assert_eq!(elements.first().map(|element| element.seq), Some(3));
    assert_eq!(elements.last().map(|element| element.seq), Some(end - 1));
    assert_eq!(elements.len(), usize::try_from(end - start).unwrap());
}

#[test]
fn queued_pages_return_the_indexed_prefix_when_photon_lags() {
    let elements = collect_queued_pages(0, 50, |start_seq, _| {
        Ok((start_seq..start_seq + 20).map(element).collect())
    })
    .unwrap();
    assert_eq!(elements.len(), 20);

    assert!(
        collect_queued_pages(0, 0, |_, _| Err(anyhow!("must not be called")))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn queued_pages_reject_a_sequence_gap() {
    let err = collect_queued_pages(0, 10, |_, _| Ok(vec![element(0), element(2)])).unwrap_err();
    assert!(err.to_string().contains("sequence gap"));
}
