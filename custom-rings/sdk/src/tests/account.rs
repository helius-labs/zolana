use bytemuck::Zeroable;
use custom_ring_interface::{
    CoSignScope, CoSigner, Delegate, DepositAudit, KeyRegistryRoot, ReadAccessRecord,
    RingProgramConfig, SourceSlot, SpendWindow, CO_SIGNER, DELEGATE, DEPOSIT_AUDIT,
    KEY_REGISTRY_ROOT, KEY_REGISTRY_ROOT_HISTORY, READ_ACCESS_RECORD, RING_PROGRAM_CONFIG,
    SPEND_WINDOW,
};
use solana_account::Account;
use solana_address::Address;
use zolana_interface::P_DERIVE_SEC1;
use zolana_keypair::ViewingKey;
use zolana_ring_client::ReaderKey;
use zolana_ring_policy::{
    ListId, ListSet, PolicyHashError, Rule, RuleTable, RuleTableError, Subject, MAX_RULES,
};

use super::support::{account, empty, pinned, ring, Accounts};
use crate::{
    client_rules_match, policy_config_table, CoSignThreshold, CurrentKeyRegistryRoot,
    CustomRingCoSigner, PoolTree, RingError,
};

type Mutation<T> = (&'static str, fn(&mut T));

fn program() -> Address {
    ring().program_id()
}

fn at(address: Address, account: Option<Account>) -> Accounts {
    let rpc = Accounts::default();
    match account {
        Some(account) => rpc.with(address, account),
        None => rpc,
    }
}

fn invalid_at<T: std::fmt::Debug>(result: Result<T, RingError>, address: Address) -> bool {
    matches!(result, Err(RingError::InvalidAccount { address: invalid }) if invalid == address)
}

fn config() -> RingProgramConfig {
    RingProgramConfig {
        discriminator: RING_PROGRAM_CONFIG,
        authority: Address::new_from_array([3; 32]),
        auditor_pubkey: *ViewingKey::new().pubkey().as_bytes(),
        bump: Address::find_program_address(&[RingProgramConfig::SEED], &program()).1,
        has_policy: 1,
        key_escrow: 0,
    }
}

fn cosigner() -> CoSigner {
    CoSigner {
        discriminator: CO_SIGNER,
        signer: Address::new_from_array([45; 32]),
        scope: CoSignScope::WITHDRAWALS.bits(),
        bump: Address::find_program_address(&[CoSigner::SEED], &program()).1,
        ..CoSigner::zeroed()
    }
}

fn delegate() -> Delegate {
    Delegate {
        discriminator: DELEGATE,
        delegate: Address::new_from_array([47; 32]),
        bump: Address::find_program_address(&[Delegate::SEED], &program()).1,
    }
}

fn window(mint: Address) -> SpendWindow {
    SpendWindow {
        discriminator: SPEND_WINDOW,
        mint,
        window_slots: 100u64.to_le_bytes(),
        deposit_cap: 7u64.to_le_bytes(),
        withdrawal_cap: 0u64.to_le_bytes(),
        window_start_slot: 1200u64.to_le_bytes(),
        deposited: 1u64.to_le_bytes(),
        withdrawn: 0u64.to_le_bytes(),
        bump: Address::find_program_address(&[SpendWindow::SEED, mint.as_array()], &program()).1,
    }
}

#[tokio::test]
async fn deposit_audit_defaults_off_and_rejects_malformed_state() {
    let address = ring().deposit_audit_pda();
    let read = |account| async move { ring().deposit_audit(&at(address, account)).await };
    assert!(!read(None).await.unwrap());
    assert!(!read(Some(Account::default())).await.unwrap());
    let bump = Address::find_program_address(&[DepositAudit::SEED], &program()).1;
    let value = DepositAudit {
        discriminator: DEPOSIT_AUDIT,
        required: 1,
        bump,
    };
    assert!(read(Some(account(program(), &value))).await.unwrap());
    let off = DepositAudit {
        required: 0,
        ..value
    };
    assert!(!read(Some(account(program(), &off))).await.unwrap());
    let mut truncated = account(program(), &value);
    truncated.data.pop();
    for invalid in [
        empty(Address::new_from_array([99; 32])),
        account(Address::default(), &value),
        truncated,
        account(
            program(),
            &DepositAudit {
                required: 2,
                ..value
            },
        ),
        account(
            program(),
            &DepositAudit {
                discriminator: 0,
                ..value
            },
        ),
        account(
            program(),
            &DepositAudit {
                bump: bump ^ 1,
                ..value
            },
        ),
    ] {
        assert!(invalid_at(read(Some(invalid)).await, address));
    }
}

#[tokio::test]
async fn config_read_accepts_only_canonical_typed_state() {
    let address = ring().config_pda();
    assert!(ring().config(&at(address, None)).await.unwrap().is_none());

    let value = config();
    let read = ring()
        .config(&at(address, Some(account(program(), &value))))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.authority, value.authority);
    assert_eq!(read.auditor_pubkey.as_bytes(), &value.auditor_pubkey);
    assert!(read.has_policy);

    let mut wrong_size = account(program(), &value);
    wrong_size.data.pop();
    let changes: [Mutation<RingProgramConfig>; 4] = [
        ("wrong discriminator", |value| value.discriminator = 0),
        ("wrong bump", |value| value.bump ^= 1),
        ("invalid key", |value| value.auditor_pubkey = [0; 33]),
        ("reserved key", |value| value.auditor_pubkey = P_DERIVE_SEC1),
    ];
    let mut invalid = vec![
        (
            "wrong owner",
            account(Address::new_from_array([9; 32]), &value),
        ),
        ("wrong size", wrong_size),
    ];
    for (name, change) in changes {
        let mut changed = value;
        change(&mut changed);
        invalid.push((name, account(program(), &changed)));
    }
    for (name, account) in invalid {
        let result = ring().config(&at(address, Some(account))).await;
        assert!(invalid_at(result.map(|_| ()), address), "{name}");
    }
}

#[tokio::test]
async fn reader_read_rejects_substituted_state() {
    let reader = ReaderKey::p256(ViewingKey::new().pubkey()).unwrap();
    let address = ring().read_access_record_pda(&reader);
    let bytes = reader.to_bytes();
    let seed_hash = ReadAccessRecord::seed_hash(&bytes).unwrap();
    let value = ReadAccessRecord {
        discriminator: READ_ACCESS_RECORD,
        reader: bytes,
        bump: Address::find_program_address(&[ReadAccessRecord::SEED, &seed_hash], &program()).1,
    };
    let valid = at(address, Some(account(program(), &value)));
    assert_eq!(
        ring().access_record(&valid, &reader).await.unwrap(),
        Some(value)
    );
    let mut wrong_reader = value;
    wrong_reader.reader[1] ^= 1;
    let mut wrong_bump = value;
    wrong_bump.bump ^= 1;
    for value in [wrong_reader, wrong_bump] {
        let rpc = at(address, Some(account(program(), &value)));
        assert!(invalid_at(
            ring().access_record(&rpc, &reader).await,
            address
        ));
    }
}

#[tokio::test]
async fn cosigner_read_rejects_noncanonical_fields() {
    let cases: [Mutation<CoSigner>; 8] = [
        ("zero signer", |value| value.signer = Address::default()),
        ("empty scope", |value| value.scope = 0),
        ("unsupported scope", |value| value.scope = 8),
        ("too many thresholds", |value| value.threshold_count = 9),
        ("count past the rows", |value| {
            value.threshold_count = u8::MAX
        }),
        ("duplicate mint", |value| value.threshold_count = 2),
        ("mint in padding", |value| {
            value.thresholds[1].mint = Address::new_from_array([1; 32]);
        }),
        ("amount in padding", |value| {
            value.thresholds[1].amount = 1u64.to_le_bytes();
        }),
    ];
    let address = ring().cosigner_pda();
    for (name, change) in cases {
        let mut value = cosigner();
        value.threshold_count = 1;
        change(&mut value);
        let rpc = at(address, Some(account(program(), &value)));
        assert!(invalid_at(ring().cosigner(&rpc).await, address), "{name}");
    }
}

#[tokio::test]
async fn cosigner_read_preserves_valid_thresholds_and_scope() {
    let mut value = cosigner();
    value.scope = CoSignScope::ALL.bits();
    value.threshold_count = value.thresholds.len() as u8;
    for (index, row) in value.thresholds.iter_mut().enumerate() {
        row.mint = Address::new_from_array([index as u8; 32]);
        row.amount = if index == 0 { 0 } else { u64::MAX }.to_le_bytes();
    }
    let expected = CustomRingCoSigner {
        signer: value.signer,
        scope: CoSignScope::ALL,
        thresholds: value
            .thresholds()
            .iter()
            .map(|row| CoSignThreshold {
                mint: row.mint,
                amount: row.amount(),
            })
            .collect(),
    };
    let rpc = at(ring().cosigner_pda(), Some(account(program(), &value)));
    assert_eq!(ring().cosigner(&rpc).await.unwrap(), Some(expected));
}

/// Reads the control at `address`, `true` when it is configured.
async fn configured(
    address: Address,
    mint: Address,
    account: Option<Account>,
) -> Result<bool, RingError> {
    let rpc = at(address, account);
    if address == ring().cosigner_pda() {
        ring().cosigner(&rpc).await.map(|value| value.is_some())
    } else if address == ring().delegate_pda() {
        ring().delegate(&rpc).await.map(|value| value.is_some())
    } else {
        ring()
            .spend_window(&rpc, &mint)
            .await
            .map(|value| value.is_some())
    }
}

#[tokio::test]
async fn optional_control_readers_reject_malformed_accounts() {
    let mint = Address::new_from_array([60; 32]);
    let controls = [
        (ring().cosigner_pda(), account(program(), &cosigner())),
        (ring().delegate_pda(), account(program(), &delegate())),
        (
            ring().spend_window_pda(&mint),
            account(program(), &window(mint)),
        ),
    ];
    let changes: [Mutation<Account>; 5] = [
        ("foreign owner", |account| {
            account.owner = Address::new_from_array([99; 32]);
        }),
        ("truncated", |account| {
            account.data.pop();
        }),
        ("oversized", |account| account.data.push(0)),
        ("wrong discriminator", |account| account.data[0] ^= 1),
        ("wrong bump", |account| {
            *account.data.last_mut().unwrap() ^= 1
        }),
    ];
    for (address, valid) in controls {
        assert!(configured(address, mint, Some(valid.clone()))
            .await
            .unwrap());
        for unconfigured in [
            None,
            Some(empty(Address::default())),
            Some(empty(program())),
        ] {
            assert!(!configured(address, mint, unconfigured).await.unwrap());
        }
        for (name, change) in changes {
            let mut changed = valid.clone();
            change(&mut changed);
            let result = configured(address, mint, Some(changed)).await;
            assert!(invalid_at(result, address), "{name} for {}", valid.data[0]);
        }
    }
    // A nonempty malformed account stays strict.
    let truncated = Account {
        data: vec![0; 4],
        ..empty(program())
    };
    assert!(configured(ring().cosigner_pda(), mint, Some(truncated))
        .await
        .is_err());
}

#[tokio::test]
async fn delegate_read_rejects_substituted_state() {
    let address = ring().delegate_pda();
    let value = delegate();
    let valid = at(address, Some(account(program(), &value)));
    assert_eq!(ring().delegate(&valid).await.unwrap(), Some(value.delegate));
    let mut wrong_bump = value;
    wrong_bump.bump ^= 1;
    let mut zero_key = value;
    zero_key.delegate = Address::default();
    for value in [wrong_bump, zero_key] {
        let rpc = at(address, Some(account(program(), &value)));
        assert!(invalid_at(ring().delegate(&rpc).await, address));
    }
}

#[tokio::test]
async fn spend_window_read_rejects_substituted_state() {
    let mint = Address::new_from_array([60; 32]);
    let address = ring().spend_window_pda(&mint);
    let value = window(mint);
    let valid = at(address, Some(account(program(), &value)));
    assert_eq!(
        ring().spend_window(&valid, &mint).await.unwrap(),
        Some(value)
    );
    let mut wrong_mint = value;
    wrong_mint.mint = Address::new_from_array([61; 32]);
    let mut wrong_bump = value;
    wrong_bump.bump ^= 1;
    let mut zero_window = value;
    zero_window.window_slots = [0; 8];
    for value in [wrong_mint, wrong_bump, zero_window] {
        let rpc = at(address, Some(account(program(), &value)));
        assert!(invalid_at(ring().spend_window(&rpc, &mint).await, address));
    }
}

fn registry_root(next_index: u64, cursor: u8, root: [u8; 32]) -> KeyRegistryRoot {
    let mut history = [[0; 32]; KEY_REGISTRY_ROOT_HISTORY];
    history[usize::from(cursor)] = root;
    KeyRegistryRoot {
        discriminator: KEY_REGISTRY_ROOT,
        next_index: next_index.to_le_bytes(),
        bump: Address::find_program_address(&[KeyRegistryRoot::SEED], &program()).1,
        history_cursor: cursor,
        history,
    }
}

#[tokio::test]
async fn the_registry_root_names_its_history_slot_and_refuses_an_empty_one() {
    let address = ring().key_registry_root_pda();
    let read = |value: KeyRegistryRoot| async move {
        ring()
            .key_registry_root(&at(address, Some(account(program(), &value))))
            .await
    };
    assert_eq!(
        read(registry_root(2, 3, [5; 32])).await.unwrap(),
        Some(CurrentKeyRegistryRoot {
            root: [5; 32],
            next_index: 2,
            history_index: 3,
        })
    );
    assert_eq!(
        ring().key_registry_root(&at(address, None)).await.unwrap(),
        None
    );
    for invalid in [
        registry_root(0, 3, [5; 32]),
        registry_root(2, 3, [0; 32]),
        registry_root(u64::MAX, 3, [5; 32]),
    ] {
        assert!(invalid_at(read(invalid).await, address));
    }
}

const PINNED: RuleTable = RuleTable::builder()
    .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
    .rule(Rule::forbid(Subject::Sender, ListId::Block))
    .build();

#[test]
fn the_stored_table_is_trusted_only_under_its_pinned_hash() {
    let config = pinned(
        ring(),
        &PINNED,
        ring().namespace_pda(),
        PoolTree::from_id(0),
    );
    assert_eq!(policy_config_table(&config).unwrap(), PINNED);
    client_rules_match(&PINNED, &config).unwrap();

    let mut hash_drift = config;
    hash_drift.policy_hash[0] ^= 1;
    assert!(matches!(
        policy_config_table(&hash_drift),
        Err(RingError::HashMismatch)
    ));
    assert!(matches!(
        client_rules_match(&PINNED, &hash_drift),
        Err(RingError::HashMismatch)
    ));

    let mut row_drift = config;
    row_drift.rules.rules[1][29] = ListSet::single(ListId::Frozen).bits();
    assert!(matches!(
        client_rules_match(&PINNED, &row_drift),
        Err(RingError::TableMismatch)
    ));
    let shorter = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
        .build();
    assert!(matches!(
        client_rules_match(&shorter, &config),
        Err(RingError::TableMismatch)
    ));

    let mut padded = config;
    padded.rules.rules[MAX_RULES - 1] = [1; 32];
    assert!(matches!(
        policy_config_table(&padded),
        Err(RingError::Rules(RuleTableError::NonZeroPadding))
    ));

    let mut unsourced = config;
    unsourced.sources[ListId::Block.slot()] = SourceSlot {
        list_id: 0,
        namespace: Address::default(),
    };
    assert!(matches!(
        policy_config_table(&unsourced),
        Err(RingError::PolicyHash(PolicyHashError::MissingSource(
            ListId::Block
        )))
    ));
}

#[tokio::test]
async fn the_pinned_policy_reads_the_canonical_account_once() {
    let config = pinned(
        ring(),
        &PINNED,
        ring().namespace_pda(),
        PoolTree::from_id(0),
    );
    let address = ring().policy_config_pda();
    let rpc = at(address, Some(account(program(), &config)));
    let pinned = ring().pinned_policy(&rpc).await.unwrap().unwrap();
    assert_eq!(pinned.table, PINNED);
    assert_eq!(pinned.config, config);
    assert_eq!(rpc.reads(), vec![address]);

    let mut wrong_bump = config;
    wrong_bump.bump ^= 1;
    let rpc = at(address, Some(account(program(), &wrong_bump)));
    assert!(invalid_at(
        ring().pinned_policy(&rpc).await.map(|_| ()),
        address
    ));
}
