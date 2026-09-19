mod common;

use common::{keypair, wallet_utxo};
use solana_address::Address;
use zolana_event::MessageData;
use zolana_hasher::{sha256::Sha256BE, Hasher};
use zolana_interface::{
    instruction::instruction_data::transact::{InterfaceTransfer, OwnerTag, TransactOutput},
    MAX_INTERFACE_TRANSFERS, N_PUBLIC_SLOTS, SOL_ASSET_FIELD, SOL_INTERFACE,
};
use zolana_transaction::{
    instructions::transact::{
        asset_field, signed_magnitude_to_field, ConfidentialTransaction, PublicTransfers,
        SettlementTarget, SettlementTransfer, SppProofInputs,
    },
    ExternalData, Mint, TransactionError, SOL_MINT,
};

fn address(byte: u8) -> Address {
    Address::new_from_array([byte; 32])
}
fn mint(byte: u8) -> Mint {
    Mint::new(address(byte), u64::from(byte) + 1)
}
fn sol(deposit: bool, amount: u64) -> SettlementTransfer {
    SettlementTransfer::Sol {
        is_deposit: deposit,
        amount,
        user_sol_account: address(70),
    }
}
fn spl(byte: u8, deposit: bool, amount: u64) -> SettlementTransfer {
    SettlementTransfer::Spl {
        mint: address(byte),
        is_deposit: deposit,
        amount,
        user_spl_token: address(71),
    }
}
fn external() -> ExternalData {
    ExternalData::new([2; 33], [3; 16], vec![], vec![], vec![])
}
fn proof(transfers: Vec<SettlementTransfer>) -> SppProofInputs {
    let mut external_data = external();
    external_data.interface_transfers = transfers;
    SppProofInputs {
        input_utxos: vec![],
        output_utxos: vec![],
        blinding_seed: [0; 32],
        output_tree_id: 0,
        external_data,
        payer: address(1),
    }
}
fn builder() -> ConfidentialTransaction {
    let owner = keypair(7);
    ConfidentialTransaction::new(vec![wallet_utxo(&owner, Mint::SOL, 100, 0, 1)], address(1))
        .unwrap()
}

#[test]
fn settlement_validation_is_atomic_for_both_directions_and_targets() {
    let mut tx = builder();
    tx.deposit_sol(2, address(20)).unwrap();
    let before = tx.public_transfers().to_vec();
    for deposit in [true, false] {
        for (asset, target) in [
            (
                Mint::SOL,
                SettlementTarget::Sol {
                    user_sol_account: address(2),
                },
            ),
            (
                mint(4),
                SettlementTarget::Spl {
                    user_spl_token: address(3),
                },
            ),
        ] {
            assert!(matches!(
                tx.settle(asset, deposit, 0, target),
                Err(TransactionError::ZeroInterfaceTransferAmount)
            ));
            assert_eq!(tx.public_transfers(), before);
        }
        for (asset, target) in [
            (
                Mint::SOL,
                SettlementTarget::Spl {
                    user_spl_token: address(2),
                },
            ),
            (
                mint(4),
                SettlementTarget::Sol {
                    user_sol_account: address(3),
                },
            ),
        ] {
            assert!(
                matches!(tx.settle(asset, deposit, 1, target), Err(TransactionError::SettlementTargetMismatch { asset: actual }) if actual == asset.asset)
            );
            assert_eq!(tx.public_transfers(), before);
        }
    }
    tx.withdraw_sol(1, address(21)).unwrap();
    assert_eq!(tx.public_transfers().len(), before.len() + 1);
}

#[test]
fn settlement_count_limit_is_enforced_at_each_public_boundary() {
    let transfers = vec![sol(true, 1); MAX_INTERFACE_TRANSFERS];
    let mut tx = builder();
    for _ in 0..MAX_INTERFACE_TRANSFERS {
        tx.deposit_sol(1, address(70)).unwrap();
    }
    assert_eq!(tx.interface_transfers().unwrap(), transfers);
    let before = tx.public_transfers().to_vec();
    assert!(
        matches!(tx.deposit_sol(1, address(70)), Err(TransactionError::TooManyInterfaceTransfers { got, max }) if got == MAX_INTERFACE_TRANSFERS + 1 && max == MAX_INTERFACE_TRANSFERS)
    );
    assert_eq!(tx.public_transfers(), before);
    let ext = external()
        .with_interface_transfers(transfers.clone())
        .unwrap();
    assert!(ext.hash().is_ok());
    assert!(proof(transfers.clone()).public_transfers().is_ok());
    assert!(
        matches!(ext.with_interface_transfer(sol(true, 1)), Err(TransactionError::TooManyInterfaceTransfers { got, max }) if got == MAX_INTERFACE_TRANSFERS + 1 && max == MAX_INTERFACE_TRANSFERS)
    );
    let excess = vec![sol(true, 1); MAX_INTERFACE_TRANSFERS + 1];
    assert!(
        matches!(external().with_interface_transfers(excess.clone()), Err(TransactionError::TooManyInterfaceTransfers { got, max }) if got == MAX_INTERFACE_TRANSFERS + 1 && max == MAX_INTERFACE_TRANSFERS)
    );
    let excessive = proof(excess);
    for result in [
        excessive.external_data.hash().map(|_| ()),
        excessive.public_transfers().map(|_| ()),
    ] {
        assert!(
            matches!(result, Err(TransactionError::TooManyInterfaceTransfers { got, max }) if got == MAX_INTERFACE_TRANSFERS + 1 && max == MAX_INTERFACE_TRANSFERS)
        );
    }
}

#[test]
fn spl_convenience_apis_require_spl_mints_and_existing_spends_but_deposits_can_introduce_assets() {
    let mut tx = builder();
    let recipient = keypair(9).shielded_address().unwrap();
    assert!(matches!(
        tx.transfer(&recipient, SOL_MINT, 1),
        Err(TransactionError::ExpectedSplMint)
    ));
    assert!(matches!(
        tx.deposit(Mint::SOL, 1, address(20)),
        Err(TransactionError::ExpectedSplMint)
    ));
    assert!(matches!(
        tx.withdraw(SOL_MINT, 1, address(20)),
        Err(TransactionError::ExpectedSplMint)
    ));
    assert!(
        matches!(tx.transfer(&recipient, address(4), 1), Err(TransactionError::UnknownMint(m)) if m == address(4))
    );
    assert!(
        matches!(tx.withdraw(address(4), 1, address(20)), Err(TransactionError::UnknownMint(m)) if m == address(4))
    );
    assert!(tx.public_transfers().is_empty());
    assert!(tx.outputs().is_empty());
    tx.deposit(mint(4), 9, address(20)).unwrap();
    assert_eq!(
        tx.interface_transfers().unwrap(),
        vec![SettlementTransfer::Spl {
            mint: address(4),
            is_deposit: true,
            amount: 9,
            user_spl_token: address(20)
        }]
    );
}

#[test]
fn public_slots_aggregate_by_mint_in_first_use_order_with_signed_amounts() {
    let got = proof(vec![
        spl(5, false, 10),
        sol(true, 20),
        spl(4, true, 8),
        spl(5, true, 4),
        sol(false, 7),
    ])
    .public_transfers()
    .unwrap();
    assert_eq!(
        got,
        PublicTransfers {
            assets: [
                asset_field(&address(5)).unwrap(),
                SOL_ASSET_FIELD,
                asset_field(&address(4)).unwrap()
            ],
            amounts: [
                signed_magnitude_to_field(false, 6),
                signed_magnitude_to_field(true, 13),
                signed_magnitude_to_field(true, 8)
            ],
        }
    );
    let one = proof(vec![spl(4, true, 8)]).public_transfers().unwrap();
    assert_eq!(
        one.assets,
        [asset_field(&address(4)).unwrap(), [0; 32], [0; 32]]
    );
    assert_eq!(
        one.amounts,
        [signed_magnitude_to_field(true, 8), [0; 32], [0; 32]]
    );
    assert_eq!(
        proof(vec![]).public_transfers().unwrap(),
        PublicTransfers::default()
    );
}

#[test]
fn public_slots_reject_zero_net_intermediate_overflow_and_excess_assets() {
    assert!(
        matches!(proof(vec![sol(true, 5), sol(false, 5)]).public_transfers(), Err(TransactionError::ZeroNetInterfaceTransferAmount { asset }) if asset == SOL_MINT)
    );
    for deposit in [true, false] {
        assert_eq!(
            proof(vec![sol(deposit, u64::MAX)])
                .public_transfers()
                .unwrap()
                .amounts[0],
            signed_magnitude_to_field(deposit, u64::MAX)
        );
        assert!(
            matches!(proof(vec![sol(deposit, u64::MAX), sol(deposit, 1), sol(!deposit, 1)]).public_transfers(), Err(TransactionError::PublicTransferOverflow { asset }) if asset == SOL_MINT)
        );
    }
    let at_limit: Vec<_> = (1..=N_PUBLIC_SLOTS)
        .map(|n| spl(u8::try_from(n).unwrap(), true, 1))
        .collect();
    assert!(proof(at_limit.clone()).public_transfers().is_ok());
    let mut too_many = at_limit;
    too_many.push(sol(true, 1));
    assert!(
        matches!(proof(too_many).public_transfers(), Err(TransactionError::TooManyPublicAssets { got, max }) if got == N_PUBLIC_SLOTS + 1 && max == N_PUBLIC_SLOTS)
    );
}

#[test]
fn zero_amount_and_spl_sol_alias_are_rejected_by_external_data_and_public_slots() {
    for deposit in [true, false] {
        for invalid in [sol(deposit, 0), spl(4, deposit, 0)] {
            assert!(matches!(
                external().with_interface_transfer(invalid),
                Err(TransactionError::ZeroInterfaceTransferAmount)
            ));
            assert!(matches!(
                external().with_interface_transfers(vec![invalid]),
                Err(TransactionError::ZeroInterfaceTransferAmount)
            ));
            assert!(matches!(
                proof(vec![invalid]).external_data.hash(),
                Err(TransactionError::ZeroInterfaceTransferAmount)
            ));
            assert!(matches!(
                proof(vec![invalid]).public_transfers(),
                Err(TransactionError::ZeroInterfaceTransferAmount)
            ));
        }
        let invalid = spl(0, deposit, 1);
        assert!(
            matches!(external().with_interface_transfer(invalid), Err(TransactionError::SettlementTargetMismatch { asset }) if asset == SOL_MINT)
        );
        assert!(
            matches!(proof(vec![invalid]).external_data.hash(), Err(TransactionError::SettlementTargetMismatch { asset }) if asset == SOL_MINT)
        );
        assert!(
            matches!(proof(vec![invalid]).public_transfers(), Err(TransactionError::SettlementTargetMismatch { asset }) if asset == SOL_MINT)
        );
    }
}

#[test]
fn signed_field_amounts_match_literal_bn254_boundaries_and_interleave_all_slots() {
    // BN254 p-1 and p-(2^64-1), computed as integer subtraction, not through the SDK.
    let cases = [
        (
            0,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            1,
            "0000000000000000000000000000000000000000000000000000000000000001",
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
        ),
        (
            u64::MAX,
            "000000000000000000000000000000000000000000000000ffffffffffffffff",
            "30644e72e131a029b85045b68181585d2833e84879b9709043e1f593f0000002",
        ),
    ];
    for (amount, positive, negative) in cases {
        assert_eq!(
            hex::encode(signed_magnitude_to_field(true, amount)),
            positive
        );
        assert_eq!(
            hex::encode(signed_magnitude_to_field(false, amount)),
            negative
        );
    }
    let values = PublicTransfers {
        assets: [[1; 32], [2; 32], [3; 32]],
        amounts: [[4; 32], [5; 32], [6; 32]],
    };
    assert_eq!(
        values.interleaved(),
        [[1; 32], [4; 32], [2; 32], [5; 32], [3; 32], [6; 32]]
    );
}

#[test]
fn ring_hashes_can_be_set_once_and_neither_existing_field_can_be_overwritten() {
    let filled = external().with_ring_hashes([4; 32], [5; 32]).unwrap();
    assert_eq!(
        (filled.data_hash, filled.ring_data_hash),
        (Some([4; 32]), Some([5; 32]))
    );
    for (data_hash, ring_data_hash) in [
        (Some([4; 32]), None),
        (None, Some([5; 32])),
        (Some([4; 32]), Some([5; 32])),
    ] {
        let mut ext = external();
        ext.data_hash = data_hash;
        ext.ring_data_hash = ring_data_hash;
        assert!(matches!(
            ext.with_ring_hashes([8; 32], [9; 32]),
            Err(TransactionError::RingHashesAlreadySet)
        ));
    }
}

#[test]
fn ordered_settlement_accounts_and_instruction_legs_survive_builder_encryption() {
    let owner = keypair(7);
    let mut tx = ConfidentialTransaction::new(
        vec![
            wallet_utxo(&owner, Mint::SOL, 100, 0, 1),
            wallet_utxo(&owner, mint(4), 100, 0, 2),
        ],
        address(1),
    )
    .unwrap();
    tx.deposit_sol(11, address(21)).unwrap();
    tx.withdraw(address(4), 12, address(22)).unwrap();
    tx.withdraw_sol(13, address(23)).unwrap();
    tx.deposit(mint(4), 14, address(24)).unwrap();
    let expected = vec![
        SettlementTransfer::Sol {
            is_deposit: true,
            amount: 11,
            user_sol_account: address(21),
        },
        SettlementTransfer::Spl {
            mint: address(4),
            is_deposit: false,
            amount: 12,
            user_spl_token: address(22),
        },
        SettlementTransfer::Sol {
            is_deposit: false,
            amount: 13,
            user_sol_account: address(23),
        },
        SettlementTransfer::Spl {
            mint: address(4),
            is_deposit: true,
            amount: 14,
            user_spl_token: address(24),
        },
    ];
    assert_eq!(tx.interface_transfers().unwrap(), expected);
    assert_eq!(
        tx.encrypt(&owner)
            .unwrap()
            .external_data
            .interface_transfers,
        expected
    );
    assert_eq!(
        expected
            .iter()
            .copied()
            .map(SettlementTransfer::settlement_accounts)
            .collect::<Vec<_>>(),
        vec![
            [SOL_INTERFACE, [21; 32]],
            [[4; 32], [22; 32]],
            [SOL_INTERFACE, [23; 32]],
            [[4; 32], [24; 32]]
        ]
    );
    // Verify the PDA bump against the address library and protocol seeds, independently of the SDK leg conversion.
    let (_, bump) = Address::find_program_address(
        &[b"spl_asset_vault", &[4; 32]],
        &Address::new_from_array(zolana_interface::SHIELDED_POOL_PROGRAM_ID),
    );
    assert_eq!(
        expected
            .iter()
            .copied()
            .map(SettlementTransfer::interface_transfer)
            .collect::<Vec<_>>(),
        vec![
            InterfaceTransfer::SolDeposit { amount: 11 },
            InterfaceTransfer::SplWithdrawal {
                amount: 12,
                spl_interface_bump: bump
            },
            InterfaceTransfer::SolWithdrawal { amount: 13 },
            InterfaceTransfer::SplDeposit {
                amount: 14,
                spl_interface_bump: bump
            }
        ]
    );
}

fn external_fixture() -> ExternalData {
    ExternalData::new(
        [2; 33],
        [3; 16],
        vec![
            TransactOutput {
                utxo_hash: [4; 32],
                owner_tag: OwnerTag::Account(0),
                data: Some(vec![5, 6]),
            },
            TransactOutput {
                utxo_hash: [7; 32],
                owner_tag: OwnerTag::Inline([8; 32]),
                data: None,
            },
        ],
        vec![[9; 32], [8; 32]],
        vec![
            MessageData {
                view_tag: [10; 32],
                data: vec![11],
            },
            MessageData {
                view_tag: [12; 32],
                data: vec![13, 14],
            },
        ],
    )
}

#[test]
fn external_hash_uses_canonical_bytes_and_only_resolves_account_owner_tags() {
    let ext = external_fixture();
    // Literal wire layout: discriminator; LE expiry; encryption context; empty
    // transfers; absent optional hashes; two outputs; two messages; resolved owner.
    let mut bytes = vec![zolana_interface::instruction::tag::TRANSACT];
    bytes.extend([255; 8]);
    bytes.extend([2; 33]);
    bytes.extend([3; 16]);
    bytes.extend([0, 0, 0, 2]);
    bytes.extend([4; 32]);
    bytes.extend([1, 0, 1, 2, 0, 5, 6]);
    bytes.extend([7; 32]);
    bytes.push(0);
    bytes.extend([8; 32]);
    bytes.push(0);
    bytes.push(2);
    bytes.extend([10; 32]);
    bytes.extend([1, 0, 11]);
    bytes.extend([12; 32]);
    bytes.extend([2, 0, 13, 14]);
    bytes.extend([9; 32]);
    assert_eq!(ext.hash().unwrap(), Sha256BE::hash(&bytes).unwrap());
    let mut changed = ext.clone();
    *changed.resolved_owner_tags.get_mut(1).unwrap() = [99; 32];
    assert_eq!(changed.hash().unwrap(), ext.hash().unwrap());
    *changed.resolved_owner_tags.first_mut().unwrap() = [99; 32];
    assert_ne!(changed.hash().unwrap(), ext.hash().unwrap());
    for tags in [vec![[9; 32]], vec![[9; 32]; 3]] {
        let provided = tags.len();
        let mut changed = ext.clone();
        changed.resolved_owner_tags = tags;
        assert!(
            matches!(changed.hash(), Err(TransactionError::Hash(message)) if message == format!("{provided} resolved owner tags for 2 outputs"))
        );
    }
}

#[test]
fn external_hash_binds_every_context_payload_order_and_settlement_field() {
    let mut ext = external_fixture()
        .with_interface_transfers(vec![sol(true, 15), spl(4, false, 16)])
        .unwrap();
    ext.data_hash = Some([17; 32]);
    ext.ring_data_hash = Some([18; 32]);
    let baseline = ext.hash().unwrap();
    let mutations: &[fn(&mut ExternalData)] = &[
        |e| e.instruction_discriminator ^= 1,
        |e| e.expiry_unix_ts -= 1,
        |e| e.tx_viewing_pk[1] ^= 1,
        |e| e.salt[0] ^= 1,
        |e| e.data_hash = Some([19; 32]),
        |e| e.ring_data_hash = Some([19; 32]),
        |e| e.data_hash = None,
        |e| e.ring_data_hash = None,
        |e| e.outputs.first_mut().unwrap().utxo_hash = [19; 32],
        |e| e.outputs.first_mut().unwrap().data = Some(vec![6, 5]),
        |e| e.outputs.first_mut().unwrap().owner_tag = OwnerTag::Account(1),
        |e| e.outputs.last_mut().unwrap().owner_tag = OwnerTag::Inline([19; 32]),
        |e| e.outputs.swap(0, 1),
        |e| e.messages.first_mut().unwrap().view_tag = [19; 32],
        |e| e.messages.first_mut().unwrap().data.push(19),
        |e| e.messages.swap(0, 1),
        |e| e.interface_transfers.swap(0, 1),
        |e| *e.interface_transfers.first_mut().unwrap() = sol(false, 15),
        |e| *e.interface_transfers.first_mut().unwrap() = sol(true, 16),
        |e| {
            *e.interface_transfers.first_mut().unwrap() = SettlementTransfer::Sol {
                is_deposit: true,
                amount: 15,
                user_sol_account: address(19),
            }
        },
        |e| *e.interface_transfers.last_mut().unwrap() = spl(5, false, 16),
        |e| {
            *e.interface_transfers.last_mut().unwrap() = SettlementTransfer::Spl {
                mint: address(4),
                is_deposit: false,
                amount: 16,
                user_spl_token: address(19),
            }
        },
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut changed = ext.clone();
        mutate(&mut changed);
        assert_ne!(changed.hash().unwrap(), baseline, "mutation {index}");
    }
}
