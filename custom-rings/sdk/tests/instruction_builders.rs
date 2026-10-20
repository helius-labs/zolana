//! The instruction builders must reproduce the account order, privileges and
//! instruction data the program's processors and SPP's loaders expect. Each
//! expected list below is the one asserted by the program's own fixtures in
//! `custom-rings/program/tests/common/mod.rs`.

use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
use custom_ring_interface::{
    AuditedDepositPrefix, CreateConfigIxData, CustomRingTransactIxData, PlainGroth16Proof,
    PolicyTableIxData, ReaderIxData, SetCoSignerIxData, SetPausedIxData, SourceSpec,
    ANONYMOUS_RING_SHAPES, CONFIG_PDA_SEED, READ_ACCESS_RECORD_PDA_SEED,
};
use custom_ring_sdk::{
    compute_unit_limit, tag, CoSignScope, CoSignThreshold, CustomRing, CustomRingDelegateTransact,
    CustomRingProof, CustomRingTransact, Deposit, EscrowBinding, ForeignBinding, InstructionTag,
    PolicyReads, PolicyTreeContext, RegistryBinding, RingError,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::v1::MAX_TRANSACTION_SIZE;
use zolana_client::{transaction_size, ComputeBudgetConfig};
use zolana_interface::{
    instruction::{
        CircuitId, DepositAssetKind, EncryptedRingDepositData, InputUtxo, InterfaceTransfer,
        MessageData, RingDepositEntry, RingDepositIxData, TransactIxData, TransactProof,
        TreeContext,
    },
    pda, BPF_LOADER_UPGRADEABLE_ID, N_PUBLIC_SLOTS, RING_AUTH_PDA_SEED,
};
use zolana_keypair::{SigningKey, X25519Keypair, X25519Pubkey};
use zolana_program::instruction::{
    DepositAsset, DepositSplAccounts, RingAssetDeposit, TransactInterfaceTransferAccounts,
    TransactSolTransferAccounts,
};
use zolana_ring_client::{ReaderKey, ReaderKeyError};
use zolana_ring_policy::{ListId, ListSet, Rule, RuleTable, Subject, MAX_INLINE_ASSETS};

/// The system program is the all-zero address.
const SYSTEM_PROGRAM: Address = Address::new_from_array([0u8; 32]);
/// The key registry root index and the forwarded SPP deposit in the audited wire.
const ROOT_INDEX: usize = 1 + CustomRingProof::SIZE;
const SPP_DATA: usize = core::mem::size_of::<AuditedDepositPrefix>();

fn payer() -> Address {
    Address::new_from_array([11; 32])
}

fn ring() -> CustomRing {
    CustomRing::new(Address::new_from_array([10; 32]))
}

fn authority() -> Address {
    Address::new_from_array([12; 32])
}

fn auditor_pubkey() -> X25519Pubkey {
    X25519Keypair::new().pubkey()
}

fn sol_deposit_entry() -> RingAssetDeposit {
    RingAssetDeposit {
        asset: DepositAsset::Sol,
        view_tag: [31; 32],
        owner_utxo_hash: [32; 32],
        amount: 7_000_000,
        ring_data_hash: [33; 32],
        encrypted: EncryptedRingDepositData {
            tx_viewing_pk: [3; 33],
            salt: [34; 16],
            ciphertext: vec![35, 36, 37],
        },
    }
}

fn split_tag(instruction: &Instruction) -> (u8, &[u8]) {
    let (ix_tag, body) = instruction
        .data
        .split_first()
        .expect("builder emits a tag byte");
    (*ix_tag, body)
}

#[test]
fn create_config_emits_the_program_account_order_and_auditor_key() {
    let auditor_pubkey = auditor_pubkey();

    let instruction = ring()
        .create_config(payer(), authority(), auditor_pubkey, true)
        .expect("instruction");

    assert_eq!(instruction.program_id, ring().program_id());
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new(payer(), true),
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new(ring().config_pda(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(ring().program_id(), false),
            AccountMeta::new_readonly(ring().program_data_pda(), false),
        ]
    );

    let (ix_tag, body) = split_tag(&instruction);
    assert_eq!(ix_tag, tag::CREATE_CONFIG);
    let decoded: CreateConfigIxData =
        wincode::deserialize_exact(body).expect("body is a complete CreateConfigIxData");
    assert_eq!(decoded.auditor_pubkey, *auditor_pubkey.as_bytes());
    assert!(decoded.has_policy);
    assert!(!decoded.anonymous);
}

#[test]
fn an_anonymous_config_differs_only_in_its_mode_byte() {
    let regular = ring()
        .create_config(payer(), authority(), auditor_pubkey(), false)
        .expect("instruction");
    let anonymous = ring()
        .create_anonymous_config(payer(), authority(), auditor_pubkey(), false)
        .expect("instruction");
    assert_eq!(anonymous.accounts, regular.accounts);
    let (_, body) = split_tag(&anonymous);
    let decoded: CreateConfigIxData =
        wincode::deserialize_exact(body).expect("body is a complete CreateConfigIxData");
    assert!(decoded.anonymous && !decoded.has_policy);
    let (_, body) = split_tag(&regular);
    let decoded: CreateConfigIxData =
        wincode::deserialize_exact(body).expect("body is a complete CreateConfigIxData");
    assert!(!decoded.anonymous);
}

#[test]
fn reserved_p256_points_are_not_auditor_keys() {
    for bytes in [[2; 33], [3; 33], [0; 33]] {
        assert!(X25519Pubkey::from_bytes(bytes).is_err());
    }
}

#[test]
fn init_spp_ring_config_emits_the_program_account_order_and_no_body() {
    let instruction = ring().init_spp_ring_config(payer(), authority(), false);

    assert_eq!(instruction.program_id, ring().program_id());
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new(payer(), true),
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new_readonly(pda::protocol_config(), false),
            AccountMeta::new(ring().ring_auth_pda(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
        ]
    );
    // The processor rejects any trailing byte, so the tag has to be the whole
    // instruction data.
    assert_eq!(instruction.data, vec![tag::INIT_SPP_RING_CONFIG]);
}

#[test]
fn a_policy_ring_registers_with_its_policy_config_as_the_eighth_account() {
    let audit_only = ring().init_spp_ring_config(payer(), authority(), false);
    let policy = ring().init_spp_ring_config(payer(), authority(), true);

    assert_eq!(audit_only.accounts.len(), 7);
    assert_eq!(policy.accounts.len(), 8);
    assert_eq!(policy.accounts[..7], audit_only.accounts[..]);
    assert_eq!(
        policy.accounts[7],
        AccountMeta::new_readonly(ring().policy_config_pda(), false)
    );
    assert_eq!(policy.data, vec![tag::INIT_SPP_RING_CONFIG]);
}

#[test]
fn create_member_registry_root_emits_the_program_account_order_and_no_body() {
    let instruction = ring().create_member_registry_root(payer(), authority());
    assert_eq!(instruction.program_id, ring().program_id());
    assert_eq!(instruction.data, vec![tag::CREATE_MEMBER_REGISTRY_ROOT]);
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new(payer(), true),
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new(ring().member_registry_root_pda(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ]
    );
}

fn reader() -> ReaderKey {
    ReaderKey::ed25519(
        SigningKey::from_ed25519_bytes(&[23; 32])
            .pubkey()
            .as_ed25519()
            .map(Address::new_from_array)
            .expect("Ed25519 public key"),
    )
    .expect("reader key")
}

fn p256_reader() -> ReaderKey {
    ReaderKey::p256(
        zolana_ring_client::P256ReaderKey::from_bytes(
            hex::decode("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap(),
    )
    .expect("reader key")
}

#[test]
fn grant_read_access_emits_the_program_account_order_and_reader() {
    let instruction = ring()
        .grant_read_access(payer(), authority(), reader())
        .expect("instruction");

    assert_eq!(instruction.program_id, ring().program_id());
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new(payer(), true),
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new(ring().read_access_record_pda(&reader()), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ]
    );
    let (ix_tag, body) = split_tag(&instruction);
    assert_eq!(ix_tag, tag::GRANT_READ_ACCESS);
    let decoded: ReaderIxData =
        wincode::deserialize_exact(body).expect("body is a complete ReaderIxData");
    assert_eq!(decoded.reader, reader().to_bytes());
}

#[test]
fn reader_keys_round_trip_through_text_and_bytes() {
    for key in [reader(), p256_reader()] {
        assert_eq!(
            key.to_string().parse::<ReaderKey>().expect("text form"),
            key
        );
        assert_eq!(ReaderKey::from_bytes(key.to_bytes()), Ok(key));
    }
    let mut pda = reader().to_bytes();
    pda[0] = 2;
    assert_eq!(ReaderKey::from_bytes(pda), Err(ReaderKeyError::Scheme));
    assert!("not-a-key".parse::<ReaderKey>().is_err());
    assert!(hex::encode([4u8; 33]).parse::<ReaderKey>().is_err());
}

#[test]
fn weak_ed25519_reader_key_is_rejected() {
    let mut weak = [0u8; 32];
    weak[0] = 1;
    assert!(ReaderKey::ed25519(Address::new_from_array(weak)).is_err());

    weak[31] = 0x80;
    assert!(ReaderKey::ed25519(Address::new_from_array(weak)).is_err());
}

#[test]
fn noncanonical_ed25519_reader_key_is_rejected() {
    let mut noncanonical = [0xff; 32];
    noncanonical[0] = 0xee;
    noncanonical[31] = 0x7f;
    assert!(ReaderKey::ed25519(Address::new_from_array(noncanonical)).is_err());
}

#[test]
fn mixed_torsion_ed25519_reader_key_is_rejected() {
    let mixed = (ED25519_BASEPOINT_POINT + EIGHT_TORSION[1])
        .compress()
        .to_bytes();
    assert!(ReaderKey::ed25519(Address::new_from_array(mixed)).is_err());
}

#[test]
fn revoke_read_access_emits_the_program_account_order_and_reader() {
    let rent_recipient = Address::new_from_array([24; 32]);
    let instruction = ring()
        .revoke_read_access(authority(), reader(), rent_recipient)
        .expect("instruction");

    assert_eq!(instruction.program_id, ring().program_id());
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new(ring().read_access_record_pda(&reader()), false),
            AccountMeta::new(rent_recipient, false),
        ]
    );
    let (ix_tag, body) = split_tag(&instruction);
    assert_eq!(ix_tag, tag::REVOKE_READ_ACCESS);
    let decoded: ReaderIxData =
        wincode::deserialize_exact(body).expect("body is a complete ReaderIxData");
    assert_eq!(decoded.reader, reader().to_bytes());
}

#[test]
fn set_authority_emits_both_signers_and_the_config() {
    let new_authority = Address::new_from_array([31; 32]);
    let instruction = ring().set_authority(authority(), new_authority);

    assert_eq!(instruction.program_id, ring().program_id());
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new_readonly(new_authority, true),
            AccountMeta::new(ring().config_pda(), false),
        ]
    );
    assert_eq!(instruction.data, vec![tag::SET_AUTHORITY]);
}

#[test]
fn set_paused_emits_the_authority_the_ring_auth_and_spp() {
    for paused in [true, false] {
        let instruction = ring().set_paused(authority(), paused).expect("instruction");

        assert_eq!(instruction.program_id, ring().program_id());
        assert_eq!(
            instruction.accounts,
            vec![
                AccountMeta::new_readonly(authority(), true),
                AccountMeta::new_readonly(ring().config_pda(), false),
                AccountMeta::new(ring().ring_auth_pda(), false),
                AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
            ]
        );
        let (ix_tag, body) = split_tag(&instruction);
        assert_eq!(ix_tag, tag::SET_PAUSED);
        let decoded: SetPausedIxData =
            wincode::deserialize_exact(body).expect("body is a complete SetPausedIxData");
        assert_eq!(decoded.paused, paused);
        assert_eq!(instruction.data, vec![tag::SET_PAUSED, u8::from(paused)]);
    }
    assert_eq!(compute_unit_limit(InstructionTag::SetPaused), 50_000);
}

#[test]
fn read_access_record_pda_derives_from_the_hashed_tagged_key() {
    use sha2::Digest;
    for key in [reader(), p256_reader()] {
        let seed_hash: [u8; 32] = sha2::Sha256::digest(key.to_bytes()).into();
        let (record, _bump) = Address::find_program_address(
            &[READ_ACCESS_RECORD_PDA_SEED, &seed_hash],
            &ring().program_id(),
        );
        assert_eq!(ring().read_access_record_pda(&key), record);
        assert_eq!(key.record_address(&ring().program_id()), record);
    }
    assert_ne!(
        ring().read_access_record_pda(&reader()),
        ring().read_access_record_pda(&p256_reader())
    );
}

#[test]
fn builders_place_the_canonical_config_and_ring_auth_pdas() {
    let (config, _bump) = Address::find_program_address(&[CONFIG_PDA_SEED], &ring().program_id());
    let (ring_auth, _bump) =
        Address::find_program_address(&[RING_AUTH_PDA_SEED], &ring().program_id());
    let (program_data, _bump) = Address::find_program_address(
        &[ring().program_id().as_ref()],
        &Address::new_from_array(BPF_LOADER_UPGRADEABLE_ID),
    );
    assert_eq!(ring().config_pda(), config);
    assert_eq!(ring().ring_auth_pda(), ring_auth);
    assert_eq!(ring().program_data_pda(), program_data);

    let create_config = ring()
        .create_config(payer(), authority(), auditor_pubkey(), true)
        .expect("instruction");
    assert_eq!(
        create_config.accounts.get(2).expect("config meta").pubkey,
        config
    );

    let init = ring().init_spp_ring_config(payer(), authority(), false);
    assert_eq!(
        init.accounts.get(4).expect("ring_auth meta").pubkey,
        ring_auth
    );

    let deposit = Deposit {
        proof: Some(sample_proof()),
        ring: ring(),
        cosigner: None,
        tree: Address::new_from_array([13; 32]),
        depositor: payer(),
        deposits: vec![sol_deposit_entry()],
        escrow: EscrowBinding::Off,
    }
    .instruction()
    .expect("single SOL deposit");
    // Deposit controls precede the forwarded SPP accounts.
    assert_eq!(
        deposit.accounts.get(6).expect("ring_config meta").pubkey,
        ring_auth
    );
}

/// `ring_auth` has no keypair: only the ring program can produce its signature,
/// and it does so with `invoke_signed` inside the CPI. A builder that already
/// marked it a signer would make every transaction unsignable.
#[test]
fn ring_auth_is_never_a_signer_in_the_outer_instruction() {
    let init = ring().init_spp_ring_config(payer(), authority(), false);
    let init_ring_auth = init.accounts.get(4).expect("ring_auth meta");
    assert!(!init_ring_auth.is_signer);
    // SPP allocates its RingConfig into the account, so the outer instruction must
    // still pass it writable.
    assert!(init_ring_auth.is_writable);

    let deposit = Deposit {
        proof: Some(sample_proof()),
        ring: ring(),
        cosigner: None,
        tree: Address::new_from_array([13; 32]),
        depositor: payer(),
        deposits: vec![sol_deposit_entry()],
        escrow: EscrowBinding::Off,
    }
    .instruction()
    .expect("single SOL deposit");
    let deposit_ring_config = deposit.accounts.get(7).expect("ring_config meta");
    assert!(!deposit_ring_config.is_signer);
}

#[test]
fn audited_deposit_targets_the_ring_program_and_wraps_spps_tag() {
    let tree = Address::new_from_array([13; 32]);
    let depositor = Address::new_from_array([14; 32]);
    let entry = sol_deposit_entry();

    let instruction = Deposit {
        proof: Some(sample_proof()),
        ring: ring(),
        cosigner: None,
        tree,
        depositor,
        deposits: vec![entry.clone()],
        escrow: EscrowBinding::Off,
    }
    .instruction()
    .expect("single SOL deposit");

    // The ring verifies the audit proof, then forwards the SPP deposit bytes.
    assert_eq!(instruction.program_id, ring().program_id());
    assert_eq!(instruction.data[0], tag::AUDITED_DEPOSIT);
    assert_eq!(
        instruction.data[SPP_DATA],
        zolana_interface::instruction::tag::RING_DEPOSIT
    );

    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new_readonly(ring().cosigner_pda(), false),
            AccountMeta::new_readonly(ring().cosigner_pda(), false),
            AccountMeta::new_readonly(ring().deposit_audit_pda(), false),
            AccountMeta::new(tree, false),
            AccountMeta::new(depositor, true),
            AccountMeta::new_readonly(ring().ring_auth_pda(), false),
            AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new(pda::sol_interface(), false),
        ]
    );

    let decoded = RingDepositIxData::deserialize(&instruction.data[SPP_DATA + 1..])
        .expect("body is complete ring deposit data");
    assert_eq!(
        decoded,
        RingDepositIxData {
            assets: vec![DepositAssetKind::Sol],
            deposits: vec![RingDepositEntry {
                asset_index: 0,
                view_tag: entry.view_tag,
                owner_utxo_hash: entry.owner_utxo_hash,
                amount: entry.amount,
                ring_data_hash: entry.ring_data_hash,
                encrypted: entry.encrypted,
            }],
        }
    );
}

#[test]
fn audited_deposit_wraps_exact_spp_bytes_and_bounds_only_the_audited_batch() {
    let build = |proof, count| {
        Deposit {
            ring: ring(),
            tree: input_tree(),
            depositor: payer(),
            deposits: vec![sol_deposit_entry(); count],
            proof,
            escrow: EscrowBinding::Off,
            cosigner: None,
        }
        .instruction()
    };
    let spp = zolana_program::instruction::RingDeposit {
        tree: input_tree(),
        depositor: payer(),
        ring_program_id: ring().program_id(),
        deposits: vec![sol_deposit_entry()],
    }
    .instruction()
    .unwrap();
    let audited = build(Some(sample_proof()), 1).unwrap();
    assert_eq!(audited.data[0], tag::AUDITED_DEPOSIT);
    assert_eq!(
        &audited.data[1..1 + CustomRingProof::SIZE],
        wincode::serialize(&sample_proof()).unwrap()
    );
    assert_eq!(audited.data[ROOT_INDEX], 0);
    assert_eq!(&audited.data[SPP_DATA..], spp.data);
    assert_eq!(&audited.accounts[4..], spp.accounts);
    assert_eq!(
        audited.accounts[3],
        AccountMeta::new_readonly(ring().deposit_audit_pda(), false)
    );
    assert!(build(Some(sample_proof()), 8).is_ok());
    assert!(build(Some(sample_proof()), 9).is_err());
    assert!(matches!(build(None, 1), Err(RingError::AuditRequired)));
    assert!(matches!(build(None, 9), Err(RingError::AuditRequired)));
}

/// An escrowed ring names its registry root after the audit setting and refuses a plain deposit.
#[test]
fn an_escrowed_deposit_names_the_registry_root_and_requires_the_audit() {
    let build = |proof| {
        Deposit {
            ring: ring(),
            tree: input_tree(),
            depositor: payer(),
            deposits: vec![sol_deposit_entry()],
            proof,
            escrow: EscrowBinding::Registry(RegistryBinding {
                root_index: 3,
                root: [3; 32],
            }),
            cosigner: None,
        }
        .instruction()
    };
    let escrowed = build(Some(sample_proof())).unwrap();
    assert_eq!(escrowed.data[ROOT_INDEX], 3);
    assert_eq!(
        escrowed.accounts[3..5],
        [
            AccountMeta::new_readonly(ring().deposit_audit_pda(), false),
            AccountMeta::new_readonly(ring().member_registry_root_pda(), false),
        ]
    );
    assert!(matches!(build(None), Err(RingError::AuditRequired)));
}

#[test]
fn deposit_audit_setting_names_its_authority_and_canonical_pda() {
    assert!(matches!(
        ring().set_deposit_audit(payer(), authority(), false),
        Err(RingError::Program(
            custom_ring_interface::CustomRingError::DepositAuditRequired
        ))
    ));
    let instruction = ring()
        .set_deposit_audit(payer(), authority(), true)
        .unwrap();
    assert_eq!(instruction.data, vec![tag::SET_DEPOSIT_AUDIT, 1]);
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new(payer(), true),
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new(ring().deposit_audit_pda(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ]
    );
}

/// A mixed batch is where an `asset_index` could silently point at the wrong
/// settlement account group, so the index-to-accounts pairing is pinned here too.
#[test]
fn deposit_batches_index_each_entry_into_its_settlement_accounts() {
    let mint = Address::new_from_array([15; 32]);
    let user_token = Address::new_from_array([16; 32]);
    let spl = DepositAsset::Spl(DepositSplAccounts {
        mint,
        user_token,
        token_program: pda::spl_token_program_id(),
    });
    let mut spl_entry = sol_deposit_entry();
    spl_entry.asset = spl;
    spl_entry.amount = 42;
    let mut second_spl_entry = spl_entry.clone();
    second_spl_entry.amount = 43;

    let instruction = Deposit {
        proof: Some(sample_proof()),
        ring: ring(),
        cosigner: None,
        tree: Address::new_from_array([13; 32]),
        depositor: payer(),
        deposits: vec![spl_entry, sol_deposit_entry(), second_spl_entry],
        escrow: EscrowBinding::Off,
    }
    .instruction()
    .expect("mixed batch");

    let decoded = RingDepositIxData::deserialize(&instruction.data[SPP_DATA + 1..])
        .expect("body is complete ring deposit data");
    // SOL is always asset 0 when present, so the SPL entry indexes 1.
    assert_eq!(
        decoded.assets,
        vec![
            DepositAssetKind::Sol,
            DepositAssetKind::Spl {
                spl_interface_bump: pda::spl_interface_with_bump(&mint).1,
            },
        ]
    );
    assert_eq!(
        decoded
            .deposits
            .iter()
            .map(|entry| (entry.asset_index, entry.amount))
            .collect::<Vec<_>>(),
        vec![(1, 42), (0, 7_000_000), (1, 43)]
    );
    assert_eq!(
        instruction
            .accounts
            .get(8..)
            .expect("settlement metas")
            .to_vec(),
        vec![
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new(pda::sol_interface(), false),
            AccountMeta::new_readonly(pda::spl_token_program_id(), false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(user_token, false),
            AccountMeta::new(pda::spl_interface(&mint), false),
        ]
    );
}

fn input_tree() -> Address {
    Address::new_from_array([41; 32])
}

fn output_tree() -> Address {
    Address::new_from_array([42; 32])
}

fn address_tree() -> Address {
    Address::new_from_array([45; 32])
}

fn second_tree() -> Address {
    Address::new_from_array([46; 32])
}

fn context(utxo: u16, nullifier: u16) -> TreeContext {
    TreeContext {
        utxo_tree_root_index: utxo,
        nullifier_tree_root_index: nullifier,
    }
}

/// The address tree and the ring's registry root at history slot 5.
fn address_tree_reads() -> PolicyReads {
    PolicyReads {
        trees: vec![PolicyTreeContext {
            tree: address_tree(),
            context: context(0, 0),
        }],
        registry: RegistryBinding {
            root_index: 5,
            root: [5; 32],
        },
        foreign: None,
    }
}

/// Two trees, the ring's registry and the curator's at history slot 4.
fn curated_reads() -> PolicyReads {
    PolicyReads {
        trees: vec![
            PolicyTreeContext {
                tree: address_tree(),
                context: context(1, 2),
            },
            PolicyTreeContext {
                tree: second_tree(),
                context: context(3, 4),
            },
        ],
        registry: RegistryBinding {
            root_index: 5,
            root: [5; 32],
        },
        foreign: Some(ForeignBinding {
            registry: CURATOR_A.member_registry_root_pda(),
            curator: CURATOR_A,
            root_index: 4,
            root: [4; 32],
            next_index: 3,
        }),
    }
}

fn owner_signer() -> Address {
    Address::new_from_array([43; 32])
}

fn sample_proof() -> CustomRingProof {
    CustomRingProof {
        groth16: PlainGroth16Proof {
            proof_a: [51; 32],
            proof_b: [52; 64],
            proof_c: [53; 32],
        },
        commitment: [54; 32],
        commitment_pok: [55; 32],
    }
}

/// Representative confidential `ConfidentialRingEddsa` content carrying the auditor message
/// the ring proof commits to.
fn transact_data(interface_transfers: Vec<InterfaceTransfer>) -> TransactIxData {
    TransactIxData {
        proof: TransactProof::zeroed(),
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [61; 32],
        circuit: CircuitId::ConfidentialRingEddsa(2, 3, N_PUBLIC_SLOTS as u8),
        tx_viewing_pk: [62; 33],
        salt: [63; 16],
        inputs: Vec::new(),
        interface_transfers,
        data_hash: None,
        ring_data_hash: None,
        outputs: Vec::new(),
        messages: vec![MessageData {
            view_tag: [64; 32],
            data: vec![65; 65],
        }],
        tree_contexts: vec![TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        }],
    }
}

/// The account list the program's `process_transact_ix` reads: its own
/// prefix, one account per policy tree, the ring's registry root and the
/// curator's, followed by SPP's `RING_TRANSACT` list, which the builder takes
/// from the interface builder instead of re-listing.
#[test]
fn custom_ring_transact_prepends_the_config_to_the_spp_list() {
    let proof = sample_proof();
    let transact = transact_data(Vec::new());
    let reads = curated_reads();

    let instruction = CustomRingTransact {
        ring: ring(),
        cosigner: None,
        payer: payer(),
        input_trees: vec![input_tree()],
        output_tree: output_tree(),
        policy: Some(reads.clone()),
        owner_signers: vec![owner_signer()],
        interface_transfer_accounts: Vec::new(),
        proof,
        approval_required: false,
        transact: transact.clone(),
    }
    .instruction()
    .expect("serialize the custom-ring transact content");

    assert_eq!(instruction.program_id, ring().program_id());
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new_readonly(ring().cosigner_pda(), false),
            AccountMeta::new_readonly(ring().cosigner_pda(), false),
            AccountMeta::new_readonly(ring().policy_config_pda(), false),
            AccountMeta::new_readonly(address_tree(), false),
            AccountMeta::new_readonly(second_tree(), false),
            AccountMeta::new_readonly(ring().member_registry_root_pda(), false),
            AccountMeta::new_readonly(CURATOR_A.member_registry_root_pda(), false),
            AccountMeta::new(payer(), true),
            AccountMeta::new(output_tree(), false),
            AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(ring().ring_auth_pda(), false),
            AccountMeta::new(input_tree(), false),
            AccountMeta::new_readonly(owner_signer(), true),
        ]
    );

    let (ix_tag, body) = split_tag(&instruction);
    assert_eq!(ix_tag, tag::TRANSACT);
    assert_eq!(ix_tag, 3);
    let decoded: CustomRingTransactIxData =
        wincode::deserialize_exact(body).expect("body is a complete CustomRingTransactIxData");
    assert_eq!(
        decoded,
        CustomRingTransactIxData {
            proof,
            policy_trees: vec![context(1, 2), context(3, 4)],
            registry_root_index: 5,
            foreign_root_indexes: [4],
            approval_required: false,
            transact,
        }
    );
}

/// `ring_config` is this program's `ring_auth` PDA, and no keypair exists for it:
/// only the program can sign for it, inside its CPI. A signer meta here would make
/// the transaction unsignable.
#[test]
fn custom_ring_transact_leaves_ring_config_unsigned() {
    let instruction = CustomRingTransact {
        ring: ring(),
        cosigner: None,
        payer: payer(),
        input_trees: vec![input_tree()],
        output_tree: output_tree(),
        policy: Some(address_tree_reads()),
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        proof: sample_proof(),
        approval_required: false,
        transact: transact_data(Vec::new()),
    }
    .instruction()
    .expect("serialize the custom-ring transact content");

    // The policy config, its one tree and the registry root sit before the forwarded SPP list.
    let ring_config_index = 10;
    let ring_config = instruction
        .accounts
        .get(ring_config_index)
        .expect("ring_config meta");
    assert_eq!(ring_config.pubkey, ring().ring_auth_pda());
    assert!(!ring_config.is_signer);
}

/// SPP creates one nullifier PDA per spent input, derived from the input's own
/// tree and the input's nullifier. The interface builder places them right after
/// the input trees and before the owner signers; the wrapper must forward them.
#[test]
fn custom_ring_transact_forwards_trees_then_nullifier_pdas_after_ring_config() {
    let mut transact = transact_data(Vec::new());
    transact.inputs = vec![
        InputUtxo {
            nullifier_hash: [71; 32],
            tree_index: 0,
        },
        InputUtxo {
            nullifier_hash: [72; 32],
            tree_index: 1,
        },
    ];
    transact.tree_contexts = vec![context(0, 0), context(0, 0)];

    let instruction = CustomRingTransact {
        ring: ring(),
        cosigner: None,
        payer: payer(),
        input_trees: vec![input_tree(), second_tree()],
        output_tree: output_tree(),
        policy: None,
        owner_signers: vec![owner_signer()],
        interface_transfer_accounts: Vec::new(),
        proof: sample_proof(),
        approval_required: false,
        transact,
    }
    .instruction()
    .expect("serialize the custom-ring transact payload");

    assert_eq!(
        instruction
            .accounts
            .get(7..)
            .expect("ring_config, input trees, nullifier PDAs and owner signer metas")
            .to_vec(),
        vec![
            AccountMeta::new_readonly(ring().ring_auth_pda(), false),
            AccountMeta::new(input_tree(), false),
            AccountMeta::new(second_tree(), false),
            AccountMeta::new(pda::nullifier_pda(&input_tree(), &[71; 32]).0, false),
            AccountMeta::new(pda::nullifier_pda(&second_tree(), &[72; 32]).0, false),
            AccountMeta::new_readonly(owner_signer(), true),
        ]
    );
    let decoded: CustomRingTransactIxData =
        wincode::deserialize_exact(split_tag(&instruction).1).expect("complete body");
    assert!(decoded.policy_trees.is_empty());
    assert_eq!(decoded.registry_root_index, 0);
    assert_eq!(decoded.foreign_root_indexes, [0]);
}

/// Settlement accounts come from the same interface builder, so a withdrawal's
/// group has to appear after the owner signers untouched.
#[test]
fn custom_ring_transact_forwards_settlement_accounts() {
    let recipient = Address::new_from_array([44; 32]);

    let instruction = CustomRingTransact {
        ring: ring(),
        cosigner: None,
        payer: payer(),
        input_trees: vec![input_tree()],
        output_tree: output_tree(),
        policy: Some(address_tree_reads()),
        owner_signers: vec![owner_signer()],
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts { recipient },
        )],
        proof: sample_proof(),
        approval_required: false,
        transact: transact_data(vec![InterfaceTransfer::SolWithdrawal { amount: 5 }]),
    }
    .instruction()
    .expect("serialize the custom-ring transact content");

    assert_eq!(
        instruction
            .accounts
            .get(12..)
            .expect("owner signer and settlement metas")
            .to_vec(),
        vec![
            AccountMeta::new_readonly(owner_signer(), true),
            AccountMeta::new(pda::sol_interface(), false),
            AccountMeta::new(recipient, false),
        ]
    );
}

/// The TS SDK hardcodes the numbers, a renumbering must fail here.
#[test]
fn ring_instruction_tags_are_stable() {
    assert_eq!(tag::CREATE_CONFIG, 1);
    assert_eq!(tag::INIT_SPP_RING_CONFIG, 2);
    assert_eq!(tag::TRANSACT, 3);
    assert_eq!(tag::GRANT_READ_ACCESS, 4);
    assert_eq!(tag::REVOKE_READ_ACCESS, 5);
    assert_eq!(tag::SET_AUTHORITY, 6);
    assert_eq!(tag::SET_PAUSED, 11);
    assert_eq!(tag::SET_POLICY_RULES, 12);
    assert_eq!(tag::DEPOSIT, 18);
    assert_eq!(tag::MERGE, 20);
    assert_eq!(tag::CREATE_MEMBER_REGISTRY_ROOT, 28);
    assert_eq!(tag::REGISTER_KEY, 29);
    assert_eq!(tag::SET_DEPOSIT_AUDIT, 30);
    assert_eq!(tag::AUDITED_DEPOSIT, 31);
    assert_eq!(tag::UPDATE_MEMBERS, 32);
}

const CURATOR_A: CustomRing = CustomRing::new(Address::new_from_array([20; 32]));
const CURATOR_B: CustomRing = CustomRing::new(Address::new_from_array([21; 32]));

/// Two owner list rules, one of them a group, and an asset list rule.
const TABLE: RuleTable = RuleTable::builder()
    .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
    .rule(Rule::any_of(
        Subject::Sender,
        ListSet::single(ListId::Approval),
        ListSet::single(ListId::Frozen),
    ))
    .rule(Rule::require(Subject::Asset, ListId::Allow))
    .build();

fn create_policy(
    rules: &RuleTable,
    shared_sources: Vec<(ListId, CustomRing)>,
) -> Result<Instruction, RingError> {
    ring().create_policy(payer(), authority(), address_tree(), rules, &shared_sources)
}

fn set_policy_rules(
    rules: &RuleTable,
    shared_sources: Vec<(ListId, CustomRing)>,
) -> Result<Instruction, RingError> {
    ring().set_policy_rules(authority(), rules, &shared_sources)
}

fn policy_body(instruction: &Instruction, expected_tag: u8) -> PolicyTableIxData {
    let (ix_tag, body) = split_tag(instruction);
    assert_eq!(ix_tag, expected_tag);
    wincode::deserialize_exact(body).expect("body is a complete PolicyTableIxData")
}

fn spec(list_id: ListId, source: u8) -> SourceSpec {
    SourceSpec {
        list_id: list_id as u8,
        source,
    }
}

#[test]
fn create_policy_pins_the_rows_with_one_source_per_referenced_list() {
    let instruction =
        create_policy(&TABLE, vec![(ListId::Frozen, CURATOR_A)]).expect("instruction");

    assert_eq!(instruction.program_id, ring().program_id());
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new(payer(), true),
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new(ring().policy_config_pda(), false),
            AccountMeta::new_readonly(address_tree(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(ring().program_id(), false),
            AccountMeta::new_readonly(ring().program_data_pda(), false),
            AccountMeta::new_readonly(CURATOR_A.member_registry_root_pda(), false),
        ]
    );
    let encoded = TABLE.encode();
    assert_eq!(
        policy_body(&instruction, tag::CREATE_POLICY),
        PolicyTableIxData {
            sources: vec![
                spec(ListId::Allow, 0),
                spec(ListId::Frozen, 1),
                spec(ListId::Approval, 0),
            ],
            rules: encoded.rules[..3].to_vec(),
            inline_assets: Vec::new(),
            inline_limits: Vec::new(),
            limits: Vec::new(),
        }
    );
    // The group row carries its absent alternative at byte 19.
    assert_eq!(encoded.rules[1][19], ListSet::single(ListId::Frozen).bits());
}

#[test]
fn set_policy_rules_gates_on_the_upgrade_authority_with_the_same_body() {
    let created = create_policy(&TABLE, vec![(ListId::Frozen, CURATOR_A)]).expect("create");
    let instruction =
        set_policy_rules(&TABLE, vec![(ListId::Frozen, CURATOR_A)]).expect("instruction");

    assert_eq!(instruction.program_id, ring().program_id());
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new(ring().policy_config_pda(), false),
            AccountMeta::new_readonly(ring().program_id(), false),
            AccountMeta::new_readonly(ring().program_data_pda(), false),
            AccountMeta::new_readonly(CURATOR_A.member_registry_root_pda(), false),
        ]
    );
    let (ix_tag, body) = split_tag(&instruction);
    assert_eq!(ix_tag, tag::SET_POLICY_RULES);
    assert_eq!(body, &created.data[1..]);
}

#[test]
fn curators_are_indexed_once_in_first_use_order() {
    let shared = vec![
        (ListId::Approval, CURATOR_B),
        (ListId::Frozen, CURATOR_A),
        (ListId::Allow, CURATOR_B),
    ];
    for instruction in [
        create_policy(&TABLE, shared.clone()).expect("create"),
        set_policy_rules(&TABLE, shared).expect("set"),
    ] {
        let curators: Vec<Address> = instruction
            .accounts
            .iter()
            .rev()
            .take(2)
            .rev()
            .map(|meta| meta.pubkey)
            .collect();
        assert_eq!(
            curators,
            vec![
                CURATOR_B.member_registry_root_pda(),
                CURATOR_A.member_registry_root_pda()
            ]
        );
        let (_, body) = split_tag(&instruction);
        let decoded: PolicyTableIxData = wincode::deserialize_exact(body).expect("body");
        assert_eq!(
            decoded.sources,
            vec![
                spec(ListId::Allow, 1),
                spec(ListId::Frozen, 2),
                spec(ListId::Approval, 1),
            ]
        );
    }
}

#[test]
fn a_shared_source_the_table_does_not_reference_is_refused() {
    assert!(matches!(
        create_policy(&TABLE, vec![(ListId::Block, CURATOR_A)]),
        Err(RingError::UnreferencedList(ListId::Block))
    ));
    assert!(matches!(
        set_policy_rules(&TABLE, vec![(ListId::Block, CURATOR_A)]),
        Err(RingError::UnreferencedList(ListId::Block))
    ));
}

/// The legacy packet the builders used to measure against, before the pin
/// moved to a transaction v1 message.
const LEGACY_PACKET_DATA_SIZE: usize = 1232;

/// One sender rule per list and a full inline pool, beside a curator account
/// per list.
///
/// This pin is past the legacy packet, so the old bound refused it and a v1
/// transaction carries it with kilobytes to spare. The body is capped at
/// `MAX_RULES` rows of 32 bytes plus `MAX_INLINE_ASSETS` assets and limits, and
/// the account list at one curator per list, so even the largest legal pin
/// stays far under the v1 ceiling: the guard the builders keep now only catches
/// a shape the table format itself forbids.
#[test]
fn the_largest_pin_is_past_a_legacy_packet_and_inside_a_v1_transaction() {
    let mut builder = RuleTable::builder();
    for list_id in ListId::ALL {
        builder = builder.rule(Rule::require(Subject::Sender, list_id));
    }
    let pool = core::array::from_fn::<_, MAX_INLINE_ASSETS, _>(|i| [i as u8 + 1; 32]);
    let full = builder
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above_by_asset())
        .inline_assets(&pool)
        .inline_limits(&[1; MAX_INLINE_ASSETS])
        .build();
    let curated: Vec<(ListId, CustomRing)> = ListId::ALL
        .into_iter()
        .map(|list_id| {
            let curator = CustomRing::new(Address::new_from_array([100 + list_id as u8; 32]));
            (list_id, curator)
        })
        .collect();

    let instruction =
        create_policy(&full, curated.clone()).expect("the largest pin fits a v1 transaction");
    // The payer and the upgrade authority sign it.
    let measured = transaction_size(
        &payer(),
        core::slice::from_ref(&instruction),
        ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::CreatePolicy)),
    )
    .expect("the pin compiles into a v1 message");
    assert!(
        measured.bytes > LEGACY_PACKET_DATA_SIZE,
        "a pin this size was refused while the bound was the legacy packet"
    );
    assert!(measured.bytes <= MAX_TRANSACTION_SIZE);
    assert!(measured.fits());
    create_policy(&full, Vec::new()).expect("own sources fit");
    set_policy_rules(&full, curated).expect("the re-pin carries no payer, tree or system account");
}

#[test]
fn set_cosigner_creates_or_replaces_under_the_config_authority() {
    let signer = Address::new_from_array([37; 32]);
    let thresholds = [
        CoSignThreshold {
            mint: Address::default(),
            amount: 10,
        },
        CoSignThreshold {
            mint: Address::new_from_array([60; 32]),
            amount: 20,
        },
    ];
    let instruction = ring()
        .set_cosigner(
            payer(),
            authority(),
            signer,
            CoSignScope::WITHDRAWALS,
            &thresholds,
        )
        .expect("instruction");

    assert_eq!(instruction.program_id, ring().program_id());
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new(payer(), true),
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new(ring().cosigner_pda(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ]
    );
    let (ix_tag, body) = split_tag(&instruction);
    assert_eq!(ix_tag, tag::SET_CO_SIGNER);
    let decoded: SetCoSignerIxData =
        wincode::deserialize_exact(body).expect("body is a complete SetCoSignerIxData");
    assert_eq!(decoded.signer, signer.to_bytes());
    assert_eq!(decoded.scope, CoSignScope::WITHDRAWALS.bits());
    assert_eq!(decoded.thresholds.len(), 2);
    assert_eq!(decoded.thresholds[0].mint, [0; 32]);
    assert_eq!(decoded.thresholds[1].amount, 20);
}

#[test]
fn clear_cosigner_closes_into_the_rent_recipient() {
    let rent_recipient = Address::new_from_array([38; 32]);
    let instruction = ring().clear_cosigner(authority(), rent_recipient);

    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new(ring().cosigner_pda(), false),
            AccountMeta::new(rent_recipient, false),
        ]
    );
    assert_eq!(instruction.data, vec![tag::CLEAR_CO_SIGNER]);
}

#[test]
fn set_delegate_runs_under_the_upgrade_authority() {
    let delegate = Address::new_from_array([47; 32]);
    let instruction = ring().set_delegate(payer(), authority(), delegate);

    assert_eq!(instruction.program_id, ring().program_id());
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new(payer(), true),
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new(ring().config_pda(), false),
            AccountMeta::new(ring().delegate_pda(), false),
            AccountMeta::new_readonly(ring().member_registry_root_pda(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(ring().program_id(), false),
            AccountMeta::new_readonly(ring().program_data_pda(), false),
        ]
    );
    let (ix_tag, body) = split_tag(&instruction);
    assert_eq!(ix_tag, tag::SET_DELEGATE);
    assert_eq!(ix_tag, 24);
    assert_eq!(body, delegate.as_array());
}

/// `[config, cosigner_pda, cosigner, delegate_pda, delegate(s)]` then
/// the policy accounts and the registry root precede SPP's authority rail list,
/// a public leg never builds.
#[test]
fn delegate_transact_places_the_delegate_before_the_policy_accounts() {
    let delegate = Address::new_from_array([47; 32]);
    let reads = curated_reads();
    let build = |legs: Vec<InterfaceTransfer>| {
        CustomRingDelegateTransact {
            ring: ring(),
            payer: payer(),
            input_trees: vec![input_tree()],
            output_tree: output_tree(),
            policy: reads.clone(),
            cosigner: None,
            delegate,
            proof: sample_proof(),
            transact: transact_data(legs),
            approval_required: false,
        }
        .instruction()
    };
    let instruction = build(Vec::new()).expect("delegate transact");
    assert_eq!(
        instruction
            .accounts
            .get(..10)
            .expect("prefix metas")
            .to_vec(),
        vec![
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new_readonly(ring().cosigner_pda(), false),
            AccountMeta::new_readonly(ring().cosigner_pda(), false),
            AccountMeta::new_readonly(ring().delegate_pda(), false),
            AccountMeta::new_readonly(delegate, true),
            AccountMeta::new_readonly(ring().policy_config_pda(), false),
            AccountMeta::new_readonly(address_tree(), false),
            AccountMeta::new_readonly(second_tree(), false),
            AccountMeta::new_readonly(ring().member_registry_root_pda(), false),
            AccountMeta::new_readonly(CURATOR_A.member_registry_root_pda(), false),
        ]
    );
    assert_eq!(
        instruction.accounts.get(14).expect("ring_config meta"),
        &AccountMeta::new_readonly(ring().ring_auth_pda(), false)
    );
    let (ix_tag, body) = split_tag(&instruction);
    assert_eq!(ix_tag, tag::DELEGATE_TRANSACT);
    assert_eq!(ix_tag, 25);
    let decoded: CustomRingTransactIxData = wincode::deserialize_exact(body).expect("body");
    assert_eq!(decoded.registry_root_index, 5);
    assert_eq!(decoded.foreign_root_indexes, [4]);
    assert_eq!(decoded.policy_trees, vec![context(1, 2), context(3, 4)]);
    assert!(matches!(
        build(vec![InterfaceTransfer::SolWithdrawal { amount: 1 }]),
        Err(RingError::DelegatePublicLeg)
    ));
}

/// Unset, the slot repeats `cosigner_pda` and the layout never moves.
#[test]
fn the_cosigner_slot_signs_only_when_set() {
    let cosigner = Address::new_from_array([37; 32]);
    let build = |cosigner: Option<Address>| {
        CustomRingTransact {
            ring: ring(),
            payer: payer(),
            input_trees: vec![input_tree()],
            output_tree: output_tree(),
            policy: None,
            cosigner,
            owner_signers: Vec::new(),
            interface_transfer_accounts: Vec::new(),
            proof: CustomRingProof {
                groth16: PlainGroth16Proof {
                    proof_a: [0; 32],
                    proof_b: [0; 64],
                    proof_c: [0; 32],
                },
                commitment: [0; 32],
                commitment_pok: [0; 32],
            },
            transact: transact_data(Vec::new()),
            approval_required: false,
        }
        .instruction()
        .expect("instruction")
    };
    assert_eq!(
        build(None).accounts[1..3],
        [
            AccountMeta::new_readonly(ring().cosigner_pda(), false),
            AccountMeta::new_readonly(ring().cosigner_pda(), false),
        ]
    );
    assert_eq!(
        build(Some(cosigner)).accounts[2],
        AccountMeta::new_readonly(cosigner, true)
    );
    let deposit = Deposit {
        proof: Some(sample_proof()),
        ring: ring(),
        cosigner: Some(cosigner),
        tree: input_tree(),
        depositor: payer(),
        deposits: vec![sol_deposit_entry()],
        escrow: EscrowBinding::Off,
    }
    .instruction()
    .expect("deposit");
    assert_eq!(
        deposit.accounts[2],
        AccountMeta::new_readonly(cosigner, true)
    );
}

/// The real v1 serializer, both proofs, all nullifiers and a full auditor message.
/// All notes stay in the ring, one input tree, one owner, no memo or extra data.
fn measured_policy_shape(
    inputs: usize,
    outputs: usize,
    curated: bool,
    rail: u8,
) -> zolana_client::TransactionSize {
    use custom_ring_interface::{
        DisclosureShape, AUDIT_OUTPUT_FIELD_COUNT, DISCLOSURE_INPUT_LEN, DISCLOSURE_OUTPUT_LEN,
        DISCLOSURE_SENDER_LEN,
    };
    use zolana_hasher::primitives::pack_be_chunks;
    use zolana_interface::instruction::{OwnerTag, TransactOutput};
    use zolana_keypair::ViewingKey;
    use zolana_transaction::{
        serialization::{
            confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
            ring_anonymous::ring_anonymous_padding,
            UtxoSerialization,
        },
        Data, SOL_ASSET_ID,
    };
    let key = ViewingKey::new();
    let plaintext = ConfidentialOutputPlaintext {
        asset_id: SOL_ASSET_ID,
        amount: u64::MAX,
        blinding: [0; 32],
        ring_program_id: Some(ring().program_id()),
        data: Data::default(),
    };
    let cx = ConfidentialEncode {
        recipient_pubkey: key.pubkey(),
        tx: key,
        salt: [0; 16],
        slot_index: 0,
    };
    // Every anonymous slot carries the fixed scheme-9 body, a padding slot measures it.
    let ciphertext = if rail == 1 {
        ring_anonymous_padding([0; 32])
    } else {
        Confidential::encode_plaintext(&plaintext, [2; 32], &cx)
    }
    .unwrap()
    .data;
    let mut transact = transact_data(Vec::new());
    transact.circuit = match rail {
        1 => CircuitId::AnonymousRingEddsa(
            inputs as u8,
            outputs as u8,
            N_PUBLIC_SLOTS as u8,
            zolana_interface::verifying_keys::AnonymousRingEddsaProofData {
                bsb22_commitment: zolana_interface::verifying_keys::Bsb22Commitment {
                    commitment: [0; 32],
                    commitment_pok: [0; 32],
                },
                default_owner_tag: None,
            },
        ),
        2 => CircuitId::RingAuthority(inputs as u8, outputs as u8, N_PUBLIC_SLOTS as u8),
        _ => CircuitId::ConfidentialRingEddsa(inputs as u8, outputs as u8, N_PUBLIC_SLOTS as u8),
    };
    transact.inputs = (0..inputs)
        .map(|index| InputUtxo {
            nullifier_hash: [index as u8 + 1; 32],
            tree_index: 0,
        })
        .collect();
    transact.outputs = (0..outputs)
        .map(|index| TransactOutput {
            utxo_hash: [index as u8 + 1; 32],
            owner_tag: OwnerTag::Inline([index as u8 + 60; 32]),
            data: Some(ciphertext.clone()),
        })
        .collect();
    let shape = DisclosureShape {
        anonymous: rail == 1,
        inputs,
        outputs,
    };
    // Capacities the circuit does not disclose are measured at the same per-slot growth.
    let fields = shape.field_count().unwrap_or_else(|| {
        if rail == 1 {
            pack_be_chunks(
                DISCLOSURE_SENDER_LEN
                    + inputs * DISCLOSURE_INPUT_LEN
                    + outputs * DISCLOSURE_OUTPUT_LEN,
            )
        } else {
            AUDIT_OUTPUT_FIELD_COUNT * outputs.max(4)
        }
    });
    transact.messages[0].data = vec![0; 65 + 32 * fields];
    let instruction = if rail == 2 {
        CustomRingDelegateTransact {
            ring: ring(),
            payer: payer(),
            cosigner: if curated { Some(authority()) } else { None },
            input_trees: vec![input_tree()],
            output_tree: input_tree(),
            policy: if curated {
                curated_reads()
            } else {
                address_tree_reads()
            },
            delegate: if curated { owner_signer() } else { payer() },
            proof: sample_proof(),
            approval_required: curated,
            transact,
        }
        .instruction_with_policy_kind(custom_ring_interface::PolicyProofKind::General)
        .unwrap()
    } else {
        CustomRingTransact {
            ring: ring(),
            payer: payer(),
            cosigner: if curated { Some(authority()) } else { None },
            input_trees: vec![input_tree()],
            output_tree: input_tree(),
            policy: Some(if curated {
                curated_reads()
            } else {
                address_tree_reads()
            }),
            owner_signers: if rail == 1 {
                Vec::new()
            } else if curated {
                vec![owner_signer()]
            } else {
                vec![payer()]
            },
            interface_transfer_accounts: Vec::new(),
            proof: sample_proof(),
            approval_required: curated,
            transact,
        }
        .instruction_with_policy_kind(custom_ring_interface::PolicyProofKind::General)
        .unwrap()
    };
    transaction_size(
        &payer(),
        &[instruction],
        ComputeBudgetConfig::new(1_400_000).with_priority_fee(u64::MAX),
    )
    .unwrap()
}

#[test]
fn policy_shape_transaction_size_matrix() {
    for shape in zolana_interface::shape::SPP_SUPPORTED_SHAPES {
        let minimum = measured_policy_shape(shape.n_inputs(), shape.n_outputs(), false, 0);
        let full = measured_policy_shape(shape.n_inputs(), shape.n_outputs(), true, 0);
        assert_eq!(
            minimum.fits(),
            custom_ring_interface::policy_shape_supported(
                shape.n_inputs(),
                shape.n_outputs(),
                false,
                false
            )
        );
        if (shape.n_inputs(), shape.n_outputs()) == (16, 4) {
            assert!(!full.fits());
        }
        println!(
            "POLICY_SIZE {} {} {} {} {} {}",
            shape.n_inputs(),
            shape.n_outputs(),
            minimum.bytes,
            minimum.addresses,
            full.bytes,
            full.addresses
        );
    }
}

#[test]
fn anonymous_and_delegate_shapes_fit_without_payload_changes() {
    let anonymous = ANONYMOUS_RING_SHAPES
        .iter()
        .map(|shape| (shape.n_inputs(), shape.n_outputs(), 1));
    let delegate = zolana_interface::shape::SPP_SUPPORTED_SHAPES
        .iter()
        .filter(|shape| {
            custom_ring_interface::policy_shape_supported(
                shape.n_inputs(),
                shape.n_outputs(),
                false,
                true,
            )
        })
        .map(|shape| (shape.n_inputs(), shape.n_outputs(), 2));
    for (n, m, rail) in anonymous.chain(delegate) {
        let minimum = measured_policy_shape(n, m, false, rail);
        let full = measured_policy_shape(n, m, true, rail);
        println!(
            "POLICY_RAIL_SIZE {rail} {n} {m} {} {} {} {}",
            minimum.bytes, minimum.addresses, full.bytes, full.addresses
        );
        assert!(minimum.fits() && full.fits(), "{n}x{m} rail {rail}");
    }
}

/// An anonymous merge at `width` slots, every real input publishing its nullifier.
fn measured_anonymous_merge(width: usize, curated: bool) -> zolana_client::TransactionSize {
    use custom_ring_interface::{
        merge_disclosure_field_count, CustomRingMergeIxData, MergeDisclosure, AUDIT_CIPHERTEXT_LEN,
        TAGGED_X25519_KEY_LEN,
    };
    use custom_ring_sdk::{CustomRingMergeInstruction, MAX_MERGE_INPUTS};
    use zolana_interface::instruction::{
        instruction_data::merge_transact::{MergeOutputEncryption, MergeProof},
        MergeTransactIxData,
    };
    let data = CustomRingMergeIxData {
        registry_root_index: 0,
        output_ring_data_hash: [0; 32],
        disclosure: Some(MergeDisclosure {
            proof: sample_proof(),
            eph_pk: [0; TAGGED_X25519_KEY_LEN],
            ciphertext: [0; AUDIT_CIPHERTEXT_LEN],
            fields: vec![[0; 32]; merge_disclosure_field_count(width)],
        }),
        merge: MergeTransactIxData {
            expiry_unix_ts: u64::MAX,
            proof: MergeProof::zeroed(),
            output_utxo_hash: [0; 32],
            output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
                salt: [0; 16],
                ciphertext: [[0; 32]; 3],
            },
            private_tx_hash: [0; 32],
            nullifiers: (0..width.min(MAX_MERGE_INPUTS))
                .map(|index| [index as u8 + 1; 32])
                .collect(),
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
            cache_slot: None,
        },
    };
    let instruction = CustomRingMergeInstruction {
        ring: ring(),
        input_tree: input_tree(),
        output_tree: output_tree(),
        payer: payer(),
        cosigner: curated.then(authority),
        data,
    }
    .instruction();
    transaction_size(
        &payer(),
        &[instruction],
        ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::Merge))
            .with_priority_fee(u64::MAX),
    )
    .unwrap()
}

#[test]
fn anonymous_merge_widths_fit_with_their_disclosure() {
    use zolana_interface::instruction::instruction_data::merge_transact::MERGE_SUPPORTED_INPUT_COUNTS;
    for width in MERGE_SUPPORTED_INPUT_COUNTS {
        let minimum = measured_anonymous_merge(width, false);
        let full = measured_anonymous_merge(width, true);
        println!(
            "ANONYMOUS_MERGE_SIZE {width} {} {} {} {}",
            minimum.bytes, minimum.addresses, full.bytes, full.addresses
        );
        assert_eq!(
            minimum.fits() && full.fits(),
            custom_ring_interface::ANONYMOUS_MERGE_WIDTHS.contains(&width),
            "{width}"
        );
    }
}

#[test]
fn anonymous_transaction_size_matrix() {
    for shape in zolana_interface::shape::SPP_SUPPORTED_SHAPES {
        if shape.n_outputs() > 4 {
            continue;
        }
        let minimum = measured_policy_shape(shape.n_inputs(), shape.n_outputs(), false, 1);
        let full = measured_policy_shape(shape.n_inputs(), shape.n_outputs(), true, 1);
        // The catalog lists shapes with keys, the fixed body leaves room for more.
        println!(
            "ANONYMOUS_SIZE {} {} {} {} {} {}",
            shape.n_inputs(),
            shape.n_outputs(),
            minimum.bytes,
            minimum.addresses,
            full.bytes,
            full.addresses
        );
        if ANONYMOUS_RING_SHAPES.contains(&shape) {
            assert!(minimum.fits() && full.fits(), "{shape:?}");
        }
    }
}
