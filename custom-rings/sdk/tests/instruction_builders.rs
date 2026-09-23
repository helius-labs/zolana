//! The instruction builders must reproduce the account order, privileges and
//! instruction data the program's processors and SPP's loaders expect. Each
//! expected list below is the one asserted by the program's own fixtures in
//! `custom-rings/program/tests/common/mod.rs`.

use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
use custom_ring_interface::{PlainGroth16Proof, SetCoSignerIxData, SetPausedIxData, SourceSpec};
use custom_ring_sdk::{
    tag, ClearCoSigner, ClearSpendWindow, CoSignScope, CoSignThreshold, CreateConfig,
    CreateConfigIxData, CreateKeyRegistryRoot, CreatePolicy, CustomRing,
    CustomRingDelegateTransact, CustomRingProof, CustomRingTransact, CustomRingTransactIxData,
    Deposit, DepositInstructionError, EntryError, EscrowBinding, GrantReadAccess,
    InitSppRingConfig, PolicyReads, PolicyTableIxData, PolicyTreeContext, ReaderIxData, ReaderKey,
    ReaderKeyError, RevokeReadAccess, SetAuthority, SetCoSigner, SetDelegate, SetPaused,
    SetPolicyRules, SetSpendWindow, TransactInstructionError, CONFIG_PDA_SEED,
    READ_ACCESS_RECORD_PDA_SEED, SET_PAUSED_COMPUTE_UNIT_LIMIT,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::v1::MAX_TRANSACTION_SIZE;
use zolana_client::{transaction_size, ComputeBudgetConfig};
use zolana_interface::{
    instruction::{
        CircuitId, DepositAsset, DepositAssetKind, DepositSplAccounts, EncryptedRingDepositData,
        InputUtxo, InterfaceTransfer, MessageData, RingAssetDeposit, RingDepositEntry,
        RingDepositIxData, TransactInterfaceTransferAccounts, TransactIxData, TransactProof,
        TransactSolTransferAccounts, TreeContext,
    },
    pda, BPF_LOADER_UPGRADEABLE_ID, N_PUBLIC_SLOTS, RING_AUTH_PDA_SEED,
};
use zolana_keypair::{P256Pubkey, SigningKey, ViewingKey};
use zolana_ring_policy::{ListId, ListSet, Rule, RuleTable, Subject, MAX_INLINE_ASSETS};

/// The system program is the all-zero address.
const SYSTEM_PROGRAM: Address = Address::new_from_array([0u8; 32]);

fn payer() -> Address {
    Address::new_from_array([11; 32])
}

fn ring() -> CustomRing {
    CustomRing::new(Address::new_from_array([10; 32]))
}

fn authority() -> Address {
    Address::new_from_array([12; 32])
}

fn auditor_pubkey() -> P256Pubkey {
    ViewingKey::new().pubkey()
}

fn sol_deposit_entry() -> RingAssetDeposit {
    RingAssetDeposit {
        asset: DepositAsset::Sol,
        view_tag: [31; 32],
        owner_utxo_hash: [32; 32],
        amount: 7_000_000,
        data_hash: None,
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

    let instruction = CreateConfig {
        ring: ring(),
        payer: payer(),
        authority: authority(),
        auditor_pubkey,
        has_policy: true,
    }
    .instruction()
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
}

#[test]
fn create_config_rejects_reserved_auditor_keys() {
    for bytes in [
        zolana_interface::P_CONST_SEC1,
        zolana_interface::P_DERIVE_SEC1,
        zolana_interface::P_PDA_SEC1,
    ] {
        let auditor_pubkey = P256Pubkey::from_bytes(bytes).expect("reserved point");
        let result = CreateConfig {
            ring: ring(),
            payer: payer(),
            authority: authority(),
            auditor_pubkey,
            has_policy: true,
        }
        .instruction();
        assert!(matches!(
            result,
            Err(custom_ring_sdk::CreateConfigError::ReservedAuditorKey)
        ));
    }
}

#[test]
fn init_spp_ring_config_emits_the_program_account_order_and_no_body() {
    let instruction = InitSppRingConfig {
        ring: ring(),
        payer: payer(),
        authority: authority(),
        has_policy: false,
    }
    .instruction();

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
    let audit_only = InitSppRingConfig {
        ring: ring(),
        payer: payer(),
        authority: authority(),
        has_policy: false,
    }
    .instruction();
    let policy = InitSppRingConfig {
        ring: ring(),
        payer: payer(),
        authority: authority(),
        has_policy: true,
    }
    .instruction();

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
fn create_key_registry_root_emits_the_program_account_order_and_no_body() {
    let instruction = CreateKeyRegistryRoot {
        ring: ring(),
        payer: payer(),
        authority: authority(),
    }
    .instruction();
    assert_eq!(instruction.program_id, ring().program_id());
    assert_eq!(instruction.data, vec![tag::CREATE_KEY_REGISTRY_ROOT]);
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new(payer(), true),
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new(ring().key_registry_root_pda(), false),
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
    ReaderKey::p256(auditor_pubkey()).expect("reader key")
}

#[test]
fn grant_read_access_emits_the_program_account_order_and_reader() {
    let instruction = GrantReadAccess {
        ring: ring(),
        payer: payer(),
        authority: authority(),
        reader: reader(),
    }
    .instruction()
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
fn reserved_p256_reader_key_is_rejected() {
    for bytes in [
        zolana_interface::P_CONST_SEC1,
        zolana_interface::P_DERIVE_SEC1,
        zolana_interface::P_PDA_SEC1,
    ] {
        let reserved = P256Pubkey::from_bytes(bytes).expect("reserved point");
        assert!(ReaderKey::p256(reserved).is_err());
    }
}

#[test]
fn revoke_read_access_emits_the_program_account_order_and_reader() {
    let rent_recipient = Address::new_from_array([24; 32]);
    let instruction = RevokeReadAccess {
        ring: ring(),
        authority: authority(),
        reader: reader(),
        rent_recipient,
    }
    .instruction()
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
    let instruction = SetAuthority {
        ring: ring(),
        authority: authority(),
        new_authority,
    }
    .instruction();

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
        let instruction = SetPaused {
            ring: ring(),
            authority: authority(),
            paused,
        }
        .instruction()
        .expect("instruction");

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
        assert_eq!(decoded.paused, u8::from(paused));
        assert_eq!(instruction.data, vec![tag::SET_PAUSED, u8::from(paused)]);
    }
    assert_eq!(SET_PAUSED_COMPUTE_UNIT_LIMIT, 50_000);
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

    let create_config = CreateConfig {
        ring: ring(),
        payer: payer(),
        authority: authority(),
        auditor_pubkey: auditor_pubkey(),
        has_policy: true,
    }
    .instruction()
    .expect("instruction");
    assert_eq!(
        create_config.accounts.get(2).expect("config meta").pubkey,
        config
    );

    let init = InitSppRingConfig {
        ring: ring(),
        payer: payer(),
        authority: authority(),
        has_policy: false,
    }
    .instruction();
    assert_eq!(
        init.accounts.get(4).expect("ring_auth meta").pubkey,
        ring_auth
    );

    let deposit = Deposit {
        proof: None,
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
        deposit.accounts.get(7).expect("ring_config meta").pubkey,
        ring_auth
    );
}

/// `ring_auth` has no keypair: only the ring program can produce its signature,
/// and it does so with `invoke_signed` inside the CPI. A builder that already
/// marked it a signer would make every transaction unsignable.
#[test]
fn ring_auth_is_never_a_signer_in_the_outer_instruction() {
    let init = InitSppRingConfig {
        ring: ring(),
        payer: payer(),
        authority: authority(),
        has_policy: false,
    }
    .instruction();
    let init_ring_auth = init.accounts.get(4).expect("ring_auth meta");
    assert!(!init_ring_auth.is_signer);
    // SPP allocates its RingConfig into the account, so the outer instruction must
    // still pass it writable.
    assert!(init_ring_auth.is_writable);

    let deposit = Deposit {
        proof: None,
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
fn deposit_targets_the_ring_program_with_spps_own_tag() {
    let tree = Address::new_from_array([13; 32]);
    let depositor = Address::new_from_array([14; 32]);
    let entry = sol_deposit_entry();

    let instruction = Deposit {
        proof: None,
        ring: ring(),
        cosigner: None,
        tree,
        depositor,
        deposits: vec![entry.clone()],
        escrow: EscrowBinding::Off,
    }
    .instruction()
    .expect("single SOL deposit");

    // The program dispatches on SPP's own deposit tag and forwards the data
    // verbatim, so the instruction is SPP-shaped but addressed to the ring.
    assert_eq!(instruction.program_id, ring().program_id());
    let (ix_tag, body) = split_tag(&instruction);
    assert_eq!(ix_tag, zolana_interface::instruction::tag::RING_DEPOSIT);
    assert_eq!(ix_tag, 18);

    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new_readonly(ring().cosigner_pda(), false),
            AccountMeta::new_readonly(ring().cosigner_pda(), false),
            AccountMeta::new_readonly(ring().deposit_audit_pda(), false),
            AccountMeta::new(ring().spend_window_pda(&Address::default()), false),
            AccountMeta::new(tree, false),
            AccountMeta::new(depositor, true),
            AccountMeta::new_readonly(ring().ring_auth_pda(), false),
            AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new(pda::sol_interface(), false),
        ]
    );

    let decoded = RingDepositIxData::deserialize(body).expect("body is complete ring deposit data");
    assert_eq!(
        decoded,
        RingDepositIxData {
            assets: vec![DepositAssetKind::Sol],
            deposits: vec![RingDepositEntry {
                asset_index: 0,
                view_tag: entry.view_tag,
                owner_utxo_hash: entry.owner_utxo_hash,
                amount: entry.amount,
                data_hash: entry.data_hash,
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
    let plain = build(None, 1).unwrap();
    let audited = build(Some(sample_proof()), 1).unwrap();
    assert_eq!(audited.data[0], tag::AUDITED_DEPOSIT);
    assert_eq!(
        &audited.data[1..1 + CustomRingProof::SIZE],
        wincode::serialize(&sample_proof()).unwrap()
    );
    assert_eq!(audited.data[1 + CustomRingProof::SIZE], 0);
    assert_eq!(&audited.data[2 + CustomRingProof::SIZE..], plain.data);
    assert_eq!(audited.accounts, plain.accounts);
    assert_eq!(
        audited.accounts[3],
        AccountMeta::new_readonly(ring().deposit_audit_pda(), false)
    );
    assert!(build(Some(sample_proof()), 8).is_ok());
    assert!(build(Some(sample_proof()), 9).is_err());
    assert!(build(None, 9).is_ok());
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
            escrow: EscrowBinding::Registry { root_index: 3 },
            cosigner: None,
        }
        .instruction()
    };
    let escrowed = build(Some(sample_proof())).unwrap();
    assert_eq!(escrowed.data[1 + CustomRingProof::SIZE], 3);
    assert_eq!(
        escrowed.accounts[3..5],
        [
            AccountMeta::new_readonly(ring().deposit_audit_pda(), false),
            AccountMeta::new_readonly(ring().key_registry_root_pda(), false),
        ]
    );
    assert_eq!(
        escrowed.accounts[5],
        AccountMeta::new(ring().spend_window_pda(&Address::default()), false)
    );
    assert!(matches!(
        build(None),
        Err(DepositInstructionError::AuditRequired)
    ));
}

#[test]
fn deposit_audit_setting_names_its_authority_and_canonical_pda() {
    let instruction = custom_ring_sdk::SetDepositAudit {
        ring: ring(),
        payer: payer(),
        authority: authority(),
        required: true,
    }
    .instruction()
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
        proof: None,
        ring: ring(),
        cosigner: None,
        tree: Address::new_from_array([13; 32]),
        depositor: payer(),
        deposits: vec![spl_entry, sol_deposit_entry(), second_spl_entry],
        escrow: EscrowBinding::Off,
    }
    .instruction()
    .expect("mixed batch");

    let (_ix_tag, body) = split_tag(&instruction);
    let decoded = RingDepositIxData::deserialize(body).expect("body is complete ring deposit data");
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
            .get(4..6)
            .expect("window metas")
            .to_vec(),
        vec![
            AccountMeta::new(ring().spend_window_pda(&Address::default()), false),
            AccountMeta::new(ring().spend_window_pda(&mint), false),
        ]
    );
    assert_eq!(
        instruction
            .accounts
            .get(10..)
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

/// Facts in the address tree only, no revocation target.
fn address_tree_reads() -> PolicyReads {
    PolicyReads {
        trees: vec![PolicyTreeContext {
            tree: address_tree(),
            context: context(0, 0),
        }],
        escrow: EscrowBinding::Off,
        revocation_targets: [[0; 32]; zolana_ring_policy::ANSWER_SLOTS],
        revocation_tree_indexes: [0; zolana_ring_policy::ANSWER_SLOTS],
    }
}

/// Fact 0 revokes in the address tree, fact 1 in the second tree.
fn two_tree_reads() -> PolicyReads {
    let mut revocation_targets = [[0; 32]; zolana_ring_policy::ANSWER_SLOTS];
    revocation_targets[0][31] = 7;
    revocation_targets[1][31] = 8;
    let mut revocation_tree_indexes = [0; zolana_ring_policy::ANSWER_SLOTS];
    revocation_tree_indexes[1] = 1;
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
        escrow: EscrowBinding::Off,
        revocation_targets,
        revocation_tree_indexes,
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

/// Representative confidential `RingEddsa` content carrying the auditor message
/// the ring proof commits to.
fn transact_data(interface_transfers: Vec<InterfaceTransfer>) -> TransactIxData {
    TransactIxData {
        proof: TransactProof::zeroed(),
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [61; 32],
        circuit: CircuitId::RingEddsa(2, 3, N_PUBLIC_SLOTS as u8),
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
/// prefix, one account per policy tree, the registry root and one revocation
/// PDA per target under its slot's tree, followed by SPP's
/// `RING_TRANSACT` list, which the builder takes from the interface builder
/// instead of re-listing.
#[test]
fn custom_ring_transact_prepends_payer_and_config_to_the_spp_list() {
    let proof = sample_proof();
    let transact = transact_data(Vec::new());
    let reads = PolicyReads {
        escrow: EscrowBinding::Registry { root_index: 5 },
        ..two_tree_reads()
    };

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
            AccountMeta::new(payer(), true),
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new_readonly(ring().cosigner_pda(), false),
            AccountMeta::new_readonly(ring().cosigner_pda(), false),
            AccountMeta::new_readonly(ring().policy_config_pda(), false),
            AccountMeta::new_readonly(address_tree(), false),
            AccountMeta::new_readonly(second_tree(), false),
            AccountMeta::new_readonly(ring().key_registry_root_pda(), false),
            AccountMeta::new_readonly(
                pda::nullifier_pda(&address_tree(), &reads.revocation_targets[0]).0,
                false,
            ),
            AccountMeta::new_readonly(
                pda::nullifier_pda(&second_tree(), &reads.revocation_targets[1]).0,
                false,
            ),
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
            key_registry_root_index: 5,
            approval_required: 0,
            revocation_targets: reads.revocation_targets,
            revocation_tree_indexes: reads.revocation_tree_indexes,
            transact,
        }
    );
}

/// A revocation slot naming a tree the statement does not read never builds.
#[test]
fn a_revocation_outside_the_policy_trees_is_refused() {
    let mut reads = two_tree_reads();
    reads.revocation_tree_indexes[1] = 2;
    let refused = CustomRingTransact {
        ring: ring(),
        cosigner: None,
        payer: payer(),
        input_trees: vec![input_tree()],
        output_tree: output_tree(),
        policy: Some(reads),
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        proof: sample_proof(),
        approval_required: false,
        transact: transact_data(Vec::new()),
    }
    .instruction();
    assert!(matches!(
        refused,
        Err(TransactInstructionError::RevocationTree {
            slot: 1,
            index: 2,
            trees: 2
        })
    ));
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

    // The policy config and its one tree sit before the forwarded SPP list.
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
            .get(8..)
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
    assert_eq!(decoded.key_registry_root_index, 0);
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
        instruction.accounts.get(6).expect("window meta"),
        &AccountMeta::new(ring().spend_window_pda(&Address::default()), false)
    );
    assert_eq!(
        instruction
            .accounts
            .get(13..)
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
}

const CURATOR_A: CustomRing = CustomRing::new(Address::new_from_array([20; 32]));
const CURATOR_B: CustomRing = CustomRing::new(Address::new_from_array([21; 32]));
const ASSET: [u8; 32] = [77; 32];

/// Two list rules, one of them a group, and an inline asset rule.
const TABLE: RuleTable = RuleTable::builder()
    .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
    .rule(Rule::any_of(
        Subject::Sender,
        ListSet::single(ListId::Approval),
        ListSet::single(ListId::Frozen),
    ))
    .rule(Rule::allow_only_assets())
    .inline_assets(&[ASSET])
    .build();

fn create_policy(rules: &RuleTable, shared_sources: Vec<(ListId, CustomRing)>) -> CreatePolicy<'_> {
    CreatePolicy {
        ring: ring(),
        payer: payer(),
        authority: authority(),
        address_tree: address_tree(),
        rules,
        shared_sources,
    }
}

fn set_policy_rules(
    rules: &RuleTable,
    shared_sources: Vec<(ListId, CustomRing)>,
) -> SetPolicyRules<'_> {
    SetPolicyRules {
        ring: ring(),
        authority: authority(),
        rules,
        shared_sources,
    }
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
    let instruction = create_policy(&TABLE, vec![(ListId::Frozen, CURATOR_A)])
        .instruction()
        .expect("instruction");

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
            AccountMeta::new_readonly(CURATOR_A.policy_config_pda(), false),
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
            inline_assets: vec![ASSET],
            inline_limits: vec![0],
            window_slots: 0,
            velocity: Vec::new(),
        }
    );
    // The group row carries its absent alternative at byte 19.
    assert_eq!(encoded.rules[1][19], ListSet::single(ListId::Frozen).bits());
}

#[test]
fn set_policy_rules_gates_on_the_upgrade_authority_with_the_same_body() {
    let created = create_policy(&TABLE, vec![(ListId::Frozen, CURATOR_A)])
        .instruction()
        .expect("create");
    let instruction = set_policy_rules(&TABLE, vec![(ListId::Frozen, CURATOR_A)])
        .instruction()
        .expect("instruction");

    assert_eq!(instruction.program_id, ring().program_id());
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new(ring().policy_config_pda(), false),
            AccountMeta::new_readonly(ring().program_id(), false),
            AccountMeta::new_readonly(ring().program_data_pda(), false),
            AccountMeta::new_readonly(CURATOR_A.policy_config_pda(), false),
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
        create_policy(&TABLE, shared.clone())
            .instruction()
            .expect("create"),
        set_policy_rules(&TABLE, shared).instruction().expect("set"),
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
            vec![CURATOR_B.policy_config_pda(), CURATOR_A.policy_config_pda()]
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
        create_policy(&TABLE, vec![(ListId::Block, CURATOR_A)]).instruction(),
        Err(EntryError::UnreferencedList(ListId::Block))
    ));
    assert!(matches!(
        set_policy_rules(&TABLE, vec![(ListId::Block, CURATOR_A)]).instruction(),
        Err(EntryError::UnreferencedList(ListId::Block))
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
    let pool = [[9u8; 32]; MAX_INLINE_ASSETS];
    let full = builder
        .rule(Rule::allow_only_assets())
        .inline_assets(&pool)
        .build();
    let curated: Vec<(ListId, CustomRing)> = ListId::ALL
        .into_iter()
        .map(|list_id| {
            let curator = CustomRing::new(Address::new_from_array([100 + list_id as u8; 32]));
            (list_id, curator)
        })
        .collect();

    let instruction = create_policy(&full, curated.clone())
        .instruction()
        .expect("the largest pin fits a v1 transaction");
    // The payer and the upgrade authority sign it.
    let measured = transaction_size(
        &payer(),
        core::slice::from_ref(&instruction),
        ComputeBudgetConfig::new(custom_ring_interface::CREATE_POLICY_COMPUTE_UNIT_LIMIT),
    )
    .expect("the pin compiles into a v1 message");
    assert!(
        measured.bytes > LEGACY_PACKET_DATA_SIZE,
        "a pin this size was refused while the bound was the legacy packet"
    );
    assert!(measured.bytes <= MAX_TRANSACTION_SIZE);
    assert!(measured.fits());
    create_policy(&full, Vec::new())
        .instruction()
        .expect("own sources fit");
    set_policy_rules(&full, curated)
        .instruction()
        .expect("the re-pin carries no payer, tree or system account");
}

#[test]
fn set_cosigner_creates_or_replaces_under_the_config_authority() {
    let signer = Address::new_from_array([37; 32]);
    let instruction = SetCoSigner {
        ring: ring(),
        payer: payer(),
        authority: authority(),
        signer,
        scope: CoSignScope::WITHDRAWALS,
        thresholds: vec![
            CoSignThreshold {
                mint: Address::default(),
                amount: 10,
            },
            CoSignThreshold {
                mint: Address::new_from_array([60; 32]),
                amount: 20,
            },
        ],
    }
    .instruction()
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
    let instruction = ClearCoSigner {
        ring: ring(),
        authority: authority(),
        rent_recipient,
    }
    .instruction();

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
fn set_spend_window_creates_or_replaces_under_the_config_authority() {
    let mint = Address::new_from_array([60; 32]);
    let instruction = SetSpendWindow {
        ring: ring(),
        payer: payer(),
        authority: authority(),
        mint,
        window_slots: 100,
        deposit_cap: 0,
        withdrawal_cap: 9,
    }
    .instruction()
    .expect("instruction");

    assert_eq!(instruction.program_id, ring().program_id());
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new(payer(), true),
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new(ring().spend_window_pda(&mint), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ]
    );
    let (ix_tag, body) = split_tag(&instruction);
    assert_eq!(ix_tag, tag::SET_SPEND_WINDOW);
    let mut expected = mint.to_bytes().to_vec();
    expected.extend_from_slice(&100u64.to_le_bytes());
    expected.extend_from_slice(&0u64.to_le_bytes());
    expected.extend_from_slice(&9u64.to_le_bytes());
    assert_eq!(body, expected.as_slice());
}

#[test]
fn clear_spend_window_closes_into_the_rent_recipient() {
    let mint = Address::new_from_array([60; 32]);
    let rent_recipient = Address::new_from_array([38; 32]);
    let instruction = ClearSpendWindow {
        ring: ring(),
        authority: authority(),
        mint,
        rent_recipient,
    }
    .instruction();

    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new(ring().spend_window_pda(&mint), false),
            AccountMeta::new(rent_recipient, false),
        ]
    );
    let (ix_tag, body) = split_tag(&instruction);
    assert_eq!(ix_tag, tag::CLEAR_SPEND_WINDOW);
    assert_eq!(body, mint.as_array());
}

#[test]
fn set_delegate_runs_under_the_upgrade_authority() {
    let delegate = Address::new_from_array([47; 32]);
    let instruction = SetDelegate {
        ring: ring(),
        payer: payer(),
        authority: authority(),
        delegate,
    }
    .instruction();

    assert_eq!(instruction.program_id, ring().program_id());
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new(payer(), true),
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new(ring().config_pda(), false),
            AccountMeta::new(ring().delegate_pda(), false),
            AccountMeta::new_readonly(ring().key_registry_root_pda(), false),
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

/// `[payer, config, cosigner_pda, cosigner, delegate_pda, delegate(s)]` then
/// the policy accounts and the registry root precede SPP's authority rail list,
/// a public leg never builds.
#[test]
fn delegate_transact_places_the_delegate_before_the_policy_accounts() {
    let delegate = Address::new_from_array([47; 32]);
    let reads = PolicyReads {
        escrow: EscrowBinding::Registry { root_index: 4 },
        ..two_tree_reads()
    };
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
        }
        .instruction()
    };
    let instruction = build(Vec::new()).expect("delegate transact");
    assert_eq!(
        instruction
            .accounts
            .get(..12)
            .expect("prefix metas")
            .to_vec(),
        vec![
            AccountMeta::new(payer(), true),
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new_readonly(ring().cosigner_pda(), false),
            AccountMeta::new_readonly(ring().cosigner_pda(), false),
            AccountMeta::new_readonly(ring().delegate_pda(), false),
            AccountMeta::new_readonly(delegate, true),
            AccountMeta::new_readonly(ring().policy_config_pda(), false),
            AccountMeta::new_readonly(address_tree(), false),
            AccountMeta::new_readonly(second_tree(), false),
            AccountMeta::new_readonly(ring().key_registry_root_pda(), false),
            AccountMeta::new_readonly(
                pda::nullifier_pda(&address_tree(), &reads.revocation_targets[0]).0,
                false,
            ),
            AccountMeta::new_readonly(
                pda::nullifier_pda(&second_tree(), &reads.revocation_targets[1]).0,
                false,
            ),
        ]
    );
    assert_eq!(
        instruction.accounts.get(16).expect("ring_config meta"),
        &AccountMeta::new_readonly(ring().ring_auth_pda(), false)
    );
    let (ix_tag, body) = split_tag(&instruction);
    assert_eq!(ix_tag, tag::DELEGATE_TRANSACT);
    assert_eq!(ix_tag, 25);
    let decoded: CustomRingTransactIxData = wincode::deserialize_exact(body).expect("body");
    assert_eq!(decoded.key_registry_root_index, 4);
    assert_eq!(decoded.policy_trees, vec![context(1, 2), context(3, 4)]);
    assert!(matches!(
        build(vec![InterfaceTransfer::SolWithdrawal { amount: 1 }]),
        Err(TransactInstructionError::PublicLeg)
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
        build(None).accounts[2..4],
        [
            AccountMeta::new_readonly(ring().cosigner_pda(), false),
            AccountMeta::new_readonly(ring().cosigner_pda(), false),
        ]
    );
    assert_eq!(
        build(Some(cosigner)).accounts[3],
        AccountMeta::new_readonly(cosigner, true)
    );
    let deposit = Deposit {
        proof: None,
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
