//! The instruction builders must reproduce the account order, privileges and
//! instruction data the program's processors and SPP's loaders expect. Each
//! expected list below is the one asserted by the program's own fixtures in
//! `custom-rings/program/tests/common/mod.rs`.

use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
use custom_ring_sdk::{
    tag, CreateConfig, CreateConfigIxData, CustomRing, CustomRingProof, CustomRingTransact,
    CustomRingTransactIxData, Deposit, GrantReadAccess, InitSppRingConfig, ReaderIxData, ReaderKey,
    ReaderKeyError, RevokeReadAccess, SetAuthority, CONFIG_PDA_SEED, READ_ACCESS_RECORD_PDA_SEED,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_interface::{
    instruction::{
        CircuitId, DepositAsset, DepositAssetKind, DepositSplAccounts, EncryptedRingDepositData,
        InterfaceTransfer, MessageData, RingAssetDeposit, RingDepositEntry, RingDepositIxData,
        TransactInterfaceTransferAccounts, TransactIxData, TransactProof,
        TransactSolTransferAccounts,
    },
    pda, BPF_LOADER_UPGRADEABLE_ID, N_PUBLIC_SLOTS, RING_AUTH_PDA_SEED,
};
use zolana_keypair::{P256Pubkey, SigningKey, ViewingKey};

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
fn read_access_record_pda_derives_from_the_hashed_tagged_key() {
    use sha2::Digest;
    for key in [reader(), p256_reader()] {
        let seed_hash: [u8; 32] = sha2::Sha256::digest(key.to_bytes()).into();
        let (entry, _bump) = Address::find_program_address(
            &[READ_ACCESS_RECORD_PDA_SEED, &seed_hash],
            &ring().program_id(),
        );
        assert_eq!(ring().read_access_record_pda(&key), entry);
        assert_eq!(key.entry_address(&ring().program_id()), entry);
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
    }
    .instruction();
    assert_eq!(
        init.accounts.get(4).expect("ring_auth meta").pubkey,
        ring_auth
    );

    let deposit = Deposit {
        ring: ring(),
        tree: Address::new_from_array([13; 32]),
        depositor: payer(),
        deposits: vec![sol_deposit_entry()],
    }
    .instruction()
    .expect("single SOL deposit");
    assert_eq!(
        deposit.accounts.get(2).expect("ring_config meta").pubkey,
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
    }
    .instruction();
    let init_ring_auth = init.accounts.get(4).expect("ring_auth meta");
    assert!(!init_ring_auth.is_signer);
    // SPP allocates its RingConfig into the account, so the outer instruction must
    // still pass it writable.
    assert!(init_ring_auth.is_writable);

    let deposit = Deposit {
        ring: ring(),
        tree: Address::new_from_array([13; 32]),
        depositor: payer(),
        deposits: vec![sol_deposit_entry()],
    }
    .instruction()
    .expect("single SOL deposit");
    let deposit_ring_config = deposit.accounts.get(2).expect("ring_config meta");
    assert!(!deposit_ring_config.is_signer);
}

#[test]
fn deposit_targets_the_ring_program_with_spps_own_tag() {
    let tree = Address::new_from_array([13; 32]);
    let depositor = Address::new_from_array([14; 32]);
    let entry = sol_deposit_entry();

    let instruction = Deposit {
        ring: ring(),
        tree,
        depositor,
        deposits: vec![entry.clone()],
    }
    .instruction()
    .expect("single SOL deposit");

    // The program dispatches on SPP's own deposit tag and forwards the data
    // verbatim, so the instruction is SPP-shaped but addressed to the ring.
    assert_eq!(instruction.program_id, ring().program_id());
    let (ix_tag, body) = split_tag(&instruction);
    assert_eq!(ix_tag, zolana_interface::instruction::tag::RING_DEPOSIT);
    assert_eq!(ix_tag, 14);

    assert_eq!(
        instruction.accounts,
        vec![
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

    let instruction = Deposit {
        ring: ring(),
        tree: Address::new_from_array([13; 32]),
        depositor: payer(),
        deposits: vec![spl_entry, sol_deposit_entry()],
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
        vec![(1, 42), (0, 7_000_000)]
    );
    assert_eq!(
        instruction
            .accounts
            .get(4..)
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

fn entries_tree() -> Address {
    Address::new_from_array([45; 32])
}

fn owner_signer() -> Address {
    Address::new_from_array([43; 32])
}

fn sample_proof() -> CustomRingProof {
    CustomRingProof {
        proof_a: [51; 32],
        proof_b: [52; 64],
        proof_c: [53; 32],
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
    }
}

/// The account list the program's `process_transact_ix` reads: its own
/// `[payer, config, policy_config, entries_tree]` prefix followed by SPP's
/// `RING_TRANSACT` list, which the builder takes from the interface builder
/// instead of re-listing.
#[test]
fn custom_ring_transact_prepends_payer_and_config_to_the_spp_list() {
    let proof = sample_proof();
    let transact = transact_data(Vec::new());

    let instruction = CustomRingTransact {
        ring: ring(),
        payer: payer(),
        input_tree: input_tree(),
        output_tree: output_tree(),
        entries_tree: Some(entries_tree()),
        owner_signers: vec![owner_signer()],
        interface_transfer_accounts: Vec::new(),
        proof,
        state_root_index: 0,
        nullifier_root_index: 0,
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
            AccountMeta::new_readonly(ring().policy_config_pda(), false),
            AccountMeta::new_readonly(entries_tree(), false),
            AccountMeta::new(payer(), true),
            AccountMeta::new(input_tree(), false),
            AccountMeta::new(output_tree(), false),
            AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(ring().ring_auth_pda(), false),
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
            state_root_index: 0,
            nullifier_root_index: 0,
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
        payer: payer(),
        input_tree: input_tree(),
        output_tree: output_tree(),
        entries_tree: Some(entries_tree()),
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        proof: sample_proof(),
        state_root_index: 0,
        nullifier_root_index: 0,
        transact: transact_data(Vec::new()),
    }
    .instruction()
    .expect("serialize the custom-ring transact content");

    // The policy config and entries tree sit before the forwarded SPP list.
    let ring_config_index = 9;
    let ring_config = instruction
        .accounts
        .get(ring_config_index)
        .expect("ring_config meta");
    assert_eq!(ring_config.pubkey, ring().ring_auth_pda());
    assert!(!ring_config.is_signer);
}

/// Settlement accounts come from the same interface builder, so a withdrawal's
/// group has to appear after the owner signers untouched.
#[test]
fn custom_ring_transact_forwards_settlement_accounts() {
    let recipient = Address::new_from_array([44; 32]);

    let instruction = CustomRingTransact {
        ring: ring(),
        payer: payer(),
        input_tree: input_tree(),
        output_tree: output_tree(),
        entries_tree: Some(entries_tree()),
        owner_signers: vec![owner_signer()],
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts { recipient },
        )],
        proof: sample_proof(),
        state_root_index: 0,
        nullifier_root_index: 0,
        transact: transact_data(vec![InterfaceTransfer::SolWithdrawal { amount: 5 }]),
    }
    .instruction()
    .expect("serialize the custom-ring transact content");

    assert_eq!(
        instruction
            .accounts
            .get(10..)
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
    assert_eq!(tag::DEPOSIT, 14);
}
