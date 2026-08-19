//! The instruction builders must reproduce the account order, privileges and
//! instruction data the program's processors and SPP's loaders expect. Each
//! expected list below is the one asserted by the program's own fixtures in
//! `custom-rings/program/tests/common/mod.rs`.

use custom_ring_sdk::{
    config_pda, program_data_pda, ring_auth_pda, tag, AuditProof, CreateConfig, CreateConfigIxData,
    CustomRingTransactIxData, Deposit, InitSppRingConfig, RingTransactWithAudit, CONFIG_PDA_SEED,
    PROGRAM_ID,
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
use zolana_keypair::{P256Pubkey, ViewingKey};

/// The system program is the all-zero address.
const SYSTEM_PROGRAM: Address = Address::new_from_array([0u8; 32]);

fn payer() -> Address {
    Address::new_from_array([11; 32])
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
        payer: payer(),
        authority: authority(),
        auditor_pubkey,
    }
    .instruction();

    assert_eq!(instruction.program_id, PROGRAM_ID);
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new(payer(), true),
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new(config_pda(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(PROGRAM_ID, false),
            AccountMeta::new_readonly(program_data_pda(), false),
        ]
    );

    let (ix_tag, body) = split_tag(&instruction);
    assert_eq!(ix_tag, tag::CREATE_CONFIG);
    let decoded: CreateConfigIxData =
        wincode::deserialize_exact(body).expect("body is a complete CreateConfigIxData");
    assert_eq!(decoded.auditor_pubkey, *auditor_pubkey.as_bytes());
}

#[test]
fn init_spp_ring_config_emits_the_program_account_order_and_no_body() {
    let instruction = InitSppRingConfig {
        payer: payer(),
        authority: authority(),
    }
    .instruction();

    assert_eq!(instruction.program_id, PROGRAM_ID);
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new(payer(), true),
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new_readonly(pda::protocol_config(), false),
            AccountMeta::new(ring_auth_pda(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
        ]
    );
    // The processor rejects any trailing byte, so the tag has to be the whole
    // instruction data.
    assert_eq!(instruction.data, vec![tag::INIT_SPP_RING_CONFIG]);
}

#[test]
fn builders_place_the_canonical_config_and_ring_auth_pdas() {
    let (config, _bump) = Address::find_program_address(&[CONFIG_PDA_SEED], &PROGRAM_ID);
    let (ring_auth, _bump) = Address::find_program_address(&[RING_AUTH_PDA_SEED], &PROGRAM_ID);
    let (program_data, _bump) = Address::find_program_address(
        &[PROGRAM_ID.as_ref()],
        &Address::new_from_array(BPF_LOADER_UPGRADEABLE_ID),
    );
    assert_eq!(config_pda(), config);
    assert_eq!(ring_auth_pda(), ring_auth);
    assert_eq!(program_data_pda(), program_data);

    let create_config = CreateConfig {
        payer: payer(),
        authority: authority(),
        auditor_pubkey: auditor_pubkey(),
    }
    .instruction();
    assert_eq!(
        create_config.accounts.get(2).expect("config meta").pubkey,
        config
    );

    let init = InitSppRingConfig {
        payer: payer(),
        authority: authority(),
    }
    .instruction();
    assert_eq!(
        init.accounts.get(4).expect("ring_auth meta").pubkey,
        ring_auth
    );

    let deposit = Deposit {
        tree: Address::new_from_array([13; 32]),
        depositor: payer(),
        deposits: vec![sol_deposit_entry()],
    }
    .instruction()
    .expect("single SOL deposit");
    assert_eq!(
        deposit.accounts.first().expect("config meta").pubkey,
        config_pda()
    );
    assert_eq!(
        deposit.accounts.get(3).expect("ring_config meta").pubkey,
        ring_auth
    );
}

/// `ring_auth` has no keypair: only the ring program can produce its signature,
/// and it does so with `invoke_signed` inside the CPI. A builder that already
/// marked it a signer would make every transaction unsignable.
#[test]
fn ring_auth_is_never_a_signer_in_the_outer_instruction() {
    let init = InitSppRingConfig {
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
        tree: Address::new_from_array([13; 32]),
        depositor: payer(),
        deposits: vec![sol_deposit_entry()],
    }
    .instruction()
    .expect("single SOL deposit");
    let deposit_ring_config = deposit.accounts.get(3).expect("ring_config meta");
    assert!(!deposit_ring_config.is_signer);
}

#[test]
fn deposit_targets_the_ring_program_with_spps_own_tag() {
    let tree = Address::new_from_array([13; 32]);
    let depositor = Address::new_from_array([14; 32]);
    let entry = sol_deposit_entry();

    let instruction = Deposit {
        tree,
        depositor,
        deposits: vec![entry.clone()],
    }
    .instruction()
    .expect("single SOL deposit");

    // The program dispatches on SPP's own deposit tag and forwards the data
    // verbatim, so the instruction is SPP-shaped but addressed to the ring, with
    // the ring config in front for the policy read.
    assert_eq!(instruction.program_id, PROGRAM_ID);
    let (ix_tag, body) = split_tag(&instruction);
    assert_eq!(ix_tag, zolana_interface::instruction::tag::RING_DEPOSIT);
    assert_eq!(ix_tag, 14);

    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new(tree, false),
            AccountMeta::new(depositor, true),
            AccountMeta::new_readonly(ring_auth_pda(), false),
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
            .get(5..)
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

fn owner_signer() -> Address {
    Address::new_from_array([43; 32])
}

fn audit_proof() -> AuditProof {
    AuditProof {
        proof_a: [51; 32],
        proof_b: [52; 64],
        proof_c: [53; 32],
        commitment: [54; 32],
        commitment_pok: [55; 32],
    }
}

/// A representative confidential `RingEddsa` payload carrying the auditor message
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
/// `[payer, config]` prefix followed by SPP's `RING_TRANSACT` list, which the
/// builder takes from the interface builder instead of re-listing.
#[test]
fn ring_transact_with_audit_prepends_payer_and_config_to_the_spp_list() {
    let proof = audit_proof();
    let transact = transact_data(Vec::new());

    let instruction = RingTransactWithAudit {
        payer: payer(),
        input_tree: input_tree(),
        output_tree: output_tree(),
        owner_signers: vec![owner_signer()],
        approval: None,
        interface_transfer_accounts: Vec::new(),
        audit_proof: proof,
        transact: transact.clone(),
    }
    .instruction()
    .expect("serialize the audited transact payload");

    assert_eq!(instruction.program_id, PROGRAM_ID);
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new(payer(), true),
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new(payer(), true),
            AccountMeta::new(input_tree(), false),
            AccountMeta::new(output_tree(), false),
            AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(ring_auth_pda(), false),
            AccountMeta::new_readonly(owner_signer(), true),
        ]
    );

    let (ix_tag, body) = split_tag(&instruction);
    assert_eq!(ix_tag, tag::TRANSACT);
    assert_eq!(ix_tag, 3);
    let decoded: CustomRingTransactIxData =
        wincode::deserialize_exact(body).expect("body is a complete CustomRingTransactIxData");
    assert_eq!(decoded, CustomRingTransactIxData { proof, transact });
}

/// `ring_config` is this program's `ring_auth` PDA, and no keypair exists for it:
/// only the program can sign for it, inside its CPI. A signer meta here would make
/// the transaction unsignable.
#[test]
fn ring_transact_with_audit_leaves_ring_config_unsigned() {
    let instruction = RingTransactWithAudit {
        payer: payer(),
        input_tree: input_tree(),
        output_tree: output_tree(),
        owner_signers: Vec::new(),
        approval: None,
        interface_transfer_accounts: Vec::new(),
        audit_proof: audit_proof(),
        transact: transact_data(Vec::new()),
    }
    .instruction()
    .expect("serialize the audited transact payload");

    let ring_config = instruction.accounts.get(7).expect("ring_config meta");
    assert_eq!(ring_config.pubkey, ring_auth_pda());
    assert!(!ring_config.is_signer);
}

/// Settlement accounts come from the same interface builder, so a withdrawal's
/// group has to appear after the owner signers untouched.
#[test]
fn ring_transact_with_audit_forwards_settlement_accounts() {
    let recipient = Address::new_from_array([44; 32]);

    let instruction = RingTransactWithAudit {
        payer: payer(),
        input_tree: input_tree(),
        output_tree: output_tree(),
        owner_signers: vec![owner_signer()],
        approval: None,
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts { recipient },
        )],
        audit_proof: audit_proof(),
        transact: transact_data(vec![InterfaceTransfer::SolWithdrawal { amount: 5 }]),
    }
    .instruction()
    .expect("serialize the audited transact payload");

    assert_eq!(
        instruction
            .accounts
            .get(8..)
            .expect("owner signer and settlement metas")
            .to_vec(),
        vec![
            AccountMeta::new_readonly(owner_signer(), true),
            AccountMeta::new(pda::sol_interface(), false),
            AccountMeta::new(recipient, false),
        ]
    );
}
