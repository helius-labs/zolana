//! LiteSVM integration tests for the `merge_transact` zone-side path: signer
//! check, merge-authority whitelist, viewing-key-account load, SPP
//! instruction-data build (shape + ciphertext-prefix checks), and the reach
//! of the SPP CPI gate.
//!
//! Like `transact_e2e`, `spp_program` is the zone program's own id -- a
//! deliberate placeholder the exact-SPP-address check in `spp_merge_transact`
//! rejects with `InvalidSppProgram`. Reaching that error proves every
//! zone-side step before the CPI ran; the whitelist negative is the
//! discriminating counterpart that fails earlier. No prover is needed: the
//! zone verifies no proof on this path (both proofs verify inside SPP).
//!
//! Requires the prebuilt program binary; build it with
//! `cd zones/squads/program && cargo build-sbf --features bpf-entrypoint`.
//! Tests skip (return early, do not fail) when the `.so` is missing.

use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_zone_tests::{custom_code, SquadsZoneTest};
use zolana_interface::instruction::instruction_data::merge_transact::{
    MERGE_ENCRYPTED_UTXO_TYPE_PREFIX, MERGE_INPUT_COUNT,
};
use zolana_squads_interface::{
    constants::{ENCRYPTION_SCHEME_P256_AES, OWNER_KIND_KEYPAIR, VIEWING_KEY_STATE_ACTIVE},
    error::SquadsZoneError,
    instruction::{
        builders::{CreateZoneConfig, MergeTransact},
        instruction_data::InputContext,
        CreateZoneConfigIxData, MergeTransactIxData,
    },
    state::viewing_key_account::ViewingKeyAccount,
    types::Address,
    ZONE_AUTH_PDA_SEED, ZONE_CONFIG_PDA_SEED,
};

fn zone_config_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[ZONE_CONFIG_PDA_SEED], program_id).0
}

fn zone_auth_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[ZONE_AUTH_PDA_SEED], program_id).0
}

/// Install the zone config with `merge_authority` whitelisted (one dummy
/// auditor key; the program enforces length 1).
fn create_zone_config(test: &mut SquadsZoneTest, merge_authority: &Pubkey) -> Pubkey {
    let creator = Keypair::new();
    test.airdrop(&creator.pubkey(), 1_000_000_000)
        .expect("fund creator");
    let zone_config = zone_config_pda(&test.program_id);
    let ix = CreateZoneConfig {
        creator: creator.pubkey(),
        zone_config,
        system_program: Pubkey::default(),
        data: CreateZoneConfigIxData {
            authority: Pubkey::new_from_array([7u8; 32]),
            co_signer: Pubkey::default(),
            max_proposal_lifetime: 3_600,
            auditor_keys: vec![[9u8; 33]],
            merge_authorities: vec![*merge_authority],
        },
    }
    .instruction();
    test.send(&[ix], &[&creator]).expect("create_zone_config");
    zone_config
}

/// Install a minimal owner viewing key account fixture; `merge_transact` only
/// loads it (owner + discriminator), never parses the key material.
fn install_owner_vka(test: &mut SquadsZoneTest) -> Pubkey {
    let address = Keypair::new().pubkey();
    let account = ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: Address::new_from_array([1u8; 32]),
        state: VIEWING_KEY_STATE_ACTIVE,
        encryption_scheme: ENCRYPTION_SCHEME_P256_AES,
        owner_kind: OWNER_KIND_KEYPAIR,
        shared_viewing_key: [2u8; 33],
        shared_viewing_key_commitment: [3u8; 32],
        key_nonce: 0,
        nullifier_pubkey: [4u8; 32],
        key_ciphertext_ephemeral: [0u8; 33],
        encrypted_nullifier_secret: [0u8; 31],
        recovery_keys: vec![],
        recovery_key_ciphertexts: vec![],
        auditor_keys: vec![],
        auditor_key_ciphertexts: vec![],
    };
    let data = account.serialize().expect("serialize vka");
    test.set_program_account(&address, data)
        .expect("install vka");
    address
}

fn merge_data() -> MergeTransactIxData {
    let input_contexts = (0..MERGE_INPUT_COUNT as u8)
        .map(|i| InputContext {
            nullifier: [i; 32],
            tree_index: 0,
            utxo_root_index: u16::from(i),
            nullifier_root_index: u16::from(i),
        })
        .collect();
    let mut encrypted_utxo = vec![MERGE_ENCRYPTED_UTXO_TYPE_PREFIX];
    encrypted_utxo.extend(std::iter::repeat_n(7u8, 109));
    MergeTransactIxData {
        spp_proof: [2u8; 192],
        expiry_unix_ts: u64::MAX,
        merge_view_tag: [5u8; 32],
        private_tx_hash: [6u8; 32],
        output_utxo_hash: [8u8; 32],
        input_contexts,
        encrypted_utxo,
    }
}

fn merge_ix(
    test: &SquadsZoneTest,
    merge_authority: &Pubkey,
    zone_config: Pubkey,
    owner_vka: Pubkey,
) -> solana_instruction::Instruction {
    MergeTransact {
        merge_authority: *merge_authority,
        zone_config,
        owner_viewing_key_account: owner_vka,
        zone_auth: zone_auth_pda(&test.program_id),
        spp_program: test.program_id,
        tree_accounts: vec![Keypair::new().pubkey()],
        data: merge_data(),
    }
    .instruction()
}

#[test]
fn merge_transact_passes_zone_checks_then_attempts_spp_cpi() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let merge_authority = Keypair::new();
    test.airdrop(&merge_authority.pubkey(), 1_000_000_000)
        .expect("fund merge authority");
    let zone_config = create_zone_config(&mut test, &merge_authority.pubkey());
    let owner_vka = install_owner_vka(&mut test);

    let ix = merge_ix(&test, &merge_authority.pubkey(), zone_config, owner_vka);
    let err = test
        .send(&[ix], &[&merge_authority])
        .expect_err("the placeholder spp_program must be rejected after all zone-side checks");
    assert_eq!(custom_code(&err), SquadsZoneError::InvalidSppProgram as u32);
}

#[test]
fn merge_transact_rejects_non_whitelisted_authority() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let merge_authority = Keypair::new();
    let impostor = Keypair::new();
    for key in [&merge_authority, &impostor] {
        test.airdrop(&key.pubkey(), 1_000_000_000).expect("fund");
    }
    let zone_config = create_zone_config(&mut test, &merge_authority.pubkey());
    let owner_vka = install_owner_vka(&mut test);

    let ix = merge_ix(&test, &impostor.pubkey(), zone_config, owner_vka);
    let err = test
        .send(&[ix], &[&impostor])
        .expect_err("a non-whitelisted merge authority must be rejected");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::MergeAuthorityNotWhitelisted as u32,
    );
}
