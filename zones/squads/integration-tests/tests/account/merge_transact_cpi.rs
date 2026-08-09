//! `spp_program` is the zone program's own id, a deliberate placeholder the
//! exact-SPP-address check in `spp_merge_transact` rejects with
//! `InvalidSppProgram`. Reaching that error proves every zone-side step
//! before the CPI ran. The whitelist negative fails earlier and
//! discriminates the two. The zone verifies no proof on this path, so no
//! prover is needed.

use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_zone_tests::{custom_code, SquadsZoneTest};
use zolana_interface::instruction::instruction_data::merge_transact::MERGE_INPUT_COUNT;
use zolana_squads_interface::{
    constants::{ENCRYPTION_SCHEME_P256_AES, OWNER_KIND_KEYPAIR, VIEWING_KEY_STATE_ACTIVE},
    error::SquadsZoneError,
    instruction::{builders::MergeTransact, instruction_data::InputContext, MergeTransactIxData},
    state::{viewing_key_account::ViewingKeyAccount, zone_config::ZoneConfig},
    types::Address,
    RING_AUTH_PDA_SEED, ZONE_CONFIG_PDA_SEED,
};

fn zone_config_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[ZONE_CONFIG_PDA_SEED], program_id).0
}

fn ring_auth_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[RING_AUTH_PDA_SEED], program_id).0
}

/// The program enforces exactly one auditor key.
fn create_zone_config(test: &mut SquadsZoneTest, merge_authority: &Pubkey) -> Pubkey {
    let zone_config = zone_config_pda(&test.program_id);
    let config = ZoneConfig::new(
        Address::new_from_array([7u8; 32]),
        Address::default(),
        3_600,
        vec![[9u8; 33]],
        vec![Address::new_from_array(merge_authority.to_bytes())],
    );
    test.set_program_account(
        &zone_config,
        config.serialize().expect("serialize zone config"),
    )
    .expect("seed zone config");
    zone_config
}

/// `merge_transact` binds the merged output's index tag to this account's
/// shared viewing key and never parses the rest of the key material.
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

/// The index tag `merge_transact` expects: the X coordinate of the account's
/// SEC1-compressed shared viewing key.
const OWNER_VIEW_TAG: [u8; 32] = [2u8; 32];

fn merge_data() -> MergeTransactIxData {
    let input_contexts = (0..MERGE_INPUT_COUNT as u8)
        .map(|i| InputContext {
            nullifier: [i; 32],
            tree_index: 0,
            utxo_root_index: u16::from(i),
            nullifier_root_index: u16::from(i),
        })
        .collect();
    MergeTransactIxData {
        spp_proof: [2u8; 192],
        expiry_unix_ts: u64::MAX,
        output_ring_data_hash: OWNER_VIEW_TAG,
        private_tx_hash: [6u8; 32],
        output_utxo_hash: [8u8; 32],
        input_contexts,
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
        ring_auth: ring_auth_pda(&test.program_id),
        spp_program: test.program_id,
        tree_accounts: vec![Keypair::new().pubkey()],
        data: merge_data(),
    }
    .instruction()
}

#[test]
fn merge_transact_passes_zone_checks_then_attempts_spp_cpi() {
    let mut test = SquadsZoneTest::new().expect("boot");
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
fn merge_transact_rejects_a_missing_authority_signature() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let merge_authority = Keypair::new();
    let zone_config = create_zone_config(&mut test, &merge_authority.pubkey());
    let owner_vka = install_owner_vka(&mut test);

    let mut ix = merge_ix(&test, &merge_authority.pubkey(), zone_config, owner_vka);
    ix.accounts[0].is_signer = false;
    let err = test
        .send(&[ix], &[])
        .expect_err("expected MissingMergeAuthoritySignature");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::MissingMergeAuthoritySignature as u32,
    );
}

/// The tag indexes the merged output for wallet discovery, so a merge that
/// files it under a different account must be rejected.
#[test]
fn merge_transact_rejects_a_foreign_output_tag() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let merge_authority = Keypair::new();
    test.airdrop(&merge_authority.pubkey(), 1_000_000_000)
        .expect("fund merge authority");
    let zone_config = create_zone_config(&mut test, &merge_authority.pubkey());
    let owner_vka = install_owner_vka(&mut test);

    let mut ix = merge_ix(&test, &merge_authority.pubkey(), zone_config, owner_vka);
    let mut data = merge_data();
    data.output_ring_data_hash = [3u8; 32];
    let mut bytes = vec![zolana_squads_interface::instruction::tag::MERGE_TRANSACT];
    bytes.extend_from_slice(&data.serialize().expect("serialize merge data"));
    ix.data = bytes;

    let err = test
        .send(&[ix], &[&merge_authority])
        .expect_err("a foreign output tag must be rejected");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::MergeOutputTagMismatch as u32,
    );
}

#[test]
fn merge_transact_rejects_non_whitelisted_authority() {
    let mut test = SquadsZoneTest::new().expect("boot");
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
