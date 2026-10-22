//! LiteSVM integration tests for the `merge_transact` ring-side path: signer
//! check, merge-authority whitelist, viewing-key-account load, the
//! no-ring-data output check, and the reach of the SPP forwarding step.
//!
//! The forwarded SPP account list is the real `merge_ring` layout built by
//! `zolana_program::instruction::MergeRing`, except that the SPP program account
//! is replaced by the ring program's own id -- a deliberate placeholder.
//! `forward_to_spp` requires the SPP program account BEFORE attempting the CPI,
//! so reaching `InvalidSppProgram` proves every ring-side step ran; the negative
//! tests are the discriminating counterparts that fail earlier. No prover is
//! needed: the ring verifies no proof on this path (the merge proof verifies
//! inside SPP).
//!
//! Requires the prebuilt program binary; build it with
//! `cd rings/squads/program && cargo build-sbf --features bpf-entrypoint`.
//! Tests skip (return early, do not fail) when the `.so` is missing.

use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_ring_tests::{custom_code, SquadsRingTest};
use zolana_interface::{
    instruction::{
        instruction_data::merge_transact::{
            MergeOutputEncryption, MergeProof, MERGE_DEFAULT_INPUT_COUNT,
        },
        MergeRingIxData, MergeTransactIxData as SppMergeTransactIxData,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_program::instruction::MergeRing;
use zolana_squads_interface::{
    constants::{ENCRYPTION_SCHEME_X25519_AES, OWNER_KIND_KEYPAIR, VIEWING_KEY_STATE_ACTIVE},
    error::SquadsRingError,
    instruction::{
        builders::{CreateRingConfig, MergeTransact},
        CreateRingConfigIxData, MergeTransactIxData,
    },
    state::viewing_key_account::ViewingKeyAccount,
    types::Address,
    RING_CONFIG_PDA_SEED,
};

fn ring_config_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[RING_CONFIG_PDA_SEED], program_id).0
}

/// Install the ring config with `merge_authority` whitelisted (one dummy
/// auditor key; the program enforces length 1).
fn create_ring_config(test: &mut SquadsRingTest, merge_authority: &Pubkey) -> Pubkey {
    let creator = Keypair::new();
    test.airdrop(&creator.pubkey(), 1_000_000_000)
        .expect("fund creator");
    let ring_config = ring_config_pda(&test.program_id);
    let ix = CreateRingConfig {
        creator: creator.pubkey(),
        ring_config,
        system_program: Pubkey::default(),
        data: CreateRingConfigIxData {
            authority: Pubkey::new_from_array([7u8; 32]),
            co_signer: Pubkey::default(),
            max_proposal_lifetime: 3_600,
            auditor_keys: vec![[9u8; 33]],
            merge_authorities: vec![*merge_authority],
        },
    }
    .instruction();
    test.send(&[ix], &[&creator]).expect("create_ring_config");
    ring_config
}

/// Install a minimal owner viewing key account fixture; `merge_transact` only
/// loads it (owner + discriminator), never parses the key material.
fn install_owner_vka(test: &mut SquadsRingTest) -> Pubkey {
    let address = Keypair::new().pubkey();
    let account = ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: Address::new_from_array([1u8; 32]),
        state: VIEWING_KEY_STATE_ACTIVE,
        encryption_scheme: ENCRYPTION_SCHEME_X25519_AES,
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

/// An SPP `merge_ring` payload with the default input count. The ring forwards
/// it unverified, so the proof and hashes are placeholders.
fn merge_data(output_ring_data_hash: [u8; 32]) -> MergeTransactIxData {
    let nullifiers = (1..=MERGE_DEFAULT_INPUT_COUNT)
        .map(|i| [u8::try_from(i).expect("small index"); 32])
        .collect();
    MergeTransactIxData {
        spp: MergeRingIxData {
            output_ring_data_hash,
            merge: SppMergeTransactIxData {
                expiry_unix_ts: u64::MAX,
                proof: MergeProof::zeroed(),
                output_utxo_hash: [8u8; 32],
                output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
                    salt: [0; 16],
                    ciphertext: [[0; 32]; 3],
                },
                private_tx_hash: [6u8; 32],
                nullifiers,
                utxo_tree_root_index: 0,
                nullifier_tree_root_index: 0,
                cache_slot: None,
            },
        },
    }
}

/// The SPP `merge_ring` account list for `data`, paid by `merge_authority`, with
/// the SPP program account replaced by the ring program's own id.
fn placeholder_spp_accounts(
    test: &SquadsRingTest,
    merge_authority: &Pubkey,
    data: &MergeTransactIxData,
) -> Vec<AccountMeta> {
    let spp_program = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    MergeRing {
        input_tree: Keypair::new().pubkey(),
        output_tree: Keypair::new().pubkey(),
        ring_program_id: test.program_id,
        payer: *merge_authority,
        data: data.spp.merge.clone(),
        output_ring_data_hash: data.spp.output_ring_data_hash,
        cache: None,
    }
    .instruction()
    .accounts
    .into_iter()
    .map(|meta| {
        if meta.pubkey == spp_program {
            AccountMeta::new_readonly(test.program_id, false)
        } else {
            meta
        }
    })
    .collect()
}

fn merge_ix(
    test: &SquadsRingTest,
    merge_authority: &Pubkey,
    ring_config: Pubkey,
    owner_vka: Pubkey,
    data: MergeTransactIxData,
) -> Instruction {
    MergeTransact {
        merge_authority: *merge_authority,
        ring_config,
        owner_viewing_key_account: owner_vka,
        spp_accounts: placeholder_spp_accounts(test, merge_authority, &data),
        data,
    }
    .instruction()
}

/// Boot, whitelist a funded merge authority, and install the owner VKA.
fn setup() -> Option<(SquadsRingTest, Keypair, Pubkey, Pubkey)> {
    let mut test = SquadsRingTest::new().expect("boot")?;
    let merge_authority = Keypair::new();
    test.airdrop(&merge_authority.pubkey(), 1_000_000_000)
        .expect("fund merge authority");
    let ring_config = create_ring_config(&mut test, &merge_authority.pubkey());
    let owner_vka = install_owner_vka(&mut test);
    Some((test, merge_authority, ring_config, owner_vka))
}

#[test]
fn merge_transact_passes_ring_checks_then_attempts_spp_cpi() {
    let Some((mut test, merge_authority, ring_config, owner_vka)) = setup() else {
        return;
    };

    let ix = merge_ix(
        &test,
        &merge_authority.pubkey(),
        ring_config,
        owner_vka,
        merge_data([0u8; 32]),
    );
    let err = test
        .send(&[ix], &[&merge_authority])
        .expect_err("the placeholder spp_program must be rejected after all ring-side checks");
    assert_eq!(custom_code(&err), SquadsRingError::InvalidSppProgram as u32);
}

#[test]
fn merge_transact_rejects_non_whitelisted_authority() {
    let Some((mut test, _merge_authority, ring_config, owner_vka)) = setup() else {
        return;
    };
    let impostor = Keypair::new();
    test.airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund impostor");

    let ix = merge_ix(
        &test,
        &impostor.pubkey(),
        ring_config,
        owner_vka,
        merge_data([0u8; 32]),
    );
    let err = test
        .send(&[ix], &[&impostor])
        .expect_err("a non-whitelisted merge authority must be rejected");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::MergeAuthorityNotWhitelisted as u32,
    );
}

/// Squads UTXOs carry no ring data, so a merged output that selects a ring data
/// hash is rejected before forwarding.
#[test]
fn merge_transact_rejects_output_ring_data_hash() {
    let Some((mut test, merge_authority, ring_config, owner_vka)) = setup() else {
        return;
    };

    let ix = merge_ix(
        &test,
        &merge_authority.pubkey(),
        ring_config,
        owner_vka,
        merge_data([5u8; 32]),
    );
    let err = test
        .send(&[ix], &[&merge_authority])
        .expect_err("a non-zero output ring data hash must be rejected");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::InvalidInstructionData as u32,
    );
}
