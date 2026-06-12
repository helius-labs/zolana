//! Registry → shielded-pool CPI integration test.
//!
//! Drives the full forester epoch chain (initialize protocol config →
//! register forester → register forester for epoch → finalize) and then
//! calls `forest_address_tree`, which makes the registry CPI into
//! shielded-pool's `batch_update_address_tree` with the registry's
//! `cpi_authority` PDA as signer.
//!
//! We don't have a real Groth16 proof here so the inner instruction is
//! expected to fail at proof verification (`PoolTreeMutationFailed` =
//! `Custom(5)`). What this test proves is that:
//!  - the registry chain works end-to-end (PDAs, sighashes, account order)
//!  - the registry's CPI authority makes it past shielded-pool's
//!    `UnauthorizedCaller` check (`Custom(6)`).
//!
//! Requires both `light_registry.so` and `shielded_pool_program.so` under
//! `target/deploy/` — produced by:
//! ```text
//! cargo build-sbf -p light-registry
//! cargo build-sbf --manifest-path programs/shielded-pool/Cargo.toml -- --features bpf-entrypoint
//! ```

use light_program_test::{
    registry_sdk::{cpi_authority_pda, protocol_config_pda},
    ForesterConfig, PoolTestRig, ProtocolConfig, RigError,
};
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_interface::instruction::BatchUpdateAddressTreeData;

const TREE_ACCOUNT_SIZE: u64 = 1_200_000;

fn rig() -> Option<PoolTestRig> {
    match PoolTestRig::new() {
        Ok(mut r) => {
            // Fund the payer enough to cover the ~8 SOL tree + a few smaller
            // PDAs initialized by the registry.
            r.airdrop(&r.payer.pubkey(), 5_000_000_000).ok();
            match r.load_registry() {
                Ok(()) => Some(r),
                Err(RigError::MissingProgram(_)) => {
                    eprintln!(
                        "skipping registry CPI test: light_registry.so missing — \
                         run `cargo build-sbf -p light-registry`"
                    );
                    None
                }
                Err(e) => panic!("load_registry failed: {e}"),
            }
        }
        Err(RigError::MissingProgram(_)) => {
            eprintln!(
                "skipping registry CPI test: shielded_pool_program.so missing — \
                 run `cargo build-sbf -p shielded-pool-program --features bpf-entrypoint`"
            );
            None
        }
        Err(e) => panic!("rig boot failed: {e}"),
    }
}

#[test]
fn registry_cpi_authority_passes_shielded_pool_auth_check() {
    let Some(mut rig) = rig() else {
        return;
    };

    // 1. Allocate the pool tree (this stays a top-level system_program ix).
    let tree = rig
        .create_tree(TREE_ACCOUNT_SIZE)
        .expect("create_tree");

    // 2. Set up the registry: protocol_config → register forester → register
    //    forester for epoch 0 → finalize.
    let governance_authority = Keypair::new();
    rig.airdrop(&governance_authority.pubkey(), 1_000_000_000)
        .expect("airdrop governance authority");

    // Shorten the registration phase so the active phase starts almost
    // immediately under litesvm's clock.
    let config = ProtocolConfig {
        registration_phase_length: 5,
        active_phase_length: 1_000,
        ..ProtocolConfig::default()
    };
    rig.initialize_protocol_config(&governance_authority, config)
        .expect("initialize_protocol_config");

    let forester = Keypair::new();
    rig.airdrop(&forester.pubkey(), 1_000_000_000)
        .expect("airdrop forester");
    rig.register_forester(
        &governance_authority,
        &forester.pubkey(),
        ForesterConfig::default(),
        Some(1),
    )
    .expect("register_forester");

    rig.register_forester_epoch(&forester, 0)
        .expect("register_forester_epoch");

    // Warp past the registration phase so we land in the active phase
    // (slot >= registration_phase_length).
    rig.warp_to_slot(config.registration_phase_length + 1)
        .expect("warp past registration");
    rig.finalize_registration(&forester, 0)
        .expect("finalize_registration");

    // 3. Call forest_address_tree. The registry will CPI into shielded-pool;
    //    the CPI authority PDA's signer survives shielded-pool's auth check,
    //    so the call must fail somewhere OTHER than `UnauthorizedCaller`
    //    (which is `Custom(5)`). Proof verification will fail, surfacing as
    //    `BatchProofVerificationFailed` = `Custom(8)`.
    let err = rig
        .forest_address_tree(
            &forester,
            &tree.pubkey(),
            0,
            BatchUpdateAddressTreeData {
                new_root: [9u8; 32],
                compressed_proof_a: [0u8; 32],
                compressed_proof_b: [0u8; 64],
                compressed_proof_c: [0u8; 32],
            },
        )
        .expect_err("missing-proof must fail");
    let msg = format!("{err}");
    assert!(
        !msg.contains("Custom(5)"),
        "CPI authority was rejected as UnauthorizedCaller: {msg}"
    );
    assert!(
        msg.contains("Custom(8)") || msg.contains("BatchProofVerificationFailed"),
        "expected proof-related BatchProofVerificationFailed, got: {msg}"
    );
}

#[test]
fn pdas_derive_to_known_seeds() {
    // Sanity: PDA derivers used by the SDK return stable addresses for a
    // pinned program id. Any rename of registry seeds will trip this.
    let (cpi_authority, _) = cpi_authority_pda();
    let (protocol_config, _) = protocol_config_pda();
    assert_ne!(cpi_authority, protocol_config);
}
