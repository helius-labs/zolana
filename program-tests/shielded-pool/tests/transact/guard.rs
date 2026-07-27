//! Proof soundness guards on the `transact` rails (tags 0, 2, 3). Every case
//! fires in an on-chain guard clause, before any pairing runs, so no real
//! proof (and no prover) is needed:
//!
//! - malformed wincode payloads (built-in `InvalidInstructionData`)
//! - tree account defects: non-writable meta, wrong owner, wrong
//!   discriminator (20002 / 7001)
//! - proof points that fail decompression (7007, `InvalidTransactProofEncoding`)
//! - more inputs or outputs than any circuit supports, and wire-valid but
//!   unsupported shapes (7006, `InvalidTransactShape`)
//! - a duplicate nullifier inside one instruction (7002)
//! - a negative clock (7005) and a paused tree on the zone rails (7013)
//! - zone-config defects on the zone rails (7014 / signer error)

use shielded_pool_tests::support::{fixtures::Pool, transact::write_zone_config_account};

use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_account_checks::AccountError;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::transact::{CircuitId, TransactIxData, TransactProof},
        Transact, ZoneAuthorityTransact, ZoneTransact,
    },
    pda, N_PUBLIC_SLOTS,
    state::{discriminator::ZONE_CONFIG, ZoneConfig},
};
use zolana_program_test::{Rejection, ZolanaProgramTest, ZONE_TEST_PROGRAM_ID};
use zolana_test_utils::transact::{eddsa_input_utxo, fe, inline_output};

/// A pure shielded transfer (no settlement accounts) with `n_in` inputs bound
/// to the signing payer and `n_out` inline outputs. The proof defaults to the
/// zeroed eddsa placeholder; callers overwrite it per case.
fn transfer_ix_data(n_in: u64, n_out: u64) -> TransactIxData {
    TransactIxData {
        proof: TransactProof::zeroed(),
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [0u8; 32],
        circuit: CircuitId::ConfidentialEddsa(n_in as u8, n_out as u8, N_PUBLIC_SLOTS as u8),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        inputs: (1..=n_in).map(|n| eddsa_input_utxo(fe(n), 0)).collect(),
        interface_transfers: Vec::new(),
        data_hash: None,
        zone_data_hash: None,
        outputs: (11..11 + n_out)
            .map(|n| inline_output(fe(n), fe(n)))
            .collect(),
        messages: Vec::new(),
    }
}

struct GuardEnv {
    rpc: ZolanaProgramTest,
    tree: Keypair,
    authority: Keypair,
}

impl GuardEnv {
    fn boot() -> Self {
        let Pool {
            rpc,
            tree,
            authority,
        } = Pool::initialized();
        Self {
            rpc,
            tree,
            authority,
        }
    }

    /// Send the transact data (with a raised CU budget, so proof-path guards
    /// are reached) and assert the exact rejection plus an untouched tree.
    #[track_caller]
    fn expect_rejection(&mut self, data: TransactIxData, expected: ShieldedPoolError) {
        let ix = Transact {
            payer: self.rpc.payer.pubkey(),
            input_tree: self.tree.pubkey(),
            output_tree: self.tree.pubkey(),
            interface_transfer_accounts: Vec::new(),
            data,
        }
        .instruction();
        self.expect_ix_rejection(ix, &[], Rejection::pool(expected));
    }

    /// Like [`Self::expect_rejection`], but for a caller-built instruction
    /// (tampered metas, zone rails) with extra transaction signers.
    #[track_caller]
    fn expect_ix_rejection(&mut self, ix: Instruction, signers: &[&Keypair], expected: Rejection) {
        let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        let error = self
            .rpc
            .create_and_send_default_payer_transaction(&[budget, ix], signers)
            .expect_err("guarded transact must be rejected");
        expected.at(1).assert_litesvm(error);
        self.rpc
            .last_transaction_trace()
            .expect("rejected transact trace")
            .assert_rolled_back_except(&[self.rpc.payer.pubkey()]);
    }

    /// Materialize a `ZoneConfig` at a fresh keypair address so tests can
    /// produce the signature the zone rails require without the zone program's
    /// `invoke_signed`. `load_zone_config` validates only owner, size, and
    /// discriminator (the `zone_auth` derivation is bound once, at creation),
    /// so a signing keypair account stands in for the canonical PDA.
    fn write_zone_config(&mut self, owner: Pubkey, discriminator: u8, enabled: bool) -> Keypair {
        let config = ZoneConfig {
            discriminator,
            authority: Address::new_from_array([9u8; 32]),
            program_id: Address::new_from_array(ZONE_TEST_PROGRAM_ID),
            zone_authority_transact_is_enabled: u8::from(enabled),
            bump: 255,
        };
        let keypair = Keypair::new();
        write_zone_config_account(
            &mut self.rpc,
            keypair.pubkey(),
            owner,
            bytemuck::bytes_of(&config).to_vec(),
        );
        keypair
    }

    /// CPI-shaped `zone_transact` / `zone_authority_transact` instruction with
    /// the fabricated `zone_config` keypair substituted for the canonical
    /// `zone_auth` PDA (still marked as a signer).
    fn zone_instruction(
        &self,
        authority_variant: bool,
        zone_config: &Keypair,
        data: TransactIxData,
    ) -> Instruction {
        let payer = self.rpc.payer.pubkey();
        let tree = self.tree.pubkey();
        let zone_program_id = Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID);
        let mut data = data;
        data.circuit = if authority_variant {
            CircuitId::ZoneAuthority(
                data.circuit.num_inputs(),
                data.circuit.num_outputs(),
                N_PUBLIC_SLOTS as u8,
            )
        } else {
            CircuitId::ZoneEddsa(
                data.circuit.num_inputs(),
                data.circuit.num_outputs(),
                N_PUBLIC_SLOTS as u8,
            )
        };
        let mut ix = if authority_variant {
            ZoneAuthorityTransact {
                payer,
                input_tree: tree,
                output_tree: tree,
                zone_program_id,
                interface_transfer_accounts: Vec::new(),
                data,
            }
            .cpi_instruction()
        } else {
            ZoneTransact {
                payer,
                input_tree: tree,
                output_tree: tree,
                zone_program_id,
                interface_transfer_accounts: Vec::new(),
                data,
            }
            .cpi_instruction()
        };
        ix.accounts.get_mut(3).expect("zone config meta").pubkey = zone_config.pubkey();
        ix
    }
}

#[test]
fn transact_rejects_a_stale_nullifier_root_index() {
    let mut env = GuardEnv::boot();
    // Root-history indices are caller-supplied; a zeroed (never-written)
    // history slot must be rejected, not treated as a valid root.
    let mut data = transfer_ix_data(2, 3);
    for input in &mut data.inputs {
        input.nullifier_tree_root_index = 7;
    }
    env.expect_rejection(data, ShieldedPoolError::StaleNullifierRoot);
}

#[test]
fn transact_rejects_a_stale_utxo_root_index() {
    let mut env = GuardEnv::boot();
    // INV-XC-09: the UTXO root history is symmetric to the nullifier root
    // history; an out-of-bounds or zeroed slot must map to StaleNullifierRoot.
    let mut data = transfer_ix_data(2, 3);
    for input in &mut data.inputs {
        input.utxo_tree_root_index = 7;
    }
    env.expect_rejection(data, ShieldedPoolError::StaleNullifierRoot);
}

#[test]
fn transact_rejects_a_paused_tree() {
    let mut env = GuardEnv::boot();
    let authority = env.authority.insecure_clone();
    env.rpc
        .pause_tree(&authority, &env.tree, true)
        .expect("pause tree");
    // Every wire field is valid; the pause alone must halt the tree mutation.
    let data = transfer_ix_data(2, 3);
    env.expect_rejection(data, ShieldedPoolError::TreePaused);
}

#[test]
fn transact_rejects_proof_points_that_fail_decompression() {
    let mut env = GuardEnv::boot();
    // 0xFF-filled points carry invalid compression flag bits, so the verifier
    // fails at point decompression, before any pairing.
    let mut data = transfer_ix_data(2, 3);
    data.proof = TransactProof {
        a: [0xFF; 32],
        b: [0xFF; 64],
        c: [0xFF; 32],
    };
    env.expect_rejection(data, ShieldedPoolError::InvalidTransactProofEncoding);
}

#[test]
fn transact_rejects_more_outputs_than_any_circuit_supports() {
    let mut env = GuardEnv::boot();
    // Nine outputs overflow the MAX_OUTPUTS = 8 resolve buffer.
    let data = transfer_ix_data(2, 9);
    env.expect_rejection(data, ShieldedPoolError::InvalidTransactShape);
}

#[test]
fn transact_rejects_an_unsupported_proof_shape() {
    let mut env = GuardEnv::boot();
    // (2 inputs, 4 outputs) is wire-valid and within the resolve buffer, but no
    // circuit exists for it: the verifying-key selection must reject it.
    let data = transfer_ix_data(2, 4);
    env.expect_rejection(data, ShieldedPoolError::InvalidTransactShape);
}

#[test]
fn zone_transact_rejects_an_unsigned_zone_config() {
    let mut env = GuardEnv::boot();
    let mut ix = ZoneTransact {
        payer: env.rpc.payer.pubkey(),
        input_tree: env.tree.pubkey(),
        output_tree: env.tree.pubkey(),
        zone_program_id: Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID),
        interface_transfer_accounts: Vec::new(),
        data: {
            let mut data = transfer_ix_data(2, 3);
            data.circuit = CircuitId::ZoneEddsa(2, 3, N_PUBLIC_SLOTS as u8);
            data
        },
    }
    .cpi_instruction();
    // The `zone_config` signature IS the zone authorization; without the zone
    // program's `invoke_signed` the flag must be rejected before the config is
    // even loaded (so the account does not need to exist).
    ix.accounts.get_mut(3).expect("zone config meta").is_signer = false;

    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("unsigned zone config must be rejected");
    Rejection::custom(u32::from(AccountError::InvalidSigner)).assert_litesvm(error);
}

#[test]
fn transact_rejects_a_non_writable_tree_meta() {
    let mut env = GuardEnv::boot();
    // INV-TRANSACT-02: the tree must be writable; `next_mut` rejects the
    // read-only meta before the tree is even loaded. input_tree and
    // output_tree are duplicate metas of one account, and the runtime unions
    // their privileges, so both must be downgraded.
    let mut ix = Transact {
        payer: env.rpc.payer.pubkey(),
        input_tree: env.tree.pubkey(),
        output_tree: env.tree.pubkey(),
        interface_transfer_accounts: Vec::new(),
        data: transfer_ix_data(2, 3),
    }
    .instruction();
    for meta in ix.accounts.iter_mut().skip(1).take(2) {
        meta.is_writable = false;
    }
    env.expect_ix_rejection(
        ix,
        &[],
        Rejection::custom(u32::from(AccountError::AccountNotMutable)),
    );
}

#[test]
fn transact_rejects_a_tree_not_owned_by_the_program() {
    let mut env = GuardEnv::boot();
    // INV-TRANSACT-03: the tree loads in the core, after parsing, so
    // valid-shape data with a garbage proof reaches the owner check.
    let impostor = Pubkey::new_unique();
    env.rpc
        .airdrop(&impostor, 1_000_000)
        .expect("fund impostor");
    let ix = Transact {
        payer: env.rpc.payer.pubkey(),
        input_tree: impostor,
        output_tree: impostor,
        interface_transfer_accounts: Vec::new(),
        data: transfer_ix_data(2, 3),
    }
    .instruction();
    env.expect_ix_rejection(
        ix,
        &[],
        Rejection::pool(ShieldedPoolError::InvalidTreeAccounts),
    );
}

#[test]
fn transact_rejects_a_tree_with_a_wrong_discriminator() {
    let mut env = GuardEnv::boot();
    // INV-TRANSACT-03: a program-owned account whose first byte is not exactly
    // TREE_ACCOUNT_DISCRIMINATOR (1) must fail the same way as a foreign tree.
    let mut account = env
        .rpc
        .svm
        .get_account(&env.tree.pubkey())
        .expect("tree account");
    *account.data.first_mut().expect("tree discriminator byte") = 0;
    env.rpc
        .svm
        .set_account(env.tree.pubkey(), account)
        .expect("corrupt tree discriminator");
    env.expect_rejection(
        transfer_ix_data(2, 3),
        ShieldedPoolError::InvalidTreeAccounts,
    );
}

#[test]
fn transact_rejects_a_malformed_wincode_payload() {
    let mut env = GuardEnv::boot();
    let template = Transact {
        payer: env.rpc.payer.pubkey(),
        input_tree: env.tree.pubkey(),
        output_tree: env.tree.pubkey(),
        interface_transfer_accounts: Vec::new(),
        data: transfer_ix_data(2, 3),
    }
    .instruction();

    // INV-TRANSACT-07: every payload `TransactIxDataRef::from_bytes` fails to
    // parse is rejected with the built-in error, never a pool code. The
    // reference decoder consumes the full well-formed buffer, so every strict
    // prefix cuts a required field; sample truncations across the payload plus
    // the exact end.
    let mut malformed: Vec<Vec<u8>> = Vec::new();
    let len = template.data.len();
    let mut cuts: Vec<usize> = (1..len).step_by(29).collect();
    if cuts.last() != Some(&(len - 1)) {
        cuts.push(len - 1);
    }
    for cut in cuts {
        malformed.push(
            template
                .data
                .get(..cut)
                .expect("truncated payload")
                .to_vec(),
        );
    }
    // An invalid circuit selector tag (u16, right after expiry + private_tx_hash
    // inside the payload): 0xFFFF names no variant and must fail decoding.
    let mut bad_tag = template.data.clone();
    let circuit_tag_offset = 1 + 8 + 32;
    *bad_tag.get_mut(circuit_tag_offset).expect("circuit tag byte") = 0xFF;
    *bad_tag
        .get_mut(circuit_tag_offset + 1)
        .expect("circuit tag byte") = 0xFF;
    malformed.push(bad_tag);
    // An overlong trailing length prefix: the final byte is the empty
    // `messages` vec's u8 count; 255 claims elements past the buffer end.
    let mut overlong = template.data.clone();
    *overlong.last_mut().expect("messages length byte") = 255;
    malformed.push(overlong);

    for data in malformed {
        let mut ix = template.clone();
        ix.data = data;
        let error = env
            .rpc
            .create_and_send_default_payer_transaction(&[ix], &[])
            .expect_err("malformed payload must be rejected");
        Rejection::new(InstructionError::InvalidInstructionData).assert_litesvm(error);
    }
}

#[test]
fn transact_rejects_trailing_payload_bytes_at_parse() {
    let mut env = GuardEnv::boot();
    // INV-TRANSACT-07 boundary: `TransactIxDataRef::from_bytes` is an exact
    // decoder, so trailing garbage after a well-formed payload fails the same
    // bare `InvalidInstructionData` as any other parse error.
    let mut ix = Transact {
        payer: env.rpc.payer.pubkey(),
        input_tree: env.tree.pubkey(),
        output_tree: env.tree.pubkey(),
        interface_transfer_accounts: Vec::new(),
        data: transfer_ix_data(2, 3),
    }
    .instruction();
    ix.data.extend_from_slice(&[0xAB; 7]);
    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("trailing payload bytes must be rejected");
    Rejection::new(solana_instruction::error::InstructionError::InvalidInstructionData)
        .assert_litesvm(error);
}

#[test]
fn transact_rejects_more_inputs_than_any_circuit_supports() {
    let mut env = GuardEnv::boot();
    // INV-TRANSACT-09: six inputs overflow the MAX_INPUTS = 5 proof-input
    // buffer before any tree write or proof check.
    let data = transfer_ix_data(6, 3);
    env.expect_rejection(data, ShieldedPoolError::InvalidTransactShape);
}

#[test]
fn transact_rejects_a_duplicate_nullifier_within_one_instruction() {
    let mut env = GuardEnv::boot();
    // INV-XC-10: the queue's non-inclusion check must fail the second insert
    // of the same nullifier inside one instruction, before proof verification.
    let mut data = transfer_ix_data(2, 3);
    let first = data.inputs.first().expect("first input").nullifier_hash;
    data.inputs.get_mut(1).expect("second input").nullifier_hash = first;
    env.expect_rejection(data, ShieldedPoolError::NullifierTreeUpdateFailed);
}

#[test]
fn transact_rejects_a_negative_clock() {
    let mut env = GuardEnv::boot();
    // INV-XC-07: a negative clock is rejected for every expiry, even u64::MAX.
    let mut clock = env.rpc.svm.get_sysvar::<solana_clock::Clock>();
    clock.unix_timestamp = -1;
    env.rpc.svm.set_sysvar(&clock);
    env.expect_rejection(
        transfer_ix_data(2, 3),
        ShieldedPoolError::ExpiredTransaction,
    );
}

#[test]
fn transact_rejects_an_expired_transaction() {
    let mut env = GuardEnv::boot();
    // INV-XC-07: a non-negative clock past the instruction's expiry_unix_ts
    // must be rejected.
    let mut clock = env.rpc.svm.get_sysvar::<solana_clock::Clock>();
    clock.unix_timestamp = 100;
    env.rpc.svm.set_sysvar(&clock);
    let mut data = transfer_ix_data(2, 3);
    data.expiry_unix_ts = 99;
    env.expect_rejection(data, ShieldedPoolError::ExpiredTransaction);
}

#[test]
fn zone_transact_rejects_a_zone_config_with_a_wrong_owner() {
    let mut env = GuardEnv::boot();
    // INV-ZONE-TRANSACT-02: correct ZoneConfig bytes at a signed but
    // system-owned account cannot authorize a zone.
    let zone_config = env.write_zone_config(Pubkey::default(), ZONE_CONFIG, true);
    let ix = env.zone_instruction(false, &zone_config, transfer_ix_data(2, 3));
    env.expect_ix_rejection(
        ix,
        &[&zone_config],
        Rejection::pool(ShieldedPoolError::InvalidZoneConfig),
    );
}

#[test]
fn zone_transact_rejects_a_zone_config_with_a_wrong_discriminator() {
    let mut env = GuardEnv::boot();
    // INV-ZONE-TRANSACT-02: program-owned and signed, but the first byte is
    // not exactly the ZoneConfig discriminator (4).
    let zone_config = env.write_zone_config(pda::shielded_pool_program_id(), 0, true);
    let ix = env.zone_instruction(false, &zone_config, transfer_ix_data(2, 3));
    env.expect_ix_rejection(
        ix,
        &[&zone_config],
        Rejection::pool(ShieldedPoolError::InvalidZoneConfig),
    );
}

#[test]
fn zone_transact_rejects_a_paused_tree() {
    let mut env = GuardEnv::boot();
    let authority = env.authority.insecure_clone();
    env.rpc
        .pause_tree(&authority, &env.tree, true)
        .expect("pause tree");
    // INV-XC-08: a valid signed zone config does not exempt zone_transact from
    // the pause; the tree load must halt the write.
    let zone_config = env.write_zone_config(pda::shielded_pool_program_id(), ZONE_CONFIG, false);
    let ix = env.zone_instruction(false, &zone_config, transfer_ix_data(2, 3));
    env.expect_ix_rejection(
        ix,
        &[&zone_config],
        Rejection::pool(ShieldedPoolError::TreePaused),
    );
}

#[test]
fn zone_authority_transact_rejects_an_unsigned_zone_config() {
    let mut env = GuardEnv::boot();
    // INV-ZONE-AUTH-01: tag 3 shares the zone loader, so the missing
    // `zone_config` signature is rejected before the config is even loaded.
    let mut ix = ZoneAuthorityTransact {
        payer: env.rpc.payer.pubkey(),
        input_tree: env.tree.pubkey(),
        output_tree: env.tree.pubkey(),
        zone_program_id: Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID),
        interface_transfer_accounts: Vec::new(),
        data: {
            // Square shape so the zone-config signer check is the branch that fires.
            let mut data = transfer_ix_data(2, 2);
            data.circuit = CircuitId::ZoneAuthority(2, 2, N_PUBLIC_SLOTS as u8);
            data
        },
    }
    .cpi_instruction();
    ix.accounts.get_mut(3).expect("zone config meta").is_signer = false;

    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("unsigned zone config must be rejected");
    Rejection::custom(u32::from(AccountError::InvalidSigner)).assert_litesvm(error);
}

#[test]
fn zone_authority_transact_rejects_a_paused_tree() {
    let mut env = GuardEnv::boot();
    let authority = env.authority.insecure_clone();
    env.rpc
        .pause_tree(&authority, &env.tree, true)
        .expect("pause tree");
    // INV-XC-08: even an enabled zone authority cannot write a paused tree.
    let zone_config = env.write_zone_config(pda::shielded_pool_program_id(), ZONE_CONFIG, true);
    let ix = env.zone_instruction(true, &zone_config, transfer_ix_data(2, 2));
    env.expect_ix_rejection(
        ix,
        &[&zone_config],
        Rejection::pool(ShieldedPoolError::TreePaused),
    );
}

#[test]
fn zone_authority_transact_rejects_a_non_square_shape() {
    let mut env = GuardEnv::boot();
    // INV-ZONE-AUTH-04: the zone-authority keys cover exactly the square
    // shapes (1,1)..(4,4); (2 inputs, 3 outputs) is wire-valid (and a
    // supported zone_transact shape) but must fail key selection here.
    let zone_config = env.write_zone_config(pda::shielded_pool_program_id(), ZONE_CONFIG, true);
    let ix = env.zone_instruction(true, &zone_config, transfer_ix_data(2, 3));
    env.expect_ix_rejection(
        ix,
        &[&zone_config],
        Rejection::pool(ShieldedPoolError::InvalidTransactShape),
    );
}

