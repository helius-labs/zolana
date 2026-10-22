//! LiteSVM integration tests for the settlement paths without a ring proof:
//! `deposit` and `full_withdrawal`. The `transact`/`execute_proposal`
//! withdrawal legs are covered by the proof-bearing `transact_e2e` /
//! `execute_proposal_e2e` suites.
//!
//! The forwarded SPP account lists are the real `ring_deposit` /
//! `ring_transact` layouts built by the `zolana_program` builders, except that
//! the SPP program account is replaced by the ring program's own id -- a
//! deliberate placeholder. `forward_to_spp` requires the SPP program account in
//! the forwarded list BEFORE attempting the CPI, so reaching `InvalidSppProgram`
//! proves every ring-side step ran and the flow proceeded to settlement. Real
//! fund movement is covered by the localnet suites.
//!
//! These need no prover: `deposit` carries no proof, and `full_withdrawal`
//! carries only the SPP proof, which the ring forwards unverified.
//!
//! Requires the prebuilt program binary; build it with
//! `cd rings/squads/program && cargo build-sbf --features bpf-entrypoint`.
//! Tests skip (return early, do not fail) when the `.so` is missing.

use solana_instruction::AccountMeta;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_ring_tests::{custom_code, SquadsRingTest};
use zolana_interface::verifying_keys::{AnonymousRingEddsaProofData, Bsb22Commitment};
use zolana_interface::{
    instruction::{
        CircuitId, DepositAssetKind, EncryptedRingDepositData, InputUtxo, InterfaceTransfer,
        OwnerTag, TransactIxData as SppTransactIxData, TransactOutput, TransactProof, TreeContext,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_program::instruction::{
    DepositAsset, DepositSplAccounts, RingAssetDeposit, RingDeposit, RingTransact,
    TransactInterfaceTransferAccounts, TransactSolTransferAccounts, TransactSplWithdrawalAccounts,
};
use zolana_squads_interface::{
    constants::{ENCRYPTION_SCHEME_X25519_AES, OWNER_KIND_KEYPAIR, VIEWING_KEY_STATE_ACTIVE},
    error::SquadsRingError,
    instruction::{
        builders::{Deposit, FullWithdrawal},
        DepositIxData, FullWithdrawalIxData,
    },
    state::viewing_key_account::ViewingKeyAccount,
    types::Address,
};

fn junk_pubkey(seed: u8) -> Pubkey {
    Pubkey::new_from_array([seed; 32])
}

/// A 32-byte value inside the BN254 field range (top byte cleared) so the
/// on-chain Poseidon over the recipient owner never rejects it.
fn field(seed: u8) -> [u8; 32] {
    let mut f = [seed; 32];
    f[0] = 0;
    f
}

/// Replace the SPP program account in a forwarded SPP account list with the
/// ring program's own id (see the module doc comment).
fn with_placeholder_spp_program(
    test: &SquadsRingTest,
    accounts: Vec<AccountMeta>,
) -> Vec<AccountMeta> {
    let spp_program = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    accounts
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

/// Install the recipient viewing key account fixture. Only the fields the
/// deposit reads (owner, nullifier_pubkey) matter; the owner is an opaque field
/// element the deposit hashes into the output, not a Solana signer.
fn install_recipient_vka(test: &mut SquadsRingTest) -> Pubkey {
    let address = Keypair::new().pubkey();
    let account = ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: Address::new_from_array(field(9)),
        state: VIEWING_KEY_STATE_ACTIVE,
        encryption_scheme: ENCRYPTION_SCHEME_X25519_AES,
        owner_kind: OWNER_KIND_KEYPAIR,
        shared_viewing_key: [2u8; 33],
        shared_viewing_key_commitment: field(4),
        key_nonce: 0,
        nullifier_pubkey: field(5),
        key_ciphertext_ephemeral: [0u8; 33],
        encrypted_nullifier_secret: [0u8; 31],
        recovery_keys: vec![],
        recovery_key_ciphertexts: vec![],
        auditor_keys: vec![],
        auditor_key_ciphertexts: vec![],
    };
    test.set_program_account(&address, account.serialize().expect("serialize vka"))
        .expect("install vka");
    address
}

fn deposit_data(asset: DepositAssetKind) -> DepositIxData {
    DepositIxData {
        view_tag: field(1),
        blinding: field(2),
        amount: 1,
        asset,
    }
}

/// The SPP `ring_deposit` account list for a single `asset` deposit, with the
/// placeholder SPP program. The entry fields are rebuilt on-chain by the ring,
/// so only the layout matters here.
fn deposit_spp_accounts(test: &SquadsRingTest, asset: DepositAsset) -> Vec<AccountMeta> {
    let accounts = RingDeposit {
        tree: junk_pubkey(4),
        depositor: test.payer.pubkey(),
        ring_program_id: test.program_id,
        deposits: vec![RingAssetDeposit {
            asset,
            view_tag: field(1),
            owner_utxo_hash: [0u8; 32],
            amount: 1,
            ring_data_hash: [0u8; 32],
            encrypted: EncryptedRingDepositData {
                tx_viewing_pk: [0u8; 33],
                salt: [0u8; 16],
                ciphertext: vec![],
            },
        }],
    }
    .instruction()
    .expect("ring deposit layout")
    .accounts;
    with_placeholder_spp_program(test, accounts)
}

fn spl_deposit_asset() -> DepositAsset {
    DepositAsset::Spl(DepositSplAccounts {
        mint: junk_pubkey(5),
        user_token: junk_pubkey(6),
        token_program: junk_pubkey(7),
    })
}

/// The SOL deposit runs the full ring-side flow (recipient VKA owner hash,
/// `ring_deposit` data build) and reaches the SPP forwarding step.
#[test]
fn deposit_sol_reaches_spp_cpi() {
    let Some(mut test) = SquadsRingTest::new().expect("boot") else {
        return;
    };
    let recipient_vka = install_recipient_vka(&mut test);

    let ix = Deposit {
        recipient_viewing_key_account: recipient_vka,
        spp_accounts: deposit_spp_accounts(&test, DepositAsset::Sol),
        data: deposit_data(DepositAssetKind::Sol),
    }
    .instruction();

    let err = test
        .send(&[ix], &[])
        .expect_err("deposit reaches the SPP CPI");
    assert_eq!(custom_code(&err), SquadsRingError::InvalidSppProgram as u32);
}

/// The SPL deposit forwards the SPL settlement group and likewise reaches the
/// SPP forwarding step.
#[test]
fn deposit_spl_reaches_spp_cpi() {
    let Some(mut test) = SquadsRingTest::new().expect("boot") else {
        return;
    };
    let recipient_vka = install_recipient_vka(&mut test);

    let ix = Deposit {
        recipient_viewing_key_account: recipient_vka,
        spp_accounts: deposit_spp_accounts(&test, spl_deposit_asset()),
        data: deposit_data(DepositAssetKind::Spl {
            spl_interface_bump: 255,
        }),
    }
    .instruction();

    let err = test
        .send(&[ix], &[])
        .expect_err("deposit reaches the SPP CPI");
    assert_eq!(custom_code(&err), SquadsRingError::InvalidSppProgram as u32);
}

#[test]
fn deposit_rejects_unsigned_depositor() {
    let Some(mut test) = SquadsRingTest::new().expect("boot") else {
        return;
    };
    let recipient_vka = install_recipient_vka(&mut test);

    let depositor = junk_pubkey(3);
    let spp_accounts = deposit_spp_accounts(&test, DepositAsset::Sol)
        .into_iter()
        .map(|meta| {
            if meta.pubkey == test.payer.pubkey() {
                AccountMeta::new(depositor, false)
            } else {
                meta
            }
        })
        .collect();
    let ix = Deposit {
        recipient_viewing_key_account: recipient_vka,
        spp_accounts,
        data: deposit_data(DepositAssetKind::Sol),
    }
    .instruction();

    let err = test
        .send(&[ix], &[])
        .expect_err("an unsigned depositor must be rejected");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::MissingAuthoritySignature as u32
    );
}

/// A withdrawal with one real input and one change output (SPP shape `1x2`) on the Ed25519 rail with the given leg. The
/// ring forwards it unverified, so the SPP proof and hashes are placeholders.
fn full_withdrawal_payload(leg: InterfaceTransfer) -> SppTransactIxData {
    SppTransactIxData {
        expiry_unix_ts: u64::MAX,
        tx_viewing_pk: [2u8; 33],
        salt: [0u8; 16],
        interface_transfers: vec![leg],
        data_hash: None,
        ring_data_hash: None,
        outputs: vec![TransactOutput {
            utxo_hash: [8u8; 32],
            owner_tag: OwnerTag::Inline([0u8; 32]),
            data: Some(vec![0u8; 40]),
        }],
        messages: vec![],
        private_tx_hash: [6u8; 32],
        circuit: CircuitId::AnonymousRingEddsa(
            1,
            2,
            3,
            AnonymousRingEddsaProofData {
                bsb22_commitment: Bsb22Commitment {
                    commitment: [0; 32],
                    commitment_pok: [0; 32],
                },
                default_owner_tag: None,
            },
        ),
        proof: TransactProof::zeroed(),
        inputs: vec![InputUtxo {
            nullifier_hash: [1u8; 32],
            tree_index: 0,
        }],
        tree_contexts: vec![TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        }],
    }
}

fn full_withdrawal_ix(
    test: &SquadsRingTest,
    spp: SppTransactIxData,
    leg_accounts: Vec<TransactInterfaceTransferAccounts>,
) -> solana_instruction::Instruction {
    let accounts = RingTransact {
        payer: test.payer.pubkey(),
        input_trees: vec![junk_pubkey(4)],
        output_tree: junk_pubkey(3),
        ring_program_id: test.program_id,
        owner_signers: vec![],
        interface_transfer_accounts: leg_accounts,
        data: spp.clone(),
    }
    .instruction()
    .accounts;
    FullWithdrawal {
        spp_accounts: with_placeholder_spp_program(test, accounts),
        data: FullWithdrawalIxData { spp },
    }
    .instruction()
}

/// `full_withdrawal` needs no co-signer or viewing key account: the forwarded
/// SPP proof authorizes the exit, and the payer is only a fee payer.
#[test]
fn full_withdrawal_sol_reaches_spp_cpi() {
    let Some(mut test) = SquadsRingTest::new().expect("boot") else {
        return;
    };
    let ix = full_withdrawal_ix(
        &test,
        full_withdrawal_payload(InterfaceTransfer::SolWithdrawal { amount: 1 }),
        vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts {
                recipient: junk_pubkey(6),
            },
        )],
    );

    let err = test
        .send(&[ix], &[])
        .expect_err("full_withdrawal reaches the SPP CPI");
    assert_eq!(custom_code(&err), SquadsRingError::InvalidSppProgram as u32);
}

#[test]
fn full_withdrawal_spl_reaches_spp_cpi() {
    let Some(mut test) = SquadsRingTest::new().expect("boot") else {
        return;
    };
    let ix = full_withdrawal_ix(
        &test,
        full_withdrawal_payload(InterfaceTransfer::SplWithdrawal {
            amount: 1,
            spl_interface_bump: 255,
        }),
        vec![TransactInterfaceTransferAccounts::SplWithdrawal(
            TransactSplWithdrawalAccounts {
                mint: junk_pubkey(5),
                spl_interface: junk_pubkey(6),
                user_token_account: junk_pubkey(7),
                token_program: junk_pubkey(8),
            },
        )],
    );

    let err = test
        .send(&[ix], &[])
        .expect_err("full_withdrawal reaches the SPP CPI");
    assert_eq!(custom_code(&err), SquadsRingError::InvalidSppProgram as u32);
}

/// The escape hatch only exits: a transfer payload (no withdrawal leg) is
/// rejected before anything is forwarded.
#[test]
fn full_withdrawal_rejects_payload_without_withdrawal_leg() {
    let Some(mut test) = SquadsRingTest::new().expect("boot") else {
        return;
    };
    let mut spp = full_withdrawal_payload(InterfaceTransfer::SolWithdrawal { amount: 1 });
    spp.interface_transfers = vec![];
    let ix = full_withdrawal_ix(&test, spp, vec![]);

    let err = test
        .send(&[ix], &[])
        .expect_err("a payload without a withdrawal leg must be rejected");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::InvalidInstructionData as u32
    );
}

/// `full_withdrawal` always settles on the Ed25519 rail; the signatureless
/// ring-authority circuit is rejected.
#[test]
fn full_withdrawal_rejects_ring_authority_circuit() {
    let Some(mut test) = SquadsRingTest::new().expect("boot") else {
        return;
    };
    let mut spp = full_withdrawal_payload(InterfaceTransfer::SolWithdrawal { amount: 1 });
    spp.circuit = CircuitId::RingAuthority(1, 1, 3);
    let ix = full_withdrawal_ix(
        &test,
        spp,
        vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts {
                recipient: junk_pubkey(6),
            },
        )],
    );

    let err = test
        .send(&[ix], &[])
        .expect_err("the ring-authority circuit must be rejected");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::InvalidInstructionData as u32
    );
}

#[test]
fn full_withdrawal_rejects_extra_output() {
    let Some(mut test) = SquadsRingTest::new().expect("boot") else {
        return;
    };
    let mut spp = full_withdrawal_payload(InterfaceTransfer::SolWithdrawal { amount: 1 });
    spp.outputs.push(spp.outputs[0].clone());
    let ix = full_withdrawal_ix(
        &test,
        spp,
        vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts {
                recipient: junk_pubkey(6),
            },
        )],
    );
    let err = test
        .send(&[ix], &[])
        .expect_err("exit must have only change");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::InvalidInstructionData as u32
    );
}

#[test]
fn full_withdrawal_rejects_more_than_two_inputs() {
    let Some(mut test) = SquadsRingTest::new().expect("boot") else {
        return;
    };
    let mut spp = full_withdrawal_payload(InterfaceTransfer::SolWithdrawal { amount: 1 });
    spp.inputs.extend([
        InputUtxo {
            nullifier_hash: [2; 32],
            tree_index: 0,
        },
        InputUtxo {
            nullifier_hash: [3; 32],
            tree_index: 0,
        },
    ]);
    let ix = full_withdrawal_ix(
        &test,
        spp,
        vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts {
                recipient: junk_pubkey(6),
            },
        )],
    );
    let err = test
        .send(&[ix], &[])
        .expect_err("exit must have one real input and at most one dummy");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::InvalidInstructionData as u32
    );
}

#[test]
fn full_withdrawal_with_two_inputs_reaches_spp_cpi() {
    let Some(mut test) = SquadsRingTest::new().expect("boot") else {
        return;
    };
    let mut spp = full_withdrawal_payload(InterfaceTransfer::SolWithdrawal { amount: 1 });
    spp.inputs.push(InputUtxo {
        nullifier_hash: [2; 32],
        tree_index: 0,
    });
    if let CircuitId::AnonymousRingEddsa(_, _, _, proof_data) = spp.circuit {
        spp.circuit = CircuitId::AnonymousRingEddsa(2, 2, 3, proof_data);
    }
    let ix = full_withdrawal_ix(
        &test,
        spp,
        vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts {
                recipient: junk_pubkey(6),
            },
        )],
    );
    let err = test
        .send(&[ix], &[])
        .expect_err("valid padded shape reaches settlement");
    assert_eq!(custom_code(&err), SquadsRingError::InvalidSppProgram as u32);
}
