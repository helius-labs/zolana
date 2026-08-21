//! End-to-end custom-ring lifecycle against localnet + photon + prover.
//!
//! [`localnet_bring_up_is_live`] proves the bring-up in `shared.rs` is real: the
//! four programs are deployed and executable, the protocol is bootstrapped with
//! the settings the ring flows need, the tree account deserializes, and the
//! indexer and prover both answer.
//!
//! [`auditor_sees_every_ring_transfer`] is the capstone: it walks the whole
//! lifecycle (create the config holding the auditor key, register the ring with
//! SPP, ring-deposit SOL, then a ring transact whose proof binds the verifiable
//! encryption of the transaction viewing key to that auditor key) and asserts
//! that the amounts, assets and blindings the AUDITOR CLIENT decrypts are the
//! ones the sender actually sent -- not merely that decryption succeeded.

mod shared;

use std::{
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use custom_ring_client::{audit_ring_transactions, AuditedOutput};
use custom_ring_program::{
    error::CustomRingError,
    state::{RingProgramConfig, RING_PROGRAM_CONFIG},
};
use custom_ring_sdk::{
    auditor_view_tag, config_pda, ring_auth_pda, to_instruction_proof, AuditProof,
    AuditProofParams, CreateConfig, CustomRingProverClient, Deposit, InitSppRingConfig,
    RingTransactWithAudit, CONFIG_PDA_SEED, PROGRAM_ID,
};
use shared::{
    custom_ring_program_id, prover_url, send, send_v0_expecting_rejection,
    send_v0_with_lookup_table, setup,
};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_signer::Signer;
use zolana_client::{
    ProverClient, RingTransferProofResult, RingTransferProver, Rpc, Shape, SolanaRpc, SpendProof,
    SppProofInputUtxo, SppProofInputs, TransferSpendInput,
};
use zolana_interface::{
    instruction::{
        tag::RING_TRANSACT, CircuitId, DepositAsset, InputUtxo, RingAssetDeposit, TransactIxData,
        TransactProof,
    },
    pda,
    state::{
        discriminator::{PROTOCOL_CONFIG, RING_CONFIG, TREE_ACCOUNT_DISCRIMINATOR},
        tree_account_size, ProtocolConfig, RingConfig,
    },
    N_PUBLIC_SLOTS, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{random_blinding, ShieldedKeypair, ViewingKey};
use zolana_program_test::Rejection;
use zolana_test_utils::{
    smart_account,
    test_validator_asserts::{
        assert_account_unchanged, fetch_account, fetch_state, wait_for_indexed_transaction,
        wait_for_merkle_proof, wait_for_non_inclusion_proof,
    },
    transact::pack_transact_proof,
};
use zolana_transaction::{
    instructions::transact::{
        encrypt_transaction_data, get_transaction_viewing_key, ExternalData, SppProofOutputUtxo,
    },
    owner_utxo_hash, Data, LocalWalletAuthority, RingDepositPlaintext, Utxo, DEFAULT_TAG_WINDOW,
    SOL_ASSET_ID, SOL_MINT,
};
use zolana_tree::TreeAccount;
use zolana_user_registry_interface::user_registry_program_id;

/// Lamports moved by the two transaction-shape probes. Small enough that the
/// payer's airdrop covers both plus fees.
const PROBE_TRANSFER: u64 = 1_234_567;

/// The protocol has no live transaction under an arbitrary view tag, so this
/// tag is only used to make the indexer answer a well-formed query.
const UNUSED_VIEW_TAG: [u8; 32] = [7u8; 32];

/// The two ring SOL deposits the audited transfer spends. Two inputs and two
/// outputs (sender change, recipient) are the (2, 2) transfer shape, which the
/// ring eddsa prover and SPP's `transfer_ring_2_2` verifying key both support.
const RING_DEPOSIT_A: u64 = 3_000_000_000;
const RING_DEPOSIT_B: u64 = 2_000_000_000;
/// What the sender sends the recipient. Every auditor-side expectation is
/// derived from this and the deposits, never read back out of the audit result.
const RING_TRANSFER_AMOUNT: u64 = 1_500_000_000;
/// The SOL change the sender keeps. A confidential transfer charges no protocol
/// fee, so the deposited total minus the sent amount is exact; evaluating it as
/// a `const` makes an arithmetic slip a compile error rather than a test that
/// asserts the audit against itself.
const RING_CHANGE: u64 = RING_DEPOSIT_A + RING_DEPOSIT_B - RING_TRANSFER_AMOUNT;

/// Output slot layout this test publishes: the sender's change first, the
/// recipient second. A slot's index is what its ciphertext is bound to, so these
/// are also the `slot_index` values the auditor must report.
const CHANGE_SLOT: u32 = 0;
const RECIPIENT_SLOT: u32 = 1;

/// Offset of the ciphertext inside the auditor message
/// (`eph_pk_compressed(33) || ciphertext(32)`), i.e. the first byte the negative
/// case tampers with.
const AUDITOR_CIPHERTEXT_OFFSET: usize = 33;

/// A UTXO's `data_hash` / `ring_data_hash` when it carries neither.
const ZERO: [u8; 32] = [0u8; 32];

#[test]
fn localnet_bring_up_is_live() -> Result<()> {
    let env = setup()?;
    let rpc = env.client.rpc();

    // 1. Every program the lifecycle CPIs into is deployed and executable. A
    //    missing `just build-programs` shows up here rather than as an opaque
    //    "program account not found" mid-flow.
    let ring_program = custom_ring_program_id()?;
    for (label, program) in [
        ("custom-ring", ring_program),
        (
            "shielded-pool",
            Address::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        ),
        ("user-registry", user_registry_program_id()),
        ("smart-account", smart_account::SMART_ACCOUNT_PROGRAM_ID),
    ] {
        rpc.assert_executable(&program)
            .with_context(|| format!("{label} program {program}"))?;
    }

    // 2. The protocol config carries exactly the bootstrap settings the ring
    //    flows depend on, `ring_creation_is_permissionless` above all: without
    //    it the custom-ring program cannot register its `ring_auth` PDA as an
    //    SPP ring config with a plain payer.
    let accounts = smart_account::standard_accounts();
    let config: ProtocolConfig = fetch_state(rpc, &pda::protocol_config())?;
    assert_eq!(
        config,
        ProtocolConfig {
            discriminator: PROTOCOL_CONFIG,
            protocol_authority: accounts.protocol_vault,
            tree_creation_authority: accounts.tree_vault,
            forester_authority: accounts.forester_vault,
            ring_creation_authority: accounts.ring_vault,
            tree_creation_is_permissionless: 0,
            ring_creation_is_permissionless: 1,
            spl_interface_creation_is_permissionless: 0,
        },
        "protocol config"
    );

    // 3. SOL-only bootstrap: the registry the wallets share resolves asset id 1
    //    to SOL with no `CreateAssetCounter`/`CreateSplInterface` step, and SOL
    //    settles through a system-owned interface PDA nothing has to create.
    assert_eq!(
        env.assets
            .resolve(SOL_ASSET_ID)
            .map_err(|e| anyhow!("resolve SOL asset: {e:?}"))?,
        SOL_MINT,
        "asset id 1 is SOL"
    );

    // 4. The default tree is owned by SPP, exactly account-sized, and parses
    //    through the canonical layout with a rooted, unpaused state tree.
    let tree_account = rpc
        .get_account(env.tree)?
        .ok_or_else(|| anyhow!("tree account {} not found", env.tree))?;
    assert_eq!(
        tree_account.owner,
        Address::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        "tree owner"
    );
    assert_eq!(tree_account.data.len(), tree_account_size(), "tree size");
    let mut tree_bytes = tree_account.data.clone();
    let tree = TreeAccount::from_bytes(&mut tree_bytes, env.tree.to_bytes())
        .map_err(|e| anyhow!("tree layout: {e:?}"))?;
    assert_eq!(
        tree.discriminator(),
        TREE_ACCOUNT_DISCRIMINATOR,
        "tree discriminator"
    );
    assert!(!tree.is_paused(), "tree must be unpaused after creation");
    let state_root = tree
        .get_utxo_tree_root(0)
        .map_err(|e| anyhow!("utxo tree root: {e:?}"))?;
    assert_ne!(state_root, [0u8; 32], "empty state tree still has a root");

    // 5. Photon answers the tag query the auditor client pages through, and has
    //    persisted at least one slot of the chain it is indexing.
    let indexed = env
        .client
        .indexer()
        .get_shielded_transactions_by_tags(
            zolana_client::ShieldedTransactionsByTagsRequest::new(UNUSED_VIEW_TAG)
                .with_limit(zolana_client::Limit::new(10).expect("valid page limit")),
        )
        .map_err(|e| anyhow!("indexer {}: {e:?}", env.indexer_url))?;
    assert!(
        indexed.transactions.is_empty(),
        "no transaction exists under the unused probe tag"
    );
    assert!(indexed.context.slot > 0, "indexer has persisted a slot");

    // 6. The prover listener the client will POST to is the one that came up.
    //    `spawn_workspace_prover` already ran the HTTP health probe; this pins
    //    that the resolved URL (per-clone `ZOLANA_PROVER_URL`) is reachable.
    let prover = prover_url();
    let host_port = prover
        .rsplit("//")
        .next()
        .map(|rest| rest.trim_end_matches('/'))
        .ok_or_else(|| anyhow!("prover url {prover} has no host"))?;
    let socket = host_port
        .to_socket_addrs()
        .with_context(|| format!("resolve prover {prover}"))?
        .next()
        .ok_or_else(|| anyhow!("prover url {prover} resolves to no address"))?;
    TcpStream::connect_timeout(&socket, Duration::from_secs(5))
        .with_context(|| format!("connect to prover {prover}"))?;

    // 7+8. Both transaction shapes the lifecycle uses work on this validator:
    //      a legacy transaction, and a v0 transaction resolved through a
    //      throwaway address lookup table (the shape the oversized ring
    //      transact needs). Each probe is asserted by its lamport effect.
    let sender = env.sender.keypair.pubkey();
    let recipient = env.recipient.keypair.pubkey();
    let sender_before = lamports(rpc, sender)?;
    let recipient_before = lamports(rpc, recipient)?;

    send(
        rpc,
        &env.payer,
        &[solana_system_interface::instruction::transfer(
            &env.payer.pubkey(),
            &sender,
            PROBE_TRANSFER,
        )],
    )?;
    assert_eq!(
        lamports(rpc, sender)?,
        sender_before + PROBE_TRANSFER,
        "legacy transfer credited the sender"
    );

    send_v0_with_lookup_table(
        rpc,
        &env.payer,
        solana_system_interface::instruction::transfer(
            &env.payer.pubkey(),
            &recipient,
            PROBE_TRANSFER,
        ),
    )?;
    assert_eq!(
        lamports(rpc, recipient)?,
        recipient_before + PROBE_TRANSFER,
        "lookup-table v0 transfer credited the recipient"
    );

    Ok(())
}

/// The full auditor lifecycle: config creation, SPP registration, two ring SOL
/// deposits, one audited ring transfer, and then the assertion that matters --
/// the auditor client's decrypted amounts, assets and blindings equal what the
/// sender actually sent.
#[test]
fn auditor_sees_every_ring_transfer() -> Result<()> {
    let mut env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    assert_eq!(
        custom_ring_program_id()?,
        PROGRAM_ID,
        "deployed program id matches the id the sdk builders target"
    );

    // 1. The auditor is off chain. Only its public key ever reaches the program;
    //    the secret never leaves this test and is what the final decryption uses.
    let auditor = ViewingKey::new();
    let auditor_pk = auditor.pubkey();
    let auditor_pubkey = *auditor_pk.as_bytes();

    // 2. Create the ring's singleton config holding the auditor key. The payer
    //    doubles as the config authority, so one signature covers both roles.
    let authority = env.payer.pubkey();
    send(
        rpc,
        &env.payer,
        &[CreateConfig {
            payer: authority,
            authority,
            auditor_pubkey,
        }
        .instruction()],
    )?;

    let (config_address, config_bump) =
        Address::find_program_address(&[CONFIG_PDA_SEED], &PROGRAM_ID);
    assert_eq!(config_address, config_pda(), "sdk config PDA helper");
    let config: RingProgramConfig = fetch_state(rpc, &config_address)?;
    assert_eq!(
        config,
        RingProgramConfig {
            discriminator: RING_PROGRAM_CONFIG,
            authority,
            auditor_pubkey,
            bump: config_bump,
        },
        "custom-ring config account"
    );

    // 3. Register the ring with SPP. The `RingConfig` SPP allocates IS the ring's
    //    `ring_auth` PDA, and the payload is built on chain from the config
    //    account, so the registered authority is the one asserted above and the
    //    authority-transact rail stays disabled.
    send(
        rpc,
        &env.payer,
        &[InitSppRingConfig {
            payer: authority,
            authority,
        }
        .instruction()],
    )?;

    let (ring_auth, ring_auth_bump) = pda::ring_auth(&PROGRAM_ID);
    assert_eq!(ring_auth, ring_auth_pda(), "sdk ring_auth PDA helper");
    let ring_config: RingConfig = fetch_state(rpc, &ring_auth)?;
    assert_eq!(
        ring_config,
        RingConfig {
            discriminator: RING_CONFIG,
            authority,
            program_id: PROGRAM_ID,
            ring_authority_transact_is_enabled: 0,
            paused: 0,
            bump: ring_auth_bump,
        },
        "SPP ring config"
    );

    // 4. Two ring SOL deposits give the sender the ring-owned UTXOs the transfer
    //    spends. Their blindings come back from the deposit builder, so the spend
    //    is rebuilt without needing a wallet sync here.
    let mut spendable = Vec::with_capacity(2);
    for amount in [RING_DEPOSIT_A, RING_DEPOSIT_B] {
        spendable.push(ring_deposit_sol(
            rpc,
            &env.sender.keypair,
            env.tree,
            amount,
        )?);
    }

    // 5a. Spends and the transaction viewing key. That key is the audit's whole
    //     subject: every output ciphertext is HPKE'd under it, so recovering this
    //     one scalar opens the transaction. It is derived from the first
    //     nullifier, which is why the sender can re-derive it here.
    let sender_address = env.sender.keypair.pubkey();
    let recipient_address = env.recipient.keypair.shielded_address()?;
    let input_utxos: Vec<SppProofInputUtxo> = spendable
        .iter()
        .map(|utxo| SppProofInputUtxo::new(utxo.clone(), &env.sender.keypair))
        .collect();
    let tx_viewing_key = get_transaction_viewing_key(&env.sender.keypair, &input_utxos)?;

    // 5b. Two explicit outputs -- the sender's change and the recipient -- which
    //     is the (2, 2) shape. This is the `SppProofInputs` layer the transaction
    //     crate documents for ring flows, not the high-level
    //     `ConfidentialTransfer`: that builder always emits three outputs (a
    //     fixed SPL change slot, padded with a random ciphertext for a SOL-only
    //     transfer, plus the SOL change and the recipient), and the padded slot
    //     pushes this instruction 61 bytes past a transaction's 1232-byte packet
    //     even behind an address lookup table. Two real slots also mean every
    //     published slot is one the auditor must be able to open.
    let change_output = SppProofOutputUtxo::new(
        SOL_MINT,
        RING_CHANGE,
        env.sender.keypair.shielded_address()?,
    )?;
    let recipient_output =
        SppProofOutputUtxo::new(SOL_MINT, RING_TRANSFER_AMOUNT, recipient_address)?;

    // 5c. ORDER MATTERS. The auditor message has to be inside `external_data`
    //     BEFORE the SPP proof runs: SPP folds `messages` into
    //     `external_data_hash` and that into `private_tx_hash`, which is element 1
    //     of the audit circuit's public-input chain. Proving SPP first and
    //     appending the message afterwards yields two irreconcilable
    //     `private_tx_hash` values -- whichever one the ring proof commits to, the
    //     other is the one SPP checks. `encrypt` returning a `PendingAuditProof`
    //     that only `finish` can turn into a witness is what makes the order
    //     unforgettable: there is no `private_tx_hash` to supply yet.
    let (pending_audit_proof, auditor_message) = AuditProofParams {
        tx_viewing_sk: tx_viewing_key.secret_bytes(),
        auditor_pk,
    }
    .encrypt()?;

    let encoded = encrypt_transaction_data(
        &[change_output.clone(), recipient_output.clone()],
        &env.assets,
        &tx_viewing_key,
    )?;
    let mut external_data = ExternalData::new(
        *tx_viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![auditor_message.to_message_data(&auditor_pk)],
    );
    // RING_TRANSACT is folded into external_data_hash and from there into
    // private_tx_hash, so it must be bound before anything hashes external data.
    external_data.instruction_discriminator = RING_TRANSACT;
    let proof_inputs = SppProofInputs::new(
        input_utxos,
        encoded.output_utxos,
        external_data,
        sender_address,
    );

    // 5d. Prove the SPP ring transfer over the message-bearing external data.
    let tx_shape = proof_inputs.check_shape()?;
    let ring_result = RingTransferProver {
        inputs: ring_spend_inputs(indexer, env.tree, &proof_inputs.input_utxos)?,
        outputs: proof_inputs.output_utxos.clone(),
        external_data: proof_inputs.external_data.clone(),
        public_transfers: proof_inputs.public_transfers()?,
        signer_pk_hashes: proof_inputs.signer_pk_hashes(tx_shape.n_inputs() + 1)?,
        allow_dummy_inputs: true,
        ring_program_id: Some(PROGRAM_ID),
        shape: Some(Shape::new(tx_shape.n_inputs(), tx_shape.n_outputs())),
    }
    .build()?;
    let spp_proof =
        pack_transact_proof(&ProverClient::local().prove_transfer_ring(&ring_result.inputs)?)?;

    // 5e. Now the real `private_tx_hash` exists, so the pending encryption can be
    //     finished into a witness over the unchanged ciphertext. The program
    //     recomputes that same public-input chain from the payload and the config
    //     account.
    let audit_inputs = pending_audit_proof.finish(&ring_result.private_tx_hash)?;
    let audit_proof = to_instruction_proof(
        &CustomRingProverClient::new().prove_auditor_key_encryption(&audit_inputs)?,
    );

    let data = assemble_ring_eddsa_ix_data(&proof_inputs, &ring_result, spp_proof)?;
    let owner_signers = proof_inputs.owner_signer_pubkeys()?;

    // 6. Negative, before the real spend so the tree snapshot is meaningful: flip
    //    one ciphertext byte of the auditor message with both proofs already
    //    fixed. The program recomputes the public input from the message it is
    //    handed, so the audit proof no longer verifies and the SPP CPI is never
    //    reached -- nothing is nullified and no leaf is appended.
    let mut tampered = data.clone();
    let tampered_byte = tampered
        .messages
        .last_mut()
        .ok_or_else(|| anyhow!("transact carries no auditor message"))?
        .data
        .get_mut(AUDITOR_CIPHERTEXT_OFFSET)
        .ok_or_else(|| anyhow!("auditor message carries no ciphertext"))?;
    *tampered_byte ^= 1;

    let tree_before = fetch_account(rpc, &env.tree)?;
    let rejection = send_v0_expecting_rejection(
        rpc,
        &env.sender.keypair,
        ring_transact_ix(
            sender_address,
            env.tree,
            owner_signers.clone(),
            audit_proof,
            tampered,
        )?,
    )?;
    Rejection::custom(CustomRingError::ProofVerificationFailed as u32)
        .at(1)
        .assert_client(&rejection);
    assert_account_unchanged(rpc, &env.tree, &tree_before)?;

    // 7. The real audited transfer.
    let signature = send_v0_with_lookup_table(
        rpc,
        &env.sender.keypair,
        ring_transact_ix(sender_address, env.tree, owner_signers, audit_proof, data)?,
    )?;

    // 8. What the auditor sees. Photon matches the auditor view tag against
    //    MESSAGE tags, which is what makes the transaction discoverable to
    //    someone who owns no output in it.
    let auditor_tag = auditor_view_tag(&auditor_pk);
    let indexed = wait_for_indexed_transaction(indexer, auditor_tag, signature);
    assert_eq!(
        indexed.messages.last().map(|message| message.view_tag),
        Some(auditor_tag),
        "the auditor message is the last published message"
    );
    assert_eq!(
        indexed.tx_viewing_pk,
        Some(tx_viewing_key.pubkey()),
        "the on-chain tx_viewing_pk is the key the sender derived"
    );

    let audited = audit_ring_transactions(indexer, &auditor, &env.assets)?;
    assert_eq!(
        audited.len(),
        1,
        "exactly one auditor-tagged transaction landed (the tampered one never did)"
    );
    let audited = audited
        .first()
        .ok_or_else(|| anyhow!("audited transaction"))?;
    assert_eq!(audited.tx_signature, signature, "audited signature");
    assert_eq!(
        audited.tx_viewing_pk,
        tx_viewing_key.pubkey(),
        "auditor recovered the transaction's viewing key"
    );
    // The expected plaintexts are the test's own inputs: the amounts from its
    // constants, the blindings from the output UTXOs the sender built and
    // committed to. Nothing here is read back out of the audit result.
    assert_eq!(
        audited.outputs,
        vec![
            AuditedOutput {
                slot_index: CHANGE_SLOT,
                asset: SOL_MINT,
                amount: RING_CHANGE,
                blinding: change_output.blinding,
                ring_program_id: None,
            },
            AuditedOutput {
                slot_index: RECIPIENT_SLOT,
                asset: SOL_MINT,
                amount: RING_TRANSFER_AMOUNT,
                blinding: recipient_output.blinding,
                ring_program_id: None,
            },
        ],
        "auditor-decrypted outputs equal what the sender sent, blindings included"
    );
    assert!(
        audited.undecryptable_slots.is_empty(),
        "both published slots are real, so the auditor opened every one: {:?}",
        audited.undecryptable_slots
    );

    // 9. Normal operation is undisturbed: the recipient still discovers its
    //    output through `Wallet::sync` on its own view tag, with no auditor key.
    let recipient_authority = LocalWalletAuthority::new(Address::default(), &env.recipient.keypair);
    env.recipient.wallet.sync(
        &recipient_authority,
        std::slice::from_ref(&indexed),
        0,
        DEFAULT_TAG_WINDOW,
    )?;
    let discovered: Vec<(Address, u64)> = env
        .recipient
        .wallet
        .utxos
        .iter()
        .filter(|held| !held.spent)
        .map(|held| (held.utxo.asset, held.utxo.amount))
        .collect();
    assert_eq!(
        discovered,
        vec![(SOL_MINT, RING_TRANSFER_AMOUNT)],
        "recipient wallet discovers exactly the transferred output"
    );

    Ok(())
}

/// Ring-deposit `amount` of SOL to `keypair`'s shielded address through the
/// custom-ring program, returning the ring-owned UTXO it created.
///
/// Mirrors `program-tests/test-utils/src/ring/ring_deposit.rs::ring_shield_sol`:
/// the public face of a ring deposit carries only the `owner_utxo_hash`
/// commitment and the recipient bootstrap view tag, while the blinding travels in
/// an envelope encrypted to the recipient's viewing key. The ring proves nothing
/// here -- deposit amounts are public on chain -- so the program only lends its
/// `ring_auth` signature and forwards the instruction.
fn ring_deposit_sol(
    rpc: &SolanaRpc,
    keypair: &ShieldedKeypair,
    tree: Address,
    amount: u64,
) -> Result<Utxo> {
    let blinding = random_blinding();
    let deposit = RingAssetDeposit {
        asset: DepositAsset::Sol,
        view_tag: keypair.recipient_bootstrap_view_tag(),
        owner_utxo_hash: owner_utxo_hash(&keypair.owner_hash()?, &blinding)?,
        amount,
        data_hash: None,
        ring_data_hash: ZERO,
        encrypted: RingDepositPlaintext {
            blinding,
            utxo_data: None,
            memo: None,
            ring_data: Vec::new(),
        }
        .encrypt(&keypair.viewing_pubkey())?,
    };
    let ix = Deposit {
        tree,
        depositor: keypair.pubkey(),
        deposits: vec![deposit],
    }
    .instruction()
    .map_err(|e| anyhow!("ring deposit instruction: {e}"))?;
    send(rpc, keypair, &[ix])?;

    Ok(Utxo {
        owner: keypair.signing_pubkey(),
        asset: SOL_MINT,
        amount,
        blinding,
        // A ring deposit's output is owned by the ring, and that binds the ring
        // into the UTXO hash the transfer proof spends.
        ring_program_id: Some(PROGRAM_ID),
        data: Data::default(),
    })
}

/// Fetch the state and non-inclusion witnesses every spend needs, waiting for the
/// indexer to catch up with the deposits. Mirrors
/// `program-tests/test-utils/src/ring/ring_transact.rs::ring_spend_inputs`; the
/// (2, 3) shape here is filled by two real inputs, so a padded slot would mean
/// the transfer was built differently than intended.
fn ring_spend_inputs<I: Rpc>(
    indexer: &I,
    tree: Address,
    spends: &[SppProofInputUtxo],
) -> Result<Vec<TransferSpendInput>> {
    let mut inputs = Vec::with_capacity(spends.len());
    for spend in spends {
        if spend.is_dummy() {
            return Err(anyhow!(
                "the audited transfer spends two real ring UTXOs; no dummy input slot expected"
            ));
        }
        let nullifier_pk = spend.nullifier_key.pubkey()?;
        let utxo_hash = spend.utxo.hash(&nullifier_pk, &ZERO, &ZERO)?;
        let nullifier = spend
            .nullifier_key
            .nullifier(&utxo_hash, &spend.utxo.blinding)?;
        inputs.push(TransferSpendInput {
            utxo: spend.utxo.clone(),
            nullifier_key: spend.nullifier_key.clone(),
            data_hash: None,
            ring_data_hash: None,
            proof: Some(SpendProof {
                state: wait_for_merkle_proof(indexer, tree, utxo_hash),
                nullifier: wait_for_non_inclusion_proof(indexer, tree, nullifier),
            }),
            nullifier_proof: None,
        });
    }
    Ok(inputs)
}

/// Fold the signed transaction's external data and the ring prover's result into
/// the `TransactIxData` SPP verifies. Mirrors
/// `program-tests/test-utils/src/ring/ring_transact.rs::assemble_ix_data`,
/// reduced to the eddsa rail this ring supports: `external_data` fields flow
/// through unchanged (already rebound to `RING_TRANSACT` and already carrying the
/// auditor message), and authorization comes from the leading signer run in the
/// account list rather than from any per-input field.
fn assemble_ring_eddsa_ix_data(
    proof_inputs: &SppProofInputs,
    result: &RingTransferProofResult,
    proof: TransactProof,
) -> Result<TransactIxData> {
    let n_inputs = proof_inputs.check_shape()?.n_inputs();
    let inputs: Vec<InputUtxo> = result
        .nullifiers
        .iter()
        .zip(result.input_root_indices.iter())
        .map(
            |(nullifier_hash, &(utxo_tree_root_index, nullifier_tree_root_index))| InputUtxo {
                nullifier_hash: *nullifier_hash,
                nullifier_tree_root_index,
                utxo_tree_root_index,
            },
        )
        .collect();
    if inputs.len() != n_inputs {
        return Err(anyhow!(
            "prover returned {} nullifier/root-index pairs for shape {n_inputs}",
            inputs.len()
        ));
    }

    let external = &proof_inputs.external_data;
    Ok(TransactIxData {
        proof,
        expiry_unix_ts: external.expiry_unix_ts,
        private_tx_hash: result.private_tx_hash,
        circuit: CircuitId::RingEddsa(
            n_inputs as u8,
            external.outputs.len() as u8,
            N_PUBLIC_SLOTS as u8,
        ),
        inputs,
        interface_transfers: external
            .interface_transfers
            .iter()
            .map(|transfer| transfer.interface_transfer())
            .collect(),
        data_hash: external.data_hash,
        ring_data_hash: external.ring_data_hash,
        tx_viewing_pk: external.tx_viewing_pk,
        salt: external.salt,
        outputs: external.outputs.clone(),
        messages: external.messages.clone(),
    })
}

/// The audited ring transact instruction. `ring_config` (the ring's `ring_auth`
/// PDA) stays unsigned here; the program flips it to a signer inside its CPI.
fn ring_transact_ix(
    payer: Address,
    tree: Address,
    owner_signers: Vec<Address>,
    audit_proof: AuditProof,
    transact: TransactIxData,
) -> Result<Instruction> {
    let ix = RingTransactWithAudit {
        payer,
        input_tree: tree,
        output_tree: tree,
        owner_signers,
        interface_transfer_accounts: Vec::new(),
        audit_proof,
        transact,
    }
    .instruction()
    .map_err(|e| anyhow!("ring transact instruction: {e}"))?;
    Ok(ix)
}

fn lamports<R: Rpc>(rpc: &R, address: Address) -> Result<u64> {
    Ok(rpc
        .get_account(address)?
        .ok_or_else(|| anyhow!("account {address} not found"))?
        .lamports)
}
