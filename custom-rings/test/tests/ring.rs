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
use custom_ring_interface::{RingProgramConfig, CONFIG_PDA_SEED, RING_PROGRAM_CONFIG};
use custom_ring_program::CustomRingError;
use custom_ring_sdk::{
    auditor_view_tag, AuditedTransfer, AuditedTransferInput, CreateConfig, CustomRing,
    InitSppRingConfig, RingDeposit, RingDepositReceipt, RingTransactWithAudit,
    TransferProofEnvironment, V0WithLookupTable,
};
use shared::{custom_ring_program_id, prover_url, send, send_v0_expecting_rejection, setup};
use solana_address::Address;
use solana_packet::PACKET_DATA_SIZE;
use solana_signer::Signer;
use zeroize::Zeroizing;
use zolana_client::{ProverClient, Rpc};
use zolana_interface::{
    pda,
    state::{
        discriminator::{PROTOCOL_CONFIG, RING_CONFIG, TREE_ACCOUNT_DISCRIMINATOR},
        tree_account_size, ProtocolConfig, RingConfig,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::ViewingKey;
use zolana_program_test::Rejection;
use zolana_ring_client::{AuditedOutput, RingAudit, RingEnvironment};
use zolana_test_utils::{
    smart_account,
    test_validator_asserts::{
        assert_account_unchanged, assert_transaction_compute_units, fetch_account, fetch_state,
        wait_for_indexed_transaction,
    },
};
use zolana_transaction::{
    instructions::{transact::ConfidentialTransfer, types::SppProofInputUtxo},
    LocalWalletAuthority, DEFAULT_TAG_WINDOW, SOL_ASSET_ID, SOL_MINT,
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
const SECOND_HOP_AMOUNT: u64 = 400_000_000;

/// Output slot layout this test publishes: the sender's change first, the
/// recipient second. A slot's index is what its ciphertext is bound to, so these
/// are also the `slot_index` values the auditor must report.
const CHANGE_SLOT: u32 = 0;
const RECIPIENT_SLOT: u32 = 1;

/// Offset of the ciphertext inside the auditor message
/// (`eph_pk_compressed(33) || ciphertext(32)`), i.e. the first byte the negative
/// case tampers with.
const AUDITOR_CIPHERTEXT_OFFSET: usize = 33;

const AUDITED_RING_TRANSACT_CU_LIMIT: u64 = 486_000;
/// A UTXO's `data_hash` / `ring_data_hash` when it carries neither.

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
            .map_err(|e| anyhow!("SOL asset resolution failed {e:?}"))?,
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
        .map_err(|e| anyhow!("tree layout failed {e:?}"))?;
    assert_eq!(
        tree.discriminator(),
        TREE_ACCOUNT_DISCRIMINATOR,
        "tree discriminator"
    );
    assert!(!tree.is_paused(), "tree must be unpaused after creation");
    let state_root = tree
        .get_utxo_tree_root(0)
        .map_err(|e| anyhow!("UTXO tree root failed {e:?}"))?;
    assert_ne!(state_root, [0u8; 32], "empty state tree still has a root");

    // 5. Photon answers the tag query the auditor client pages through, and has
    //    persisted at least one slot of the chain it is indexing.
    let indexed = env
        .client
        .indexer()
        .get_shielded_transactions_by_tags(vec![UNUSED_VIEW_TAG], None, Some(10), None)
        .map_err(|e| anyhow!("indexer {} failed {e:?}", env.indexer_url))?;
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

    V0WithLookupTable {
        payer: &env.payer,
        signers: &[],
        instruction: solana_system_interface::instruction::transfer(
            &env.payer.pubkey(),
            &recipient,
            PROBE_TRANSFER,
        ),
    }
    .send(rpc)?;
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
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);

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
            ring,
            payer: authority,
            authority,
            auditor_pubkey: auditor_pk,
        }
        .instruction()?],
    )?;

    let (config_address, config_bump) =
        Address::find_program_address(&[CONFIG_PDA_SEED], &ring_program);
    assert_eq!(config_address, ring.config_pda(), "sdk config PDA helper");
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
            ring,
            payer: authority,
            authority,
        }
        .instruction()],
    )?;

    let (ring_auth, ring_auth_bump) = pda::ring_auth(&ring_program);
    assert_eq!(ring_auth, ring.ring_auth_pda(), "sdk ring_auth PDA helper");
    let ring_config: RingConfig = fetch_state(rpc, &ring_auth)?;
    assert_eq!(
        ring_config,
        RingConfig {
            discriminator: RING_CONFIG,
            authority,
            program_id: ring_program,
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
        let RingDepositReceipt { utxo, .. } = RingDeposit {
            ring,
            payer: &env.sender.keypair,
            recipient: &env.sender.keypair,
            tree: env.tree,
            amount,
        }
        .send(rpc)?;
        spendable.push(utxo);
    }

    // 5a. Spends and the transaction viewing key. That key is the audit's whole
    //     subject: every output ciphertext is HPKE'd under it, so recovering this
    //     one scalar opens the transaction. It is derived from the first
    //     nullifier, which is why the sender can re-derive it here.
    let sender_address = env.sender.keypair.pubkey();
    let inputs = spendable
        .into_iter()
        .map(|utxo| SppProofInputUtxo::new(utxo, &env.sender.keypair))
        .collect();
    let mut transfer = ConfidentialTransfer::new(
        env.sender.keypair.shielded_address()?,
        inputs,
        sender_address,
    );
    transfer.send(
        &env.recipient.keypair.shielded_address()?,
        SOL_MINT,
        RING_TRANSFER_AMOUNT,
    )?;
    let prepared = transfer.prepare()?;
    let change_output = prepared
        .outputs
        .iter()
        .find(|output| output.amount == RING_CHANGE)
        .cloned()
        .ok_or_else(|| anyhow!("ring change output"))?;
    let recipient_output = prepared
        .outputs
        .iter()
        .find(|output| output.amount == RING_TRANSFER_AMOUNT)
        .cloned()
        .ok_or_else(|| anyhow!("ring recipient output"))?;

    let prover = ProverClient::local();
    let proven = AuditedTransfer::new(AuditedTransferInput {
        ring,
        sender: &env.sender.keypair,
        prepared,
    })
    .with_tree(env.tree)
    .with_assets(&env.assets)
    .prove(TransferProofEnvironment {
        indexer,
        rpc,
        prover: &prover,
    })?;
    let tx_viewing_pk = proven.tx_viewing_key.pubkey();

    let mut tampered_data = proven.data.clone();
    let tampered_byte = tampered_data
        // 6. Negative, before the real spend so the tree snapshot is meaningful: flip
        //    one ciphertext byte of the auditor message with both proofs already
        //    fixed. The program recomputes the public input from the message it is
        //    handed, so the audit proof no longer verifies and the SPP CPI is never
        //    reached -- nothing is nullified and no leaf is appended.
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
        RingTransactWithAudit {
            ring,
            payer: sender_address,
            input_tree: env.tree,
            output_tree: env.tree,
            owner_signers: proven.owner_signers.clone(),
            interface_transfer_accounts: Vec::new(),
            audit_proof: proven.audit_proof,
            transact: tampered_data,
        }
        .instruction()?,
    )?;
    Rejection::custom(CustomRingError::ProofVerificationFailed as u32)
        .at(1)
        .assert_client(&rejection);
    assert_account_unchanged(rpc, &env.tree, &tree_before)?;

    let transaction = V0WithLookupTable {
        payer: &env.sender.keypair,
        signers: &[],
        instruction: proven.instruction()?,
    }
    .build(rpc)?;
    let transaction_size =
        bincode::serde::encode_to_vec(&transaction, bincode::config::legacy())?.len();
    assert!(
        transaction_size <= PACKET_DATA_SIZE,
        "transaction packet size"
    );
    let signature = rpc
        .client()
        .send_and_confirm_transaction(&transaction)
        .map_err(|error| anyhow!("send v0 failed {error}"))?;
    assert_transaction_compute_units(
        // 7. The real audited transfer.
        rpc,
        &signature,
        "audited ring transact 2x2",
        AUDITED_RING_TRANSACT_CU_LIMIT,
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
        Some(tx_viewing_pk),
        "the on-chain tx_viewing_pk is the key the sender derived"
    );

    let audited = RingAudit::new(ring_program, &auditor)
        .run(
            RingEnvironment {
                indexer,
                origin: rpc,
            },
            &env.assets,
        )?
        .transactions;
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
        audited.tx_viewing_pk, tx_viewing_pk,
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
                recipient_viewing_pk: env.sender.keypair.viewing_pubkey(),
                owner_tag: env
                    .sender
                    .keypair
                    .signing_pubkey()
                    .confidential_view_tag()
                    .expect("sender owner tag"),
                asset: SOL_MINT,
                amount: RING_CHANGE,
                blinding: Zeroizing::new(change_output.blinding),
                ring_program_id: Some(ring_program),
            },
            AuditedOutput {
                slot_index: RECIPIENT_SLOT,
                recipient_viewing_pk: env.recipient.keypair.viewing_pubkey(),
                owner_tag: env
                    .recipient
                    .keypair
                    .signing_pubkey()
                    .confidential_view_tag()
                    .expect("recipient owner tag"),
                asset: SOL_MINT,
                amount: RING_TRANSFER_AMOUNT,
                blinding: Zeroizing::new(recipient_output.blinding),
                ring_program_id: Some(ring_program),
            },
        ],
        "auditor-decrypted outputs equal what the sender sent, recipients and blindings included"
    );
    assert!(audited.undecryptable_slots.is_empty());

    // 9. Normal operation is undisturbed: the recipient still discovers its
    //    output through `Wallet::sync` on its own view tag, with no auditor key.
    let recipient_authority = LocalWalletAuthority::new(Address::default(), &env.recipient.keypair);
    env.recipient.wallet.sync(
        &recipient_authority,
        std::slice::from_ref(&indexed),
        0,
        DEFAULT_TAG_WINDOW,
    )?;
    let discovered: Vec<(Address, u64, Option<Address>)> = env
        .recipient
        .wallet
        .utxos
        .iter()
        .filter(|held| !held.spent)
        .map(|held| (held.utxo.asset, held.utxo.amount, held.utxo.ring_program_id))
        .collect();
    assert_eq!(
        discovered,
        vec![(SOL_MINT, RING_TRANSFER_AMOUNT, Some(ring_program))],
        "recipient wallet discovers the custom ring output"
    );

    let received = env
        .recipient
        .wallet
        .utxos
        .iter()
        .find(|held| !held.spent)
        .map(|held| held.utxo.clone())
        .ok_or_else(|| anyhow!("recipient note"))?;
    let hop_inputs = vec![SppProofInputUtxo::new(received, &env.recipient.keypair)];
    let mut hop_transfer = ConfidentialTransfer::new(
        env.recipient.keypair.shielded_address()?,
        hop_inputs,
        env.recipient.keypair.pubkey(),
    );
    hop_transfer.send(
        &env.sender.keypair.shielded_address()?,
        SOL_MINT,
        SECOND_HOP_AMOUNT,
    )?;
    let hop_prepared = hop_transfer.prepare()?;
    let hop = AuditedTransfer::new(AuditedTransferInput {
        ring,
        sender: &env.recipient.keypair,
        prepared: hop_prepared,
    })
    .with_tree(env.tree)
    .with_assets(&env.assets)
    .prove(TransferProofEnvironment {
        indexer,
        rpc,
        prover: &prover,
    })?;
    let hop_signature = V0WithLookupTable {
        payer: &env.recipient.keypair,
        signers: &[],
        instruction: hop.instruction()?,
    }
    .send(rpc)?;
    wait_for_indexed_transaction(indexer, auditor_tag, hop_signature);
    let audited = RingAudit::new(ring_program, &auditor)
        .run(
            RingEnvironment {
                indexer,
                origin: rpc,
            },
            &env.assets,
        )?
        .transactions;
    let hop_outputs: Vec<(u64, Option<Address>)> = audited
        .iter()
        .find(|tx| tx.tx_signature == hop_signature)
        .ok_or_else(|| anyhow!("second hop audited"))?
        .outputs
        .iter()
        .map(|output| (output.amount, output.ring_program_id))
        .collect();
    assert_eq!(
        hop_outputs,
        vec![
            (RING_TRANSFER_AMOUNT - SECOND_HOP_AMOUNT, Some(ring_program)),
            (SECOND_HOP_AMOUNT, Some(ring_program)),
        ],
        "second hop outputs"
    );

    Ok(())
}

fn lamports<R: Rpc>(rpc: &R, address: Address) -> Result<u64> {
    Ok(rpc
        .get_account(address)?
        .ok_or_else(|| anyhow!("account {address} not found"))?
        .lamports)
}
