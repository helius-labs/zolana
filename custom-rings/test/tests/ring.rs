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
//!
//! [`an_audit_only_ring_audits_every_transfer`] runs the lighter tier, no
//! policy and the audit statement alone, with the same auditor recovery.
//! Its second hop, like the capstone's, is proven through the blocking client and
//! through a native async client, and lands the native proof (see [`AsyncHopParity`]).
//!
//! [`an_anonymous_ring_hides_owners_and_preserves_auditor_access`] pays ring
//! addresses on the inbox and pair streams, and fresh wallets find every payment,
//! the change and a merge by exact tags.
//!
//! [`ring_value_leaves_and_enters_through_audited_transfers`] crosses the ring
//! boundary in both directions under the auditor and pins that a note of
//! another ring is refused before proving.

#[path = "ring_shapes.rs"]
mod shapes;

use std::{
    collections::HashMap,
    net::{TcpStream, ToSocketAddrs},
    path::PathBuf,
    time::Duration,
};

use anyhow::{anyhow, ensure, Context, Result};
use custom_ring_cli::{address::ring_address, wait_for, Landing, ModeName, Probe, Queued};
use custom_ring_interface::{
    stream::RingTag, AnonymousProofData, CustomRingError, RingMode, RingProgramConfig, RingRail,
    RingTransactData, CONFIG_PDA_SEED, DEFAULT_INSERT_FEE, RING_PROGRAM_CONFIG,
};
use custom_ring_sdk::{
    compute_unit_limit, AnonymousTransfer, CoSignScope, CoSignThreshold, CustomRing,
    CustomRingMerge, CustomRingTransfer, CustomRingTransferInput, DelegateOutput, DelegateTransfer,
    DelegateTransferInput, DepositRecipient, InstructionTag, MergeProofInput, PendingFirstContact,
    ProvenRingTransfer, RegisterKey, RingDeposit, RingDepositReceipt, RingError,
    RingMergeOperation, RingOperation, RingRegistration,
};
use custom_ring_test_validator::{
    cli::{merged, RingProject, RingToml},
    policy::{
        owner_member, policy_registry, RegistryWrite, RingNotes, EMPTY, LIMIT_CAP,
        LIMIT_COSIGN_ABOVE, OUTFLOW_LIMIT,
    },
    ring_rpc::RingRpcSpec,
    shared::{
        custom_ring_program_id, prover_url, send, send_expecting_rejection, setup, ExpectRejection,
        RegisterRing, RejectedTransact, TestEnv, Tier, USDC_ASSET_ID,
    },
};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::v1::MAX_TRANSACTION_SIZE;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    compile_message, sign_transaction, AnonymousRingState, AsyncProverClient, AsyncSolanaRpc,
    AsyncZolanaClient, AsyncZolanaIndexer, ComputeBudgetConfig, ProofDataSource, ProverClient, Rpc,
    ShieldedTransaction, SolanaRpc, ZolanaIndexer,
};
use zolana_interface::{
    error::ShieldedPoolError,
    pda,
    state::{
        discriminator::{PROTOCOL_CONFIG, RING_CONFIG, TREE_ACCOUNT_DISCRIMINATOR},
        tree_account_size, ProtocolConfig, RingConfig,
    },
    SHIELDED_POOL_PROGRAM_ID, ZERO_NULLIFIER_PUBKEY,
};
use zolana_keypair::{
    random_blinding, RingAddress, RingPaymentRequest, ShieldedAddress, ShieldedKeypair,
    X25519Keypair,
};
use zolana_program::instruction::{
    AssetDeposit, Deposit as SppDeposit, DepositAsset, DepositSplAccounts,
    TransactInterfaceTransferAccounts, TransactSplWithdrawalAccounts, UpdateRingConfig,
};
use zolana_program_test::Rejection;
use zolana_ring_client::{
    auditor_view_tag,
    rpc::{write_auditor_key, CreateAuditorKeyRequest},
    AuditedTransaction, OutputOpening, RingRecovery, RingScan, SourceMember,
};
use zolana_ring_policy::{ListId, Member, Rule, RuleTable, Subject};
use zolana_ring_rpc::{
    ChainSource, Hub, RingRpcError, RootSecret, TransactionSource, Unauthorized, Upstreams,
};
use zolana_test_utils::wallet::{sync_wallet, KeypairWalletAuthority, Wallet, DEFAULT_TAG_WINDOW};
use zolana_test_utils::{
    localnet::isolated_temp_path,
    smart_account,
    spl::{create_token_account, mint_to},
    test_validator_asserts::{
        assert_account_unchanged, assert_transaction_compute_units, fetch_account, fetch_state,
        token_amount, wait_for_indexed_transaction, wait_for_merkle_proof,
    },
};
use zolana_transaction::{
    decrypt_spendable,
    instructions::transact::{canonical_shape, ConfidentialTransaction, SppProofOutputUtxo},
    AssetRegistry, Data, EncryptedScheme, Mint, Utxo, WalletUtxo, SOL_ASSET_ID, SOL_MINT,
};
use zolana_tree::TreeAccount;
use zolana_user_registry_interface::user_registry_program_id;

/// Lamports moved by the two transaction-shape probes. Small enough that the
/// payer's airdrop covers both plus fees.
const PROBE_TRANSFER: u64 = 1_234_567;

/// The protocol has no live transaction under an arbitrary view tag, so this
/// tag is only used to make the indexer answer a well-formed query.
const UNUSED_VIEW_TAG: [u8; 32] = [7u8; 32];

/// The two ring SOL deposits the custom-ring transfer spends. Two inputs and two
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
const PAIR_AMOUNT: u64 = 250_000_000;
const MERGED_AMOUNT: u64 = RING_TRANSFER_AMOUNT - SECOND_HOP_AMOUNT + PAIR_AMOUNT;
const MERGED_SPEND: u64 = 100_000_000;

/// Output slot layout this test publishes: the sender's change first, the
/// recipient second. A slot's index is what its ciphertext is bound to, so these
/// are also the `slot_index` values the auditor must report.
const CHANGE_SLOT: u32 = 1;
const RECIPIENT_SLOT: u32 = 0;

/// The program audit's estimate for the widest keyed transfer.
const WIDEST_TRANSACT_ESTIMATE_CU: u64 = 720_000;
const CUSTOM_RING_TRANSACT_CU_LIMIT: u64 = 1_000_000;

// Below the requested budget a confirmed transfer can still exceed the ceiling.
const _: () = assert!(
    WIDEST_TRANSACT_ESTIMATE_CU <= CUSTOM_RING_TRANSACT_CU_LIMIT
        && CUSTOM_RING_TRANSACT_CU_LIMIT < compute_unit_limit(InstructionTag::Transact) as u64
);

const DEFAULT_DEPOSIT: u64 = 4_000_000_000;
const ENTRY_AMOUNT: u64 = 2_500_000_000;
const ENTRY_CHANGE: u64 = DEFAULT_DEPOSIT - ENTRY_AMOUNT;
const EXIT_AMOUNT: u64 = 1_000_000_000;
const EXIT_CHANGE: u64 = ENTRY_CHANGE - EXIT_AMOUNT;
const REFUSED_AMOUNT: u64 = 100_000_000;
const FOREIGN_RING: Address = Address::new_from_array([9; 32]);

const USDC_FUNDING: u64 = 50_000_000;
const USDC_DEFAULT_DEPOSIT: u64 = 40_000_000;
const USDC_ENTRY_AMOUNT: u64 = 25_000_000;
const USDC_ENTRY_CHANGE: u64 = USDC_DEFAULT_DEPOSIT - USDC_ENTRY_AMOUNT;
const USDC_HOP_AMOUNT: u64 = 10_000_000;
const USDC_HOP_CHANGE: u64 = USDC_ENTRY_CHANGE - USDC_HOP_AMOUNT;
const USDC_RING_DEPOSIT: u64 = 5_000_000;
const USDC_EXIT_AMOUNT: u64 = 6_000_000;
const USDC_EXIT_CHANGE: u64 = USDC_HOP_CHANGE + USDC_RING_DEPOSIT - USDC_EXIT_AMOUNT;
const USDC_WITHDRAW_AMOUNT: u64 = 2_500_000;
const USDC_FINAL_SEND: u64 = 1_000_000;
const USDC_FINAL_CHANGE: u64 = USDC_EXIT_CHANGE - USDC_WITHDRAW_AMOUNT - USDC_FINAL_SEND;

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
    //    flows depend on, `ring_activation_is_permissionless` above all: without
    //    it the custom-ring program cannot register its `ring_auth` PDA as an
    //    SPP ring config with a plain payer.
    let accounts = smart_account::standard_accounts();
    let config: ProtocolConfig = fetch_state(rpc, &pda::protocol_config())?;
    assert_eq!(
        config,
        ProtocolConfig {
            discriminator: PROTOCOL_CONFIG,
            protocol_authority: accounts.protocol_vault,
            fee_authority: accounts.protocol_vault,
            tree_creation_authority: accounts.tree_vault,
            forester_authority: accounts.forester_vault,
            ring_creation_authority: accounts.ring_vault,
            tree_creation_is_permissionless: 0,
            ring_activation_is_permissionless: 1,
            spl_interface_creation_is_permissionless: 0,
            next_tree_id: 1,
        },
        "protocol config"
    );

    // 3. The registry the wallets share resolves SOL and the bring-up's USDC
    //    mint, and the USDC interface vault exists empty beside the counter.
    assert_eq!(
        env.assets
            .resolve(SOL_ASSET_ID)
            .map_err(|e| anyhow!("SOL asset resolution failed {e:?}"))?
            .asset,
        SOL_MINT,
        "asset id 1 is SOL"
    );
    assert_eq!(
        env.assets
            .resolve(USDC_ASSET_ID)
            .map_err(|e| anyhow!("USDC asset resolution failed {e:?}"))?
            .asset,
        env.usdc_mint,
        "the bring-up USDC mint sits at the first allocated id"
    );
    fetch_account(rpc, &pda::spl_asset_counter())?;
    assert_eq!(
        token_amount(&fetch_account(rpc, &pda::spl_interface(&env.usdc_mint))?),
        0,
        "USDC interface vault starts empty"
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

    // 7+8. Both send paths the lifecycle uses work on this validator: the
    //      harness helper and the client's compile and sign path that a ring
    //      submission takes. Both build transaction v1 messages, whose
    //      4096-byte limit is what a ring transact needs; this validator must
    //      accept the format at all. Each probe is asserted by its lamport
    //      effect.
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
        "harness v1 transfer credited the sender"
    );

    let (blockhash, _) = rpc.get_latest_blockhash()?;
    let message = compile_message(
        &env.payer.pubkey(),
        &[solana_system_interface::instruction::transfer(
            &env.payer.pubkey(),
            &recipient,
            PROBE_TRANSFER,
        )],
        blockhash,
        ComputeBudgetConfig::for_instruction_count(1),
    )?;
    rpc.process_transaction(sign_transaction(message, &[&env.payer])?)?;
    assert_eq!(
        lamports(rpc, recipient)?,
        recipient_before + PROBE_TRANSFER,
        "client v1 transfer credited the recipient"
    );

    Ok(())
}

/// The ring rpc reads the Loader v3 upgrade authority and the config authority
/// from the chain, so this runs against the deployed program, not a mock.
#[test]
fn auditor_key_is_released_only_to_the_ring_authority() -> Result<()> {
    let env = setup()?;
    let rpc = env.client.rpc();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let runtime = tokio::runtime::Runtime::new()?;
    let source = ChainSource::connect(Upstreams {
        indexer_url: &env.indexer_url,
        rpc_url: &env.rpc_url,
        timeout: Duration::from_secs(30),
    })
    .map_err(|e| anyhow!("ring rpc upstreams {e:?}"))?;
    let genesis_hash = runtime
        .block_on(source.genesis_hash())
        .map_err(|e| anyhow!("genesis hash {e:?}"))?;
    let hub = Hub::builder(source, genesis_hash)
        .derived(RootSecret::from_bytes([7; 32])?)
        .map_err(|e| anyhow!("hub {e:?}"))?;
    let service = hub
        .service(Some(ring_program))
        .map_err(|e| anyhow!("service {e:?}"))?;
    let request = |authority: &Keypair, genesis: [u8; 32]| {
        CreateAuditorKeyRequest::for_ring(ring_program, genesis).sign(authority)
    };
    let authorize = |request: &CreateAuditorKeyRequest| {
        runtime
            .block_on(service.auditor_key_statement(&request.auth))
            .map(drop)
    };
    let expect_refusal = |result: Result<(), RingRpcError>, expected: Unauthorized| match result {
        Err(RingRpcError::Unauthorized(reason)) if reason == expected => Ok(()),
        other => Err(anyhow!("expected {expected:?}, got {other:?}")),
    };
    let stranger = Keypair::new();
    let config_authority = Keypair::new();

    // 1. No config yet, so only the program's upgrade authority is accepted.
    expect_refusal(
        authorize(&request(&stranger, genesis_hash)?),
        Unauthorized::NotRingAuthority,
    )?;
    expect_refusal(
        authorize(&request(&config_authority, genesis_hash)?),
        Unauthorized::NotRingAuthority,
    )?;
    expect_refusal(
        authorize(&request(&env.payer, [0; 32])?),
        Unauthorized::ClusterMismatch,
    )?;
    let released = request(&env.payer, genesis_hash)?;
    authorize(&released).map_err(|e| anyhow!("upgrade authority {e:?}"))?;
    expect_refusal(authorize(&released), Unauthorized::Replay)?;

    // 2. Once the config exists its authority alone is accepted, even after
    //    the deployer hands it over.
    rpc.create_and_send_transaction(
        &[
            custom_ring_sdk::CreateConfig {
                ring,
                payer: env.payer.pubkey(),
                authority: env.payer.pubkey(),
                auditor_pubkey: service.auditor_pubkey(),
                kind: custom_ring_sdk::RingKind::Policy,
            }
            .instruction()?,
            custom_ring_sdk::SetAuthority {
                ring,
                authority: env.payer.pubkey(),
                new_authority: config_authority.pubkey(),
            }
            .instruction(),
        ],
        env.payer.pubkey(),
        &[&env.payer, &config_authority],
        ComputeBudgetConfig::for_instruction_count(2),
    )?;
    authorize(&request(&config_authority, genesis_hash)?)
        .map_err(|e| anyhow!("config authority {e:?}"))?;
    for refused in [&env.payer, &stranger] {
        expect_refusal(
            authorize(&request(refused, genesis_hash)?),
            Unauthorized::NotRingAuthority,
        )?;
    }
    Ok(())
}

/// The operator cli against the deployed program, the config authority is a
/// second key and the rerun sees the config through a hosted-looking ring rpc.
#[test]
fn cli_init_hands_the_config_over_and_reruns_from_the_chain() -> Result<()> {
    let env = setup()?;
    let ring = CustomRing::new(custom_ring_program_id()?);
    let auditor = X25519Keypair::new();
    let project = RingProject::create(&env, &auditor.pubkey())?;
    let init = || project.run(&["init"]);

    // 1. A local ring rpc lets the key file through, the config is created
    //    under the deployer and handed over in the same run.
    project.write_config(RingToml {
        env: &env,
        ring_rpc: "http://127.0.0.1:1",
        policy: None,
        mode: ModeName::Confidential,
    })?;
    let first = init()?;
    assert!(first.contains("authority   transferred"), "{first}");
    let config = env
        .run(ring.config(env.client.as_async()))?
        .ok_or_else(|| anyhow!("config after init"))?;
    assert_eq!(config.authority, project.config_authority.pubkey());
    assert_eq!(config.auditor_pubkey, auditor.pubkey());

    // 2. The rerun takes the key from the chain, so the hosted-looking rpc is
    //    never asked and the key file is not mistaken for a local key.
    project.write_config(RingToml {
        env: &env,
        ring_rpc: "http://ring.invalid:1",
        policy: None,
        mode: ModeName::Confidential,
    })?;
    let second = init()?;
    assert!(second.contains("config      already present"), "{second}");
    assert!(second.contains("authority   already present"), "{second}");

    // 3. The config authority closes and reopens the ring through the program,
    //    the SPP flag follows each run.
    let paused = project.run(&["authority", "pause"])?;
    assert!(paused.contains("spp ring    paused"), "{paused}");
    assert!(registration(&env, ring)?.paused, "paused by the cli");
    let resumed = project.run(&["authority", "resume"])?;
    assert!(resumed.contains("spp ring    resumed"), "{resumed}");
    assert!(!registration(&env, ring)?.paused, "reopened by the cli");
    project.remove()?;
    Ok(())
}

/// The operator can consolidate notes owned by the persistent demo wallet. The
/// command proves, lands and reads back the merge instead of stopping at an
/// instruction-builder assertion.
#[test]
fn cli_merges_fragmented_custom_ring_notes() -> Result<()> {
    cli_merge_fragments(&[3_000_000, 5_000_000])
}

#[test]
fn cli_merges_twenty_four_custom_ring_utxos() -> Result<()> {
    cli_merge_fragments(&[3_000_000; 24])
}

/// The widest `merge --count` still fits one transaction, the proof pads its spare slots.
#[test]
fn cli_merges_maximum_custom_ring_utxos() -> Result<()> {
    cli_merge_fragments(&[3_000_000; custom_ring_sdk::MAX_MERGE_INPUTS])
}

fn cli_merge_fragments(amounts: &[u64]) -> Result<()> {
    let count = amounts.len().to_string();
    let total: u64 = amounts.iter().sum();
    let env = setup()?;
    let tree = env.register_default_tree()?;
    let ring = CustomRing::new(custom_ring_program_id()?);
    let auditor = X25519Keypair::new();
    let project = RingProject::create(&env, &auditor.pubkey())?;
    project.write_config(RingToml {
        env: &env,
        ring_rpc: "http://127.0.0.1:1",
        policy: None,
        mode: ModeName::Confidential,
    })?;
    project.run(&["init"])?;

    // The first run creates the persistent sender key, but correctly refuses
    // to manufacture a merge from fewer than two notes.
    let empty = project.output(&["merge", "--count", &count])?;
    assert!(!empty.status.success(), "an empty wallet cannot merge");
    let empty_text = merged(&empty);
    assert!(
        empty_text.contains("found only 0 mergeable notes"),
        "{empty_text}"
    );
    let sender = project.demo_sender()?;

    for &amount in amounts {
        let deposit = RingDeposit {
            ring,
            payer: &env.payer,
            recipient: DepositRecipient::Confidential(sender.shielded_address()?),
            tree,
            asset: DepositAsset::Sol,
            amount,
            cosigner: None,
        };
        let receipt = env.run(deposit.send(env.client.as_async()))?;
        custom_ring_cli::wait_for_indexed_transaction(&env.client, receipt.signature)?;
    }

    let output = project.run(&["merge", "--count", &count])?;
    for line in [
        format!("inputs      {count}"),
        format!("amount      {total}"),
        "merge preserves value".to_owned(),
    ] {
        assert!(output.contains(&line), "{line} in\n{output}");
    }

    let scan = zolana_client::UtxoScan::new(&sender, &env.assets)
        .with_ring_deposit_payload(ring.program_id(), zolana_ring_client::deposit_payload)
        .fetch(env.client.indexer())?;
    assert_eq!(
        scan.spendable
            .utxos()
            .map(|utxo| utxo.utxo.amount)
            .collect::<Vec<_>>(),
        vec![total],
        "a scan apart from the cli finds every input spent and the whole value merged"
    );

    let signature = output
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("merge"))
                .then(|| fields.next()?.parse::<Signature>().ok())
                .flatten()
        })
        .context("merge CLI did not print its confirmed signature")?;
    let confirmed: serde_json::Value = env.client.rpc().client().send(
        solana_rpc_client_api::request::RpcRequest::GetTransaction,
        serde_json::json!([signature.to_string(), {
            "encoding": "base64",
            "commitment": "confirmed",
            "maxSupportedTransactionVersion": 1,
        }]),
    )?;
    assert!(confirmed["meta"]["err"].is_null(), "{confirmed}");
    let encoded = confirmed["transaction"][0]
        .as_str()
        .context("confirmed merge has no base64 transaction")?;
    let bytes = encoded.len() / 4 * 3 - encoded.bytes().rev().take_while(|b| *b == b'=').count();
    assert!(bytes <= MAX_TRANSACTION_SIZE, "merge has {bytes} bytes");
    println!(
        "merge inputs={count} amount={total} bytes={bytes} compute_units={} signature={signature}",
        confirmed["meta"]["computeUnitsConsumed"]
    );
    project.remove()?;
    Ok(())
}

/// The operator cli runs an anonymous ring, a separate fee payer funds the hidden owner's
/// deposits and payment, and `audit` opens the payment with the auditor key.
#[test]
fn cli_pays_an_anonymous_ring_address_end_to_end() -> Result<()> {
    let env = setup()?;
    let ring = CustomRing::new(custom_ring_program_id()?);
    let keys = PathBuf::from(isolated_temp_path("zolana-ring-anonymous"));
    std::fs::create_dir_all(&keys)?;
    let auditor_key = keys.join("auditor.key");
    let auditor = write_auditor_key(&auditor_key)?;
    let ring_rpc = RingRpcSpec {
        env: &env,
        ring: ring.program_id(),
        auditor: auditor.clone(),
    }
    .serve()?;
    let project = RingProject::create(&env, &auditor.pubkey())?;
    project.write_config(RingToml {
        env: &env,
        ring_rpc: &ring_rpc.url,
        policy: None,
        mode: ModeName::Anonymous,
    })?;
    let init = project.run(&["init"])?;
    assert!(init.contains("spp ring    registered"), "{init}");
    let config = env.run(ring.require_config(env.client.as_async()))?;
    assert_eq!(config.mode, RingMode::Anonymous);

    // 1. Without a fee payer the cli refuses, it never charges the hidden owner or the authority.
    let recipient = ShieldedKeypair::new_ed25519()?;
    let request =
        RingPaymentRequest::new(ring_address(&recipient, ring.program_id(), 0)?).to_string();
    let amount = PAIR_AMOUNT.to_string();
    let refused = project.output(&["transfer", &request, "--amount", &amount])?;
    assert!(
        !refused.status.success(),
        "an anonymous transfer needs a fee payer"
    );
    let text = merged(&refused);
    assert!(text.contains("--fee-payer-keypair"), "{text}");

    // 2. The fee payer funds two deposits into the hidden balance and the payment.
    let fee_payer = keys.join("fee-payer.json");
    solana_keypair::write_keypair_file(&Keypair::new(), &fee_payer)
        .map_err(|e| anyhow!("write the fee payer keypair {e}"))?;
    let fee_payer = fee_payer.to_str().context("the fee payer path is utf-8")?;
    let paid = project.run(&[
        "--fee-payer-keypair",
        fee_payer,
        "transfer",
        &request,
        "--amount",
        &amount,
    ])?;
    assert!(
        paid.contains(&format!("{amount} base units")),
        "the payment names its amount in\n{paid}"
    );
    let sender = project.demo_sender()?;
    assert_eq!(
        env.client.rpc().get_balance(sender.pubkey())?,
        0,
        "the hidden owner never holds a lamport, it pays nothing"
    );

    // 3. `audit` opens the payment, its hidden sender and the recipient's output.
    let auditor_key = auditor_key
        .to_str()
        .context("the auditor key path is utf-8")?;
    let audited = project.run(&["audit", "--auditor-key", auditor_key])?;
    for line in [
        format!("hidden sender {}", sender.pubkey()),
        format!("ring to {}", recipient.pubkey()),
    ] {
        assert!(audited.contains(&line), "{line} in\n{audited}");
    }
    project.remove()?;
    std::fs::remove_dir_all(keys)?;
    Ok(())
}

/// The full custom-ring lifecycle: config creation, SPP registration, two ring SOL
/// deposits, one custom-ring transfer, and then the assertion that matters --
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
    let auditor = X25519Keypair::new();
    let auditor_pk = auditor.pubkey();
    let auditor_pubkey = *auditor_pk.as_bytes();

    // 2. The SPP registration waits for the policy pin.
    let authority = env.payer.pubkey();
    let configured = RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor_pk,
        tier: Tier::policy(&EMPTY),
    }
    .configure(rpc)?;
    let rejection = ExpectRejection {
        payer: &env.payer,
        instructions: &[configured.registration(&env.client)?],
    }
    .send(rpc)?;
    Rejection::custom(CustomRingError::PolicyNotSet as u32)
        .at(0)
        .assert_client(&rejection);
    assert!(
        env.run(ring.registration(env.client.as_async()))?.is_none(),
        "no SPP ring config before the policy is pinned"
    );
    let pinned = configured.pin(&env.client)?;
    // The ring forwards the protocol config unchecked.
    let mut substituted = pinned.registration();
    substituted.accounts[3].pubkey = Address::new_unique();
    let rejection = ExpectRejection {
        payer: &env.payer,
        instructions: &[substituted],
    }
    .send(rpc)?;
    Rejection::pool(ShieldedPoolError::InvalidProtocolConfig)
        .at(0)
        .assert_client(&rejection);
    pinned.register(rpc)?;

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
            has_policy: 1,
            mode: RingMode::Off as u8,
            ..config
        },
        "custom-ring config account"
    );
    assert_eq!(
        config.insert_fee(),
        DEFAULT_INSERT_FEE,
        "default insert fee"
    );
    assert_eq!(config.co_signer(), None, "no co-signer");
    assert_eq!(config.delegate(), None, "no delegate");

    // 3. Register the ring with SPP. The `RingConfig` SPP allocates IS the ring's
    //    `ring_auth` PDA, and the content is built on chain from the config
    //    account, so the registered authority is `ring_auth` itself and the
    //    authority-transact rail stays disabled.
    let (ring_auth, ring_auth_bump) = pda::ring_auth(&ring_program);
    assert_eq!(ring_auth, ring.ring_auth_pda(), "sdk ring_auth PDA helper");
    let ring_config: RingConfig = fetch_state(rpc, &ring_auth)?;
    assert_eq!(
        ring_config,
        RingConfig {
            discriminator: RING_CONFIG,
            authority: ring_auth,
            program_id: ring_program,
            ring_authority_transact_is_enabled: 0,
            paused: 0,
            // The fixture bootstraps with permissionless activation.
            activated: 1,
            bump: ring_auth_bump,
        },
        "SPP ring config"
    );

    // 3b. The human authority reaches the SPP flags only through the program,
    //     and a paused ring takes no deposit until it is reopened.
    let rejection = ExpectRejection {
        payer: &env.payer,
        instructions: &[UpdateRingConfig {
            authority,
            ring_config: ring_auth,
            paused: true,
        }
        .instruction()],
    }
    .send(rpc)?;
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller)
        .at(0)
        .assert_client(&rejection);
    let sender_address = env.sender.keypair.shielded_address()?;
    let deposit = |amount| RingDeposit {
        ring,
        payer: &env.sender.keypair,
        recipient: DepositRecipient::Confidential(sender_address),
        tree: env.tree,
        asset: DepositAsset::Sol,
        amount,
        cosigner: None,
    };
    let proven_while_open = {
        let prepared = env.run(deposit(RING_DEPOSIT_A).prepare(env.client.as_async()))?;
        env.run(prepared.prove(env.client.as_async()))?
    };
    send(rpc, &env.payer, &[ring.pause(authority)?])?;
    assert!(
        registration(&env, ring)?.paused,
        "paused by the ring authority"
    );
    match env.run(deposit(RING_DEPOSIT_A).send(env.client.as_async())) {
        Err(RingError::RingPaused) => {}
        Err(other) => return Err(anyhow!("expected RingPaused, got {other}")),
        Ok(_) => return Err(anyhow!("the paused ring took a deposit")),
    }
    let rejection = send_expecting_rejection(rpc, &env.sender.keypair, proven_while_open)?;
    Rejection::pool(ShieldedPoolError::RingPaused)
        .at(0)
        .assert_client(&rejection);
    send(rpc, &env.payer, &[ring.resume(authority)?])?;

    // 4. Two ring SOL deposits give the sender the ring-owned UTXOs the transfer
    //    spends. Their blindings come back from the deposit builder, so the spend
    //    is rebuilt without needing a wallet sync here.
    let mut spendable = Vec::with_capacity(2);
    for amount in [RING_DEPOSIT_A, RING_DEPOSIT_B] {
        let RingDepositReceipt { utxo, .. } =
            env.run(deposit(amount).send(env.client.as_async()))?;
        spendable.push(utxo);
    }

    // 5. Every output opens under the transaction viewing key the auditor recovers.
    let inputs = spendable
        .into_iter()
        .map(|utxo| indexed_note(utxo, &env.sender.keypair, &env, env.tree))
        .collect::<Result<Vec<_>, _>>()?;
    let mut prepared =
        ConfidentialTransaction::new_with_ring(inputs, env.sender.keypair.pubkey(), ring_program)?;
    prepared.transfer_sol(
        &env.recipient.keypair.shielded_address()?,
        RING_TRANSFER_AMOUNT,
    )?;
    prepared.pad_utxos(
        canonical_shape(prepared.inputs().len(), 2)?,
        &sender_address,
    )?;
    let transfer = CustomRingTransfer::new(CustomRingTransferInput {
        ring,
        sender: &env.sender.keypair,
        nullifier_key: Some(&env.sender.keypair.nullifier_key),
        transaction: prepared,
    });
    let proven = env.run(transfer.prove(env.client.as_async()))?;
    let tx_viewing_pk = proven.tx_viewing_key.pubkey();
    let recipient_utxo = Note {
        owner: &env.recipient.keypair,
        asset: SOL_MINT,
        amount: RING_TRANSFER_AMOUNT,
        blinding: output_blinding(&proven.outputs, RECIPIENT_SLOT)?,
        ring_program_id: Some(ring_program),
    };
    let change_note = Note {
        owner: &env.sender.keypair,
        asset: SOL_MINT,
        amount: RING_CHANGE,
        blinding: output_blinding(&proven.outputs, CHANGE_SLOT)?,
        ring_program_id: Some(ring_program),
    };

    // 6. Before the real spend, a flipped byte of the sealed transaction key fails the audit
    //    proof and leaves the tree unchanged.
    let instruction = proven.instruction()?;
    let tampered = {
        let original = frame(&instruction, RingRail::Confidential)?;
        let mut sealed = *original.sealed;
        sealed[0] ^= 1;
        reframed(
            &instruction,
            &RingTransactData {
                sealed: &sealed,
                ..original
            },
        )?
    };
    let tree_before = fetch_account(rpc, &env.tree)?;
    let rejection = send_expecting_rejection(rpc, &env.sender.keypair, tampered)?;
    Rejection::custom(CustomRingError::ProofVerificationFailed as u32)
        .at(0)
        .assert_client(&rejection);
    assert_account_unchanged(rpc, &env.tree, &tree_before)?;

    let (blockhash, _) = rpc.get_latest_blockhash()?;
    let message = compile_message(
        &env.sender.keypair.pubkey(),
        &[instruction],
        blockhash,
        ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::Transact)),
    )?;
    let transaction = sign_transaction(message, &[&env.sender.keypair])?;
    let transaction_size =
        bincode::serde::encode_to_vec(&transaction, bincode::config::legacy())?.len();
    assert!(
        transaction_size <= MAX_TRANSACTION_SIZE,
        "transaction v1 size {transaction_size} exceeds {MAX_TRANSACTION_SIZE}"
    );
    let signature = rpc
        .client()
        .send_and_confirm_transaction(&transaction)
        .map_err(|error| anyhow!("send v1 failed {error}"))?;
    assert_transaction_compute_units(
        // 7. The real custom-ring transfer.
        rpc,
        &signature,
        "custom-ring transact 2x2",
        CUSTOM_RING_TRANSACT_CU_LIMIT,
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
    assert_eq!(indexed.nullifiers.len(), 2, "both inputs spent");
    assert_eq!(
        indexed.tx_viewing_pk,
        Some(tx_viewing_pk),
        "the on-chain tx_viewing_pk is the key the sender derived"
    );

    let client = env.client.as_async();
    let audited = env
        .client
        .block_on(RingScan::new(ring_program, auditor.pubkey()).audit(
            &auditor,
            client.indexer(),
            client.rpc(),
            &env.assets,
        ))?
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
    assert_eq!(
        opened(audited),
        vec![
            recipient_utxo.opened(RECIPIENT_SLOT)?,
            change_note.opened(CHANGE_SLOT)?
        ],
        "auditor-decrypted outputs equal what the sender sent, owners and blindings included"
    );
    assert!(audited.payload_errors.is_empty());

    // 9. Normal operation is undisturbed: the recipient still discovers its
    //    output through `Wallet::sync` on its own view tag, with no auditor key.
    let recipient_authority =
        KeypairWalletAuthority::new(Address::default(), &env.recipient.keypair);
    env.recipient.wallet.sync(
        &recipient_authority,
        std::slice::from_ref(&indexed),
        0,
        DEFAULT_TAG_WINDOW,
    )?;
    assert_eq!(
        sorted_unspent_notes(&env.recipient.wallet),
        vec![(SOL_MINT, RING_TRANSFER_AMOUNT, Some(ring_program))],
        "recipient wallet discovers the custom ring output"
    );
    let received = unspent_utxo(&env.recipient.wallet, RING_TRANSFER_AMOUNT)?;

    // 10. The second hop is proven through both clients, the policy statement
    //     holds the same parity as the audit statement.
    let hop = AsyncHopParity {
        ring,
        sender: &env.recipient.keypair,
        blocking: second_hop(&env, received.clone())?,
        asynchronous: second_hop(&env, received)?,
        auditor_tag,
    }
    .send(&env)?;
    let audited_hop = AuditLookup {
        scan: RingScan::new(ring_program, auditor.pubkey()),
        auditor: &auditor,
        signature: hop.signature,
    }
    .run(&env)?;
    assert_eq!(
        ring_amounts(&audited_hop)?,
        vec![SECOND_HOP_AMOUNT, RING_TRANSFER_AMOUNT - SECOND_HOP_AMOUNT],
        "second hop outputs"
    );

    // 11. The config authority hands over, only the new key pauses the ring.
    let successor = env.funded_keypair()?;
    rpc.create_and_send_transaction(
        &[custom_ring_sdk::SetAuthority {
            ring,
            authority,
            new_authority: successor.pubkey(),
        }
        .instruction()],
        authority,
        &[&env.payer, &successor],
        ComputeBudgetConfig::for_instruction_count(1),
    )?;
    let rejection = ExpectRejection {
        payer: &env.payer,
        instructions: &[ring.pause(authority)?],
    }
    .send(rpc)?;
    Rejection::custom(CustomRingError::UnauthorizedAuthority as u32)
        .at(0)
        .assert_client(&rejection);
    send(rpc, &successor, &[ring.pause(successor.pubkey())?])?;
    assert!(registration(&env, ring)?.paused, "paused by the successor");
    send(rpc, &successor, &[ring.resume(successor.pubkey())?])?;
    assert!(
        !registration(&env, ring)?.paused,
        "reopened by the successor"
    );

    Ok(())
}

#[test]
fn an_audit_only_ring_audits_every_transfer() -> Result<()> {
    let mut env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Keypair::new();
    let auditor_pk = auditor.pubkey();
    let auditor_tag = auditor_view_tag(&auditor_pk);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor_pk,
        tier: Tier::AuditOnly,
    }
    .send(&env.client)?;
    assert!(
        env.run(ring.registry(env.client.as_async()))?.is_none(),
        "an audit-only ring keeps no member registry"
    );
    let config: RingProgramConfig = fetch_state(rpc, &ring.config_pda())?;
    assert_eq!(config.has_policy, 0, "audit-only config flag");

    let sender = &env.sender.keypair;
    let sender_address = sender.shielded_address()?;
    let deposit_source = env.funded_keypair()?;
    env.fund(deposit_source.pubkey(), RING_DEPOSIT_A + RING_DEPOSIT_B)?;
    let mut spendable = Vec::with_capacity(2);
    for amount in [RING_DEPOSIT_A, RING_DEPOSIT_B] {
        let deposit = RingDeposit {
            ring,
            payer: &deposit_source,
            recipient: DepositRecipient::Confidential(sender_address),
            tree: env.tree,
            asset: DepositAsset::Sol,
            amount,
            cosigner: None,
        };
        let RingDepositReceipt { utxo, .. } =
            env.run(deposit.send_with_fee_payer(env.client.as_async(), sender))?;
        spendable.push(utxo);
    }

    let inputs = spendable
        .into_iter()
        .map(|utxo| indexed_note(utxo, sender, &env, env.tree))
        .collect::<Result<Vec<_>, _>>()?;
    let mut prepared =
        ConfidentialTransaction::new_with_ring(inputs, sender.pubkey(), ring_program)?;
    prepared.transfer_sol(
        &env.recipient.keypair.shielded_address()?,
        RING_TRANSFER_AMOUNT,
    )?;
    prepared.pad_utxos(
        canonical_shape(prepared.inputs().len(), 2)?,
        &sender_address,
    )?;
    let transfer = CustomRingTransfer::new(CustomRingTransferInput {
        ring,
        sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction: prepared,
    });
    let proven = env.run(transfer.prove(env.client.as_async()))?;
    let tx_viewing_pk = proven.tx_viewing_key.pubkey();
    let signature = land(&env, proven.instruction()?, sender, &[])?;

    let indexed = wait_for_indexed_transaction(indexer, auditor_tag, signature);
    assert_eq!(indexed.nullifiers.len(), 2, "both inputs spent");
    assert_eq!(
        indexed.tx_viewing_pk,
        Some(tx_viewing_pk),
        "the on-chain tx_viewing_pk is the sender's"
    );
    let audited = AuditLookup {
        scan: RingScan::new(ring_program, auditor_pk),
        auditor: &auditor,
        signature,
    }
    .run(&env)?;
    assert_eq!(
        audited.tx_viewing_pk, tx_viewing_pk,
        "auditor recovered the transaction viewing key"
    );
    assert_eq!(
        ring_amounts(&audited)?,
        [RING_TRANSFER_AMOUNT, RING_CHANGE],
        "auditor decrypts both output amounts"
    );

    let recipient_authority =
        KeypairWalletAuthority::new(Address::default(), &env.recipient.keypair);
    env.recipient.wallet.sync(
        &recipient_authority,
        std::slice::from_ref(&indexed),
        0,
        DEFAULT_TAG_WINDOW,
    )?;
    let received = unspent_utxo(&env.recipient.wallet, RING_TRANSFER_AMOUNT)?;
    let hop = AsyncHopParity {
        ring,
        sender: &env.recipient.keypair,
        blocking: second_hop(&env, received.clone())?,
        asynchronous: second_hop(&env, received)?,
        auditor_tag,
    }
    .send(&env)?;
    let audited_hop = AuditLookup {
        scan: RingScan::new(ring_program, auditor_pk),
        auditor: &auditor,
        signature: hop.signature,
    }
    .run(&env)?;
    assert_eq!(
        ring_amounts(&audited_hop)?,
        vec![SECOND_HOP_AMOUNT, RING_TRANSFER_AMOUNT - SECOND_HOP_AMOUNT],
        "second hop outputs"
    );
    Ok(())
}

/// No public signer names an owner, the auditor opens the sender and every note.
#[test]
fn an_anonymous_ring_hides_owners_and_preserves_auditor_access() -> Result<()> {
    let mut env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Keypair::new();
    let auditor_pk = auditor.pubkey();
    let auditor_tag = auditor_view_tag(&auditor_pk);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor_pk,
        tier: Tier::AnonymousAuditOnly,
    }
    .send(&env.client)?;
    let config = env.run(ring.require_config(env.client.as_async()))?;
    assert_eq!(config.mode, RingMode::Anonymous);
    let fresh_state = || AnonymousRingState::new(ring_program, config.creation_epoch());

    // 1. The ring payer funds every spend and a separate source the deposits,
    //    the owner's key signs nothing in public.
    let payer = &env.payer;
    let deposit_source = env.funded_keypair()?;
    env.fund(deposit_source.pubkey(), RING_DEPOSIT_A + RING_DEPOSIT_B)?;
    let mut spendable = Vec::with_capacity(2);
    let deposit_state = fresh_state();
    for amount in [RING_DEPOSIT_A, RING_DEPOSIT_B] {
        let deposit = RingDeposit {
            ring,
            payer: &deposit_source,
            recipient: DepositRecipient::Anonymous {
                keys: &env.sender.keypair,
                state: &deposit_state,
            },
            tree: env.tree,
            asset: DepositAsset::Sol,
            amount,
            cosigner: None,
        };
        let RingDepositReceipt { signature, utxo } =
            env.run(deposit.send_with_fee_payer(env.client.as_async(), payer))?;
        custom_ring_cli::wait_for_indexed_transaction(&env.client, signature)?;
        spendable.push(utxo);
    }

    // 2. The first payment to the recipient's address takes its inbox stream.
    let inputs = spendable
        .into_iter()
        .map(|utxo| indexed_note(utxo, &env.sender.keypair, &env, env.tree))
        .collect::<Result<Vec<_>, _>>()?;
    let mut sender_ring = fresh_state();
    let mut recipient_ring = fresh_state();
    let transfer = AnonymousPayment {
        ring,
        sender: &env.sender.keypair,
        state: &sender_ring,
        payer,
        inputs,
        to: ring_address(&env.recipient.keypair, ring_program, 0)?,
        amount: RING_TRANSFER_AMOUNT,
    }
    .transfer()?;
    let proven = env.run(transfer.prove(env.client.as_async()))?;
    assert_eq!(
        proven.first_contacts.len(),
        1,
        "an inbox payment is a first contact"
    );
    let tx_viewing_pk = proven.tx_viewing_key.pubkey();
    let instruction = proven.instruction_at(rpc.get_slot()?)?;
    assert!(
        !signers(&instruction).contains(&env.sender.keypair.pubkey()),
        "no transaction signer names the owner"
    );

    // 3. A corrupted inner BSB22 commitment reaches SPP with every proof fixed,
    //    SPP refuses the encoding or the proof of knowledge.
    let valid = frame(&instruction, RingRail::Anonymous)?
        .anonymous
        .context("an anonymous transfer carries its BSB22 commitment")?;
    let (commitment, pok) = (*valid.commitment, *valid.commitment_pok);
    let tree_before = fetch_account(rpc, &env.tree)?;
    for (commitment, commitment_pok, error) in [
        (
            [0xff; 32],
            pok,
            ShieldedPoolError::InvalidTransactProofEncoding,
        ),
        (
            commitment,
            [0xff; 32],
            ShieldedPoolError::InvalidTransactProofEncoding,
        ),
        (
            commitment,
            commitment,
            ShieldedPoolError::TransactProofVerificationFailed,
        ),
    ] {
        let tampered = reframed(
            &instruction,
            &RingTransactData {
                anonymous: Some(AnonymousProofData {
                    commitment: &commitment,
                    commitment_pok: &commitment_pok,
                    ..valid
                }),
                ..frame(&instruction, RingRail::Anonymous)?
            },
        )?;
        let rejection = send_expecting_rejection(rpc, payer, tampered)?;
        Rejection::pool(error).at(0).assert_client(&rejection);
        assert_account_unchanged(rpc, &env.tree, &tree_before)?;
    }
    let landed = PaymentLanding {
        transfer,
        payer,
        auditor_tag,
    }
    .land(&env)?;
    landed.record(&mut sender_ring)?;
    let indexed = landed.indexed;
    assert_eq!(indexed.nullifiers.len(), 2, "both inputs spent");
    assert_eq!(
        indexed.tx_viewing_pk,
        Some(tx_viewing_pk),
        "the first nullifier fixes the transaction viewing key of every attempt"
    );
    assert!(
        indexed.output_slots.iter().all(|slot| {
            RingTag::from_owner_tag(&slot.view_tag).is_some()
                && slot
                    .encrypted_body(EncryptedScheme::RingAnonymous)
                    .is_some()
        }),
        "every anonymous output publishes a stream tag and an anonymous body"
    );

    // 4. The auditor opens the hidden sender, its inputs and both outputs.
    let audited = AuditLookup {
        scan: RingScan::new(ring_program, auditor_pk).with_mode(RingMode::Anonymous),
        auditor: &auditor,
        signature: indexed.tx_signature,
    }
    .run(&env)?;
    let mut amounts = ring_amounts(&audited)?;
    amounts.sort_unstable();
    assert_eq!(amounts, [RING_TRANSFER_AMOUNT, RING_CHANGE]);
    assert_eq!(
        audited.sender.map(|sender| sender.owner_key),
        Some(env.sender.keypair.signing_pubkey().as_ed25519()?),
        "the auditor names the hidden sender"
    );
    let mut input_amounts: Vec<u64> = audited
        .inputs
        .iter()
        .filter_map(|input| input.opening.opened().map(|opening| opening.amount))
        .collect();
    input_amounts.sort_unstable();
    assert_eq!(input_amounts, [RING_DEPOSIT_B, RING_DEPOSIT_A]);

    // 5. The recipient finds the inbox payment, its first contact anchors the sender's pair stream.
    env.recipient
        .wallet
        .anonymous_rings
        .insert(ring_program, fresh_state());
    let recipient_authority =
        KeypairWalletAuthority::new(Address::default(), &env.recipient.keypair);
    sync_wallet(&mut env.recipient.wallet, &recipient_authority, indexer)?;
    assert_eq!(
        sorted_unspent_notes(&env.recipient.wallet),
        vec![(SOL_MINT, RING_TRANSFER_AMOUNT, Some(ring_program))]
    );
    assert_eq!(
        env.recipient.wallet.anonymous_rings[&ring_program]
            .received()
            .len(),
        1,
        "the first contact anchors a pair stream"
    );

    // 6. The recipient pays the sender's first address and keeps its change.
    let received = unspent_utxo(&env.recipient.wallet, RING_TRANSFER_AMOUNT)?;
    let transfer = AnonymousPayment {
        ring,
        sender: &env.recipient.keypair,
        state: &recipient_ring,
        payer,
        inputs: vec![indexed_note(
            received,
            &env.recipient.keypair,
            &env,
            env.tree,
        )?],
        to: ring_address(&env.sender.keypair, ring_program, 0)?,
        amount: SECOND_HOP_AMOUNT,
    }
    .transfer()?;
    PaymentLanding {
        transfer,
        payer,
        auditor_tag,
    }
    .land(&env)?
    .record(&mut recipient_ring)?;
    sync_wallet(&mut env.recipient.wallet, &recipient_authority, indexer)?;
    assert_eq!(
        sorted_unspent_notes(&env.recipient.wallet),
        vec![(
            SOL_MINT,
            RING_TRANSFER_AMOUNT - SECOND_HOP_AMOUNT,
            Some(ring_program)
        )],
        "the recipient keeps the change of its spend"
    );

    // 7. A fresh wallet of the sender finds its deposits on the deposit stream,
    //    its change from their spend and the payment on its first address.
    let sender_authority = KeypairWalletAuthority::new(Address::default(), &env.sender.keypair);
    let mut fresh_sender = Wallet::new(env.sender.keypair.shielded_address()?, env.assets.clone())?
        .with_ring_deposit_payload(ring_program, zolana_ring_client::deposit_payload)
        .with_anonymous_ring(fresh_state());
    sync_wallet(&mut fresh_sender, &sender_authority, indexer)?;
    assert_eq!(
        sorted_unspent_notes(&fresh_sender),
        vec![
            (SOL_MINT, SECOND_HOP_AMOUNT, Some(ring_program)),
            (SOL_MINT, RING_CHANGE, Some(ring_program)),
        ]
    );
    assert_eq!(
        fresh_sender.anonymous_rings[&ring_program].issued().len(),
        1,
        "a payment on index 0 issues it"
    );

    // 8. The sender's second payment rides the pair stream its first one anchored.
    let change = unspent_utxo(&fresh_sender, RING_CHANGE)?;
    let transfer = AnonymousPayment {
        ring,
        sender: &env.sender.keypair,
        state: &sender_ring,
        payer,
        inputs: vec![indexed_note(change, &env.sender.keypair, &env, env.tree)?],
        to: ring_address(&env.recipient.keypair, ring_program, 0)?,
        amount: PAIR_AMOUNT,
    }
    .transfer()?;
    let landed = PaymentLanding {
        transfer,
        payer,
        auditor_tag,
    }
    .land(&env)?;
    assert!(
        landed.first_contacts.is_empty(),
        "a pair stream payment is no first contact"
    );
    sync_wallet(&mut env.recipient.wallet, &recipient_authority, indexer)?;
    assert_eq!(
        sorted_unspent_notes(&env.recipient.wallet),
        vec![
            (SOL_MINT, PAIR_AMOUNT, Some(ring_program)),
            (
                SOL_MINT,
                RING_TRANSFER_AMOUNT - SECOND_HOP_AMOUNT,
                Some(ring_program)
            ),
        ],
        "the recipient finds the pair stream payment"
    );

    // 9. The recipient merges both notes, a fresh wallet finds the merge from
    //    its own spends and sees both inputs spent.
    let merged_inputs: Vec<WalletUtxo> = env.recipient.wallet.unspent().cloned().collect();
    let tree_id = env.tree_id(env.tree)?;
    let prepared = CustomRingMerge::new(ring, merged_inputs.clone(), None)?
        .with_output_tree_id(tree_id)
        .encrypt(&env.recipient.keypair)?;
    let merged_hash = prepared.output().hash(tree_id)?;
    let merge = RingMergeOperation::new(
        prepared,
        MergeProofInput {
            nullifier_key: env.recipient.keypair.nullifier_key.clone(),
            input_tree: env.tree,
            output_tree: env.tree,
        },
    );
    land(&env, merge, payer, &[])?;
    let mut fresh_recipient = Wallet::new(
        env.recipient.keypair.shielded_address()?,
        env.assets.clone(),
    )?
    .with_anonymous_ring(fresh_state());
    sync_wallet(&mut fresh_recipient, &recipient_authority, indexer)?;
    for input in &merged_inputs {
        assert!(fresh_recipient.is_spent(input), "the merge spent its input");
    }
    assert_eq!(
        sorted_unspent_notes(&fresh_recipient),
        vec![(SOL_MINT, MERGED_AMOUNT, Some(ring_program))],
        "the sync opens the merge"
    );

    // 10. The merged note spends like any other.
    let merged = fresh_recipient
        .unspent()
        .find(|held| held.utxo_hash == merged_hash)
        .cloned()
        .context("the merged note")?;
    let transfer = AnonymousPayment {
        ring,
        sender: &env.recipient.keypair,
        state: &recipient_ring,
        payer,
        inputs: vec![indexed_note(
            merged.utxo.clone(),
            &env.recipient.keypair,
            &env,
            env.tree,
        )?],
        to: ring_address(&env.sender.keypair, ring_program, 0)?,
        amount: MERGED_SPEND,
    }
    .transfer()?;
    PaymentLanding {
        transfer,
        payer,
        auditor_tag,
    }
    .land(&env)?;
    sync_wallet(&mut fresh_recipient, &recipient_authority, indexer)?;
    assert!(fresh_recipient.is_spent(&merged));
    Ok(())
}

/// A Frozen hidden sender is refused.
const FROZEN_SENDERS: RuleTable = RuleTable::builder()
    .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
    .build();

/// The anonymous ring's policy proof screens the hidden sender against its own record.
#[test]
fn an_anonymous_policy_ring_screens_its_hidden_sender() -> Result<()> {
    let env = setup()?;
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Keypair::new();
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::anonymous_policy(&FROZEN_SENDERS),
    }
    .send(&env.client)?;
    let config = env.run(ring.require_config(env.client.as_async()))?;
    assert_eq!(config.mode, RingMode::Anonymous);
    assert!(config.has_policy, "the anonymous ring pins a table");
    assert_eq!(policy_registry(ring, &env)?.rule_table()?, FROZEN_SENDERS);

    // 1. A separate depositor funds the hidden note, the owner signs nothing.
    let sender = &env.sender.keypair;
    let depositor = env.funded_keypair()?;
    let deposited = RingNotes {
        ring,
        owner: sender,
        amount: RING_DEPOSIT_B,
        count: 1,
        env: &env,
    }
    .deposit_hidden_from(&depositor)?
    .into_iter()
    .next()
    .context("the hidden note")?;
    let input = indexed_note(deposited, sender, &env, env.tree)?;
    let state = AnonymousRingState::new(ring_program, config.creation_epoch());
    let to = ring_address(&env.recipient.keypair, ring_program, 0)?;
    let payment = || AnonymousPayment {
        ring,
        sender,
        state: &state,
        payer: &env.payer,
        inputs: vec![input.clone()],
        to: to.clone(),
        amount: PAIR_AMOUNT,
    };
    let sender_member = owner_member(sender)?;
    let frozen = |present| RegistryWrite {
        ring,
        list_id: ListId::Frozen,
        member: sender_member,
        present,
        env: &env,
    };

    // 2. A Frozen hidden sender is refused before any prover round.
    frozen(true).send()?;
    let unreachable = env.client_with(
        ProverClient::new("http://127.0.0.1:1".to_owned())
            .with_proof_data_source(ProofDataSource::Client),
    );
    match unreachable.block_on(payment().transfer()?.prove(unreachable.as_async())) {
        Err(RingError::PolicyRuleUnsatisfied(_)) => {}
        other => {
            return Err(anyhow!(
                "expected PolicyRuleUnsatisfied, got {:?}",
                other.err()
            ))
        }
    }

    // 3. Clearing the bit admits the same payment, and the auditor opens its hidden sender.
    frozen(false).send()?;
    let landed = PaymentLanding {
        transfer: payment().transfer()?,
        payer: &env.payer,
        auditor_tag: auditor_view_tag(&auditor.pubkey()),
    }
    .land(&env)?;
    let audited = AuditLookup {
        scan: RingScan::new(ring_program, auditor.pubkey()).with_mode(config.mode),
        auditor: &auditor,
        signature: landed.indexed.tx_signature,
    }
    .run(&env)?;
    let opened = audited
        .sender
        .context("an anonymous transfer discloses its sender to the auditor")?;
    assert_eq!(
        opened.owner_key,
        sender.signing_pubkey().confidential_view_tag()?,
        "the auditor opens the screened owner"
    );
    Ok(())
}

/// Default-ring notes are legal ring transact inputs and outputs
/// (`AssertRingMemberOrFree`).
#[test]
fn ring_value_leaves_and_enters_through_audited_transfers() -> Result<()> {
    let mut env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Keypair::new();
    let auditor_tag = auditor_view_tag(&auditor.pubkey());
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::policy(&EMPTY),
    }
    .send(&env.client)?;
    let sender = &env.sender.keypair;
    let recipient = &env.recipient.keypair;
    let sender_address = sender.shielded_address()?;
    let recipient_address = recipient.shielded_address()?;
    let recipient_authority = KeypairWalletAuthority::new(Address::default(), recipient);
    let scan = || RingScan::new(ring_program, auditor.pubkey());

    // 1. Entry, a default-ring deposit is spent into ring-bound notes.
    let deposited = DefaultRingDeposit {
        depositor: sender,
        tree: env.tree,
        asset: DepositAsset::Sol,
        amount: DEFAULT_DEPOSIT,
    }
    .send(rpc, indexer, &env.assets)?;
    let entry_input = deposited.input_utxo(&env)?;
    wait_for_merkle_proof(indexer, env.tree, entry_input.utxo_hash);
    let mut prepared =
        ConfidentialTransaction::new_with_ring(vec![entry_input], sender.pubkey(), ring_program)?;
    prepared.transfer_sol(&recipient_address, ENTRY_AMOUNT)?;
    prepared.pad_utxos(
        canonical_shape(prepared.inputs().len(), 2)?,
        &sender_address,
    )?;
    let entry = OwnerTransfer {
        ring,
        sender,
        prepared,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;
    let recipient_ring_note = Note {
        owner: recipient,
        asset: SOL_MINT,
        amount: ENTRY_AMOUNT,
        blinding: output_blinding(&entry.outputs, RECIPIENT_SLOT)?,
        ring_program_id: Some(ring_program),
    };
    let sender_change = Note {
        owner: sender,
        asset: SOL_MINT,
        amount: ENTRY_CHANGE,
        blinding: output_blinding(&entry.outputs, CHANGE_SLOT)?,
        ring_program_id: Some(ring_program),
    };
    assert_eq!(
        opened(
            &AuditLookup {
                scan: scan(),
                auditor: &auditor,
                signature: entry.signature,
            }
            .run(&env)?
        ),
        vec![
            recipient_ring_note.opened(RECIPIENT_SLOT)?,
            sender_change.opened(CHANGE_SLOT)?
        ],
        "entry outputs"
    );
    env.recipient.wallet.sync(
        &recipient_authority,
        std::slice::from_ref(&entry.indexed),
        0,
        DEFAULT_TAG_WINDOW,
    )?;
    assert_eq!(
        sorted_unspent_notes(&env.recipient.wallet),
        vec![(SOL_MINT, ENTRY_AMOUNT, Some(ring_program))],
        "recipient wallet after the entry"
    );

    // 2. Exit, the ring-bound change is spent into a default-ring note for the
    //    recipient, the new change stays in the ring.
    let mut prepared = ConfidentialTransaction::new_with_ring(
        vec![sender_change.input_utxo(&env)?],
        sender.pubkey(),
        ring_program,
    )?;
    prepared.transfer_with_ring(
        &recipient_address,
        env.assets.mint(&SOL_MINT)?,
        EXIT_AMOUNT,
        None,
    )?;
    prepared.pad_utxos(
        canonical_shape(prepared.inputs().len(), 2)?,
        &sender_address,
    )?;
    let exit = OwnerTransfer {
        ring,
        sender,
        prepared,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;
    let recipient_default_note = Note {
        owner: recipient,
        asset: SOL_MINT,
        amount: EXIT_AMOUNT,
        blinding: output_blinding(&exit.outputs, RECIPIENT_SLOT)?,
        ring_program_id: None,
    };
    let exit_change = Note {
        owner: sender,
        asset: SOL_MINT,
        amount: EXIT_CHANGE,
        blinding: output_blinding(&exit.outputs, CHANGE_SLOT)?,
        ring_program_id: Some(ring_program),
    };
    assert_eq!(
        opened(
            &AuditLookup {
                scan: scan(),
                auditor: &auditor,
                signature: exit.signature,
            }
            .run(&env)?
        ),
        vec![
            recipient_default_note.opened(RECIPIENT_SLOT)?,
            exit_change.opened(CHANGE_SLOT)?
        ],
        "exit outputs"
    );
    env.recipient.wallet.sync(
        &recipient_authority,
        std::slice::from_ref(&exit.indexed),
        0,
        DEFAULT_TAG_WINDOW,
    )?;
    assert_eq!(
        sorted_unspent_notes(&env.recipient.wallet),
        vec![
            (SOL_MINT, EXIT_AMOUNT, None),
            (SOL_MINT, ENTRY_AMOUNT, Some(ring_program)),
        ],
        "recipient wallet after the exit"
    );

    // 3. Refusal, a note of another ring, as the recipient output or as the
    //    input, is refused before the unreachable prover is asked.
    let unreachable = env.client_with(ProverClient::new("http://127.0.0.1:1".to_string()));
    let prove = |prepared: ConfidentialTransaction| {
        let transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring,
            sender,
            nullifier_key: Some(&sender.nullifier_key),
            transaction: prepared,
        });
        unreachable.block_on(transfer.prove(unreachable.as_async()))
    };
    let mut foreign_output = ConfidentialTransaction::new_with_ring(
        vec![exit_change.input_utxo(&env)?],
        sender.pubkey(),
        ring_program,
    )?;
    foreign_output.transfer_with_ring(
        &recipient_address,
        Mint::SOL,
        REFUSED_AMOUNT,
        Some(FOREIGN_RING),
    )?;
    foreign_output.pad_utxos(canonical_shape(1, 2)?, &sender_address)?;
    expect_foreign_ring(prove(foreign_output), FOREIGN_RING)?;

    let foreign_note = Note {
        owner: sender,
        asset: SOL_MINT,
        amount: EXIT_CHANGE,
        blinding: random_blinding(),
        ring_program_id: Some(FOREIGN_RING),
    };
    let mut foreign_input = ConfidentialTransaction::new_with_ring(
        vec![foreign_note.input_utxo(&env)?],
        sender.pubkey(),
        ring_program,
    )?;
    foreign_input.transfer_sol(&recipient_address, REFUSED_AMOUNT)?;
    foreign_input.pad_utxos(canonical_shape(1, 2)?, &sender_address)?;
    expect_foreign_ring(prove(foreign_input), FOREIGN_RING)?;

    Ok(())
}

/// The same crossing carries an SPL mint, and a ring transact settles a public
/// USDC withdrawal.
#[test]
fn usdc_crosses_the_ring_boundary_and_withdraws_through_a_ring_transact() -> Result<()> {
    let mut env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Keypair::new();
    let auditor_tag = auditor_view_tag(&auditor.pubkey());
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::policy(&EMPTY),
    }
    .send(&env.client)?;
    let usdc = env.usdc_mint;
    let usdc_deposit = |user_token| {
        DepositAsset::Spl(DepositSplAccounts {
            mint: usdc,
            user_token,
            token_program: pda::spl_token_program_id(),
        })
    };
    let sender = &env.sender.keypair;
    let recipient = &env.recipient.keypair;
    let sender_address = sender.shielded_address()?;
    let recipient_address = recipient.shielded_address()?;
    let recipient_authority = KeypairWalletAuthority::new(Address::default(), recipient);
    let scan = || RingScan::new(ring_program, auditor.pubkey());
    let ring_utxo = |owner, amount, blinding| Note {
        owner,
        asset: usdc,
        amount,
        blinding,
        ring_program_id: Some(ring_program),
    };

    let sender_usdc = create_token_account(rpc, &env.payer, &usdc, &sender.pubkey())?;
    mint_to(rpc, &env.payer, &usdc, &sender_usdc, USDC_FUNDING)?;

    // 1. Public -> default ring, the sender signs as the token authority.
    let deposited = DefaultRingDeposit {
        depositor: sender,
        tree: env.tree,
        asset: usdc_deposit(sender_usdc),
        amount: USDC_DEFAULT_DEPOSIT,
    }
    .send(rpc, indexer, &env.assets)?;
    assert_eq!(
        token_amount(&fetch_account(rpc, &sender_usdc)?),
        USDC_FUNDING - USDC_DEFAULT_DEPOSIT,
        "funding account after the default deposit"
    );
    let entry_input = deposited.input_utxo(&env)?;
    wait_for_merkle_proof(indexer, env.tree, entry_input.utxo_hash);

    // 2. Entry, the default USDC note is spent into ring-bound notes.
    let mut prepared =
        ConfidentialTransaction::new_with_ring(vec![entry_input], sender.pubkey(), ring_program)?;
    prepared.transfer(&recipient_address, usdc, USDC_ENTRY_AMOUNT)?;
    prepared.pad_utxos(
        canonical_shape(prepared.inputs().len(), 2)?,
        &sender_address,
    )?;
    let entry = OwnerTransfer {
        ring,
        sender,
        prepared,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;
    let recipient_ring_note = ring_utxo(
        recipient,
        USDC_ENTRY_AMOUNT,
        output_blinding(&entry.outputs, RECIPIENT_SLOT)?,
    );
    let entry_change = ring_utxo(
        sender,
        USDC_ENTRY_CHANGE,
        output_blinding(&entry.outputs, CHANGE_SLOT)?,
    );
    assert_eq!(
        opened(
            &AuditLookup {
                scan: scan(),
                auditor: &auditor,
                signature: entry.signature,
            }
            .run(&env)?
        ),
        vec![
            recipient_ring_note.opened(RECIPIENT_SLOT)?,
            entry_change.opened(CHANGE_SLOT)?
        ],
        "entry outputs"
    );
    env.recipient.wallet.sync(
        &recipient_authority,
        std::slice::from_ref(&entry.indexed),
        0,
        DEFAULT_TAG_WINDOW,
    )?;
    assert_eq!(
        sorted_unspent_notes(&env.recipient.wallet),
        vec![(usdc, USDC_ENTRY_AMOUNT, Some(ring_program))],
        "recipient wallet after the entry"
    );

    // 3. In-ring hop.
    let mut prepared = ConfidentialTransaction::new_with_ring(
        vec![entry_change.input_utxo(&env)?],
        sender.pubkey(),
        ring_program,
    )?;
    prepared.transfer(&recipient_address, usdc, USDC_HOP_AMOUNT)?;
    prepared.pad_utxos(
        canonical_shape(prepared.inputs().len(), 2)?,
        &sender_address,
    )?;
    let hop = OwnerTransfer {
        ring,
        sender,
        prepared,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;
    let recipient_hop_note = ring_utxo(
        recipient,
        USDC_HOP_AMOUNT,
        output_blinding(&hop.outputs, RECIPIENT_SLOT)?,
    );
    let hop_change = ring_utxo(
        sender,
        USDC_HOP_CHANGE,
        output_blinding(&hop.outputs, CHANGE_SLOT)?,
    );
    assert_eq!(
        opened(
            &AuditLookup {
                scan: scan(),
                auditor: &auditor,
                signature: hop.signature,
            }
            .run(&env)?
        ),
        vec![
            recipient_hop_note.opened(RECIPIENT_SLOT)?,
            hop_change.opened(CHANGE_SLOT)?
        ],
        "hop outputs"
    );
    env.recipient.wallet.sync(
        &recipient_authority,
        std::slice::from_ref(&hop.indexed),
        0,
        DEFAULT_TAG_WINDOW,
    )?;
    assert_eq!(
        sorted_unspent_notes(&env.recipient.wallet),
        vec![
            (usdc, USDC_HOP_AMOUNT, Some(ring_program)),
            (usdc, USDC_ENTRY_AMOUNT, Some(ring_program)),
        ],
        "recipient wallet after the hop"
    );

    // 4. Direct USDC ring deposit.
    let deposit = RingDeposit {
        ring,
        payer: sender,
        recipient: DepositRecipient::Confidential(sender_address),
        tree: env.tree,
        asset: usdc_deposit(sender_usdc),
        amount: USDC_RING_DEPOSIT,
        cosigner: None,
    };
    let RingDepositReceipt { utxo: receipt, .. } = env.run(deposit.send(env.client.as_async()))?;
    assert_eq!(
        token_amount(&fetch_account(rpc, &sender_usdc)?),
        USDC_FUNDING - USDC_DEFAULT_DEPOSIT - USDC_RING_DEPOSIT,
        "funding account after the ring deposit"
    );
    let receipt_input = indexed_note(receipt, sender, &env, env.tree)?;
    wait_for_merkle_proof(indexer, env.tree, receipt_input.utxo_hash);

    // 5. Exit, the hop change and the ring-deposit receipt are spent together,
    //    the receipt spend proves the sdk receipt utxo matches the leaf.
    let mut prepared = ConfidentialTransaction::new_with_ring(
        vec![hop_change.input_utxo(&env)?, receipt_input],
        sender.pubkey(),
        ring_program,
    )?;
    prepared.transfer_with_ring(
        &recipient_address,
        env.assets.mint(&usdc)?,
        USDC_EXIT_AMOUNT,
        None,
    )?;
    prepared.pad_utxos(
        canonical_shape(prepared.inputs().len(), 2)?,
        &sender_address,
    )?;
    let exit = OwnerTransfer {
        ring,
        sender,
        prepared,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;
    let recipient_default_note = Note {
        ring_program_id: None,
        ..ring_utxo(
            recipient,
            USDC_EXIT_AMOUNT,
            output_blinding(&exit.outputs, RECIPIENT_SLOT)?,
        )
    };
    let exit_change = ring_utxo(
        sender,
        USDC_EXIT_CHANGE,
        output_blinding(&exit.outputs, CHANGE_SLOT)?,
    );
    assert_eq!(
        opened(
            &AuditLookup {
                scan: scan(),
                auditor: &auditor,
                signature: exit.signature,
            }
            .run(&env)?
        ),
        vec![
            recipient_default_note.opened(RECIPIENT_SLOT)?,
            exit_change.opened(CHANGE_SLOT)?
        ],
        "exit outputs"
    );
    env.recipient.wallet.sync(
        &recipient_authority,
        std::slice::from_ref(&exit.indexed),
        0,
        DEFAULT_TAG_WINDOW,
    )?;
    assert_eq!(
        sorted_unspent_notes(&env.recipient.wallet),
        vec![
            (usdc, USDC_EXIT_AMOUNT, None),
            (usdc, USDC_HOP_AMOUNT, Some(ring_program)),
            (usdc, USDC_ENTRY_AMOUNT, Some(ring_program)),
        ],
        "recipient wallet after the exit"
    );

    // 6. A ring transact settles a public USDC withdrawal beside a ring send,
    //    the withdrawal past the threshold demands the co-signer.
    let recipient_usdc = create_token_account(rpc, &env.payer, &usdc, &recipient.pubkey())?;
    let cosigner = Keypair::new();
    send(
        rpc,
        &env.payer,
        &[custom_ring_sdk::SetCoSigner {
            ring,
            authority: env.payer.pubkey(),
            signer: cosigner.pubkey(),
            scope: CoSignScope::WITHDRAWALS,
            thresholds: &[CoSignThreshold {
                mint: usdc,
                amount: USDC_WITHDRAW_AMOUNT - 1,
            }],
        }
        .instruction()?],
    )?;
    let withdraw = || -> Result<ConfidentialTransaction> {
        let mut transfer = ConfidentialTransaction::new_with_ring(
            vec![exit_change.input_utxo(&env)?],
            sender.pubkey(),
            ring_program,
        )?;
        transfer.withdraw(usdc, USDC_WITHDRAW_AMOUNT, recipient_usdc)?;
        transfer.transfer(&recipient_address, usdc, USDC_FINAL_SEND)?;
        transfer.pad_utxos(
            canonical_shape(transfer.inputs().len(), 2)?,
            &sender_address,
        )?;
        Ok(transfer)
    };
    let settlement =
        TransactInterfaceTransferAccounts::SplWithdrawal(TransactSplWithdrawalAccounts {
            mint: usdc,
            spl_interface: pda::spl_interface(&usdc),
            user_token_account: recipient_usdc,
            token_program: pda::spl_token_program_id(),
        });
    let unsigned = CustomRingTransfer::new(CustomRingTransferInput {
        ring,
        sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction: withdraw()?,
    })
    .with_interface_transfer_accounts(vec![settlement]);
    let unsigned = env.run(unsigned.prove(env.client.as_async()))?;
    assert_eq!(unsigned.co_signer, Some(cosigner.pubkey()));
    let rejection = send_expecting_rejection(
        rpc,
        sender,
        without_signer(unsigned.instruction()?, cosigner.pubkey()),
    )?;
    Rejection::custom(CustomRingError::MissingCoSigner as u32)
        .at(0)
        .assert_client(&rejection);
    let withdrawal = OwnerTransfer {
        ring,
        sender,
        prepared: withdraw()?,
        interface_transfer_accounts: vec![settlement],
        auditor_tag,
        cosigner: Some(&cosigner),
    }
    .send(&env)?;
    let recipient_final_note = ring_utxo(
        recipient,
        USDC_FINAL_SEND,
        output_blinding(&withdrawal.outputs, RECIPIENT_SLOT)?,
    );
    let final_change = ring_utxo(
        sender,
        USDC_FINAL_CHANGE,
        output_blinding(&withdrawal.outputs, CHANGE_SLOT)?,
    );
    assert_eq!(
        token_amount(&fetch_account(rpc, &recipient_usdc)?),
        USDC_WITHDRAW_AMOUNT,
        "public recipient after the ring withdrawal"
    );
    assert_eq!(
        token_amount(&fetch_account(rpc, &pda::spl_interface(&usdc))?),
        USDC_DEFAULT_DEPOSIT + USDC_RING_DEPOSIT - USDC_WITHDRAW_AMOUNT,
        "vault keeps the shielded remainder"
    );
    assert_eq!(
        opened(
            &AuditLookup {
                scan: scan(),
                auditor: &auditor,
                signature: withdrawal.signature,
            }
            .run(&env)?
        ),
        vec![
            recipient_final_note.opened(RECIPIENT_SLOT)?,
            final_change.opened(CHANGE_SLOT)?
        ],
        "withdrawal outputs"
    );
    env.recipient.wallet.sync(
        &recipient_authority,
        std::slice::from_ref(&withdrawal.indexed),
        0,
        DEFAULT_TAG_WINDOW,
    )?;
    assert_eq!(
        sorted_unspent_notes(&env.recipient.wallet),
        vec![
            (usdc, USDC_FINAL_SEND, Some(ring_program)),
            (usdc, USDC_EXIT_AMOUNT, None),
            (usdc, USDC_HOP_AMOUNT, Some(ring_program)),
            (usdc, USDC_ENTRY_AMOUNT, Some(ring_program)),
        ],
        "recipient wallet after the withdrawal"
    );

    // 7. The delegate re-owns the recipient's final note to the sender over the
    //    authority rail, refused until governance enables the rail.
    let delegate = Keypair::new();
    EscrowedDelegate {
        ring,
        delegate: &delegate,
        members: &[sender],
    }
    .set(&env)?;
    let moved = || -> Result<ProvenRingTransfer> {
        let transfer = DelegateTransfer::new(DelegateTransferInput {
            ring,
            delegate: delegate.pubkey(),
            payer: env.payer.pubkey(),
            source: recipient_address,
            source_nullifier_key: &recipient.nullifier_key,
            inputs: vec![recipient_final_note.input_utxo(&env)?],
            outputs: vec![DelegateOutput {
                recipient: sender_address,
                asset: usdc,
                amount: USDC_FINAL_SEND,
            }],
        })
        .with_assets(&env.assets);
        Ok(env.run(transfer.prove(env.client.as_async()))?)
    };
    let rejection = RejectedTransact {
        payer: &env.payer,
        signers: &[&delegate],
        instruction: moved()?.instruction()?,
    }
    .send(rpc)?;
    Rejection::pool(ShieldedPoolError::RingAuthorityTransactDisabled)
        .at(0)
        .assert_client(&rejection);
    env.enable_authority_rail(ring)?;
    let proven = moved()?;
    let moved_note = ring_utxo(
        sender,
        USDC_FINAL_SEND,
        output_blinding(&proven.outputs, 0)?,
    );
    let signature = land(&env, proven.instruction()?, &env.payer, &[&delegate])?;
    let indexed = wait_for_indexed_transaction(indexer, auditor_tag, signature);
    // Key escrow keeps the owner's nullifier key out of the disclosure, the record holds it.
    let escrowed_key = env
        .member_record(ring, owner_member(sender)?)?
        .nullifier_pk
        .context("the sender's record escrows no nullifier key")?;
    let escrowed = HashMap::from([(
        sender.signing_pubkey().confidential_view_tag()?,
        escrowed_key,
    )]);
    assert_eq!(
        opened(
            &AuditLookup {
                scan: scan().with_escrowed_keys(escrowed),
                auditor: &auditor,
                signature,
            }
            .run(&env)?
        ),
        vec![moved_note.opened(0)?],
        "delegate move outputs"
    );
    env.recipient.wallet.sync(
        &recipient_authority,
        std::slice::from_ref(&indexed),
        0,
        DEFAULT_TAG_WINDOW,
    )?;
    assert_eq!(
        sorted_unspent_notes(&env.recipient.wallet),
        vec![
            (usdc, USDC_EXIT_AMOUNT, None),
            (usdc, USDC_HOP_AMOUNT, Some(ring_program)),
            (usdc, USDC_ENTRY_AMOUNT, Some(ring_program)),
        ],
        "recipient wallet after the delegate move"
    );

    Ok(())
}

#[test]
fn an_outflow_limit_ring_bounds_each_transfer() -> Result<()> {
    const UNDER_THRESHOLD: u64 = 250_000_000;
    const OVER_THRESHOLD: u64 = 350_000_000;
    const OVER_CAP: u64 = 700_000_000;
    const DEPOSITS: [u64; 3] = [300_000_000, 400_000_000, 800_000_000];
    const _: () = assert!(UNDER_THRESHOLD <= LIMIT_COSIGN_ABOVE);
    const _: () = assert!(OVER_THRESHOLD > LIMIT_COSIGN_ABOVE && OVER_THRESHOLD <= LIMIT_CAP);
    const _: () = assert!(OVER_CAP > LIMIT_CAP);

    let env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Keypair::new();
    let auditor_pk = auditor.pubkey();
    let auditor_tag = auditor_view_tag(&auditor_pk);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor_pk,
        tier: Tier::policy(&OUTFLOW_LIMIT),
    }
    .send(&env.client)?;
    let sender = &env.sender.keypair;
    let sender_address = sender.shielded_address()?;
    let recipient = env.recipient.keypair.shielded_address()?;

    let mut utxos = Vec::with_capacity(DEPOSITS.len());
    for amount in DEPOSITS {
        let deposit = RingDeposit {
            ring,
            payer: sender,
            recipient: DepositRecipient::Confidential(sender_address),
            tree: env.tree,
            asset: DepositAsset::Sol,
            amount,
            cosigner: None,
        };
        let RingDepositReceipt { utxo, .. } = env.run(deposit.send(env.client.as_async()))?;
        utxos.push(utxo);
    }
    let tree_id = env.tree_id(env.tree)?;
    let prepare = |input: Utxo, amount: u64| -> Result<ConfidentialTransaction> {
        let input = indexed_note(input, sender, &env, env.tree)?;
        let mut transfer =
            ConfidentialTransaction::new_with_ring(vec![input], sender.pubkey(), ring_program)?
                .with_output_tree_id(tree_id)?;
        transfer.transfer_sol(&recipient, amount)?;
        transfer.pad_utxos(
            canonical_shape(transfer.inputs().len(), 2)?,
            &sender_address,
        )?;
        Ok(transfer)
    };
    let prove = |transaction: ConfidentialTransaction| {
        let transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring,
            sender,
            nullifier_key: Some(&sender.nullifier_key),
            transaction,
        });
        env.run(transfer.prove(env.client.as_async()))
    };

    // A send below the threshold lands with no approval.
    let proven = prove(prepare(utxos[0].clone(), UNDER_THRESHOLD)?)?;
    let instruction = proven.instruction()?;
    assert!(
        !frame(&instruction, RingRail::Confidential)?.approval_required,
        "an under-threshold send asks nobody"
    );
    let signature = land(&env, instruction, sender, &[])?;
    wait_for_indexed_transaction(indexer, auditor_tag, signature);

    // Above the threshold the chain refuses the send until the co-signer signs.
    let cosigner = Keypair::new();
    send(
        rpc,
        &env.payer,
        &[custom_ring_sdk::SetCoSigner {
            ring,
            authority: env.payer.pubkey(),
            signer: cosigner.pubkey(),
            scope: CoSignScope::WITHDRAWALS,
            thresholds: &[],
        }
        .instruction()?],
    )?;
    let proven = prove(prepare(utxos[1].clone(), OVER_THRESHOLD)?)?;
    let instruction = proven.instruction()?;
    assert!(
        frame(&instruction, RingRail::Confidential)?.approval_required,
        "an over-threshold send asks the co-signer"
    );
    assert_eq!(proven.co_signer, Some(cosigner.pubkey()));
    let rejection =
        send_expecting_rejection(rpc, sender, without_signer(instruction, cosigner.pubkey()))?;
    Rejection::custom(CustomRingError::MissingCoSigner as u32)
        .at(0)
        .assert_client(&rejection);
    let signed = prove(prepare(utxos[1].clone(), OVER_THRESHOLD)?)?;
    let signature = land(&env, signed.instruction()?, sender, &[&cosigner])?;
    wait_for_indexed_transaction(indexer, auditor_tag, signature);

    // A single send above the cap is refused before any proof.
    match prove(prepare(utxos[2].clone(), OVER_CAP)?) {
        Err(RingError::OutflowCapExceeded { cap, outflow, .. }) => {
            assert_eq!(cap, LIMIT_CAP);
            assert_eq!(outflow, OVER_CAP);
        }
        Err(other) => return Err(anyhow!("expected the cap refusal, got {other}")),
        Ok(_) => return Err(anyhow!("the capped send was proven")),
    }
    Ok(())
}

/// Registers every member in the pinned registry before the delegate turns key escrow on.
struct EscrowedDelegate<'a> {
    ring: CustomRing,
    delegate: &'a Keypair,
    members: &'a [&'a ShieldedKeypair],
}

impl EscrowedDelegate<'_> {
    fn set(self, env: &TestEnv) -> Result<()> {
        for member in self.members {
            register_key(env, self.ring, member)?;
        }
        Queued::now(&env.client, self.ring)?.apply(&env.client, &env.payer)?;
        DelegateAppointment {
            ring: self.ring,
            delegate: self.delegate,
        }
        .send(env)
    }
}

/// The delegate signs its appointment beside the upgrade authority.
struct DelegateAppointment<'a> {
    ring: CustomRing,
    delegate: &'a Keypair,
}

impl DelegateAppointment<'_> {
    fn send(self, env: &TestEnv) -> Result<()> {
        env.client.rpc().create_and_send_transaction(
            &[custom_ring_sdk::SetDelegate {
                ring: self.ring,
                authority: env.payer.pubkey(),
                delegate: self.delegate.pubkey(),
            }
            .instruction()],
            env.payer.pubkey(),
            &[&env.payer, self.delegate],
            ComputeBudgetConfig::for_instruction_count(1),
        )?;
        Ok(())
    }
}

#[test]
fn the_key_escrow_lifecycle_ends_in_a_delegate_move() -> Result<()> {
    const SEND: u64 = DEFAULT_DEPOSIT / 4;

    let env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Keypair::new();
    let auditor_pk = auditor.pubkey();
    let auditor_tag = auditor_view_tag(&auditor_pk);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor_pk,
        tier: Tier::policy(&EMPTY),
    }
    .send(&env.client)?;
    let member = &env.sender.keypair;
    let member_address = member.shielded_address()?;
    let deposit = |recipient: ShieldedAddress| RingDeposit {
        ring,
        payer: member,
        recipient: DepositRecipient::Confidential(recipient),
        tree: env.tree,
        asset: DepositAsset::Sol,
        amount: DEFAULT_DEPOSIT,
        cosigner: None,
    };
    let RingDepositReceipt { signature, utxo } =
        env.run(deposit(member_address).send(env.client.as_async()))?;
    let input = indexed_note(utxo, member, &env, env.tree)?;
    // 1. Recover the direct deposit before any transfer can disclose its
    // opening.
    assert_transaction_compute_units(
        rpc,
        &signature,
        "audited ring deposit",
        u64::from(compute_unit_limit(InstructionTag::AuditedDeposit)),
    )?;
    let recovery = RingRecovery::new(ring_program, &auditor).for_member(SourceMember {
        address: &member_address,
        nullifier_key: &member.nullifier_key,
    });
    let client = env.client.as_async();
    let deposited =
        env.client
            .block_on(recovery.run(client.indexer(), client.rpc(), &env.assets))?;
    assert!(deposited.unopened.is_empty());
    assert!(deposited.unsupported_deposits.is_empty());
    assert_eq!(deposited.utxos.len(), 1);
    assert_eq!(deposited.utxos[0].utxo, input.utxo);
    assert_eq!(deposited.utxos[0].utxo.amount, DEFAULT_DEPOSIT);

    let tree_id = env.tree_id(env.tree)?;
    let mut transfer =
        ConfidentialTransaction::new_with_ring(vec![input], member.pubkey(), ring_program)?
            .with_output_tree_id(tree_id)?;
    transfer.transfer_sol(&member_address, SEND)?;
    transfer.pad_utxos(
        canonical_shape(transfer.inputs().len(), 2)?,
        &member_address,
    )?;
    OwnerTransfer {
        ring,
        sender: member,
        prepared: transfer,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;

    // 2. The member escrows its nullifier key, the auditor opens it from the
    //    applied record.
    register_key(&env, ring, member)?;
    Queued::now(&env.client, ring)?.apply(&env.client, &env.payer)?;
    let member_tag = owner_member(member)?;
    let read = wait_for("the registered key", || {
        Ok(match env.member_record(ring, member_tag) {
            Ok(read) if read.sealed.is_some() => Probe::Ready(read),
            Ok(_) => Probe::Retry(anyhow!("no sealed key yet")),
            Err(error) => Probe::Retry(error),
        })
    })?;
    let escrowed = read
        .escrowed(&member_address.nullifier_pubkey)?
        .context("the record escrows the member's nullifier key")?;
    let nullifier_key = escrowed.sealed.open(&auditor)?;
    assert_eq!(nullifier_key.pubkey()?, member_address.nullifier_pubkey);
    assert_eq!(
        policy_registry(ring, &env)?.next_index(),
        2,
        "one registered member plus sentinel"
    );

    let delegate = Keypair::new();
    DelegateAppointment {
        ring,
        delegate: &delegate,
    }
    .send(&env)?;
    env.enable_authority_rail(ring)?;
    let recovery = RingRecovery::new(ring_program, &auditor).for_member(SourceMember {
        address: &member_address,
        nullifier_key: &nullifier_key,
    });
    let client = env.client.as_async();
    let recovered =
        env.client
            .block_on(recovery.run(client.indexer(), client.rpc(), &env.assets))?;
    assert!(recovered.unopened.is_empty(), "every audited note opens");
    let mut amounts: Vec<u64> = recovered
        .utxos
        .iter()
        .map(|held| held.utxo.amount)
        .collect();
    amounts.sort_unstable();
    assert_eq!(amounts, [SEND, DEFAULT_DEPOSIT - SEND]);
    let (moved, change): (Vec<_>, Vec<_>) = recovered
        .utxos
        .into_iter()
        .partition(|held| held.utxo.amount == SEND);
    let moved = moved.into_iter().next().context("the sent note")?;
    let change = change.into_iter().next().context("the change note")?;
    let pay = |to: &ShieldedAddress| -> Result<ConfidentialTransaction> {
        let mut transfer = ConfidentialTransaction::new_with_ring(
            vec![change.clone()],
            member.pubkey(),
            ring_program,
        )?
        .with_output_tree_id(tree_id)?;
        transfer.transfer_sol(to, 1)?;
        transfer.pad_utxos(canonical_shape(1, 2)?, &member_address)?;
        Ok(transfer)
    };

    // 3. Key escrow refuses an owner without an enrolled key before any prover
    //    round, for the zero key and for an enrolled owner naming another key.
    let unreachable = env.client_with(
        ProverClient::new("http://127.0.0.1:1".to_owned())
            .with_proof_data_source(ProofDataSource::Client),
    );
    let refused = |to: &ShieldedAddress| -> Result<Member> {
        let transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring,
            sender: member,
            nullifier_key: Some(&member.nullifier_key),
            transaction: pay(to)?,
        });
        match unreachable.block_on(transfer.prove(unreachable.as_async())) {
            Err(RingError::UnregisteredOutputKey { owner }) => Ok(owner),
            other => Err(anyhow!(
                "expected UnregisteredOutputKey, got {:?}",
                other.err()
            )),
        }
    };
    let unregistered = env.recipient.keypair.shielded_address()?;
    let unregistered_owner =
        Member::from_bytes(unregistered.signing_pubkey.owner_proof_input_hash()?)?;
    assert_eq!(refused(&unregistered)?, unregistered_owner);
    let zero_key = ShieldedAddress {
        nullifier_pubkey: ZERO_NULLIFIER_PUBKEY,
        ..unregistered
    };
    assert_eq!(refused(&zero_key)?, unregistered_owner);
    let mismatched = ShieldedAddress {
        nullifier_pubkey: ZERO_NULLIFIER_PUBKEY,
        ..member_address
    };
    assert_eq!(
        refused(&mismatched)?,
        Member::from_bytes(member_address.signing_pubkey.owner_proof_input_hash()?)?
    );
    match env.run(
        custom_ring_sdk::EscrowedRecipients {
            ring,
            recipients: &[member_address, unregistered],
        }
        .check(env.client.as_async()),
    ) {
        Err(RingError::UnregisteredOutputKey { owner }) => assert_eq!(owner, unregistered_owner),
        other => return Err(anyhow!("expected UnregisteredOutputKey, got {other:?}")),
    }

    // 4. A deposit binds the recipient's record under key escrow, one to an owner
    //    without an escrowed key is refused before proving.
    match env.run(deposit(unregistered).send(env.client.as_async())) {
        Err(RingError::UnregisteredOutputKey { owner }) => {
            assert_eq!(owner, unregistered_owner)
        }
        Err(other) => return Err(anyhow!("expected UnregisteredOutputKey, got {other}")),
        Ok(_) => return Err(anyhow!("a deposit to an unregistered owner landed")),
    }
    let RingDepositReceipt { signature, .. } =
        env.run(deposit(member_address).send(env.client.as_async()))?;
    assert_transaction_compute_units(
        rpc,
        &signature,
        "escrowed audited deposit",
        u64::from(compute_unit_limit(InstructionTag::AuditedDeposit)),
    )?;

    // 5. The delegate moves the enrolled member's note back to the member.
    let moved_nullifier = moved.nullifier;
    let proven = DelegateTransfer::new(DelegateTransferInput {
        ring,
        delegate: delegate.pubkey(),
        payer: env.payer.pubkey(),
        source: member_address,
        source_nullifier_key: &nullifier_key,
        inputs: vec![moved],
        outputs: vec![DelegateOutput {
            recipient: member_address,
            asset: SOL_MINT,
            amount: SEND,
        }],
    })
    .with_assets(&env.assets);
    let proven = env.run(proven.prove(env.client.as_async()))?;
    let signature = land(&env, proven.instruction()?, &env.payer, &[&delegate])?;
    let indexed = wait_for_indexed_transaction(indexer, auditor_tag, signature);
    assert!(
        indexed.nullifiers.contains(&moved_nullifier),
        "the delegate spent the note"
    );
    let mut member_wallet = Wallet::new(member_address, env.assets.clone())?;
    let member_authority = KeypairWalletAuthority::new(Address::default(), member);
    member_wallet.sync(
        &member_authority,
        std::slice::from_ref(&indexed),
        0,
        DEFAULT_TAG_WINDOW,
    )?;
    assert_eq!(
        sorted_unspent_notes(&member_wallet),
        vec![(SOL_MINT, SEND, Some(ring_program))],
        "the delegate moved the registered member's note"
    );
    Ok(())
}

#[test]
fn an_old_tree_note_migrates_into_the_active_tree() -> Result<()> {
    let mut env = setup()?;
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Keypair::new();
    let auditor_tag = auditor_view_tag(&auditor.pubkey());

    let old_tree = env.create_registered_tree()?;
    assert_ne!(old_tree, env.tree);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::policy(&EMPTY),
    }
    .send(&env.client)?;

    let sender = &env.sender.keypair;
    let recipient = &env.recipient.keypair;
    let deposit = RingDeposit {
        ring,
        payer: sender,
        recipient: DepositRecipient::Confidential(sender.shielded_address()?),
        tree: old_tree,
        asset: DepositAsset::Sol,
        amount: DEFAULT_DEPOSIT,
        cosigner: None,
    };
    let RingDepositReceipt { utxo, .. } = env.run(deposit.send(env.client.as_async()))?;
    let mut prepared = ConfidentialTransaction::new_with_ring(
        vec![indexed_note(utxo, sender, &env, old_tree)?],
        sender.pubkey(),
        ring_program,
    )?
    .with_output_tree_id(env.tree_id(env.tree)?)?;
    prepared.transfer_sol(&recipient.shielded_address()?, ENTRY_AMOUNT)?;
    prepared.pad_utxos(
        canonical_shape(prepared.inputs().len(), 2)?,
        &sender.shielded_address()?,
    )?;
    let migrated = OwnerTransfer {
        ring,
        sender,
        prepared,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;
    assert_eq!(
        migrated.indexed.nullifiers.len(),
        1,
        "the old-tree note is spent"
    );

    let recipient_authority = KeypairWalletAuthority::new(Address::default(), recipient);
    env.recipient.wallet.sync(
        &recipient_authority,
        std::slice::from_ref(&migrated.indexed),
        0,
        DEFAULT_TAG_WINDOW,
    )?;
    let received = unspent_utxo(&env.recipient.wallet, ENTRY_AMOUNT)?;
    let mut prepared = ConfidentialTransaction::new_with_ring(
        vec![indexed_note(received, recipient, &env, env.tree)?],
        recipient.pubkey(),
        ring_program,
    )?;
    prepared.transfer_sol(&sender.shielded_address()?, SECOND_HOP_AMOUNT)?;
    prepared.pad_utxos(
        canonical_shape(prepared.inputs().len(), 2)?,
        &recipient.shielded_address()?,
    )?;
    let hop = OwnerTransfer {
        ring,
        sender: recipient,
        prepared,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;
    let audited = AuditLookup {
        scan: RingScan::new(ring_program, auditor.pubkey()),
        auditor: &auditor,
        signature: hop.signature,
    }
    .run(&env)?;
    assert_eq!(
        ring_amounts(&audited)?,
        vec![SECOND_HOP_AMOUNT, ENTRY_AMOUNT - SECOND_HOP_AMOUNT],
        "the active-tree note spends in turn"
    );
    Ok(())
}

fn lamports<R: Rpc>(rpc: &R, address: Address) -> Result<u64> {
    Ok(rpc
        .get_account(address)?
        .ok_or_else(|| anyhow!("account {address} not found"))?
        .lamports)
}

fn registration(env: &TestEnv, ring: CustomRing) -> Result<RingRegistration> {
    env.run(ring.registration(env.client.as_async()))?
        .ok_or_else(|| anyhow!("SPP ring config of {}", ring.program_id()))
}

/// Proves, signs and settles one ring operation, a failed one is an error.
fn land<'a>(
    env: &TestEnv,
    operation: impl Into<RingOperation<'a>>,
    payer: &(dyn Signer + Sync),
    signers: &[&(dyn Signer + Sync)],
) -> Result<Signature> {
    let landed = Landing {
        operation: operation.into(),
        payer,
        signers,
    }
    .settle(&env.client)?;
    Ok(landed.signature)
}

/// The write waits in the record queue until `Queued::apply`.
fn register_key(env: &TestEnv, ring: CustomRing, member: &ShieldedKeypair) -> Result<()> {
    let registration = RegisterKey {
        ring,
        member: member.shielded_address()?,
        payer: member.pubkey(),
        authority: member,
    };
    land(env, registration, member, &[])?;
    Ok(())
}

fn frame(instruction: &Instruction, rail: RingRail) -> Result<RingTransactData<'_>> {
    let (_, body) = instruction
        .data
        .split_first()
        .context("a tagged ring instruction")?;
    Ok(RingTransactData::parse(body, rail)?.into_data())
}

fn reframed(instruction: &Instruction, frame: &RingTransactData<'_>) -> Result<Instruction> {
    Ok(Instruction {
        data: [&instruction.data[..1], frame.encode()?.as_slice()].concat(),
        ..instruction.clone()
    })
}

fn signers(instruction: &Instruction) -> Vec<Address> {
    instruction
        .accounts
        .iter()
        .filter(|meta| meta.is_signer)
        .map(|meta| meta.pubkey)
        .collect()
}

/// Lets the transaction compile without `signer`'s signature.
fn without_signer(mut instruction: Instruction, signer: Address) -> Instruction {
    for meta in &mut instruction.accounts {
        if meta.pubkey == signer {
            meta.is_signer = false;
        }
    }
    instruction
}

/// The test's own view of a note, spent and audited from the same values.
#[derive(Clone, Copy)]
struct Note<'a> {
    owner: &'a ShieldedKeypair,
    asset: Address,
    amount: u64,
    blinding: [u8; 32],
    ring_program_id: Option<Address>,
}

impl Note<'_> {
    fn input_utxo(self, env: &TestEnv) -> Result<WalletUtxo> {
        let utxo = Utxo {
            owner: self.owner.signing_pubkey(),
            asset: env.assets.mint(&self.asset)?,
            amount: self.amount,
            blinding: self.blinding,
            ring_program_id: self.ring_program_id,
            data: Data::default(),
        };
        if self.ring_program_id == Some(FOREIGN_RING) {
            return zolana_test_utils::utxo::wallet(
                utxo,
                &self.owner.nullifier_key,
                0,
                0,
                None,
                None,
            );
        }
        indexed_note(utxo, self.owner, env, env.tree)
    }

    fn opened(self, slot_index: u32) -> Result<Opened> {
        Ok(Opened {
            slot_index,
            exit: self.ring_program_id.is_none(),
            owner_key: self.owner.signing_pubkey().confidential_view_tag()?,
            mint: Some(self.asset),
            amount: self.amount,
            blinding: self.blinding,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Opened {
    slot_index: u32,
    exit: bool,
    owner_key: [u8; 32],
    mint: Option<Address>,
    amount: u64,
    blinding: [u8; 32],
}

fn opened(audited: &AuditedTransaction) -> Vec<Opened> {
    audited
        .outputs
        .iter()
        .filter_map(|output| {
            let (utxo, exit) = match &output.opening {
                OutputOpening::Ring { utxo, .. } => (utxo, false),
                OutputOpening::Exit(utxo) => (utxo, true),
                OutputOpening::Dummy => return None,
            };
            Some(Opened {
                slot_index: output.slot_index,
                exit,
                owner_key: utxo.owner_key,
                mint: utxo.mint,
                amount: utxo.amount,
                blinding: utxo.blinding,
            })
        })
        .collect()
}

fn ring_amounts(audited: &AuditedTransaction) -> Result<Vec<u64>> {
    opened(audited)
        .into_iter()
        .map(|opened| match opened.exit {
            false => Ok(opened.amount),
            true => Err(anyhow!("slot {} left the ring", opened.slot_index)),
        })
        .collect()
}

fn output_blinding(outputs: &[SppProofOutputUtxo], slot: u32) -> Result<[u8; 32]> {
    Ok(outputs
        .get(usize::try_from(slot)?)
        .with_context(|| format!("output slot {slot}"))?
        .blinding)
}

struct DefaultRingDeposit<'a> {
    depositor: &'a ShieldedKeypair,
    tree: Address,
    asset: DepositAsset,
    amount: u64,
}

impl<'a> DefaultRingDeposit<'a> {
    fn send(
        self,
        rpc: &SolanaRpc,
        indexer: &ZolanaIndexer,
        assets: &AssetRegistry,
    ) -> Result<Note<'a>> {
        let address = self.depositor.shielded_address()?;
        let view_tag = address.viewing_pubkey.u();
        let deposit = SppDeposit {
            tree: self.tree,
            depositor: self.depositor.pubkey(),
            deposits: vec![AssetDeposit {
                asset: self.asset,
                view_tag,
                owner: address.owner_hash()?,
                amount: self.amount,
                memo: None,
            }],
        }
        .instruction()?;
        let signature = send(rpc, self.depositor, &[deposit])?;
        // A proofless deposit publishes its UTXO in the clear, so read it back
        // from the indexer.
        let indexed = wait_for_indexed_transaction(indexer, view_tag, signature);
        let mint = self.asset.mint();
        let balances = decrypt_spendable(self.depositor, std::slice::from_ref(&indexed), assets)
            .map_err(|e| anyhow!("decrypt deposit {signature}: {e:?}"))?
            .balances;
        let deposited = balances
            .get_balance(mint)
            .and_then(|balance| balance.utxos.first())
            .ok_or_else(|| anyhow!("deposit {signature} not indexed for {mint}"))?;
        assert_eq!(deposited.utxo.amount, self.amount, "deposited amount");
        Ok(Note {
            owner: self.depositor,
            asset: mint,
            amount: self.amount,
            blinding: deposited.utxo.blinding,
            ring_program_id: None,
        })
    }
}

/// `cosigner` must be the co-signer the config demands.
struct OwnerTransfer<'a> {
    ring: CustomRing,
    sender: &'a ShieldedKeypair,
    prepared: ConfidentialTransaction,
    interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    auditor_tag: [u8; 32],
    cosigner: Option<&'a Keypair>,
}

struct TransferReceipt {
    signature: Signature,
    indexed: ShieldedTransaction,
    /// Indexed by slot, padding included.
    outputs: Vec<SppProofOutputUtxo>,
}

impl OwnerTransfer<'_> {
    fn send(self, env: &TestEnv) -> Result<TransferReceipt> {
        let transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring: self.ring,
            sender: self.sender,
            nullifier_key: Some(&self.sender.nullifier_key),
            transaction: self.prepared,
        })
        .with_interface_transfer_accounts(self.interface_transfer_accounts);
        let proven = env.run(transfer.prove(env.client.as_async()))?;
        assert_eq!(
            proven.co_signer,
            self.cosigner.map(|cosigner| cosigner.pubkey()),
            "the config demands exactly this co-signer"
        );
        let signers: Vec<&(dyn Signer + Sync)> = self
            .cosigner
            .into_iter()
            .map(|keypair| keypair as &(dyn Signer + Sync))
            .collect();
        let signature = land(env, proven.instruction()?, self.sender, &signers)?;
        let indexed =
            wait_for_indexed_transaction(env.client.indexer(), self.auditor_tag, signature);
        Ok(TransferReceipt {
            signature,
            indexed,
            outputs: proven.outputs,
        })
    }
}

/// The recipient's note `received` paid back to the sender in the note's ring.
fn second_hop(env: &TestEnv, received: Utxo) -> Result<ConfidentialTransaction> {
    let ring = received.ring_program_id.context("a ring note")?;
    let mut hop = ConfidentialTransaction::new_with_ring(
        vec![indexed_note(
            received,
            &env.recipient.keypair,
            env,
            env.tree,
        )?],
        env.recipient.keypair.pubkey(),
        ring,
    )?;
    hop.transfer_sol(&env.sender.keypair.shielded_address()?, SECOND_HOP_AMOUNT)?;
    hop.pad_utxos(
        canonical_shape(hop.inputs().len(), 2)?,
        &env.recipient.keypair.shielded_address()?,
    )?;
    Ok(hop)
}

struct AsyncHopParity<'a> {
    ring: CustomRing,
    sender: &'a ShieldedKeypair,
    blocking: ConfidentialTransaction,
    asynchronous: ConfidentialTransaction,
    auditor_tag: [u8; 32],
}

impl AsyncHopParity<'_> {
    fn send(self, env: &TestEnv) -> Result<TransferReceipt> {
        let blocking = CustomRingTransfer::new(CustomRingTransferInput {
            ring: self.ring,
            sender: self.sender,
            nullifier_key: Some(&self.sender.nullifier_key),
            transaction: self.blocking,
        });
        let blocking = env.run(blocking.prove(env.client.as_async()))?;

        // `local()` on both clients, a parity failure cannot be two different provers.
        let native = AsyncZolanaClient::new(
            AsyncSolanaRpc::new(env.rpc_url.clone()),
            AsyncZolanaIndexer::new(env.indexer_url.clone()),
            AsyncProverClient::local(),
        );
        let runtime = tokio::runtime::Runtime::new()?;
        let transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring: self.ring,
            sender: self.sender,
            nullifier_key: Some(&self.sender.nullifier_key),
            transaction: self.asynchronous,
        });
        let proven = runtime.block_on(transfer.prove(&native))?;

        let (native_ix, blocking_ix) = (proven.instruction()?, blocking.instruction()?);
        let native_frame = frame(&native_ix, RingRail::Confidential)?;
        let blocking_frame = frame(&blocking_ix, RingRail::Confidential)?;
        assert_eq!(
            proven.tx_viewing_key.pubkey(),
            blocking.tx_viewing_key.pubkey(),
            "async and blocking derive the same transaction viewing key"
        );
        assert_eq!(
            native_frame.tx_viewing_u, blocking_frame.tx_viewing_u,
            "async and blocking publish the same tx_viewing_pk"
        );
        assert_eq!(
            native_frame.circuit(),
            blocking_frame.circuit(),
            "async and blocking select the same circuit"
        );
        assert_eq!(
            native_frame.nullifiers, blocking_frame.nullifiers,
            "async and blocking nullify the same note"
        );
        assert_eq!(
            signers(&native_ix),
            signers(&blocking_ix),
            "async and blocking require the same signatures"
        );
        assert_eq!(
            native_frame.expiry_unix_ts, blocking_frame.expiry_unix_ts,
            "async and blocking carry the same expiry"
        );
        assert_ne!(
            native_frame.private_tx_hash, blocking_frame.private_tx_hash,
            "each proof draws its own blindings, salt and auditor ciphertext"
        );

        let outputs = proven.outputs.clone();
        let signature = land(env, native_ix, self.sender, &[])?;
        let indexed =
            wait_for_indexed_transaction(env.client.indexer(), self.auditor_tag, signature);
        Ok(TransferReceipt {
            signature,
            indexed,
            outputs,
        })
    }
}

struct AuditLookup<'a> {
    scan: RingScan,
    auditor: &'a X25519Keypair,
    signature: Signature,
}

impl AuditLookup<'_> {
    fn run(self, env: &TestEnv) -> Result<AuditedTransaction> {
        let client = env.client.as_async();
        env.client
            .block_on(
                self.scan
                    .audit(self.auditor, client.indexer(), client.rpc(), &env.assets),
            )?
            .transactions
            .into_iter()
            .find(|tx| tx.tx_signature == self.signature)
            .ok_or_else(|| anyhow!("transaction {} audited", self.signature))
    }
}

/// An anonymous ring payment, the ring payer funds it so no public signer names the owner.
struct AnonymousPayment<'a> {
    ring: CustomRing,
    sender: &'a ShieldedKeypair,
    /// The sender's side of the ring, a recorded first contact picks the pair stream.
    state: &'a AnonymousRingState,
    payer: &'a Keypair,
    inputs: Vec<WalletUtxo>,
    to: RingAddress,
    amount: u64,
}

impl<'a> AnonymousPayment<'a> {
    fn transfer(self) -> Result<AnonymousTransfer<'a>> {
        let shape = canonical_shape(self.inputs.len(), 2)?;
        let transaction = ConfidentialTransaction::new_with_ring(
            self.inputs,
            self.payer.pubkey(),
            self.ring.program_id(),
        )?;
        Ok(CustomRingTransfer::new(CustomRingTransferInput {
            ring: self.ring,
            sender: self.sender,
            nullifier_key: Some(&self.sender.nullifier_key),
            transaction,
        })
        .with_anonymous_signer(&self.sender.signing_key, self.state)
        .with_payment(custom_ring_sdk::AnonymousPayment {
            to: self.to,
            asset: Mint::SOL,
            amount: self.amount,
        })?
        .with_shape(shape)?)
    }
}

struct PaymentLanding<'a> {
    transfer: AnonymousTransfer<'a>,
    payer: &'a Keypair,
    auditor_tag: [u8; 32],
}

struct LandedPayment {
    indexed: ShieldedTransaction,
    first_contacts: Vec<PendingFirstContact>,
}

impl PaymentLanding<'_> {
    fn land(self, env: &TestEnv) -> Result<LandedPayment> {
        let landed = Landing {
            operation: self.transfer.into(),
            payer: self.payer,
            signers: &[],
        }
        .settle(&env.client)?;
        Ok(LandedPayment {
            indexed: wait_for_indexed_transaction(
                env.client.indexer(),
                self.auditor_tag,
                landed.signature,
            ),
            first_contacts: landed.first_contacts,
        })
    }
}

impl LandedPayment {
    /// Each first contact confirmed at the leaf the indexer reports for it.
    fn record(&self, state: &mut AnonymousRingState) -> Result<()> {
        for pending in &self.first_contacts {
            let slot = self
                .indexed
                .output_slots
                .iter()
                .find(|slot| slot.output_context.hash == pending.utxo_hash)
                .context("the first contact's output")?;
            state.record_first_contact(pending.confirm(slot.output_context.leaf_index));
        }
        Ok(())
    }
}

fn unspent_utxo(wallet: &Wallet, amount: u64) -> Result<Utxo> {
    wallet
        .unspent()
        .find(|held| held.utxo.amount == amount)
        .map(|held| held.utxo.clone())
        .ok_or_else(|| anyhow!("an unspent note of {amount}"))
}

fn sorted_unspent_notes(wallet: &Wallet) -> Vec<(Address, u64, Option<Address>)> {
    let mut notes: Vec<_> = wallet
        .unspent()
        .map(|held| {
            (
                held.utxo.asset.asset,
                held.utxo.amount,
                held.utxo.ring_program_id,
            )
        })
        .collect();
    notes.sort_unstable();
    notes
}

fn expect_foreign_ring(result: Result<ProvenRingTransfer, RingError>, ring: Address) -> Result<()> {
    match result {
        Err(RingError::ForeignRing(refused)) if refused == ring => Ok(()),
        Err(other) => Err(anyhow!("expected ForeignRing({ring}), got {other}")),
        Ok(_) => Err(anyhow!(
            "expected ForeignRing({ring}), the transfer was proven"
        )),
    }
}

fn indexed_note(
    utxo: Utxo,
    owner: &ShieldedKeypair,
    env: &TestEnv,
    tree: Address,
) -> Result<WalletUtxo> {
    let tree_id = env.tree_id(tree)?;
    let hash = utxo.hash(&owner.nullifier_key.pubkey()?, &[0; 32], &[0; 32], tree_id)?;
    let state = wait_for_merkle_proof(env.client.indexer(), tree, hash);
    zolana_test_utils::utxo::wallet(
        utxo,
        &owner.nullifier_key,
        tree_id,
        state.leaf_index,
        None,
        None,
    )
}
