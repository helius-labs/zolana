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
//! policy config and the audit statement alone, with the same auditor recovery.
//! Its second hop, like the capstone's, is proven through the blocking client and
//! through a native async client, and lands the native proof (see [`AsyncHopParity`]).
//!
//! [`ring_value_leaves_and_enters_through_audited_transfers`] crosses the ring
//! boundary in both directions under the auditor and pins that a note of
//! another ring is refused before proving.

use std::{
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use custom_ring_cli::{wait_for, Probe};
use custom_ring_interface::{
    CustomRingError, RingMode, RingProgramConfig, CONFIG_PDA_SEED, RING_PROGRAM_CONFIG,
};
use custom_ring_sdk::{
    compute_unit_limit, CoSignScope, CoSignThreshold, CustomRing, CustomRingTransact,
    CustomRingTransfer, CustomRingTransferInput, DelegateOutput, DelegateTransfer,
    DelegateTransferInput, Deposit, EscrowBinding, InstructionTag, ProvenDelegateTransfer,
    ProvenTransfer, ReadSealedKey, RegisterKey, RingDeposit, RingDepositReceipt, RingError,
    RingOperation, RingSubmission, SettledSubmission,
};
use custom_ring_test_validator::{
    cli::{merged, RingProject, RingToml},
    policy::{EMPTY, LIMIT_CAP, LIMIT_COSIGN_ABOVE, OUTFLOW_LIMIT},
    shared::{
        custom_ring_program_id, prover_url, send, send_expecting_rejection, setup, ExpectRejection,
        RegisterRing, RejectedTransact, TestEnv, Tier, USDC_ASSET_ID,
    },
};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_message::v1::MAX_TRANSACTION_SIZE;
use solana_signature::Signature;
use solana_signer::Signer;
use zeroize::Zeroizing;
use zolana_client::{
    compile_message, sign_transaction, AsyncProverClient, AsyncSolanaRpc, AsyncZolanaClient,
    AsyncZolanaIndexer, ComputeBudgetConfig, ProofDataSource, ProverClient, Rpc,
    ShieldedTransaction, SolanaRpc, ZolanaClient, ZolanaIndexer,
};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::EncryptedRingDepositData,
    pda,
    state::{
        discriminator::{PROTOCOL_CONFIG, RING_CONFIG, TREE_ACCOUNT_DISCRIMINATOR},
        tree_account_size, ProtocolConfig, RingConfig,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{random_blinding, ShieldedAddress, ShieldedKeypair, X25519Secret};
use zolana_program::instruction::{
    AssetDeposit, Deposit as SppDeposit, DepositAsset, DepositSplAccounts, RingAssetDeposit,
    TransactInterfaceTransferAccounts, TransactSplWithdrawalAccounts, UpdateRingConfig,
};
use zolana_program_test::Rejection;
use zolana_ring_client::{
    auditor_view_tag, rpc::CreateAuditorKeyRequest, AuditedOutput, AuditedTransaction,
    RingRecovery, RingScan, SourceMember,
};
use zolana_ring_policy::{Member, ZERO_NULLIFIER_PK};
use zolana_ring_rpc::{
    ChainSource, Hub, RingRpcError, RootSecret, TransactionSource, Unauthorized, Upstreams,
};
use zolana_test_utils::wallet::{KeypairWalletAuthority, Wallet, DEFAULT_TAG_WINDOW};
use zolana_test_utils::{
    smart_account,
    spl::{create_token_account, mint_to},
    test_validator_asserts::{
        assert_account_unchanged, assert_transaction_compute_units, fetch_account, fetch_state,
        token_amount, wait_for_indexed_transaction, wait_for_merkle_proof,
    },
};
use zolana_transaction::{
    decrypt_spendable,
    instructions::transact::{canonical_shape, ConfidentialTransaction},
    utxo::SppProofInputUtxo,
    AssetRegistry, Data, Utxo, WalletUtxo, SOL_ASSET_ID, SOL_MINT,
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

/// Output slot layout this test publishes: the sender's change first, the
/// recipient second. A slot's index is what its ciphertext is bound to, so these
/// are also the `slot_index` values the auditor must report.
const CHANGE_SLOT: u32 = 1;
const RECIPIENT_SLOT: u32 = 0;

/// Offset of the ciphertext inside the auditor message
/// (`eph_pk_compressed(33) || ciphertext(32)`), i.e. the first byte the negative
/// case tampers with.
const AUDITOR_CIPHERTEXT_OFFSET: usize = 33;

const CUSTOM_RING_TRANSACT_CU_LIMIT: u64 = 520_000;

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
        runtime.block_on(service.authorize_auditor_key(&request.auth))
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
            ring.create_config(
                env.payer.pubkey(),
                env.payer.pubkey(),
                service.auditor_pubkey(),
                true,
            )?,
            ring.set_authority(env.payer.pubkey(), config_authority.pubkey()),
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
    let auditor = X25519Secret::new();
    let project = RingProject::create(&env, &auditor.pubkey())?;
    let init = || project.run(&["init"]);

    // 1. A local ring rpc lets the key file through, the config is created
    //    under the deployer and handed over in the same run.
    project.write_config(RingToml {
        env: &env,
        ring_rpc: "http://127.0.0.1:1",
        policy: None,
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
    })?;
    let second = init()?;
    assert!(second.contains("config      already present"), "{second}");
    assert!(second.contains("authority   already present"), "{second}");

    // 3. The config authority closes and reopens the ring through the program,
    //    the SPP flag follows each run.
    let paused = project.run(&["authority", "pause"])?;
    assert!(paused.contains("spp ring    paused"), "{paused}");
    assert!(
        spp_ring_config(&env, ring)?.is_paused(),
        "paused by the cli"
    );
    let resumed = project.run(&["authority", "resume"])?;
    assert!(resumed.contains("spp ring    resumed"), "{resumed}");
    assert!(
        !spp_ring_config(&env, ring)?.is_paused(),
        "reopened by the cli"
    );
    project.remove()?;
    Ok(())
}

/// The operator can consolidate notes owned by the persistent demo wallet. The
/// command proves, lands and reads back the merge instead of stopping at an
/// instruction-builder assertion.
#[test]
fn cli_merges_fragmented_custom_ring_notes() -> Result<()> {
    let env = setup()?;
    let tree = env.register_default_tree()?;
    let ring = CustomRing::new(custom_ring_program_id()?);
    let auditor = X25519Secret::new();
    let project = RingProject::create(&env, &auditor.pubkey())?;
    project.write_config(RingToml {
        env: &env,
        ring_rpc: "http://127.0.0.1:1",
        policy: None,
    })?;
    project.run(&["init"])?;

    // The first run creates the persistent sender key, but correctly refuses
    // to manufacture a merge from fewer than two notes.
    let empty = project.output(&["merge", "--count", "2"])?;
    assert!(!empty.status.success(), "an empty wallet cannot merge");
    let empty_text = merged(&empty);
    assert!(
        empty_text.contains("found only 0 mergeable notes"),
        "{empty_text}"
    );
    let sender = project.demo_sender()?;

    for amount in [3_000_000_u64, 5_000_000] {
        let deposit = RingDeposit {
            ring,
            payer: &env.payer,
            recipient: &sender,
            tree,
            asset: DepositAsset::Sol,
            amount,
            cosigner: None,
        };
        let receipt = env.run(deposit.send(env.client.as_async()))?;
        custom_ring_cli::wait_for_indexed_transaction(&env.client, receipt.signature)?;
    }

    let output = project.run(&["merge", "--count", "2"])?;
    for line in [
        "inputs      2",
        "amount      8000000",
        "merge is value-preserving",
    ] {
        assert!(output.contains(line), "{line} in\n{output}");
    }
    project.remove()?;
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
    let auditor = X25519Secret::new();
    let auditor_pk = auditor.pubkey();
    let auditor_pubkey = *auditor_pk.as_bytes();

    // 2. Create the ring's singleton config holding the auditor key. The payer
    //    doubles as the config authority, so one signature covers both roles.
    //    The ring program refuses the SPP registration until the policy is pinned.
    let authority = env.payer.pubkey();
    let configured = RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor_pk,
        tier: Tier::policy(&EMPTY, env.tree),
    }
    .configure(rpc)?;
    let rejection = ExpectRejection {
        payer: &env.payer,
        instructions: &[configured.registration()],
    }
    .send(rpc)?;
    Rejection::custom(CustomRingError::PolicyConfigNotInitialized as u32)
        .at(0)
        .assert_client(&rejection);
    assert!(
        env.run(ring.spp_ring_config(env.client.as_async()))?
            .is_none(),
        "no SPP ring config before the policy is pinned"
    );
    let pinned = configured.pin(rpc)?;
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
            mode: 0,
        },
        "custom-ring config account"
    );

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
    let deposit = |amount| RingDeposit {
        ring,
        payer: &env.sender.keypair,
        recipient: &env.sender.keypair,
        tree: env.tree,
        asset: DepositAsset::Sol,
        amount,
        cosigner: None,
    };
    let pause = |authority: Address, paused: bool| ring.set_paused(authority, paused);
    send(rpc, &env.payer, &[pause(authority, true)?])?;
    assert!(
        spp_ring_config(&env, ring)?.is_paused(),
        "paused by the ring authority"
    );
    match env.run(deposit(RING_DEPOSIT_A).send(env.client.as_async())) {
        Err(RingError::Rejected { error, .. }) => {
            Rejection::pool(ShieldedPoolError::RingPaused).assert_transaction(&error)
        }
        Err(other) => return Err(anyhow!("expected RingPaused, got {other}")),
        Ok(_) => return Err(anyhow!("the paused ring took a deposit")),
    }
    send(rpc, &env.payer, &[pause(authority, false)?])?;

    // 4. Two ring SOL deposits give the sender the ring-owned UTXOs the transfer
    //    spends. Their blindings come back from the deposit builder, so the spend
    //    is rebuilt without needing a wallet sync here.
    let mut spendable = Vec::with_capacity(2);
    for amount in [RING_DEPOSIT_A, RING_DEPOSIT_B] {
        let RingDepositReceipt { utxo, .. } =
            env.run(deposit(amount).send(env.client.as_async()))?;
        spendable.push(utxo);
    }

    // 5a. Spends and the transaction viewing key. That key is the audit's whole
    //     subject: every output ciphertext is HPKE'd under it, so recovering this
    //     one scalar opens the transaction. It is derived from the first
    //     nullifier, which is why the sender can re-derive it here.
    let sender_address = env.sender.keypair.pubkey();
    let inputs = spendable
        .into_iter()
        .map(|utxo| indexed_note(utxo, &env.sender.keypair, &env, env.tree))
        .collect::<Result<Vec<_>, _>>()?;
    let mut transfer =
        ConfidentialTransaction::new_with_ring(inputs, sender_address, ring_program)?;
    transfer.transfer_sol(
        &env.recipient.keypair.shielded_address()?,
        RING_TRANSFER_AMOUNT,
    )?;
    let prepared = {
        transfer.pad_utxos(
            zolana_transaction::instructions::transact::canonical_shape(
                transfer.inputs().len(),
                2,
            )?,
            &(env.sender.keypair.shielded_address()?),
        )?;
        transfer
    };
    let change_blinding = output_blinding(&prepared, CHANGE_SLOT)?;
    let recipient_blinding = output_blinding(&prepared, RECIPIENT_SLOT)?;

    let transfer = CustomRingTransfer::new(CustomRingTransferInput {
        ring,
        sender: &env.sender.keypair,
        nullifier_key: Some(&env.sender.keypair.nullifier_key),
        transaction: prepared,
    });
    let proven = env.run(transfer.prove(env.client.as_async()))?;
    let tx_viewing_pk = proven.tx_viewing_key.pubkey();

    let mut tampered_data = proven.data.clone();
    let tampered_byte = tampered_data
        // 6. Negative, before the real spend so the tree snapshot is meaningful: flip
        //    one ciphertext byte of the auditor message with both proofs already
        //    fixed. The program recomputes the public input from the message it is
        //    handed, so the custom-ring proof no longer verifies and the SPP CPI is never
        //    reached -- nothing is nullified and no leaf is appended.
        .messages
        .last_mut()
        .ok_or_else(|| anyhow!("transact carries no auditor message"))?
        .data
        .get_mut(AUDITOR_CIPHERTEXT_OFFSET)
        .ok_or_else(|| anyhow!("auditor message carries no ciphertext"))?;
    *tampered_byte ^= 1;

    let tree_before = fetch_account(rpc, &env.tree)?;
    let rejection = send_expecting_rejection(
        rpc,
        &env.sender.keypair,
        CustomRingTransact {
            cosigner: None,
            ring,
            payer: sender_address,
            input_trees: vec![env.tree],
            output_tree: env.tree,
            policy: proven.policy.clone(),
            owner_signers: proven.owner_signers.clone(),
            interface_transfer_accounts: Vec::new(),
            proof: proven.proof,
            transact: tampered_data,
            approval_required: false,
        }
        .instruction()?,
    )?;
    Rejection::custom(CustomRingError::ProofVerificationFailed as u32)
        .at(0)
        .assert_client(&rejection);
    assert_account_unchanged(rpc, &env.tree, &tree_before)?;

    let (blockhash, _) = rpc.get_latest_blockhash()?;
    let message = compile_message(
        &sender_address,
        &[proven.instruction()?],
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
    assert_eq!(indexed.nullifiers.len(), 2, "both inputs input_utxo");
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
    // The expected plaintexts are the test's own inputs: the amounts from its
    // constants, the blindings from the output UTXOs the sender built and
    // committed to. Nothing here is read back out of the audit result.
    assert_eq!(
        audited.outputs,
        vec![
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
                blinding: Zeroizing::new(recipient_blinding),
                ring_program_id: Some(ring_program),
                data: Data::default(),
            },
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
                blinding: Zeroizing::new(change_blinding),
                ring_program_id: Some(ring_program),
                data: Data::default(),
            },
        ],
        "auditor-decrypted outputs equal what the sender sent, recipients and blindings included"
    );
    assert!(audited.undecryptable_slots.is_empty());

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
    let discovered: Vec<(Address, u64, Option<Address>)> = env
        .recipient
        .wallet
        .unspent()
        .map(|held| {
            (
                held.utxo.asset.asset,
                held.utxo.amount,
                held.utxo.ring_program_id,
            )
        })
        .collect();
    assert_eq!(
        discovered,
        vec![(SOL_MINT, RING_TRANSFER_AMOUNT, Some(ring_program))],
        "recipient wallet discovers the custom ring output"
    );

    let received = env
        .recipient
        .wallet
        .unspent()
        .next()
        .map(|held| held.utxo.clone())
        .ok_or_else(|| anyhow!("recipient note"))?;
    let prepare_hop = || -> Result<ConfidentialTransaction> {
        let mut hop_transfer = ConfidentialTransaction::new_with_ring(
            vec![indexed_note(
                received.clone(),
                &env.recipient.keypair,
                &env,
                env.tree,
            )?],
            env.recipient.keypair.pubkey(),
            ring_program,
        )?;
        hop_transfer.transfer_sol(&env.sender.keypair.shielded_address()?, SECOND_HOP_AMOUNT)?;
        Ok({
            hop_transfer.pad_utxos(
                zolana_transaction::instructions::transact::canonical_shape(
                    hop_transfer.inputs().len(),
                    2,
                )?,
                &env.recipient.keypair.shielded_address()?,
            )?;
            hop_transfer
        })
    };

    // 10. The second hop is proven through both clients, the policy statement
    //     holds the same parity as the audit statement.
    let hop = AsyncHopParity {
        ring,
        sender: &env.recipient.keypair,
        blocking: prepare_hop()?,
        asynchronous: prepare_hop()?,
        auditor_tag,
    }
    .send(&env)?;
    let hop_outputs: Vec<(u64, Option<Address>)> = AuditLookup {
        ring_program,
        auditor: &auditor,
        signature: hop.signature,
    }
    .run(&env)?
    .outputs
    .iter()
    .map(|output| (output.amount, output.ring_program_id))
    .collect();
    assert_eq!(
        hop_outputs,
        vec![
            (SECOND_HOP_AMOUNT, Some(ring_program)),
            (RING_TRANSFER_AMOUNT - SECOND_HOP_AMOUNT, Some(ring_program)),
        ],
        "second hop outputs"
    );

    // 11. The config authority hands over, only the new key pauses the ring.
    let successor = env.funded_keypair()?;
    rpc.create_and_send_transaction(
        &[ring.set_authority(authority, successor.pubkey())],
        authority,
        &[&env.payer, &successor],
        ComputeBudgetConfig::for_instruction_count(1),
    )?;
    let rejection = ExpectRejection {
        payer: &env.payer,
        instructions: &[pause(authority, true)?],
    }
    .send(rpc)?;
    Rejection::custom(CustomRingError::UnauthorizedAuthority as u32)
        .at(0)
        .assert_client(&rejection);
    send(rpc, &successor, &[pause(successor.pubkey(), true)?])?;
    assert!(
        spp_ring_config(&env, ring)?.is_paused(),
        "paused by the successor"
    );
    send(rpc, &successor, &[pause(successor.pubkey(), false)?])?;
    assert!(
        !spp_ring_config(&env, ring)?.is_paused(),
        "reopened by the successor"
    );

    Ok(())
}

/// An audit-only ring pins no policy config, its transfer proves the lighter
/// audit statement and the auditor still recovers every output.
#[test]
fn an_audit_only_ring_audits_every_transfer() -> Result<()> {
    audit_only_lifecycle(false)
}

#[test]
fn an_anonymous_ring_hides_owners_and_preserves_recipient_and_auditor_access() -> Result<()> {
    audit_only_lifecycle(true)
}

fn audit_only_lifecycle(anonymous: bool) -> Result<()> {
    let mut env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);

    let auditor = X25519Secret::new();
    let auditor_pk = auditor.pubkey();

    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor_pk,
        tier: if anonymous {
            Tier::AnonymousAuditOnly
        } else {
            Tier::AuditOnly
        },
    }
    .send(rpc)?;

    assert!(
        env.run(ring.policy_config(env.client.as_async()))?
            .is_none(),
        "an audit-only ring pins no policy config"
    );
    let config: RingProgramConfig = fetch_state(rpc, &ring.config_pda())?;
    assert_eq!(config.has_policy, 0, "audit-only config flag");

    // An anonymous owner never signs in public, the ring payer funds its spends.
    let payer: &(dyn Signer + Sync) = match anonymous {
        true => &env.payer,
        false => &env.sender.keypair,
    };
    let deposit_source = env.funded_keypair()?;
    env.fund(deposit_source.pubkey(), RING_DEPOSIT_A + RING_DEPOSIT_B)?;
    assert_ne!(deposit_source.pubkey(), payer.pubkey());
    assert_ne!(deposit_source.pubkey(), env.sender.keypair.pubkey());
    let mut spendable = Vec::with_capacity(2);
    for amount in [RING_DEPOSIT_A, RING_DEPOSIT_B] {
        let deposit = RingDeposit {
            ring,
            payer: &deposit_source,
            recipient: &env.sender.keypair,
            tree: env.tree,
            asset: DepositAsset::Sol,
            amount,
            cosigner: None,
        };
        let RingDepositReceipt { utxo, .. } =
            env.run(deposit.send_with_fee_payer(env.client.as_async(), payer))?;
        spendable.push(utxo);
    }

    let sender_address = payer.pubkey();
    let inputs = spendable
        .into_iter()
        .map(|utxo| indexed_note(utxo, &env.sender.keypair, &env, env.tree))
        .collect::<Result<Vec<_>, _>>()?;
    let mut transfer =
        ConfidentialTransaction::new_with_ring(inputs, sender_address, ring_program)?;
    transfer.transfer_sol(
        &env.recipient.keypair.shielded_address()?,
        RING_TRANSFER_AMOUNT,
    )?;
    let prepared = {
        transfer.pad_utxos(
            zolana_transaction::instructions::transact::canonical_shape(
                transfer.inputs().len(),
                2,
            )?,
            &(env.sender.keypair.shielded_address()?),
        )?;
        transfer
    };

    let transfer = CustomRingTransfer::new(CustomRingTransferInput {
        ring,
        sender: &env.sender.keypair,
        nullifier_key: Some(&env.sender.keypair.nullifier_key),
        transaction: prepared,
    });
    let mut proven = match anonymous {
        true => {
            let transfer = transfer.with_anonymous_signer(&env.sender.keypair.signing_key);
            env.run(transfer.prove(env.client.as_async()))?
        }
        false => env.run(transfer.prove(env.client.as_async()))?,
    };
    let tx_viewing_pk = proven.tx_viewing_key.pubkey();
    if anonymous {
        use zolana_interface::instruction::instruction_data::transact::CircuitId;

        assert_ne!(payer.pubkey(), env.sender.keypair.pubkey());
        assert!(proven.owner_signers.is_empty());
        let valid_circuit = proven.data.circuit;
        let CircuitId::AnonymousRingEd25519(inputs, outputs, slots, commitment) = valid_circuit
        else {
            panic!("anonymous transfer must prove its hidden Ed25519 owner");
        };
        let mut malformed_commitment = commitment;
        malformed_commitment.commitment = [0xff; 32];
        let mut malformed_pok = commitment;
        malformed_pok.commitment_pok = [0xff; 32];
        let mut invalid_pok = commitment;
        invalid_pok.commitment_pok = commitment.commitment;

        // Keep both valid proofs fixed while corrupting the inner commitment or its selector.
        let tree_before = fetch_account(rpc, &env.tree)?;
        for (circuit, error) in [
            (
                CircuitId::AnonymousRingEd25519(inputs, outputs, slots, malformed_commitment),
                ShieldedPoolError::InvalidTransactProofEncoding as u32,
            ),
            (
                CircuitId::AnonymousRingEd25519(inputs, outputs, slots, malformed_pok),
                ShieldedPoolError::InvalidTransactProofEncoding as u32,
            ),
            (
                CircuitId::AnonymousRingEd25519(inputs, outputs, slots, invalid_pok),
                ShieldedPoolError::TransactProofVerificationFailed as u32,
            ),
            (
                CircuitId::ConfidentialRingEd25519(inputs, outputs, slots),
                CustomRingError::UnsupportedCircuit as u32,
            ),
        ] {
            proven.data.circuit = circuit;
            let rejection = send_expecting_rejection(rpc, payer, proven.instruction()?)?;
            Rejection::custom(error).at(0).assert_client(&rejection);
            assert_account_unchanged(rpc, &env.tree, &tree_before)?;
        }
        proven.data.circuit = valid_circuit;
    }
    let signature = land(&env, proven.instruction()?, payer, &[])?;

    let auditor_tag = auditor_view_tag(&auditor_pk);
    let indexed = wait_for_indexed_transaction(indexer, auditor_tag, signature);
    assert_eq!(indexed.nullifiers.len(), 2, "both inputs input_utxo");
    assert_eq!(
        indexed.tx_viewing_pk,
        Some(tx_viewing_pk),
        "the on-chain tx_viewing_pk is the sender's"
    );

    if anonymous {
        assert!(indexed
            .output_slots
            .iter()
            .all(|slot| slot.view_tag == [0; 32]));
        assert!(indexed.output_slots.iter().all(|slot| matches!(
            slot.output_data(),
            Some(zolana_interface::event::OutputDataEncoding::Encrypted(ref body))
                if body.first() == Some(&zolana_transaction::EncryptedScheme::RingAnonymous.as_byte())
        )));
    }
    let mode = match anonymous {
        true => RingMode::Anonymous,
        false => RingMode::Off,
    };
    let client = env.client.as_async();
    let audited = env
        .client
        .block_on(
            RingScan::new(ring_program, auditor.pubkey())
                .with_mode(mode)
                .audit(&auditor, client.indexer(), client.rpc(), &env.assets),
        )?
        .transactions;
    assert_eq!(audited.len(), 1, "one auditor-tagged transaction");
    let audited = audited
        .first()
        .ok_or_else(|| anyhow!("audited transaction"))?;
    assert_eq!(audited.tx_signature, signature, "audited signature");
    assert_eq!(
        audited.tx_viewing_pk, tx_viewing_pk,
        "auditor recovered the transaction viewing key"
    );
    let mut amounts: Vec<u64> = audited.outputs.iter().map(|output| output.amount).collect();
    amounts.sort_unstable();
    let mut expected = vec![RING_CHANGE, RING_TRANSFER_AMOUNT];
    expected.sort_unstable();
    assert_eq!(amounts, expected, "auditor decrypts both output amounts");

    let recipient_authority =
        KeypairWalletAuthority::new(Address::default(), &env.recipient.keypair);
    env.recipient.wallet.sync(
        &recipient_authority,
        std::slice::from_ref(&indexed),
        0,
        DEFAULT_TAG_WINDOW,
    )?;
    let received = env
        .recipient
        .wallet
        .unspent()
        .next()
        .map(|held| held.utxo.clone())
        .ok_or_else(|| anyhow!("recipient note"))?;
    if anonymous {
        assert_eq!(received.amount, RING_TRANSFER_AMOUNT);
        let disclosure = audited.anonymous.as_ref().context("anonymous disclosure")?;
        assert_eq!(
            disclosure.sender,
            env.sender.keypair.signing_pubkey().as_ed25519()?
        );
        let mut input_amounts: Vec<_> =
            disclosure.inputs.iter().map(|input| input.amount).collect();
        input_amounts.sort_unstable();
        assert_eq!(input_amounts, [RING_DEPOSIT_B, RING_DEPOSIT_A]);
        let scan = zolana_client::UtxoScan::new(&env.recipient.keypair, &env.assets)
            .with_ring_deposit_payload(ring_program, zolana_ring_client::deposit_payload)
            .fetch(indexer)?;
        assert_eq!(
            scan.spendable
                .utxos()
                .map(|note| note.utxo.amount)
                .collect::<Vec<_>>(),
            vec![RING_TRANSFER_AMOUNT]
        );
        return Ok(());
    }
    // The second hop is proven through the blocking client and a native async
    // client, the native proof lands. Preparing draws fresh output blindings,
    // so the two transactions are prepared independently.
    let prepare_hop = || -> Result<ConfidentialTransaction> {
        let mut hop_transfer = ConfidentialTransaction::new_with_ring(
            vec![indexed_note(
                received.clone(),
                &env.recipient.keypair,
                &env,
                env.tree,
            )?],
            env.recipient.keypair.pubkey(),
            ring_program,
        )?;
        hop_transfer.transfer_sol(&env.sender.keypair.shielded_address()?, SECOND_HOP_AMOUNT)?;
        Ok({
            hop_transfer.pad_utxos(
                zolana_transaction::instructions::transact::canonical_shape(
                    hop_transfer.inputs().len(),
                    2,
                )?,
                &env.recipient.keypair.shielded_address()?,
            )?;
            hop_transfer
        })
    };
    let hop = AsyncHopParity {
        ring,
        sender: &env.recipient.keypair,
        blocking: prepare_hop()?,
        asynchronous: prepare_hop()?,
        auditor_tag,
    }
    .send(&env)?;
    let hop_outputs: Vec<(u64, Option<Address>)> = AuditLookup {
        ring_program,
        auditor: &auditor,
        signature: hop.signature,
    }
    .run(&env)?
    .outputs
    .iter()
    .map(|output| (output.amount, output.ring_program_id))
    .collect();
    assert_eq!(
        hop_outputs,
        vec![
            (SECOND_HOP_AMOUNT, Some(ring_program)),
            (RING_TRANSFER_AMOUNT - SECOND_HOP_AMOUNT, Some(ring_program)),
        ],
        "second hop outputs"
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
    let auditor = X25519Secret::new();
    let auditor_tag = auditor_view_tag(&auditor.pubkey());
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::policy(&EMPTY, env.tree),
    }
    .send(rpc)?;
    let sender = &env.sender.keypair;
    let recipient = &env.recipient.keypair;
    let sender_address = sender.shielded_address()?;
    let recipient_address = recipient.shielded_address()?;
    let recipient_authority = KeypairWalletAuthority::new(Address::default(), recipient);

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
    let mut entry_transfer =
        ConfidentialTransaction::new_with_ring(vec![entry_input], sender.pubkey(), ring_program)?;
    entry_transfer.transfer_sol(&recipient_address, ENTRY_AMOUNT)?;
    let prepared = {
        entry_transfer.pad_utxos(
            zolana_transaction::instructions::transact::canonical_shape(
                entry_transfer.inputs().len(),
                2,
            )?,
            &(sender_address),
        )?;
        entry_transfer
    };
    let sender_change = Note {
        owner: sender,
        asset: SOL_MINT,
        amount: ENTRY_CHANGE,
        blinding: output_blinding(&prepared, CHANGE_SLOT)?,
        ring_program_id: Some(ring_program),
    };
    let recipient_ring_note = Note {
        owner: recipient,
        asset: SOL_MINT,
        amount: ENTRY_AMOUNT,
        blinding: output_blinding(&prepared, RECIPIENT_SLOT)?,
        ring_program_id: Some(ring_program),
    };
    let entry = RingTransfer {
        ring,
        sender,
        prepared,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;
    assert_eq!(
        AuditLookup {
            ring_program,
            auditor: &auditor,
            signature: entry.signature,
        }
        .run(&env)?
        .outputs,
        vec![
            recipient_ring_note.audited(RECIPIENT_SLOT)?,
            sender_change.audited(CHANGE_SLOT)?
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
    let mut exit_transfer = ConfidentialTransaction::new_with_ring(
        vec![sender_change.input_utxo(&env)?],
        sender.pubkey(),
        ring_program,
    )?;
    exit_transfer.transfer_with_ring(
        &recipient_address,
        env.assets.mint(&SOL_MINT)?,
        EXIT_AMOUNT,
        None,
    )?;
    let prepared = {
        exit_transfer.pad_utxos(
            zolana_transaction::instructions::transact::canonical_shape(
                exit_transfer.inputs().len(),
                2,
            )?,
            &(sender_address),
        )?;
        exit_transfer
    };
    let exit_change = Note {
        owner: sender,
        asset: SOL_MINT,
        amount: EXIT_CHANGE,
        blinding: output_blinding(&prepared, CHANGE_SLOT)?,
        ring_program_id: Some(ring_program),
    };
    let recipient_default_note = Note {
        owner: recipient,
        asset: SOL_MINT,
        amount: EXIT_AMOUNT,
        blinding: output_blinding(&prepared, RECIPIENT_SLOT)?,
        ring_program_id: None,
    };
    let exit = RingTransfer {
        ring,
        sender,
        prepared,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;
    assert_eq!(
        AuditLookup {
            ring_program,
            auditor: &auditor,
            signature: exit.signature,
        }
        .run(&env)?
        .outputs,
        vec![
            recipient_default_note.audited(RECIPIENT_SLOT)?,
            exit_change.audited(CHANGE_SLOT)?
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
        let mut transfer = CustomRingTransfer::new(CustomRingTransferInput {
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
        zolana_transaction::Mint::SOL,
        REFUSED_AMOUNT,
        Some(FOREIGN_RING),
    )?;
    foreign_output.pad_utxos(
        zolana_transaction::instructions::transact::Shape::IN1_OUT2,
        &sender_address,
    )?;
    let prepared = foreign_output;
    expect_foreign_ring(prove(prepared), FOREIGN_RING)?;

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
    expect_foreign_ring(
        prove({
            foreign_input.pad_utxos(
                zolana_transaction::instructions::transact::canonical_shape(
                    foreign_input.inputs().len(),
                    2,
                )?,
                &(sender_address),
            )?;
            foreign_input
        }),
        FOREIGN_RING,
    )?;

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
    let auditor = X25519Secret::new();
    let auditor_tag = auditor_view_tag(&auditor.pubkey());
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::policy(&EMPTY, env.tree),
    }
    .send(rpc)?;
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
    let mut entry_transfer =
        ConfidentialTransaction::new_with_ring(vec![entry_input], sender.pubkey(), ring_program)?;
    entry_transfer.transfer(&recipient_address, usdc, USDC_ENTRY_AMOUNT)?;
    let prepared = {
        entry_transfer.pad_utxos(
            zolana_transaction::instructions::transact::canonical_shape(
                entry_transfer.inputs().len(),
                2,
            )?,
            &(sender_address),
        )?;
        entry_transfer
    };
    let entry_change = Note {
        owner: sender,
        asset: usdc,
        amount: USDC_ENTRY_CHANGE,
        blinding: output_blinding(&prepared, CHANGE_SLOT)?,
        ring_program_id: Some(ring_program),
    };
    let recipient_ring_note = Note {
        owner: recipient,
        asset: usdc,
        amount: USDC_ENTRY_AMOUNT,
        blinding: output_blinding(&prepared, RECIPIENT_SLOT)?,
        ring_program_id: Some(ring_program),
    };
    let entry = RingTransfer {
        ring,
        sender,
        prepared,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;
    assert_eq!(
        AuditLookup {
            ring_program,
            auditor: &auditor,
            signature: entry.signature,
        }
        .run(&env)?
        .outputs,
        vec![
            recipient_ring_note.audited(RECIPIENT_SLOT)?,
            entry_change.audited(CHANGE_SLOT)?
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
    let mut hop_transfer = ConfidentialTransaction::new_with_ring(
        vec![entry_change.input_utxo(&env)?],
        sender.pubkey(),
        ring_program,
    )?;
    hop_transfer.transfer(&recipient_address, usdc, USDC_HOP_AMOUNT)?;
    let prepared = {
        hop_transfer.pad_utxos(
            zolana_transaction::instructions::transact::canonical_shape(
                hop_transfer.inputs().len(),
                2,
            )?,
            &(sender_address),
        )?;
        hop_transfer
    };
    let hop_change = Note {
        owner: sender,
        asset: usdc,
        amount: USDC_HOP_CHANGE,
        blinding: output_blinding(&prepared, CHANGE_SLOT)?,
        ring_program_id: Some(ring_program),
    };
    let recipient_hop_note = Note {
        owner: recipient,
        asset: usdc,
        amount: USDC_HOP_AMOUNT,
        blinding: output_blinding(&prepared, RECIPIENT_SLOT)?,
        ring_program_id: Some(ring_program),
    };
    let hop = RingTransfer {
        ring,
        sender,
        prepared,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;
    assert_eq!(
        AuditLookup {
            ring_program,
            auditor: &auditor,
            signature: hop.signature,
        }
        .run(&env)?
        .outputs,
        vec![
            recipient_hop_note.audited(RECIPIENT_SLOT)?,
            hop_change.audited(CHANGE_SLOT)?
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
        recipient: sender,
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
    let mut exit_transfer = ConfidentialTransaction::new_with_ring(
        vec![hop_change.input_utxo(&env)?, receipt_input],
        sender.pubkey(),
        ring_program,
    )?;
    exit_transfer.transfer_with_ring(
        &recipient_address,
        env.assets.mint(&usdc)?,
        USDC_EXIT_AMOUNT,
        None,
    )?;
    let prepared = {
        exit_transfer.pad_utxos(
            zolana_transaction::instructions::transact::canonical_shape(
                exit_transfer.inputs().len(),
                2,
            )?,
            &(sender_address),
        )?;
        exit_transfer
    };
    let exit_change = Note {
        owner: sender,
        asset: usdc,
        amount: USDC_EXIT_CHANGE,
        blinding: output_blinding(&prepared, CHANGE_SLOT)?,
        ring_program_id: Some(ring_program),
    };
    let recipient_default_note = Note {
        owner: recipient,
        asset: usdc,
        amount: USDC_EXIT_AMOUNT,
        blinding: output_blinding(&prepared, RECIPIENT_SLOT)?,
        ring_program_id: None,
    };
    let exit = RingTransfer {
        ring,
        sender,
        prepared,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;
    assert_eq!(
        AuditLookup {
            ring_program,
            auditor: &auditor,
            signature: exit.signature,
        }
        .run(&env)?
        .outputs,
        vec![
            recipient_default_note.audited(RECIPIENT_SLOT)?,
            exit_change.audited(CHANGE_SLOT)?
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

    // 6. A ring transact settles a public USDC withdrawal beside a ring send.
    let recipient_usdc = create_token_account(rpc, &env.payer, &usdc, &recipient.pubkey())?;
    let cosigner = Keypair::new();
    send(
        rpc,
        &env.payer,
        &[ring.set_cosigner(
            env.payer.pubkey(),
            env.payer.pubkey(),
            cosigner.pubkey(),
            CoSignScope::WITHDRAWALS,
            &[CoSignThreshold {
                mint: usdc,
                amount: USDC_WITHDRAW_AMOUNT - 1,
            }],
        )?],
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
            zolana_transaction::instructions::transact::canonical_shape(
                transfer.inputs().len(),
                2,
            )?,
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
    let rejection = send_expecting_rejection(rpc, sender, unsigned.instruction()?)?;
    Rejection::custom(CustomRingError::MissingCoSigner as u32)
        .at(0)
        .assert_client(&rejection);
    let prepared = withdraw()?;
    let final_change = Note {
        owner: sender,
        asset: usdc,
        amount: USDC_FINAL_CHANGE,
        blinding: output_blinding(&prepared, CHANGE_SLOT)?,
        ring_program_id: Some(ring_program),
    };
    let recipient_final_note = Note {
        owner: recipient,
        asset: usdc,
        amount: USDC_FINAL_SEND,
        blinding: output_blinding(&prepared, RECIPIENT_SLOT)?,
        ring_program_id: Some(ring_program),
    };
    let recipient_final_blinding = recipient_final_note.blinding;
    let withdrawal = RingTransfer {
        ring,
        sender,
        prepared,
        interface_transfer_accounts: vec![settlement],
        auditor_tag,
        cosigner: Some(&cosigner),
    }
    .send(&env)?;
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
        AuditLookup {
            ring_program,
            auditor: &auditor,
            signature: withdrawal.signature,
        }
        .run(&env)?
        .outputs,
        vec![
            recipient_final_note.audited(RECIPIENT_SLOT)?,
            final_change.audited(CHANGE_SLOT)?
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

    // The delegate re-owns the recipient's final note to the sender over the
    // authority rail, refused until governance enables the rail.
    let delegate = Keypair::new();
    EscrowedDelegate {
        ring,
        delegate: delegate.pubkey(),
        members: &[sender],
    }
    .set(&env)?;
    let moved = || -> Result<ProvenDelegateTransfer> {
        let transfer = DelegateTransfer::new(DelegateTransferInput {
            ring,
            delegate: delegate.pubkey(),
            payer: env.payer.pubkey(),
            source_nullifier_key: &recipient.nullifier_key,
            inputs: vec![Note {
                owner: recipient,
                asset: usdc,
                amount: USDC_FINAL_SEND,
                blinding: recipient_final_blinding,
                ring_program_id: Some(ring_program),
            }
            .input_utxo(&env)?
            .into()],
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
    let moved_note = Note {
        owner: sender,
        asset: usdc,
        amount: USDC_FINAL_SEND,
        blinding: proven.outputs[0].blinding,
        ring_program_id: Some(ring_program),
    };
    let signature = land(&env, proven.instruction()?, &env.payer, &[&delegate])?;
    let indexed = wait_for_indexed_transaction(indexer, auditor_tag, signature);
    assert_eq!(
        AuditLookup {
            ring_program,
            auditor: &auditor,
            signature,
        }
        .run(&env)?
        .outputs,
        vec![moved_note.audited(0)?],
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
    let auditor = X25519Secret::new();
    let auditor_pk = auditor.pubkey();
    let auditor_tag = auditor_view_tag(&auditor_pk);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor_pk,
        tier: Tier::policy(&OUTFLOW_LIMIT, env.tree),
    }
    .send(rpc)?;
    let sender = &env.sender.keypair;
    let sender_address = sender.pubkey();
    let recipient = env.recipient.keypair.shielded_address()?;

    let mut notes = Vec::with_capacity(DEPOSITS.len());
    for amount in DEPOSITS {
        let deposit = RingDeposit {
            ring,
            payer: sender,
            recipient: sender,
            tree: env.tree,
            asset: DepositAsset::Sol,
            amount,
            cosigner: None,
        };
        let RingDepositReceipt { utxo, .. } = env.run(deposit.send(env.client.as_async()))?;
        notes.push(utxo);
    }
    let tree_id = env.tree_id(env.tree)?;
    let prepare = |input: Utxo, amount: u64| -> Result<ConfidentialTransaction> {
        let input = indexed_note(input, sender, &env, env.tree)?;
        let mut transfer =
            ConfidentialTransaction::new_with_ring(vec![input], sender_address, ring_program)?
                .with_output_tree_id(tree_id)?;
        transfer.transfer_sol(&recipient, amount)?;
        transfer.pad_utxos(
            canonical_shape(transfer.inputs().len(), 2)?,
            &sender.shielded_address()?,
        )?;
        Ok(transfer)
    };
    let prove = |transaction: ConfidentialTransaction, cosigner: Option<Address>| {
        let mut transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring,
            sender,
            nullifier_key: Some(&sender.nullifier_key),
            transaction,
        });
        if let Some(cosigner) = cosigner {
            transfer = transfer.with_cosigner(cosigner);
        }
        env.run(transfer.prove(env.client.as_async()))
    };

    // A send below the threshold lands with no approval and no record.
    let proven = prove(prepare(notes[0].clone(), UNDER_THRESHOLD)?, None)?;
    assert!(
        !proven.approval_required,
        "an under-threshold send asks nobody"
    );
    let signature = land(&env, proven.instruction()?, sender, &[])?;
    wait_for_indexed_transaction(indexer, auditor_tag, signature);

    // Above the threshold the chain refuses the send until the co-signer signs.
    let cosigner = Keypair::new();
    send(
        rpc,
        &env.payer,
        &[ring.set_cosigner(
            env.payer.pubkey(),
            env.payer.pubkey(),
            cosigner.pubkey(),
            CoSignScope::WITHDRAWALS,
            &[],
        )?],
    )?;
    let proven = prove(
        prepare(notes[1].clone(), OVER_THRESHOLD)?,
        Some(cosigner.pubkey()),
    )?;
    assert!(
        proven.approval_required,
        "an over-threshold send asks the co-signer"
    );
    let mut unsigned = proven.instruction()?;
    for account in &mut unsigned.accounts {
        if account.pubkey == cosigner.pubkey() {
            account.is_signer = false;
        }
    }
    let rejection = send_expecting_rejection(rpc, sender, unsigned)?;
    Rejection::custom(CustomRingError::MissingCoSigner as u32)
        .at(0)
        .assert_client(&rejection);
    let signed = prove(
        prepare(notes[1].clone(), OVER_THRESHOLD)?,
        Some(cosigner.pubkey()),
    )?;
    let signature = land(&env, signed.instruction()?, sender, &[&cosigner])?;
    wait_for_indexed_transaction(indexer, auditor_tag, signature);

    // A single send above the cap is refused before any proof.
    match prove(
        prepare(notes[2].clone(), OVER_CAP)?,
        Some(cosigner.pubkey()),
    ) {
        Err(RingError::OutflowCapExceeded { cap, outflow, .. }) => {
            assert_eq!(cap, LIMIT_CAP);
            assert_eq!(outflow, OVER_CAP);
        }
        Err(other) => return Err(anyhow!("expected the cap refusal, got {other}")),
        Ok(_) => return Err(anyhow!("the capped send was proven")),
    }
    Ok(())
}

/// Registers every member before the delegate turns key escrow on.
struct EscrowedDelegate<'a> {
    ring: CustomRing,
    delegate: Address,
    members: &'a [&'a ShieldedKeypair],
}

impl EscrowedDelegate<'_> {
    fn set(self, env: &TestEnv) -> Result<()> {
        let rpc = env.client.rpc();
        let authority = env.payer.pubkey();
        send(
            rpc,
            &env.payer,
            &[self.ring.create_key_registry_root(authority, authority)],
        )?;
        for member in self.members {
            let registration = RegisterKey {
                ring: self.ring,
                member,
            };
            let registration = env.run(registration.prove(env.client.as_async()))?;
            send(rpc, *member, &[registration.instruction()?])?;
        }
        send(
            rpc,
            &env.payer,
            &[self.ring.set_delegate(authority, authority, self.delegate)],
        )?;
        Ok(())
    }
}

#[test]
fn the_key_escrow_lifecycle_ends_in_a_delegate_move() -> Result<()> {
    const SEND: u64 = DEFAULT_DEPOSIT / 4;

    let mut env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Secret::new();
    let auditor_pk = auditor.pubkey();
    let auditor_tag = auditor_view_tag(&auditor_pk);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor_pk,
        tier: Tier::policy(&EMPTY, env.tree),
    }
    .send(rpc)?;
    send(
        rpc,
        &env.payer,
        &[
            ring.create_key_registry_root(env.payer.pubkey(), env.payer.pubkey()),
            ring.set_deposit_audit(env.payer.pubkey(), env.payer.pubkey(), true)?,
        ],
    )?;
    let member = &env.sender.keypair;
    let member_address = member.shielded_address()?;

    let deposit = RingDeposit {
        ring,
        payer: member,
        recipient: member,
        tree: env.tree,
        asset: DepositAsset::Sol,
        amount: DEFAULT_DEPOSIT,
        cosigner: None,
    };
    let RingDepositReceipt { signature, utxo } = env.run(deposit.send(env.client.as_async()))?;
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
    RingTransfer {
        ring,
        sender: member,
        prepared: transfer,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;

    let registration = env.run(RegisterKey { ring, member }.prove(env.client.as_async()))?;
    send(rpc, member, &[registration.instruction()?])?;
    let root = env
        .run(ring.key_registry_root(env.client.as_async()))?
        .context("key registry")?;
    assert_eq!(root.next_index, 2, "one registered member plus sentinel");
    let member_tag = Member::owner_tag(member.pubkey().as_array())?;
    let sealed = wait_for("the registered key", || {
        let read = ReadSealedKey {
            ring,
            member: member_tag,
            root,
        };
        match env.run(read.read(env.client.as_async())) {
            Ok(entry) => Ok(Probe::Ready(entry)),
            Err(error @ RingError::Client(_)) => Ok(Probe::Retry(error.into())),
            Err(error) => Err(error.into()),
        }
    })?;
    let nullifier_key = sealed.open(&auditor)?;
    assert_eq!(nullifier_key.pubkey()?, member_address.nullifier_pubkey);

    let delegate = Keypair::new();
    send(
        rpc,
        &env.payer,
        &[ring.set_delegate(env.payer.pubkey(), env.payer.pubkey(), delegate.pubkey())],
    )?;
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

    // 2. An owner without an enrolled key is refused before any prover round.
    let unreachable = env.client_with(
        ProverClient::new("http://127.0.0.1:1".to_owned())
            .with_proof_data_source(ProofDataSource::Client),
    );
    let prover = env.client_with(ProverClient::local());
    let refused = |to: &ShieldedAddress, client: &ZolanaClient<SolanaRpc>| -> Result<Member> {
        let mut transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring,
            sender: member,
            nullifier_key: Some(&member.nullifier_key),
            transaction: pay(to)?,
        });
        match client.block_on(transfer.prove(client.as_async())) {
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
    // The prover's registry lookup refuses the same owner when it fetches proof data.
    for prover in [&unreachable, &prover] {
        assert_eq!(refused(&unregistered, prover)?, unregistered_owner);
    }

    // 3. The zero key is refused on every rail.
    let zero_key = ShieldedAddress {
        nullifier_pubkey: ZERO_NULLIFIER_PK,
        ..unregistered
    };
    assert_eq!(refused(&zero_key, &unreachable)?, unregistered_owner);
    // An enrolled owner whose output names another nullifier key is refused by the prover too.
    let mismatched = ShieldedAddress {
        nullifier_pubkey: ZERO_NULLIFIER_PK,
        ..member_address
    };
    assert_eq!(
        refused(&mismatched, &prover)?,
        Member::from_bytes(member_address.signing_pubkey.owner_proof_input_hash()?)?
    );

    // 4. A plain deposit never builds, the audited one binds the registry root.
    let root = env
        .run(ring.key_registry_root(env.client.as_async()))?
        .context("key registry")?;
    let plain = RingAssetDeposit {
        asset: DepositAsset::Sol,
        view_tag: [0; 32],
        owner_utxo_hash: [1; 32],
        amount: 1,
        ring_data_hash: [0; 32],
        encrypted: EncryptedRingDepositData {
            tx_viewing_pk: [2; 33],
            salt: [0; 16],
            ciphertext: vec![3],
        },
    };
    assert!(matches!(
        Deposit {
            ring,
            tree: env.tree,
            depositor: member.pubkey(),
            deposits: vec![plain],
            proof: None,
            escrow: EscrowBinding::Registry {
                root_index: root.history_index,
                root: root.root,
            },
            cosigner: None,
        }
        .instruction(),
        Err(RingError::AuditRequired)
    ));
    let deposit = RingDeposit {
        ring,
        payer: member,
        recipient: member,
        tree: env.tree,
        asset: DepositAsset::Sol,
        amount: DEFAULT_DEPOSIT,
        cosigner: None,
    };
    let RingDepositReceipt { signature, .. } = env.run(deposit.send(env.client.as_async()))?;
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
        source_nullifier_key: &nullifier_key,
        inputs: vec![SppProofInputUtxo::from(moved)],
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
    // The single note pads to the 2x2 ring-authority shape with a random dummy.
    assert_eq!(
        indexed.nullifiers.len(),
        2,
        "the delegate spent the note and a dummy"
    );
    assert_eq!(
        indexed.nullifiers.first(),
        Some(&moved_nullifier),
        "the delegate spent the note"
    );
    let member_authority = KeypairWalletAuthority::new(Address::default(), member);
    env.sender.wallet.sync(
        &member_authority,
        std::slice::from_ref(&indexed),
        0,
        DEFAULT_TAG_WINDOW,
    )?;
    assert_eq!(
        sorted_unspent_notes(&env.sender.wallet),
        vec![(SOL_MINT, SEND, Some(ring_program))],
        "the delegate moved the registered member's note"
    );
    Ok(())
}

/// A note stranded in an old tree spends into the active tree while the ring's
/// address tree stays fixed.
#[test]
fn an_old_tree_note_migrates_into_the_active_tree() -> Result<()> {
    let mut env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Secret::new();
    let auditor_tag = auditor_view_tag(&auditor.pubkey());

    // Spend from a separate input tree, the ring's address tree stays env.tree.
    let old_tree = env.create_registered_tree()?;
    assert_ne!(old_tree, env.tree);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::policy(&EMPTY, env.tree),
    }
    .send(rpc)?;

    let sender = &env.sender.keypair;
    let recipient = &env.recipient.keypair;
    let deposit = RingDeposit {
        ring,
        payer: sender,
        recipient: sender,
        tree: old_tree,
        asset: DepositAsset::Sol,
        amount: DEFAULT_DEPOSIT,
        cosigner: None,
    };
    let RingDepositReceipt { utxo, .. } = env.run(deposit.send(env.client.as_async()))?;
    wait_for_merkle_proof(
        indexer,
        old_tree,
        indexed_note(utxo.clone(), sender, &env, old_tree)?.utxo_hash,
    );

    let mut transfer = ConfidentialTransaction::new_with_ring(
        vec![indexed_note(utxo, sender, &env, old_tree)?],
        sender.pubkey(),
        ring_program,
    )?
    .with_output_tree_id(env.tree_id(env.tree)?)?;
    transfer.transfer_sol(&recipient.shielded_address()?, ENTRY_AMOUNT)?;
    let prepared = {
        transfer.pad_utxos(
            zolana_transaction::instructions::transact::canonical_shape(
                transfer.inputs().len(),
                2,
            )?,
            &(sender.shielded_address()?),
        )?;
        transfer
    };
    let transfer = CustomRingTransfer::new(CustomRingTransferInput {
        ring,
        sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction: prepared,
    });
    let proven = env.run(transfer.prove(env.client.as_async()))?;
    let signature = land(&env, proven.instruction()?, sender, &[])?;
    let migrated = wait_for_indexed_transaction(indexer, auditor_tag, signature);
    assert_eq!(migrated.nullifiers.len(), 1, "the old-tree note is spent");

    let recipient_authority = KeypairWalletAuthority::new(Address::default(), recipient);
    env.recipient.wallet.sync(
        &recipient_authority,
        std::slice::from_ref(&migrated),
        0,
        DEFAULT_TAG_WINDOW,
    )?;
    let received = env
        .recipient
        .wallet
        .unspent()
        .next()
        .map(|held| held.utxo.clone())
        .ok_or_else(|| anyhow!("migrated recipient note"))?;
    assert_eq!(
        received.amount, ENTRY_AMOUNT,
        "recipient holds the migrated amount in the active tree"
    );

    let mut hop = ConfidentialTransaction::new_with_ring(
        vec![indexed_note(received, recipient, &env, env.tree)?],
        recipient.pubkey(),
        ring_program,
    )?;
    hop.transfer_sol(&sender.shielded_address()?, SECOND_HOP_AMOUNT)?;
    let hop_prepared = {
        hop.pad_utxos(
            zolana_transaction::instructions::transact::canonical_shape(hop.inputs().len(), 2)?,
            &(recipient.shielded_address()?),
        )?;
        hop
    };
    let hop = RingTransfer {
        ring,
        sender: recipient,
        prepared: hop_prepared,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;
    let hop_outputs: Vec<u64> = AuditLookup {
        ring_program,
        auditor: &auditor,
        signature: hop.signature,
    }
    .run(&env)?
    .outputs
    .iter()
    .map(|output| output.amount)
    .collect();
    assert_eq!(
        hop_outputs,
        vec![SECOND_HOP_AMOUNT, ENTRY_AMOUNT - SECOND_HOP_AMOUNT],
        "the active-tree note input_utxos in turn"
    );
    Ok(())
}

/// Money moves between two trees apart from the address tree.
#[test]
fn a_transfer_outputs_apart_from_the_address_tree() -> Result<()> {
    let env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Secret::new();
    let auditor_tag = auditor_view_tag(&auditor.pubkey());

    let input_tree = env.create_registered_tree()?;
    let output_tree = env.create_registered_tree()?;
    assert_ne!(input_tree, env.tree);
    assert_ne!(output_tree, env.tree);
    assert_ne!(input_tree, output_tree);
    let input_tree_id = env.tree_id(input_tree)?;
    let output_tree_id = env.tree_id(output_tree)?;
    assert_ne!(input_tree_id, output_tree_id);

    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::policy(&EMPTY, env.tree),
    }
    .send(rpc)?;

    let sender = &env.sender.keypair;
    let recipient = &env.recipient.keypair;
    let deposit = RingDeposit {
        ring,
        payer: sender,
        recipient: sender,
        tree: input_tree,
        asset: DepositAsset::Sol,
        amount: DEFAULT_DEPOSIT,
        cosigner: None,
    };
    let RingDepositReceipt { utxo, .. } = env.run(deposit.send(env.client.as_async()))?;
    wait_for_merkle_proof(
        indexer,
        input_tree,
        indexed_note(utxo.clone(), sender, &env, input_tree)?.utxo_hash,
    );

    let mut transfer = ConfidentialTransaction::new_with_ring(
        vec![indexed_note(utxo, sender, &env, input_tree)?],
        sender.pubkey(),
        ring_program,
    )?
    .with_output_tree_id(output_tree_id)?;
    transfer.transfer_sol(&recipient.shielded_address()?, ENTRY_AMOUNT)?;
    let prepared = {
        transfer.pad_utxos(
            zolana_transaction::instructions::transact::canonical_shape(
                transfer.inputs().len(),
                2,
            )?,
            &(sender.shielded_address()?),
        )?;
        transfer
    };
    let mut recipient_output = prepared
        .outputs()
        .get(RECIPIENT_SLOT as usize)
        .ok_or_else(|| anyhow!("recipient output"))?
        .clone();
    assert_eq!(recipient_output.amount, ENTRY_AMOUNT);
    recipient_output.blinding = output_blinding(&prepared, RECIPIENT_SLOT)?;
    let recipient_hash = recipient_output.hash(output_tree_id)?;
    let transfer = CustomRingTransfer::new(CustomRingTransferInput {
        ring,
        sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction: prepared,
    });
    let proven = env.run(transfer.prove(env.client.as_async()))?;
    let signature = land(&env, proven.instruction()?, sender, &[])?;
    let indexed = wait_for_indexed_transaction(indexer, auditor_tag, signature);
    assert_eq!(indexed.nullifiers.len(), 1, "the input note is spent");

    // The wallet syncs under tree id 0 only, so the leaf is checked from the slot.
    let recipient_slot = indexed
        .output_slots
        .iter()
        .find(|slot| slot.output_context.hash == recipient_hash)
        .ok_or_else(|| anyhow!("recipient output hashed under the output tree id"))?;
    assert_eq!(
        recipient_slot.output_context.tree_id, output_tree_id,
        "recipient output tree"
    );
    wait_for_merkle_proof(indexer, output_tree, recipient_hash);

    Ok(())
}

fn lamports<R: Rpc>(rpc: &R, address: Address) -> Result<u64> {
    Ok(rpc
        .get_account(address)?
        .ok_or_else(|| anyhow!("account {address} not found"))?
        .lamports)
}

fn spp_ring_config(env: &TestEnv, ring: CustomRing) -> Result<RingConfig> {
    env.run(ring.spp_ring_config(env.client.as_async()))?
        .ok_or_else(|| anyhow!("SPP ring config of {}", ring.program_id()))
}

/// Proves, signs and settles one ring operation, a failed one is an error.
fn land<'a>(
    env: &TestEnv,
    operation: impl Into<RingOperation<'a>>,
    payer: &(dyn Signer + Sync),
    signers: &[&(dyn Signer + Sync)],
) -> Result<Signature> {
    let mut submission = RingSubmission::new(operation);
    let settled = env.run(submission.send_until_settled(env.client.as_async(), payer, signers))?;
    match settled {
        SettledSubmission::Confirmed { signature, .. } => Ok(signature),
        SettledSubmission::Failed { signature, error } => {
            Err(RingError::Rejected { signature, error }.into())
        }
    }
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

    fn audited(self, slot_index: u32) -> Result<AuditedOutput> {
        Ok(AuditedOutput {
            slot_index,
            recipient_viewing_pk: self.owner.viewing_pubkey(),
            owner_tag: self.owner.signing_pubkey().confidential_view_tag()?,
            asset: self.asset,
            amount: self.amount,
            blinding: Zeroizing::new(self.blinding),
            ring_program_id: self.ring_program_id,
            data: Data::default(),
        })
    }
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

struct RingTransfer<'a> {
    ring: CustomRing,
    sender: &'a ShieldedKeypair,
    prepared: ConfidentialTransaction,
    interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    auditor_tag: [u8; 32],
    cosigner: Option<&'a Keypair>,
}

struct RingTransferReceipt {
    signature: Signature,
    indexed: ShieldedTransaction,
}

impl RingTransfer<'_> {
    fn send(self, env: &TestEnv) -> Result<RingTransferReceipt> {
        let mut transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring: self.ring,
            sender: self.sender,
            nullifier_key: Some(&self.sender.nullifier_key),
            transaction: self.prepared,
        })
        .with_interface_transfer_accounts(self.interface_transfer_accounts);
        if let Some(cosigner) = self.cosigner {
            transfer = transfer.with_cosigner(cosigner.pubkey());
        }
        let signers: Vec<&(dyn Signer + Sync)> = self
            .cosigner
            .into_iter()
            .map(|keypair| keypair as &(dyn Signer + Sync))
            .collect();
        let signature = land(env, transfer, self.sender, &signers)?;
        let indexed =
            wait_for_indexed_transaction(env.client.indexer(), self.auditor_tag, signature);
        Ok(RingTransferReceipt { signature, indexed })
    }
}

/// One ring transfer proven through the blocking client and a native async client,
/// the native proof lands. Fields the spent note fixes must agree, fresh draws differ.
struct AsyncHopParity<'a> {
    ring: CustomRing,
    sender: &'a ShieldedKeypair,
    blocking: ConfidentialTransaction,
    asynchronous: ConfidentialTransaction,
    auditor_tag: [u8; 32],
}

impl AsyncHopParity<'_> {
    fn send(self, env: &TestEnv) -> Result<RingTransferReceipt> {
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
        let mut transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring: self.ring,
            sender: self.sender,
            nullifier_key: Some(&self.sender.nullifier_key),
            transaction: self.asynchronous,
        });
        let proven = runtime.block_on(transfer.prove(&native))?;

        assert_eq!(
            proven.tx_viewing_key.pubkey(),
            blocking.tx_viewing_key.pubkey(),
            "async and blocking derive the same transaction viewing key"
        );
        assert_eq!(
            proven.data.tx_viewing_pk, blocking.data.tx_viewing_pk,
            "async and blocking publish the same tx_viewing_pk"
        );
        assert_eq!(
            proven.data.circuit, blocking.data.circuit,
            "async and blocking select the same circuit"
        );
        assert_eq!(
            nullifier_hashes(&proven),
            nullifier_hashes(&blocking),
            "async and blocking nullify the same note"
        );
        assert_eq!(
            proven.owner_signers, blocking.owner_signers,
            "async and blocking require the same owner signatures"
        );
        assert_eq!(
            proven.data.expiry_unix_ts, blocking.data.expiry_unix_ts,
            "async and blocking carry the same expiry"
        );
        assert_ne!(
            proven.data.private_tx_hash, blocking.data.private_tx_hash,
            "each proof draws its own blindings, salt and auditor ciphertext"
        );

        let signature = land(env, proven.instruction()?, self.sender, &[])?;
        let indexed =
            wait_for_indexed_transaction(env.client.indexer(), self.auditor_tag, signature);
        Ok(RingTransferReceipt { signature, indexed })
    }
}

fn nullifier_hashes(proven: &ProvenTransfer) -> Vec<[u8; 32]> {
    proven
        .data
        .inputs
        .iter()
        .map(|input| input.nullifier_hash)
        .collect()
}

struct AuditLookup<'a> {
    ring_program: Address,
    auditor: &'a X25519Secret,
    signature: Signature,
}

impl AuditLookup<'_> {
    fn run(self, env: &TestEnv) -> Result<AuditedTransaction> {
        let client = env.client.as_async();
        env.client
            .block_on(
                RingScan::new(self.ring_program, self.auditor.pubkey()).audit(
                    self.auditor,
                    client.indexer(),
                    client.rpc(),
                    &env.assets,
                ),
            )?
            .transactions
            .into_iter()
            .find(|tx| tx.tx_signature == self.signature)
            .ok_or_else(|| anyhow!("transaction {} audited", self.signature))
    }
}

fn output_blinding(prepared: &ConfidentialTransaction, slot: u32) -> Result<[u8; 32]> {
    prepared
        .outputs()
        .get(usize::try_from(slot)?)
        .ok_or_else(|| anyhow!("output slot {slot}"))?;
    let seed = zolana_transaction::derive_output_blinding_seed(
        prepared.first_nullifier(),
        prepared.blinding_seed(),
    )?;
    Ok(zolana_transaction::utxo::derive_transact_output_blinding(
        prepared.first_nullifier(),
        &seed,
        slot,
    )?)
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

fn expect_foreign_ring(result: Result<ProvenTransfer, RingError>, ring: Address) -> Result<()> {
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
