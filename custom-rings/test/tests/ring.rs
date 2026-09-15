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
//! Its second hop, like the capstone's, is proven over BOTH transports and
//! lands the async one, so `CustomRingTransfer::prove_async` is held to parity
//! with `prove` on both statements (see [`AsyncHopParity`]).
//!
//! [`ring_value_leaves_and_enters_through_audited_transfers`] crosses the ring
//! boundary in both directions under the auditor and pins that a note of
//! another ring is refused before proving.

use std::{
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use custom_ring_cli::transact::{self, Probe};
use custom_ring_interface::{RingProgramConfig, CONFIG_PDA_SEED, RING_PROGRAM_CONFIG};
use custom_ring_program::CustomRingError;
use custom_ring_sdk::{
    auditor_view_tag, find_counters_message, AsyncTransferProofEnvironment, ClearSpendWindow,
    CoSignScope, CoSignThreshold, CreateConfig, CreateKeyRegistryRoot, CustomRing,
    CustomRingTransact, CustomRingTransfer, CustomRingTransferInput, DelegateOutput,
    DelegateTransfer, DelegateTransferInput, DepositError, EntryProofError, KeyRegistrationError,
    LiveSpendRecord, ProvenDelegateTransfer, ProvenTransfer, ReadEnvironment, ReadSealedKey,
    ReadSpendRecord, RegisterKey, RegisterSpend, RingDeposit, RingDepositReceipt, SealedCounters,
    SetAuthority, SetCoSigner, SetDelegate, SetPaused, SetSpendWindow, TransactSend, TransferError,
    TransferProofEnvironment,
};
use custom_ring_test_validator::{
    cli::{merged, RingProject, RingToml},
    policy::{EMPTY, TRANSFER_CAP, VELOCITY, VELOCITY_CAP, VELOCITY_COSIGN_ABOVE},
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
    AsyncProverClient, AsyncSolanaRpc, AsyncZolanaIndexer, ComputeBudgetConfig, ProverClient, Rpc,
    ShieldedTransaction, SolanaRpc, ZolanaIndexer,
};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        AssetDeposit, Deposit as SppDeposit, DepositAsset, DepositSplAccounts,
        TransactInterfaceTransferAccounts, TransactSplWithdrawalAccounts, UpdateRingConfig,
    },
    pda,
    state::{
        discriminator::{PROTOCOL_CONFIG, RING_CONFIG, TREE_ACCOUNT_DISCRIMINATOR},
        tree_account_size, ProtocolConfig, RingConfig,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{random_blinding, ShieldedKeypair, ViewingKey};
use zolana_program_test::Rejection;
use zolana_ring_client::{
    AuditedOutput, AuditedTransaction, RecoveryEnvironment, RecoveryError, RingAudit,
    RingEnvironment, RingRecovery, SourceMember,
};
use zolana_ring_policy::Member;
use zolana_ring_rpc::{
    ChainSource, CreateAuditorKeyRequest, Hub, RingRpcError, RootSecret, TransactionSource,
    Unauthorized, Upstreams,
};
use zolana_test_utils::{
    smart_account,
    spl::{create_token_account, mint_to},
    test_validator_asserts::{
        assert_account_unchanged, assert_transaction_compute_units, fetch_account, fetch_state,
        token_amount, wait_for_indexed_transaction, wait_for_merkle_proof,
    },
};
use zolana_transaction::{
    decrypt_transactions,
    instructions::{
        transact::{ConfidentialTransfer, PreparedTransfer, SettlementTarget},
        types::SppProofInputUtxo,
    },
    AssetRegistry, Data, KeypairWalletAuthority, Utxo, Wallet, DEFAULT_TAG_WINDOW, SOL_ASSET_ID,
    SOL_MINT,
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
const CHANGE_SLOT: u32 = 0;
const RECIPIENT_SLOT: u32 = 1;

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
            .map_err(|e| anyhow!("SOL asset resolution failed {e:?}"))?,
        SOL_MINT,
        "asset id 1 is SOL"
    );
    assert_eq!(
        env.assets
            .resolve(USDC_ASSET_ID)
            .map_err(|e| anyhow!("USDC asset resolution failed {e:?}"))?,
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
    //      harness helper and the SDK's `TransactSend` (the path the oversized
    //      ring transact needs). Both build transaction v1 messages, whose
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

    TransactSend {
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
        "SDK v1 transfer credited the recipient"
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
        .service_for(ring_program)
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
            CreateConfig {
                ring,
                payer: env.payer.pubkey(),
                authority: env.payer.pubkey(),
                auditor_pubkey: service.auditor_pubkey(),
                has_policy: true,
            }
            .instruction()?,
            SetAuthority {
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
    let rpc = env.client.rpc();
    let ring = CustomRing::new(custom_ring_program_id()?);
    let auditor = ViewingKey::new();
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
    let config = ring
        .read_config(rpc)?
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
    assert!(spp_ring_config(rpc, ring)?.is_paused(), "paused by the cli");
    let resumed = project.run(&["authority", "resume"])?;
    assert!(resumed.contains("spp ring    resumed"), "{resumed}");
    assert!(
        !spp_ring_config(rpc, ring)?.is_paused(),
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
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let tree = env.register_default_tree()?;
    let ring = CustomRing::new(custom_ring_program_id()?);
    let auditor = ViewingKey::new();
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
        let receipt = RingDeposit {
            ring,
            payer: &env.payer,
            recipient: &sender,
            tree,
            asset: DepositAsset::Sol,
            amount,
            cosigner: None,
        }
        .send(rpc)?;
        transact::wait_for_indexed_transaction(indexer, receipt.signature)?;
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
    let auditor = ViewingKey::new();
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
        ring.read_spp_ring_config(rpc)?.is_none(),
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
    let pause = |authority: Address, paused: bool| {
        SetPaused {
            ring,
            authority,
            paused,
        }
        .instruction()
    };
    send(rpc, &env.payer, &[pause(authority, true)?])?;
    assert!(
        spp_ring_config(rpc, ring)?.is_paused(),
        "paused by the ring authority"
    );
    match deposit(RING_DEPOSIT_A).send(rpc) {
        Err(DepositError::Client(error)) => {
            Rejection::pool(ShieldedPoolError::RingPaused).assert_client(&error)
        }
        Err(other) => return Err(anyhow!("expected RingPaused, got {other}")),
        Ok(_) => return Err(anyhow!("the paused ring took a deposit")),
    }
    send(rpc, &env.payer, &[pause(authority, false)?])?;

    // Public deposit caps apply independently of shielded policy proofs.
    send(
        rpc,
        &env.payer,
        &[SetSpendWindow {
            ring,
            payer: env.payer.pubkey(),
            authority,
            mint: Address::default(),
            window_slots: 1_000,
            deposit_cap: RING_DEPOSIT_A - 1,
            withdrawal_cap: 0,
        }
        .instruction()?],
    )?;
    match deposit(RING_DEPOSIT_A).send(rpc) {
        Err(DepositError::Client(error)) => {
            Rejection::custom(CustomRingError::SpendWindowExceeded as u32).assert_client(&error)
        }
        Err(other) => return Err(anyhow!("expected SpendWindowExceeded, got {other}")),
        Ok(_) => return Err(anyhow!("the capped ring took a deposit")),
    }
    send(
        rpc,
        &env.payer,
        &[ClearSpendWindow {
            ring,
            authority,
            mint: Address::default(),
            rent_recipient: authority,
        }
        .instruction()],
    )?;

    // 4. Two ring SOL deposits give the sender the ring-owned UTXOs the transfer
    //    spends. Their blindings come back from the deposit builder, so the spend
    //    is rebuilt without needing a wallet sync here.
    let mut spendable = Vec::with_capacity(2);
    for amount in [RING_DEPOSIT_A, RING_DEPOSIT_B] {
        let RingDepositReceipt { utxo, .. } = deposit(amount).send(rpc)?;
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
    )
    .with_compact_change()
    .with_ring_program_id(ring_program);
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
    let proven = CustomRingTransfer::new(CustomRingTransferInput {
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
            input_tree: env.tree,
            output_tree: env.tree,
            entries_tree: Some(env.tree),
            head_map_root: None,
            owner_signers: proven.owner_signers.clone(),
            interface_transfer_accounts: Vec::new(),
            proof: proven.proof,
            transact: tampered_data,
            state_root_index: 0,
            nullifier_root_index: 0,
            approval_required: false,
            head_transition: None,
        }
        .instruction()?,
    )?;
    Rejection::custom(CustomRingError::ProofVerificationFailed as u32)
        .at(0)
        .assert_client(&rejection);
    assert_account_unchanged(rpc, &env.tree, &tree_before)?;

    let transaction = TransactSend {
        payer: &env.sender.keypair,
        signers: &[],
        instruction: proven.instruction()?,
    }
    .build(rpc)?;
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
    assert_eq!(indexed.nullifiers.len(), 2, "both inputs spend");
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
                data: Data::default(),
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
    let prepare_hop = || -> Result<PreparedTransfer> {
        let mut hop_transfer = ConfidentialTransfer::new(
            env.recipient.keypair.shielded_address()?,
            vec![SppProofInputUtxo::new(
                received.clone(),
                &env.recipient.keypair,
            )],
            env.recipient.keypair.pubkey(),
        )
        .with_compact_change()
        .with_ring_program_id(ring_program);
        hop_transfer.send(
            &env.sender.keypair.shielded_address()?,
            SOL_MINT,
            SECOND_HOP_AMOUNT,
        )?;
        Ok(hop_transfer.prepare()?)
    };

    // 10. The second hop goes over BOTH transports, the policy statement holds
    //     the same parity as the audit statement.
    let hop = AsyncHopParity {
        ring,
        sender: &env.recipient.keypair,
        blocking: prepare_hop()?,
        asynchronous: prepare_hop()?,
        auditor_tag,
    }
    .send(&env, &prover)?;
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
            (RING_TRANSFER_AMOUNT - SECOND_HOP_AMOUNT, Some(ring_program)),
            (SECOND_HOP_AMOUNT, Some(ring_program)),
        ],
        "second hop outputs"
    );

    // 11. The config authority hands over, only the new key pauses the ring.
    let successor = env.funded_keypair()?;
    rpc.create_and_send_transaction(
        &[SetAuthority {
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
        instructions: &[pause(authority, true)?],
    }
    .send(rpc)?;
    Rejection::custom(CustomRingError::UnauthorizedAuthority as u32)
        .at(0)
        .assert_client(&rejection);
    send(rpc, &successor, &[pause(successor.pubkey(), true)?])?;
    assert!(
        spp_ring_config(rpc, ring)?.is_paused(),
        "paused by the successor"
    );
    send(rpc, &successor, &[pause(successor.pubkey(), false)?])?;
    assert!(
        !spp_ring_config(rpc, ring)?.is_paused(),
        "reopened by the successor"
    );

    Ok(())
}

/// An audit-only ring pins no policy config, its transfer proves the lighter
/// audit statement and the auditor still recovers every output.
#[test]
fn an_audit_only_ring_audits_every_transfer() -> Result<()> {
    let mut env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);

    let auditor = ViewingKey::new();
    let auditor_pk = auditor.pubkey();

    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor_pk,
        tier: Tier::AuditOnly,
    }
    .send(rpc)?;

    assert!(
        ring.read_policy_config(rpc)?.is_none(),
        "an audit-only ring pins no policy config"
    );
    let config: RingProgramConfig = fetch_state(rpc, &ring.config_pda())?;
    assert_eq!(config.has_policy, 0, "audit-only config flag");

    let mut spendable = Vec::with_capacity(2);
    for amount in [RING_DEPOSIT_A, RING_DEPOSIT_B] {
        let RingDepositReceipt { utxo, .. } = RingDeposit {
            ring,
            payer: &env.sender.keypair,
            recipient: &env.sender.keypair,
            tree: env.tree,
            asset: DepositAsset::Sol,
            amount,
            cosigner: None,
        }
        .send(rpc)?;
        spendable.push(utxo);
    }

    let sender_address = env.sender.keypair.pubkey();
    let inputs = spendable
        .into_iter()
        .map(|utxo| SppProofInputUtxo::new(utxo, &env.sender.keypair))
        .collect();
    let mut transfer = ConfidentialTransfer::new(
        env.sender.keypair.shielded_address()?,
        inputs,
        sender_address,
    )
    .with_compact_change()
    .with_ring_program_id(ring_program);
    transfer.send(
        &env.recipient.keypair.shielded_address()?,
        SOL_MINT,
        RING_TRANSFER_AMOUNT,
    )?;
    let prepared = transfer.prepare()?;

    let prover = ProverClient::local();
    let proven = CustomRingTransfer::new(CustomRingTransferInput {
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

    let transaction = TransactSend {
        payer: &env.sender.keypair,
        signers: &[],
        instruction: proven.instruction()?,
    }
    .build(rpc)?;
    let signature = rpc
        .client()
        .send_and_confirm_transaction(&transaction)
        .map_err(|error| anyhow!("send v1 failed {error}"))?;

    let auditor_tag = auditor_view_tag(&auditor_pk);
    let indexed = wait_for_indexed_transaction(indexer, auditor_tag, signature);
    assert_eq!(indexed.nullifiers.len(), 2, "both inputs spend");
    assert_eq!(
        indexed.tx_viewing_pk,
        Some(tx_viewing_pk),
        "the on-chain tx_viewing_pk is the sender's"
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
        .utxos
        .iter()
        .find(|held| !held.spent)
        .map(|held| held.utxo.clone())
        .ok_or_else(|| anyhow!("recipient note"))?;
    // The second hop goes over the ASYNC transport, with a blocking proof of
    // the same note alongside it as the parity reference. `prove_async`
    // exists for a host that cannot link the blocking Solana client, and a
    // path only that host runs is a path nothing checks; proving the same
    // spend both ways and landing the async proof is what keeps the two
    // honest. `PreparedTransfer` is not `Clone` and preparing draws fresh
    // output blindings, so the two are prepared independently: equivalent,
    // not identical.
    let prepare_hop = || -> Result<PreparedTransfer> {
        let mut hop_transfer = ConfidentialTransfer::new(
            env.recipient.keypair.shielded_address()?,
            vec![SppProofInputUtxo::new(
                received.clone(),
                &env.recipient.keypair,
            )],
            env.recipient.keypair.pubkey(),
        )
        .with_compact_change()
        .with_ring_program_id(ring_program);
        hop_transfer.send(
            &env.sender.keypair.shielded_address()?,
            SOL_MINT,
            SECOND_HOP_AMOUNT,
        )?;
        Ok(hop_transfer.prepare()?)
    };
    let hop = AsyncHopParity {
        ring,
        sender: &env.recipient.keypair,
        blocking: prepare_hop()?,
        asynchronous: prepare_hop()?,
        auditor_tag,
    }
    .send(&env, &prover)?;
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
            (RING_TRANSFER_AMOUNT - SECOND_HOP_AMOUNT, Some(ring_program)),
            (SECOND_HOP_AMOUNT, Some(ring_program)),
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
    let auditor = ViewingKey::new();
    let auditor_tag = auditor_view_tag(&auditor.pubkey());
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::policy(&EMPTY, env.tree),
    }
    .send(rpc)?;
    let prover = ProverClient::local();
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
    let entry_input = deposited.spend();
    wait_for_merkle_proof(indexer, env.tree, entry_input.hash()?);
    let mut entry_transfer =
        ConfidentialTransfer::new(sender_address, vec![entry_input], sender.pubkey())
            .with_compact_change()
            .with_ring_program_id(ring_program);
    entry_transfer.send(&recipient_address, SOL_MINT, ENTRY_AMOUNT)?;
    let prepared = entry_transfer.prepare()?;
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
    .send(&env, &prover)?;
    assert_eq!(
        AuditLookup {
            ring_program,
            auditor: &auditor,
            signature: entry.signature,
        }
        .run(&env)?
        .outputs,
        vec![
            sender_change.audited(CHANGE_SLOT)?,
            recipient_ring_note.audited(RECIPIENT_SLOT)?,
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
    let mut exit_transfer =
        ConfidentialTransfer::new(sender_address, vec![sender_change.spend()], sender.pubkey())
            .with_compact_change()
            .with_ring_program_id(ring_program);
    exit_transfer.send_default_ring(&recipient_address, SOL_MINT, EXIT_AMOUNT)?;
    let prepared = exit_transfer.prepare()?;
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
    .send(&env, &prover)?;
    assert_eq!(
        AuditLookup {
            ring_program,
            auditor: &auditor,
            signature: exit.signature,
        }
        .run(&env)?
        .outputs,
        vec![
            exit_change.audited(CHANGE_SLOT)?,
            recipient_default_note.audited(RECIPIENT_SLOT)?,
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
    let unreachable = ProverClient::new("http://127.0.0.1:1".to_string());
    let prove = |prepared: PreparedTransfer| {
        CustomRingTransfer::new(CustomRingTransferInput {
            ring,
            sender,
            prepared,
        })
        .with_tree(env.tree)
        .with_assets(&env.assets)
        .prove(TransferProofEnvironment {
            indexer,
            rpc,
            prover: &unreachable,
        })
    };
    let mut foreign_output =
        ConfidentialTransfer::new(sender_address, vec![exit_change.spend()], sender.pubkey())
            .with_compact_change()
            .with_ring_program_id(ring_program);
    foreign_output.send(&recipient_address, SOL_MINT, REFUSED_AMOUNT)?;
    let mut prepared = foreign_output.prepare()?;
    prepared
        .outputs
        .get_mut(RECIPIENT_SLOT as usize)
        .ok_or_else(|| anyhow!("recipient slot"))?
        .ring_program_id = Some(FOREIGN_RING);
    expect_foreign_ring(prove(prepared), FOREIGN_RING)?;

    let foreign_note = Note {
        owner: sender,
        asset: SOL_MINT,
        amount: EXIT_CHANGE,
        blinding: random_blinding(),
        ring_program_id: Some(FOREIGN_RING),
    };
    let mut foreign_input =
        ConfidentialTransfer::new(sender_address, vec![foreign_note.spend()], sender.pubkey())
            .with_compact_change()
            .with_ring_program_id(ring_program);
    foreign_input.send(&recipient_address, SOL_MINT, REFUSED_AMOUNT)?;
    expect_foreign_ring(prove(foreign_input.prepare()?), FOREIGN_RING)?;

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
    let auditor = ViewingKey::new();
    let auditor_tag = auditor_view_tag(&auditor.pubkey());
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::policy(&EMPTY, env.tree),
    }
    .send(rpc)?;
    let prover = ProverClient::local();
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
    let entry_input = deposited.spend();
    wait_for_merkle_proof(indexer, env.tree, entry_input.hash()?);

    // 2. Entry, the default USDC note is spent into ring-bound notes.
    let mut entry_transfer =
        ConfidentialTransfer::new(sender_address, vec![entry_input], sender.pubkey())
            .with_compact_change()
            .with_ring_program_id(ring_program);
    entry_transfer.send(&recipient_address, usdc, USDC_ENTRY_AMOUNT)?;
    let prepared = entry_transfer.prepare()?;
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
    .send(&env, &prover)?;
    assert_eq!(
        AuditLookup {
            ring_program,
            auditor: &auditor,
            signature: entry.signature,
        }
        .run(&env)?
        .outputs,
        vec![
            entry_change.audited(CHANGE_SLOT)?,
            recipient_ring_note.audited(RECIPIENT_SLOT)?,
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
    let mut hop_transfer =
        ConfidentialTransfer::new(sender_address, vec![entry_change.spend()], sender.pubkey())
            .with_compact_change()
            .with_ring_program_id(ring_program);
    hop_transfer.send(&recipient_address, usdc, USDC_HOP_AMOUNT)?;
    let prepared = hop_transfer.prepare()?;
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
    .send(&env, &prover)?;
    assert_eq!(
        AuditLookup {
            ring_program,
            auditor: &auditor,
            signature: hop.signature,
        }
        .run(&env)?
        .outputs,
        vec![
            hop_change.audited(CHANGE_SLOT)?,
            recipient_hop_note.audited(RECIPIENT_SLOT)?,
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
    let RingDepositReceipt { utxo: receipt, .. } = RingDeposit {
        ring,
        payer: sender,
        recipient: sender,
        tree: env.tree,
        asset: usdc_deposit(sender_usdc),
        amount: USDC_RING_DEPOSIT,
        cosigner: None,
    }
    .send(rpc)?;
    assert_eq!(
        token_amount(&fetch_account(rpc, &sender_usdc)?),
        USDC_FUNDING - USDC_DEFAULT_DEPOSIT - USDC_RING_DEPOSIT,
        "funding account after the ring deposit"
    );
    let receipt_input = SppProofInputUtxo::new(receipt, sender);
    wait_for_merkle_proof(indexer, env.tree, receipt_input.hash()?);

    // 5. Exit, the hop change and the ring-deposit receipt are spent together,
    //    the receipt spend proves the sdk receipt utxo matches the leaf.
    let mut exit_transfer = ConfidentialTransfer::new(
        sender_address,
        vec![hop_change.spend(), receipt_input],
        sender.pubkey(),
    )
    .with_compact_change()
    .with_ring_program_id(ring_program);
    exit_transfer.send_default_ring(&recipient_address, usdc, USDC_EXIT_AMOUNT)?;
    let prepared = exit_transfer.prepare()?;
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
    .send(&env, &prover)?;
    assert_eq!(
        AuditLookup {
            ring_program,
            auditor: &auditor,
            signature: exit.signature,
        }
        .run(&env)?
        .outputs,
        vec![
            exit_change.audited(CHANGE_SLOT)?,
            recipient_default_note.audited(RECIPIENT_SLOT)?,
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
        &[SetCoSigner {
            ring,
            payer: env.payer.pubkey(),
            authority: env.payer.pubkey(),
            signer: cosigner.pubkey(),
            scope: CoSignScope::WITHDRAWALS,
            thresholds: vec![CoSignThreshold {
                mint: usdc,
                amount: USDC_WITHDRAW_AMOUNT - 1,
            }],
        }
        .instruction()?],
    )?;
    let withdraw = || -> Result<PreparedTransfer> {
        let mut transfer =
            ConfidentialTransfer::new(sender_address, vec![exit_change.spend()], sender.pubkey())
                .with_compact_change()
                .with_ring_program_id(ring_program);
        transfer.withdraw(
            usdc,
            USDC_WITHDRAW_AMOUNT,
            SettlementTarget::Spl {
                user_spl_token: recipient_usdc,
            },
        )?;
        transfer.send(&recipient_address, usdc, USDC_FINAL_SEND)?;
        Ok(transfer.prepare()?)
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
        prepared: withdraw()?,
    })
    .with_tree(env.tree)
    .with_assets(&env.assets)
    .with_interface_transfer_accounts(vec![settlement])
    .prove(TransferProofEnvironment {
        indexer,
        rpc,
        prover: &prover,
    })?;
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
    .send(&env, &prover)?;
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
            final_change.audited(CHANGE_SLOT)?,
            recipient_final_note.audited(RECIPIENT_SLOT)?,
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
    send(
        rpc,
        &env.payer,
        &[SetDelegate {
            ring,
            payer: env.payer.pubkey(),
            authority: env.payer.pubkey(),
            delegate: delegate.pubkey(),
        }
        .instruction()],
    )?;
    let tree_id = custom_ring_sdk::tree_id(rpc, env.tree)?;
    let moved = || -> Result<ProvenDelegateTransfer> {
        Ok(DelegateTransfer::new(DelegateTransferInput {
            ring,
            delegate: delegate.pubkey(),
            payer: env.payer.pubkey(),
            inputs: vec![Note {
                owner: recipient,
                asset: usdc,
                amount: USDC_FINAL_SEND,
                blinding: recipient_final_blinding,
                ring_program_id: Some(ring_program),
            }
            .spend()
            .in_tree(tree_id)],
            outputs: vec![DelegateOutput {
                recipient: sender_address,
                asset: usdc,
                amount: USDC_FINAL_SEND,
            }],
        })
        .with_tree(env.tree)
        .with_assets(&env.assets)
        .prove(TransferProofEnvironment {
            indexer,
            rpc,
            prover: &prover,
        })?)
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
    let signature = TransactSend {
        payer: &env.payer,
        signers: &[&delegate],
        instruction: proven.instruction()?,
    }
    .send(rpc)?;
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
fn a_velocity_ring_bounds_each_senders_outflow() -> Result<()> {
    const WINDOW_SLOTS: u64 = VELOCITY.window_slots();
    const FIRST_SEND: u64 = 250_000_000;
    const SECOND_SEND: u64 = 350_000_000;
    const THIRD_SEND: u64 = 100_000_000;
    const DEPOSITS: [u64; 2] = [400_000_000, 300_000_000];
    const _: () =
        assert!(FIRST_SEND <= VELOCITY_COSIGN_ABOVE && SECOND_SEND > VELOCITY_COSIGN_ABOVE);
    const _: () = assert!(FIRST_SEND + SECOND_SEND <= VELOCITY_CAP);
    const _: () = assert!(FIRST_SEND + SECOND_SEND + THIRD_SEND > VELOCITY_CAP);

    let env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    advance_local_clock(rpc, (rpc.get_slot()? / WINDOW_SLOTS + 1) * WINDOW_SLOTS)?;
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = ViewingKey::new();
    let auditor_pk = auditor.pubkey();
    let auditor_tag = auditor_view_tag(&auditor_pk);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor_pk,
        tier: Tier::policy(&VELOCITY, env.tree),
    }
    .send(rpc)?;
    let prover = ProverClient::local();
    let sender = &env.sender.keypair;
    let sender_address = sender.pubkey();
    let recipient = env.recipient.keypair.shielded_address()?;
    let sol_field = zolana_interface::SOL_ASSET_FIELD;
    let head_map = || -> Result<_> { ring.read_head_map_root(rpc)?.context("head map") };

    let mut notes = Vec::with_capacity(DEPOSITS.len());
    for amount in DEPOSITS {
        let RingDepositReceipt { utxo, .. } = RingDeposit {
            ring,
            payer: sender,
            recipient: sender,
            tree: env.tree,
            asset: DepositAsset::Sol,
            amount,
            cosigner: None,
        }
        .send(rpc)?;
        notes.push(utxo);
    }
    let prepare = |inputs: Vec<Utxo>, amount: u64| -> Result<PreparedTransfer> {
        let inputs = inputs
            .into_iter()
            .map(|utxo| SppProofInputUtxo::new(utxo, sender))
            .collect();
        let mut transfer =
            ConfidentialTransfer::new(sender.shielded_address()?, inputs, sender_address)
                .with_compact_change()
                .with_ring_program_id(ring_program);
        transfer.send(&recipient, SOL_MINT, amount)?;
        Ok(transfer.prepare()?)
    };
    let prove = |prepared: PreparedTransfer, cosigner: Option<Address>| {
        let mut transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring,
            sender,
            prepared,
        })
        .with_tree(env.tree)
        .with_assets(&env.assets);
        if let Some(cosigner) = cosigner {
            transfer = transfer.with_cosigner(cosigner);
        }
        transfer.prove(TransferProofEnvironment {
            indexer,
            rpc,
            prover: &prover,
        })
    };
    let member = Member::owner_tag(sender_address.as_array())?;
    let read_record = || {
        ReadSpendRecord {
            ring,
            entries_tree: env.tree,
            entries_tree_id: 0,
            member,
        }
        .read_current(ReadEnvironment { indexer, rpc })
    };

    // Nothing moves before the sender registers.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let unregistered = loop {
        let error = prove(prepare(notes.clone(), FIRST_SEND)?, None)
            .err()
            .context("an unregistered sender reached proving")?;
        let catching_up = matches!(
            &error,
            TransferError::ListEntry(error)
                if matches!(error.as_ref(), custom_ring_sdk::EntryProofError::Client(error)
                    if matches!(error.as_ref(), zolana_client::ClientError::RingHeadMapOutOfSync))
        );
        if !catching_up || std::time::Instant::now() >= deadline {
            break error;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(
        matches!(unregistered, TransferError::SpendRecordMissing),
        "an unregistered sender is refused before proving: {unregistered}"
    );
    let registration = RegisterSpend {
        ring,
        payer: sender_address,
    }
    .prove(TransferProofEnvironment {
        indexer,
        rpc,
        prover: &prover,
    })?;
    let window = registration.record().window;
    send(rpc, sender, &[registration.instruction()?])?;
    let registered = wait_for_spend_record(read_record, 0)?;
    assert_eq!(
        registered.record.window, window,
        "registered at the proven window"
    );
    let registered_head = head_map()?;
    assert_eq!(
        registered_head.next_index, 2,
        "one registered member plus sentinel"
    );
    assert_ne!(
        registered_head.root,
        custom_ring_interface::HEAD_MAP_EMPTY_ROOT
    );

    // Another member's registration makes an unchanged sender's head proof stale.
    let stale = prove(prepare(notes.clone(), FIRST_SEND)?, None)?;
    let other = &env.recipient.keypair;
    let other_registration = RegisterSpend {
        ring,
        payer: other.pubkey(),
    }
    .prove(TransferProofEnvironment {
        indexer,
        rpc,
        prover: &prover,
    })?;
    send(rpc, other, &[other_registration.instruction()?])?;
    let other_member = Member::owner_tag(other.pubkey().as_array())?;
    wait_for_spend_record(
        || {
            ReadSpendRecord {
                ring,
                entries_tree: env.tree,
                entries_tree_id: 0,
                member: other_member,
            }
            .read_current(ReadEnvironment { indexer, rpc })
        },
        0,
    )?;
    let rejection = send_expecting_rejection(rpc, sender, stale.instruction()?)?;
    Rejection::custom(CustomRingError::StaleHeadMapRoot as u32)
        .at(0)
        .assert_client(&rejection);
    assert_eq!(
        read_record()?
            .ok_or_else(|| anyhow!("sender record"))?
            .record
            .version,
        0
    );
    let head_before_transfer = head_map()?;
    assert_eq!(head_before_transfer.next_index, 3);

    // Failed SPP verification rolls back the head before a valid send advances both.
    let prepared = prepare(notes, FIRST_SEND)?;
    let change = prepared
        .outputs
        .iter()
        .find(|output| output.amount == DEPOSITS[0] + DEPOSITS[1] - FIRST_SEND)
        .cloned()
        .ok_or_else(|| anyhow!("change output"))?;
    let mut proven = prove(prepared, None)?;
    assert!(
        !proven.approval_required,
        "a send at the threshold needs no approval"
    );
    let root_before_cpi = fetch_account(rpc, &ring.head_map_root_pda())?;
    let tree_before_cpi = fetch_account(rpc, &env.tree)?;
    let valid_c = proven.data.proof.c;
    proven.data.proof.c = proven.data.proof.a;
    let rejection = send_expecting_rejection(rpc, sender, proven.instruction()?)?;
    Rejection::custom(ShieldedPoolError::TransactProofVerificationFailed as u32)
        .at(0)
        .assert_client(&rejection);
    assert_account_unchanged(rpc, &ring.head_map_root_pda(), &root_before_cpi)?;
    assert_account_unchanged(rpc, &env.tree, &tree_before_cpi)?;
    proven.data.proof.c = valid_c;
    let signature = TransactSend {
        payer: sender,
        signers: &[],
        instruction: proven.instruction()?,
    }
    .send(rpc)?;
    let indexed = wait_for_indexed_transaction(indexer, auditor_tag, signature);
    let live = wait_for_spend_record(read_record, 1)?;
    let first_head = head_map()?;
    assert_ne!(first_head.root, head_before_transfer.root);
    assert_eq!(
        first_head.next_index, 3,
        "transfers do not allocate map leaves"
    );
    let tx_key = sender.get_transaction_viewing_key(&indexed.nullifiers[0])?;
    let counters = SealedCounters {
        body: &find_counters_message(&indexed.messages, ring.namespace_pda().as_array())
            .ok_or_else(|| anyhow!("counters message"))?
            .data,
        salt: indexed.salt.ok_or_else(|| anyhow!("transaction salt"))?,
    }
    .open(&tx_key)?;
    assert_eq!(
        counters.spent(&sol_field),
        FIRST_SEND,
        "the counter holds the first send"
    );
    assert_eq!(counters.commitment()?, live.record.counters_commitment);
    let audited = AuditLookup {
        ring_program,
        auditor: &auditor,
        signature,
    }
    .run(&env)?;
    assert_eq!(
        audited.spend_records.len(),
        1,
        "the auditor sees the record"
    );
    assert_eq!(audited.spend_records[0].record, live.record);
    assert_eq!(audited.spend_records[0].counters, Some(counters));
    assert!(audited.undecryptable_slots.is_empty());

    // The proved approval bit requires a co-signer even outside its configured scope.
    let change_note = Utxo {
        owner: sender.signing_pubkey(),
        asset: SOL_MINT,
        amount: change.amount,
        blinding: change.blinding,
        ring_program_id: Some(ring_program),
        data: Data::default(),
    };
    let proven = prove(prepare(vec![change_note.clone()], SECOND_SEND)?, None)?;
    assert!(
        proven.approval_required,
        "a send above the threshold needs approval"
    );
    let rejection = send_expecting_rejection(rpc, sender, proven.instruction()?)?;
    Rejection::custom(CustomRingError::ApprovalWithoutCoSigner as u32)
        .at(0)
        .assert_client(&rejection);
    let cosigner = Keypair::new();
    send(
        rpc,
        &env.payer,
        &[SetCoSigner {
            ring,
            payer: env.payer.pubkey(),
            authority: env.payer.pubkey(),
            signer: cosigner.pubkey(),
            scope: CoSignScope::DEPOSITS,
            thresholds: Vec::new(),
        }
        .instruction()?],
    )?;
    let proven = prove(prepare(vec![change_note.clone()], SECOND_SEND)?, None)?;
    let rejection = send_expecting_rejection(rpc, sender, proven.instruction()?)?;
    Rejection::custom(CustomRingError::MissingCoSigner as u32)
        .at(0)
        .assert_client(&rejection);
    let prepared = prepare(vec![change_note], SECOND_SEND)?;
    let second_change = prepared
        .outputs
        .iter()
        .find(|output| output.amount == change.amount - SECOND_SEND)
        .cloned()
        .ok_or_else(|| anyhow!("second change output"))?;
    let proven = prove(prepared, Some(cosigner.pubkey()))?;
    let signature = TransactSend {
        payer: sender,
        signers: &[&cosigner],
        instruction: proven.instruction()?,
    }
    .send(rpc)?;
    wait_for_indexed_transaction(indexer, auditor_tag, signature);
    let live = wait_for_spend_record(read_record, 2)?;
    let second_head = head_map()?;
    assert_ne!(second_head.root, first_head.root);
    assert_eq!(second_head.next_index, 3);
    assert_eq!(
        live.record.window, window,
        "the same window carries both sends"
    );

    // The cap refuses the send that would cross it before any proof.
    let third = Utxo {
        owner: sender.signing_pubkey(),
        asset: SOL_MINT,
        amount: second_change.amount,
        blinding: second_change.blinding,
        ring_program_id: Some(ring_program),
        data: Data::default(),
    };
    match prove(
        prepare(vec![third.clone()], THIRD_SEND)?,
        Some(cosigner.pubkey()),
    ) {
        Err(TransferError::VelocityCapExceeded { cap, spent, .. }) => {
            assert_eq!(cap, VELOCITY_CAP);
            assert_eq!(spent, FIRST_SEND + SECOND_SEND + THIRD_SEND);
        }
        Err(other) => return Err(anyhow!("expected the cap refusal, got {other}")),
        Ok(_) => return Err(anyhow!("the capped send was proven")),
    }

    // Delegation exceeds the velocity cap without changing member counters or the head map.
    let delegate = Keypair::new();
    send(
        rpc,
        &env.payer,
        &[SetDelegate {
            ring,
            payer: env.payer.pubkey(),
            authority: env.payer.pubkey(),
            delegate: delegate.pubkey(),
        }
        .instruction()],
    )?;
    env.enable_authority_rail(ring)?;
    let RingDepositReceipt {
        utxo: delegated_note,
        ..
    } = RingDeposit {
        ring,
        payer: sender,
        recipient: sender,
        tree: env.tree,
        asset: DepositAsset::Sol,
        amount: VELOCITY_CAP + 1,
        cosigner: Some(&cosigner),
    }
    .send(rpc)?;
    let delegated_input = SppProofInputUtxo::new(delegated_note, sender).in_tree(0);
    wait_for_merkle_proof(indexer, env.tree, delegated_input.hash()?);
    let moved = DelegateTransfer::new(DelegateTransferInput {
        ring,
        delegate: delegate.pubkey(),
        payer: env.payer.pubkey(),
        inputs: vec![delegated_input],
        outputs: vec![DelegateOutput {
            recipient,
            asset: SOL_MINT,
            amount: VELOCITY_CAP + 1,
        }],
    })
    .with_tree(env.tree)
    .with_assets(&env.assets)
    .prove(TransferProofEnvironment {
        indexer,
        rpc,
        prover: &prover,
    })?;
    let delegate_signature = TransactSend {
        payer: &env.payer,
        signers: &[&delegate],
        instruction: moved.instruction()?,
    }
    .send(rpc)?;
    wait_for_indexed_transaction(indexer, auditor_tag, delegate_signature);
    assert_eq!(head_map()?, second_head);
    assert_eq!(
        read_record()?
            .ok_or_else(|| anyhow!("sender record"))?
            .record,
        live.record
    );

    // The next window rejects the old proof and resets counters on a newly proved spend.
    let stale = prove(prepare(vec![third.clone()], 1)?, None)?;
    advance_local_clock(rpc, (window + 1) * WINDOW_SLOTS)?;
    let rejection = send_expecting_rejection(rpc, sender, stale.instruction()?)?;
    Rejection::custom(CustomRingError::ProofVerificationFailed as u32)
        .at(0)
        .assert_client(&rejection);
    assert_eq!(head_map()?, second_head);
    wait_for_spend_record(read_record, 2)?;
    let reset = prove(prepare(vec![third], THIRD_SEND)?, None)?;
    let signature = TransactSend {
        payer: sender,
        signers: &[],
        instruction: reset.instruction()?,
    }
    .send(rpc)?;
    wait_for_indexed_transaction(indexer, auditor_tag, signature);
    let reset = wait_for_spend_record(read_record, 3)?;
    assert_eq!(reset.record.window, window + 1);
    let audited = AuditLookup {
        ring_program,
        auditor: &auditor,
        signature,
    }
    .run(&env)?;
    assert_eq!(audited.spend_records.len(), 1);
    assert_eq!(
        audited.spend_records[0]
            .counters
            .as_ref()
            .ok_or_else(|| anyhow!("reset counters"))?
            .spent(&sol_field),
        THIRD_SEND
    );
    Ok(())
}

fn advance_local_clock(rpc: &SolanaRpc, slot: u64) -> Result<()> {
    let scope = std::env::var_os("ZOLANA_PROCESS_SCOPE_DIR")
        .ok_or_else(|| anyhow!("a scoped local runtime is required"))?;
    anyhow::ensure!(
        std::path::Path::new(&scope).is_dir(),
        "process scope is absent"
    );
    let url = rpc.client().url();
    let port = std::env::var("ZOLANA_LOCALNET_RPC_PORT").unwrap_or_else(|_| "8899".into());
    anyhow::ensure!(
        url == format!("http://127.0.0.1:{port}"),
        "RPC must match the scoped runtime port"
    );
    let _: serde_json::Value = rpc.client().send(
        solana_rpc_client_api::request::RpcRequest::Custom {
            method: "surfnet_timeTravel",
        },
        serde_json::json!([{ "absoluteSlot": slot }]),
    )?;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if rpc.get_slot()? >= slot {
            return Ok(());
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "the local clock did not advance"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_transfer_cap_ring_bounds_each_transfer() -> Result<()> {
    const UNDER_THRESHOLD: u64 = 250_000_000;
    const OVER_THRESHOLD: u64 = 350_000_000;
    const OVER_CAP: u64 = 700_000_000;
    const DEPOSITS: [u64; 3] = [300_000_000, 400_000_000, 800_000_000];
    const _: () = assert!(UNDER_THRESHOLD <= VELOCITY_COSIGN_ABOVE);
    const _: () = assert!(OVER_THRESHOLD > VELOCITY_COSIGN_ABOVE && OVER_THRESHOLD <= VELOCITY_CAP);
    const _: () = assert!(OVER_CAP > VELOCITY_CAP);

    let env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = ViewingKey::new();
    let auditor_pk = auditor.pubkey();
    let auditor_tag = auditor_view_tag(&auditor_pk);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor_pk,
        tier: Tier::policy(&TRANSFER_CAP, env.tree),
    }
    .send(rpc)?;
    let prover = ProverClient::local();
    let sender = &env.sender.keypair;
    let sender_address = sender.pubkey();
    let recipient = env.recipient.keypair.shielded_address()?;

    let mut notes = Vec::with_capacity(DEPOSITS.len());
    for amount in DEPOSITS {
        let RingDepositReceipt { utxo, .. } = RingDeposit {
            ring,
            payer: sender,
            recipient: sender,
            tree: env.tree,
            asset: DepositAsset::Sol,
            amount,
            cosigner: None,
        }
        .send(rpc)?;
        notes.push(utxo);
    }
    let prepare = |input: Utxo, amount: u64| -> Result<PreparedTransfer> {
        let mut transfer = ConfidentialTransfer::new(
            sender.shielded_address()?,
            vec![SppProofInputUtxo::new(input, sender)],
            sender_address,
        )
        .with_compact_change()
        .with_ring_program_id(ring_program);
        transfer.send(&recipient, SOL_MINT, amount)?;
        Ok(transfer.prepare()?)
    };
    let prove = |prepared: PreparedTransfer, cosigner: Option<Address>| {
        let mut transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring,
            sender,
            prepared,
        })
        .with_tree(env.tree)
        .with_assets(&env.assets);
        if let Some(cosigner) = cosigner {
            transfer = transfer.with_cosigner(cosigner);
        }
        transfer.prove(TransferProofEnvironment {
            indexer,
            rpc,
            prover: &prover,
        })
    };

    // A send below the threshold lands with no approval and no record.
    let proven = prove(prepare(notes[0].clone(), UNDER_THRESHOLD)?, None)?;
    assert!(
        !proven.approval_required,
        "an under-threshold send asks nobody"
    );
    let signature = TransactSend {
        payer: sender,
        signers: &[],
        instruction: proven.instruction()?,
    }
    .send(rpc)?;
    wait_for_indexed_transaction(indexer, auditor_tag, signature);

    // Above the threshold the chain refuses the send until the co-signer signs.
    let cosigner = Keypair::new();
    send(
        rpc,
        &env.payer,
        &[SetCoSigner {
            ring,
            payer: env.payer.pubkey(),
            authority: env.payer.pubkey(),
            signer: cosigner.pubkey(),
            scope: CoSignScope::WITHDRAWALS,
            thresholds: Vec::new(),
        }
        .instruction()?],
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
    let signature = TransactSend {
        payer: sender,
        signers: &[&cosigner],
        instruction: prove(
            prepare(notes[1].clone(), OVER_THRESHOLD)?,
            Some(cosigner.pubkey()),
        )?
        .instruction()?,
    }
    .send(rpc)?;
    wait_for_indexed_transaction(indexer, auditor_tag, signature);

    // A single send above the cap is refused before any proof.
    match prove(
        prepare(notes[2].clone(), OVER_CAP)?,
        Some(cosigner.pubkey()),
    ) {
        Err(TransferError::VelocityCapExceeded { cap, spent, .. }) => {
            assert_eq!(cap, VELOCITY_CAP);
            assert_eq!(spent, OVER_CAP);
        }
        Err(other) => return Err(anyhow!("expected the cap refusal, got {other}")),
        Ok(_) => return Err(anyhow!("the capped send was proven")),
    }
    Ok(())
}

fn wait_for_spend_record(
    read: impl Fn() -> Result<Option<LiveSpendRecord>, EntryProofError>,
    version: u64,
) -> Result<LiveSpendRecord> {
    Ok(transact::wait_for(
        format!("spend record v{version}"),
        || {
            Ok(match read() {
                Ok(Some(live)) if live.record.version == version => Probe::Ready(live),
                Ok(_) => Probe::NotYet,
                Err(error) => Probe::Retry(error),
            })
        },
    )?)
}

#[test]
fn the_delegate_moves_a_registered_members_notes_with_the_auditor_key() -> Result<()> {
    const SEND: u64 = DEFAULT_DEPOSIT / 2;

    let mut env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = ViewingKey::new();
    let auditor_pk = auditor.pubkey();
    let auditor_tag = auditor_view_tag(&auditor_pk);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor_pk,
        tier: Tier::AuditOnly,
    }
    .send(rpc)?;
    send(
        rpc,
        &env.payer,
        &[CreateKeyRegistryRoot {
            ring,
            payer: env.payer.pubkey(),
            authority: env.payer.pubkey(),
        }
        .instruction()],
    )?;
    let prover = ProverClient::local();
    let member = &env.sender.keypair;
    let member_address = member.shielded_address()?;

    let RingDepositReceipt { utxo, .. } = RingDeposit {
        ring,
        payer: member,
        recipient: member,
        tree: env.tree,
        asset: DepositAsset::Sol,
        amount: DEFAULT_DEPOSIT,
        cosigner: None,
    }
    .send(rpc)?;
    let input = SppProofInputUtxo::new(utxo, member);
    wait_for_merkle_proof(indexer, env.tree, input.hash()?);
    let mut transfer =
        ConfidentialTransfer::new(member.shielded_address()?, vec![input], member.pubkey())
            .with_compact_change()
            .with_ring_program_id(ring_program);
    transfer.send(&member_address, SOL_MINT, SEND)?;
    RingTransfer {
        ring,
        sender: member,
        prepared: transfer.prepare()?,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env, &prover)?;

    let registration = RegisterKey { ring, member }.prove(TransferProofEnvironment {
        indexer,
        rpc,
        prover: &prover,
    })?;
    send(rpc, member, &[registration.instruction()?])?;
    let root = ring.read_key_registry_root(rpc)?.context("key registry")?;
    assert_eq!(root.next_index, 2, "one registered member plus sentinel");
    let member_tag = Member::owner_tag(member.pubkey().as_array())?;
    let sealed = transact::wait_for("the registered key".to_owned(), || {
        let read = ReadSealedKey {
            ring,
            member: member_tag,
            root,
        };
        match read.read(indexer) {
            Ok(entry) => Ok(Probe::Ready(entry)),
            Err(error @ KeyRegistrationError::Client(_)) => Ok(Probe::Retry(error)),
            Err(error) => Err(error),
        }
    })?;
    let nullifier_key = sealed.open(&auditor)?;
    assert_eq!(nullifier_key.pubkey()?, member_address.nullifier_pubkey);

    let delegate = Keypair::new();
    send(
        rpc,
        &env.payer,
        &[SetDelegate {
            ring,
            payer: env.payer.pubkey(),
            authority: env.payer.pubkey(),
            delegate: delegate.pubkey(),
        }
        .instruction()],
    )?;
    env.enable_authority_rail(ring)?;
    let recovered = RingRecovery::new(ring_program, &auditor)
        .for_member(SourceMember {
            address: &member_address,
            nullifier_key: &nullifier_key,
        })
        .run(RecoveryEnvironment {
            ring: RingEnvironment {
                indexer,
                origin: rpc,
            },
            assets: &env.assets,
            tree_ids: |tree| {
                custom_ring_sdk::tree_id(rpc, tree).map_err(|_| RecoveryError::UnknownTree(tree))
            },
        })?;
    assert!(recovered.unopened.is_empty(), "every audited note opens");
    let mut amounts: Vec<u64> = recovered
        .utxos
        .iter()
        .map(|held| held.utxo.amount)
        .collect();
    amounts.sort_unstable();
    assert_eq!(amounts, [SEND, DEFAULT_DEPOSIT - SEND]);
    let moved = recovered
        .utxos
        .into_iter()
        .find(|held| held.utxo.amount == SEND)
        .context("the sent note")?;
    let proven = DelegateTransfer::new(DelegateTransferInput {
        ring,
        delegate: delegate.pubkey(),
        payer: env.payer.pubkey(),
        inputs: vec![SppProofInputUtxo::new(moved.utxo, &nullifier_key).in_tree(moved.tree_id)],
        outputs: vec![DelegateOutput {
            recipient: env.recipient.keypair.shielded_address()?,
            asset: SOL_MINT,
            amount: SEND,
        }],
    })
    .with_tree(env.tree)
    .with_assets(&env.assets)
    .prove(TransferProofEnvironment {
        indexer,
        rpc,
        prover: &prover,
    })?;
    let signature = TransactSend {
        payer: &env.payer,
        signers: &[&delegate],
        instruction: proven.instruction()?,
    }
    .send(rpc)?;
    let indexed = wait_for_indexed_transaction(indexer, auditor_tag, signature);
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
        vec![(SOL_MINT, SEND, Some(ring_program))],
        "the delegate moved the registered member's note"
    );
    Ok(())
}

/// A note stranded in an old tree spends into the active tree while the ring's
/// entries tree stays fixed.
#[test]
fn an_old_tree_note_migrates_into_the_active_tree() -> Result<()> {
    let mut env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = ViewingKey::new();
    let auditor_tag = auditor_view_tag(&auditor.pubkey());
    let prover = ProverClient::local();

    // env.tree is the active tree and the ring's entries tree, the genesis
    // default tree holds the stranded note.
    let old_tree = env.register_default_tree()?;
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::policy(&EMPTY, env.tree),
    }
    .send(rpc)?;

    let sender = &env.sender.keypair;
    let recipient = &env.recipient.keypair;
    let RingDepositReceipt { utxo, .. } = RingDeposit {
        ring,
        payer: sender,
        recipient: sender,
        tree: old_tree,
        asset: DepositAsset::Sol,
        amount: DEFAULT_DEPOSIT,
        cosigner: None,
    }
    .send(rpc)?;
    wait_for_merkle_proof(
        indexer,
        old_tree,
        SppProofInputUtxo::new(utxo.clone(), sender).hash()?,
    );

    let mut transfer = ConfidentialTransfer::new(
        sender.shielded_address()?,
        vec![SppProofInputUtxo::new(utxo, sender)],
        sender.pubkey(),
    )
    .with_compact_change()
    .with_ring_program_id(ring_program);
    transfer.send(&recipient.shielded_address()?, SOL_MINT, ENTRY_AMOUNT)?;
    let prepared = transfer.prepare()?;
    let proven = CustomRingTransfer::new(CustomRingTransferInput {
        ring,
        sender,
        prepared,
    })
    .with_tree(old_tree)
    .with_output_tree(env.tree)
    .with_assets(&env.assets)
    .prove(TransferProofEnvironment {
        indexer,
        rpc,
        prover: &prover,
    })?;
    let signature = TransactSend {
        payer: sender,
        signers: &[],
        instruction: proven.instruction()?,
    }
    .send(rpc)?;
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
        .utxos
        .iter()
        .find(|held| !held.spent)
        .map(|held| held.utxo.clone())
        .ok_or_else(|| anyhow!("migrated recipient note"))?;
    assert_eq!(
        received.amount, ENTRY_AMOUNT,
        "recipient holds the migrated amount in the active tree"
    );

    let mut hop = ConfidentialTransfer::new(
        recipient.shielded_address()?,
        vec![SppProofInputUtxo::new(received, recipient)],
        recipient.pubkey(),
    )
    .with_compact_change()
    .with_ring_program_id(ring_program);
    hop.send(&sender.shielded_address()?, SOL_MINT, SECOND_HOP_AMOUNT)?;
    let hop_prepared = hop.prepare()?;
    let hop = RingTransfer {
        ring,
        sender: recipient,
        prepared: hop_prepared,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env, &prover)?;
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
        vec![ENTRY_AMOUNT - SECOND_HOP_AMOUNT, SECOND_HOP_AMOUNT],
        "the active-tree note spends in turn"
    );
    Ok(())
}

/// The money output tree is free of the pinned entries tree, output lands in a
/// third tree while the policy roots stay bound to the entries tree.
#[test]
fn a_transfer_outputs_apart_from_the_entries_tree() -> Result<()> {
    let env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = ViewingKey::new();
    let auditor_tag = auditor_view_tag(&auditor.pubkey());
    let prover = ProverClient::local();

    // Three distinct trees, the entries tree the policy roots bind stays env.tree
    // while the money moves between two other trees.
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
    let RingDepositReceipt { utxo, .. } = RingDeposit {
        ring,
        payer: sender,
        recipient: sender,
        tree: input_tree,
        asset: DepositAsset::Sol,
        amount: DEFAULT_DEPOSIT,
        cosigner: None,
    }
    .send(rpc)?;
    wait_for_merkle_proof(
        indexer,
        input_tree,
        SppProofInputUtxo::new(utxo.clone(), sender)
            .in_tree(input_tree_id)
            .hash()?,
    );

    let mut transfer = ConfidentialTransfer::new(
        sender.shielded_address()?,
        vec![SppProofInputUtxo::new(utxo, sender).in_tree(input_tree_id)],
        sender.pubkey(),
    )
    .with_compact_change()
    .with_ring_program_id(ring_program)
    .with_output_tree_id(output_tree_id);
    transfer.send(&recipient.shielded_address()?, SOL_MINT, ENTRY_AMOUNT)?;
    let prepared = transfer.prepare()?;
    let recipient_hash = prepared
        .outputs
        .iter()
        .find(|output| output.amount == ENTRY_AMOUNT)
        .ok_or_else(|| anyhow!("recipient output"))?
        .hash(output_tree_id)?;
    let proven = CustomRingTransfer::new(CustomRingTransferInput {
        ring,
        sender,
        prepared,
    })
    .with_tree(input_tree)
    .with_output_tree(output_tree)
    .with_assets(&env.assets)
    .prove(TransferProofEnvironment {
        indexer,
        rpc,
        prover: &prover,
    })?;
    let signature = TransactSend {
        payer: sender,
        signers: &[],
        instruction: proven.instruction()?,
    }
    .send(rpc)?;
    let indexed = wait_for_indexed_transaction(indexer, auditor_tag, signature);
    assert_eq!(indexed.nullifiers.len(), 1, "the input note is spent");

    // The wallet syncs under tree id 0 only, so the leaf is checked from the slot.
    let recipient_slot = indexed
        .output_slots
        .iter()
        .find(|slot| slot.output_context.hash == recipient_hash)
        .ok_or_else(|| anyhow!("recipient output hashed under the output tree id"))?;
    assert_eq!(
        recipient_slot.output_context.tree, output_tree,
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

fn spp_ring_config(rpc: &SolanaRpc, ring: CustomRing) -> Result<RingConfig> {
    ring.read_spp_ring_config(rpc)?
        .ok_or_else(|| anyhow!("SPP ring config of {}", ring.program_id()))
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
    fn spend(self) -> SppProofInputUtxo {
        SppProofInputUtxo::new(
            Utxo {
                owner: self.owner.signing_pubkey(),
                asset: self.asset,
                amount: self.amount,
                blinding: self.blinding,
                ring_program_id: self.ring_program_id,
                data: Data::default(),
            },
            self.owner,
        )
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
        let view_tag = address.viewing_pubkey.x();
        let deposit = SppDeposit {
            tree: self.tree,
            depositor: self.depositor.pubkey(),
            deposits: vec![AssetDeposit {
                asset: self.asset,
                view_tag,
                owner: address.owner_hash()?,
                amount: self.amount,
                utxo_data: None,
                memo: None,
            }],
        }
        .instruction()?;
        let signature = send(rpc, self.depositor, &[deposit])?;
        // A proofless deposit publishes its UTXO in the clear, so read it back
        // from the indexer.
        let indexed = wait_for_indexed_transaction(indexer, view_tag, signature);
        let mint = self.asset.mint();
        let balances = decrypt_transactions(self.depositor, std::slice::from_ref(&indexed), assets)
            .map_err(|e| anyhow!("decrypt deposit {signature}: {e:?}"))?;
        let deposited = balances
            .get_balance(mint)
            .and_then(|balance| balance.utxos.first())
            .ok_or_else(|| anyhow!("deposit {signature} not indexed for {mint}"))?;
        assert_eq!(deposited.amount, self.amount, "deposited amount");
        Ok(Note {
            owner: self.depositor,
            asset: mint,
            amount: self.amount,
            blinding: deposited.blinding,
            ring_program_id: None,
        })
    }
}

struct RingTransfer<'a> {
    ring: CustomRing,
    sender: &'a ShieldedKeypair,
    prepared: PreparedTransfer,
    interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    auditor_tag: [u8; 32],
    cosigner: Option<&'a Keypair>,
}

struct RingTransferReceipt {
    signature: Signature,
    indexed: ShieldedTransaction,
}

impl RingTransfer<'_> {
    fn send(self, env: &TestEnv, prover: &ProverClient) -> Result<RingTransferReceipt> {
        let rpc = env.client.rpc();
        let indexer = env.client.indexer();
        let mut transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring: self.ring,
            sender: self.sender,
            prepared: self.prepared,
        })
        .with_tree(env.tree)
        .with_assets(&env.assets)
        .with_interface_transfer_accounts(self.interface_transfer_accounts);
        if let Some(cosigner) = self.cosigner {
            transfer = transfer.with_cosigner(cosigner.pubkey());
        }
        let proven = transfer.prove(TransferProofEnvironment {
            indexer,
            rpc,
            prover,
        })?;
        let signers: Vec<&dyn Signer> = self
            .cosigner
            .into_iter()
            .map(|k| k as &dyn Signer)
            .collect();
        let signature = TransactSend {
            payer: self.sender,
            signers: &signers,
            instruction: proven.instruction()?,
        }
        .send(rpc)?;
        let indexed = wait_for_indexed_transaction(indexer, self.auditor_tag, signature);
        Ok(RingTransferReceipt { signature, indexed })
    }
}

/// One ring transfer proven over BOTH transports, of which the async proof is
/// the one that lands.
///
/// The blocking proof is the parity reference. Everything the spent note fixes
/// -- the circuit, the nullifiers, the transaction viewing key and the owner
/// signers -- has to agree across the two paths; only what is freshly drawn per
/// proof (output blindings, the salt, the auditor ciphertext, and with them
/// `private_tx_hash`) may differ, which is why the two are compared field by
/// field rather than whole.
///
/// The root indices in `data.inputs` are deliberately left out: they record the
/// tree state each read saw, not anything about the transport.
struct AsyncHopParity<'a> {
    ring: CustomRing,
    sender: &'a ShieldedKeypair,
    blocking: PreparedTransfer,
    asynchronous: PreparedTransfer,
    auditor_tag: [u8; 32],
}

impl AsyncHopParity<'_> {
    fn send(self, env: &TestEnv, prover: &ProverClient) -> Result<RingTransferReceipt> {
        let rpc = env.client.rpc();
        let indexer = env.client.indexer();
        let blocking = CustomRingTransfer::new(CustomRingTransferInput {
            ring: self.ring,
            sender: self.sender,
            prepared: self.blocking,
        })
        .with_tree(env.tree)
        .with_assets(&env.assets)
        .prove(TransferProofEnvironment {
            indexer,
            rpc,
            prover,
        })?;

        // A separate async transport all the way down: a non-blocking Solana
        // client for the config and tree reads, an async Photon client for the
        // inclusion and non-inclusion proofs, and an async prover client.
        let async_rpc = AsyncSolanaRpc::new(env.rpc_url.clone());
        let async_indexer = AsyncZolanaIndexer::new(env.indexer_url.clone());
        // `local()` on both clients, so the two paths resolve the prover the
        // same way and a parity failure cannot be two different servers.
        let async_prover = AsyncProverClient::local();
        let runtime = tokio::runtime::Runtime::new()?;
        let proven = runtime.block_on(
            CustomRingTransfer::new(CustomRingTransferInput {
                ring: self.ring,
                sender: self.sender,
                prepared: self.asynchronous,
            })
            .with_tree(env.tree)
            .with_assets(&env.assets)
            .prove_async(AsyncTransferProofEnvironment {
                indexer: &async_indexer,
                rpc: &async_rpc,
                prover: &async_prover,
            }),
        )?;

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

        let signature = TransactSend {
            payer: self.sender,
            signers: &[],
            instruction: proven.instruction()?,
        }
        .send(rpc)?;
        let indexed = wait_for_indexed_transaction(indexer, self.auditor_tag, signature);
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
    auditor: &'a ViewingKey,
    signature: Signature,
}

impl AuditLookup<'_> {
    fn run(self, env: &TestEnv) -> Result<AuditedTransaction> {
        RingAudit::new(self.ring_program, self.auditor)
            .run(
                RingEnvironment {
                    indexer: env.client.indexer(),
                    origin: env.client.rpc(),
                },
                &env.assets,
            )?
            .transactions
            .into_iter()
            .find(|tx| tx.tx_signature == self.signature)
            .ok_or_else(|| anyhow!("transaction {} audited", self.signature))
    }
}

fn output_blinding(prepared: &PreparedTransfer, slot: u32) -> Result<[u8; 32]> {
    usize::try_from(slot)
        .ok()
        .and_then(|index| prepared.outputs.get(index))
        .map(|output| output.blinding)
        .ok_or_else(|| anyhow!("output slot {slot}"))
}

fn sorted_unspent_notes(wallet: &Wallet) -> Vec<(Address, u64, Option<Address>)> {
    let mut notes: Vec<_> = wallet
        .utxos
        .iter()
        .filter(|held| !held.spent)
        .map(|held| (held.utxo.asset, held.utxo.amount, held.utxo.ring_program_id))
        .collect();
    notes.sort_unstable();
    notes
}

fn expect_foreign_ring(result: Result<ProvenTransfer, TransferError>, ring: Address) -> Result<()> {
    match result {
        Err(TransferError::ForeignRing(refused)) if refused == ring => Ok(()),
        Err(other) => Err(anyhow!("expected ForeignRing({ring}), got {other}")),
        Ok(_) => Err(anyhow!(
            "expected ForeignRing({ring}), the transfer was proven"
        )),
    }
}
