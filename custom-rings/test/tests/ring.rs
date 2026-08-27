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
//! [`ring_value_leaves_and_enters_through_audited_transfers`] crosses the ring
//! boundary in both directions under the auditor and pins that a note of
//! another ring is refused before proving.

mod shared;

use std::{
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use custom_ring_interface::{RingProgramConfig, CONFIG_PDA_SEED, RING_PROGRAM_CONFIG};
use custom_ring_program::CustomRingError;
use custom_ring_sdk::{
    auditor_view_tag, CreateConfig, CreatePolicy, CustomRing, CustomRingTransact,
    CustomRingTransfer, CustomRingTransferInput, InitSppRingConfig, ProvenTransfer, RingDeposit,
    RingDepositReceipt, SetAuthority, TransferError, TransferProofEnvironment, V0WithLookupTable,
};
use shared::{
    custom_ring_program_id, prover_url, send, send_v0_expecting_rejection, setup, TestEnv,
};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_packet::PACKET_DATA_SIZE;
use solana_signature::Signature;
use solana_signer::Signer;
use zeroize::Zeroizing;
use zolana_client::{ProverClient, Rpc, ShieldedTransaction, SolanaRpc};
use zolana_interface::{
    instruction::{AssetDeposit, Deposit as SppDeposit, DepositAsset},
    pda,
    state::{
        discriminator::{PROTOCOL_CONFIG, RING_CONFIG, TREE_ACCOUNT_DISCRIMINATOR},
        tree_account_size, ProtocolConfig, RingConfig,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{random_blinding, P256Pubkey, ShieldedKeypair, ViewingKey};
use zolana_program_test::Rejection;
use zolana_ring_client::{AuditedOutput, AuditedTransaction, RingAudit, RingEnvironment};
use zolana_ring_rpc::{
    ChainSource, CreateAuditorKeyRequest, Hub, RingRpcError, RootSecret, TransactionSource,
    Unauthorized, Upstreams,
};
use zolana_test_utils::{
    smart_account,
    test_validator_asserts::{
        assert_account_unchanged, assert_transaction_compute_units, fetch_account, fetch_state,
        wait_for_indexed_transaction, wait_for_merkle_proof,
    },
};
use zolana_transaction::{
    instructions::{
        transact::{ConfidentialTransfer, PreparedTransfer},
        types::SppProofInputUtxo,
    },
    Data, KeypairWalletAuthority, Utxo, Wallet, DEFAULT_TAG_WINDOW, SOL_ASSET_ID, SOL_MINT,
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
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let dir = std::env::temp_dir().join(format!("zolana-ring-cli-{}", std::process::id()));
    let keys = dir.join("keys");
    std::fs::create_dir_all(&keys)?;
    let config_authority = Keypair::new();
    let upgrade_path = dir.join("upgrade.json");
    let config_path = dir.join("config.json");
    solana_keypair::write_keypair_file(&env.payer, &upgrade_path)
        .map_err(|e| anyhow!("write upgrade keypair {e}"))?;
    solana_keypair::write_keypair_file(&config_authority, &config_path)
        .map_err(|e| anyhow!("write config keypair {e}"))?;
    let auditor = ViewingKey::new();
    std::fs::write(
        keys.join("auditor.key.pub"),
        format!("{}\n", hex::encode(auditor.pubkey().as_bytes())),
    )?;
    let ring_toml = dir.join("ring.toml");
    let write_config = |ring_rpc: &str| {
        std::fs::write(
            &ring_toml,
            format!(
                "name = \"cli\"\ntarget = \"localnet\"\nprogram_id = \"{ring_program}\"\n\
                 authority_keypair = \"{}\"\nconfig_authority_keypair = \"{}\"\n\n\
                 [localnet]\nrpc = \"{}\"\nindexer = \"{}\"\nprover = \"{}\"\nring_rpc = \"{ring_rpc}\"\n\n\
                 [devnet]\nrpc = \"https://api.devnet.solana.com\"\nindexer = \"http://indexer.invalid\"\n\
                 prover = \"http://prover.invalid\"\nring_rpc = \"http://ring.invalid\"\n",
                upgrade_path.display(),
                config_path.display(),
                env.rpc_url,
                env.indexer_url,
                prover_url(),
            ),
        )
    };
    let cli = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/debug/zolana-ring"
    );
    let init = || -> Result<String> {
        let output = std::process::Command::new(cli)
            // The harness tree is not the default address, the policy step
            // must name it.
            .args([
                "--config",
                &ring_toml.to_string_lossy(),
                "init",
                "--entries-tree",
                &env.tree.to_string(),
            ])
            .output()
            .context("run zolana-ring init")?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if !output.status.success() {
            return Err(anyhow!("init failed\n{text}"));
        }
        Ok(text)
    };

    // 1. A local ring rpc lets the key file through, the config is created
    //    under the deployer and handed over in the same run.
    write_config("http://127.0.0.1:1")?;
    let first = init()?;
    assert!(first.contains("authority   transferred"), "{first}");
    let config = ring
        .read_config(rpc)?
        .ok_or_else(|| anyhow!("config after init"))?;
    assert_eq!(config.authority, config_authority.pubkey());
    assert_eq!(config.auditor_pubkey, auditor.pubkey());

    // 2. The rerun takes the key from the chain, so the hosted-looking rpc is
    //    never asked and the key file is not mistaken for a local key.
    write_config("http://ring.invalid:1")?;
    let second = init()?;
    assert!(second.contains("config      already present"), "{second}");
    assert!(second.contains("authority   already present"), "{second}");
    std::fs::remove_dir_all(dir)?;
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
    let authority = env.payer.pubkey();
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor_pk,
        entries_tree: env.tree,
    }
    .send(rpc)?;

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
    //    `ring_auth` PDA, and the content is built on chain from the config
    //    account, so the registered authority is the one asserted above and the
    //    authority-transact rail stays disabled.
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
    let rejection = send_v0_expecting_rejection(
        rpc,
        &env.sender.keypair,
        CustomRingTransact {
            ring,
            payer: sender_address,
            input_tree: env.tree,
            output_tree: env.tree,
            owner_signers: proven.owner_signers.clone(),
            interface_transfer_accounts: Vec::new(),
            proof: proven.proof,
            transact: tampered_data,
            state_root_index: 0,
            nullifier_root_index: 0,
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
    let hop_inputs = vec![SppProofInputUtxo::new(received, &env.recipient.keypair)];
    let mut hop_transfer = ConfidentialTransfer::new(
        env.recipient.keypair.shielded_address()?,
        hop_inputs,
        env.recipient.keypair.pubkey(),
    )
    .with_compact_change()
    .with_ring_program_id(ring_program);
    hop_transfer.send(
        &env.sender.keypair.shielded_address()?,
        SOL_MINT,
        SECOND_HOP_AMOUNT,
    )?;
    let hop_prepared = hop_transfer.prepare()?;
    let hop = RingTransfer {
        ring,
        sender: &env.recipient.keypair,
        prepared: hop_prepared,
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
        entries_tree: env.tree,
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
        amount: DEFAULT_DEPOSIT,
    }
    .send(rpc)?;
    let entry_input = deposited.spend();
    wait_for_merkle_proof(indexer, env.tree, entry_input.hash()?);
    let mut entry_transfer =
        ConfidentialTransfer::new(sender_address, vec![entry_input], sender.pubkey())
            .with_compact_change()
            .with_ring_program_id(ring_program);
    entry_transfer.send(&recipient_address, SOL_MINT, ENTRY_AMOUNT)?;
    let prepared = entry_transfer.prepare()?;
    let sender_change = SolNote {
        owner: sender,
        amount: ENTRY_CHANGE,
        blinding: output_blinding(&prepared, CHANGE_SLOT)?,
        ring_program_id: Some(ring_program),
    };
    let recipient_ring_note = SolNote {
        owner: recipient,
        amount: ENTRY_AMOUNT,
        blinding: output_blinding(&prepared, RECIPIENT_SLOT)?,
        ring_program_id: Some(ring_program),
    };
    let entry = RingTransfer {
        ring,
        sender,
        prepared,
        auditor_tag,
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
    let exit_change = SolNote {
        owner: sender,
        amount: EXIT_CHANGE,
        blinding: output_blinding(&prepared, CHANGE_SLOT)?,
        ring_program_id: Some(ring_program),
    };
    let recipient_default_note = SolNote {
        owner: recipient,
        amount: EXIT_AMOUNT,
        blinding: output_blinding(&prepared, RECIPIENT_SLOT)?,
        ring_program_id: None,
    };
    let exit = RingTransfer {
        ring,
        sender,
        prepared,
        auditor_tag,
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

    let foreign_note = SolNote {
        owner: sender,
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

fn lamports<R: Rpc>(rpc: &R, address: Address) -> Result<u64> {
    Ok(rpc
        .get_account(address)?
        .ok_or_else(|| anyhow!("account {address} not found"))?
        .lamports)
}

struct RegisterRing<'a> {
    ring: CustomRing,
    payer: &'a Keypair,
    auditor_pubkey: P256Pubkey,
    entries_tree: Address,
}

impl RegisterRing<'_> {
    fn send(self, rpc: &SolanaRpc) -> Result<()> {
        let authority = self.payer.pubkey();
        send(
            rpc,
            self.payer,
            &[CreateConfig {
                ring: self.ring,
                payer: authority,
                authority,
                auditor_pubkey: self.auditor_pubkey,
            }
            .instruction()?],
        )?;
        send(
            rpc,
            self.payer,
            &[InitSppRingConfig {
                ring: self.ring,
                payer: authority,
                authority,
            }
            .instruction()],
        )?;
        // Every transact loads the policy config, a rules-free ring pins the
        // empty table.
        send(
            rpc,
            self.payer,
            &[CreatePolicy {
                ring: self.ring,
                payer: authority,
                authority,
                entries_tree: self.entries_tree,
                shared_sources: vec![],
            }
            .instruction()?],
        )?;
        Ok(())
    }
}

/// The test's own view of a SOL note, spent and audited from the same values.
#[derive(Clone, Copy)]
struct SolNote<'a> {
    owner: &'a ShieldedKeypair,
    amount: u64,
    blinding: [u8; 32],
    ring_program_id: Option<Address>,
}

impl SolNote<'_> {
    fn spend(self) -> SppProofInputUtxo {
        SppProofInputUtxo::new(
            Utxo {
                owner: self.owner.signing_pubkey(),
                asset: SOL_MINT,
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
            asset: SOL_MINT,
            amount: self.amount,
            blinding: Zeroizing::new(self.blinding),
            ring_program_id: self.ring_program_id,
        })
    }
}

struct DefaultRingDeposit<'a> {
    depositor: &'a ShieldedKeypair,
    tree: Address,
    amount: u64,
}

impl<'a> DefaultRingDeposit<'a> {
    fn send(self, rpc: &SolanaRpc) -> Result<SolNote<'a>> {
        let blinding = random_blinding();
        let address = self.depositor.shielded_address()?;
        let deposit = SppDeposit {
            tree: self.tree,
            depositor: self.depositor.pubkey(),
            deposits: vec![AssetDeposit {
                asset: DepositAsset::Sol,
                view_tag: address.viewing_pubkey.x(),
                owner: address.owner_hash()?,
                blinding,
                amount: self.amount,
                utxo_data: None,
                memo: None,
            }],
        }
        .instruction()?;
        send(rpc, self.depositor, &[deposit])?;
        Ok(SolNote {
            owner: self.depositor,
            amount: self.amount,
            blinding,
            ring_program_id: None,
        })
    }
}

struct RingTransfer<'a> {
    ring: CustomRing,
    sender: &'a ShieldedKeypair,
    prepared: PreparedTransfer,
    auditor_tag: [u8; 32],
}

struct RingTransferReceipt {
    signature: Signature,
    indexed: ShieldedTransaction,
}

impl RingTransfer<'_> {
    fn send(self, env: &TestEnv, prover: &ProverClient) -> Result<RingTransferReceipt> {
        let rpc = env.client.rpc();
        let indexer = env.client.indexer();
        let proven = CustomRingTransfer::new(CustomRingTransferInput {
            ring: self.ring,
            sender: self.sender,
            prepared: self.prepared,
        })
        .with_tree(env.tree)
        .with_assets(&env.assets)
        .prove(TransferProofEnvironment {
            indexer,
            rpc,
            prover,
        })?;
        let signature = V0WithLookupTable {
            payer: self.sender,
            signers: &[],
            instruction: proven.instruction()?,
        }
        .send(rpc)?;
        let indexed = wait_for_indexed_transaction(indexer, self.auditor_tag, signature);
        Ok(RingTransferReceipt { signature, indexed })
    }
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
