// This module is included via `mod shared;` in every localnet test binary in
// this crate; each binary only exercises the subset of setup outputs relevant
// to its own flow, so unused-item warnings here are compilation-unit noise, not
// dead code in the crate as a whole. Only the localnet bring-up (`setup`) and
// the generic v1 transaction sender (`send`) live here; every dynamic-swap
// domain flow is inlined into the test that uses it.
#![allow(dead_code)]

use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use dynamic_swap_program::state::Pair;
use dynamic_swap_sdk::{
    instructions::{create_pair::CreatePair, deposit_liquidity::DepositLiquidity},
    pair_pda, pool_authority_pda,
    state::{IndexedPoolNote, PoolUtxo},
};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{ComputeBudgetConfig, Rpc, SolanaRpc};
use zolana_interface::{pda, state::SplAssetRegistry};
use zolana_keypair::{PublicKey, ShieldedKeypair, ShieldedPda, SigningKey};
use zolana_program::instruction::CreateSplInterface;
use zolana_program_test::{
    fixture,
    localnet::{FixtureLocalnet, LocalnetPaths, LocalnetPorts},
    workspace_path,
};
use zolana_test_utils::{
    spl::{create_mint, create_token_account, mint_to},
    test_validator_asserts::{wait_for_indexed_utxo, wait_for_merkle_proof},
};
use zolana_transaction::{
    instructions::transact::asset_field, utxo::Blinding, AssetRegistry, Mint,
};
use zolana_user_registry_interface::user_registry_program_id;
use zolana_wallet::{ensure_registered, Deposit, DepositParams};

// The whole per-transaction budget: an escrow settle verifies an SPP proof.
const TRANSACT_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

/// The fixture's SPL mint is the pair's source asset (escrowed by the taker);
/// a second SPL mint, registered at boot, is the destination asset (the maker
/// deposits it into the pool, the recipient is paid it on settle). Both are the
/// pool's asset ids, which the tests also pass into `create_pair`.
pub const SOURCE_ASSET_ID: u64 = fixture::SPL_ASSET_ID;
pub const DESTINATION_ASSET_ID: u64 = fixture::SPL_ASSET_ID + 1;
pub const PRICE_TOLERANCE: u64 = 1;
pub const MIN_ORDER_AMOUNT: u64 = 1;

pub const USER_SPL_SHIELD: u64 = 1_000_000_000;
/// Minted to the maker's destination-asset token account; the budget its pool
/// deposits draw from.
pub const MAKER_DEST_BALANCE: u64 = 10_000_000_000;

/// Each actor is one ed25519 identity: the wallet's signing key doubles as the
/// Solana fee payer (`to_solana_keypair`), and the wallet holds the asset
/// registry and (for real, non-PDA actors) synced spendable notes.
pub struct TestWallet {
    pub keypair: ShieldedKeypair,
}

impl TestWallet {
    pub fn address(&self) -> Result<zolana_keypair::ShieldedAddress> {
        self.keypair
            .shielded_address()
            .map_err(|e| anyhow!("shielded address: {e:?}"))
    }

    pub fn owner_hash(&self) -> Result<[u8; 32]> {
        self.keypair
            .owner_hash()
            .map_err(|e| anyhow!("owner hash: {e:?}"))
    }
}

pub struct TestEnv {
    /// The localnet with its client and default tree. Dropping it stops the
    /// validator, so it lives as long as the test.
    pub localnet: FixtureLocalnet,
    pub authority: TestWallet,
    pub user: TestWallet,
    pub spl_mint: Address,
    /// The pair's destination asset: a second SPL mint the maker deposits into
    /// the pool and the recipient is paid on settle.
    pub dest_mint: Address,
    /// The maker's destination-asset token account (`MAKER_DEST_BALANCE`
    /// minted in `setup()`): the pool deposit source and the withdrawal
    /// destination.
    pub authority_dest_token: Pubkey,
    pub assets: AssetRegistry,
    /// The blinding of the user's own funding UTXO shielded in `setup()`
    /// (`USER_SPL_SHIELD` of `spl_mint`), read back from the indexer: SPP
    /// derives it from the leaf index the output lands at, so it is not known
    /// before the deposit executes.
    pub user_spl_blinding: Blinding,
}

impl TestEnv {
    pub fn source_mint(&self) -> Mint {
        Mint::new(self.spl_mint, SOURCE_ASSET_ID)
    }

    pub fn destination_mint(&self) -> Mint {
        Mint::new(self.dest_mint, DESTINATION_ASSET_ID)
    }

    /// The leaf index of a committed UTXO, read from the indexer.
    pub fn leaf_index(&self, utxo_hash: [u8; 32]) -> u64 {
        wait_for_merkle_proof(
            self.localnet.client.indexer(),
            self.localnet.tree,
            utxo_hash,
        )
        .leaf_index
    }
}

/// Boot the localnet of test number `test` ([`LocalnetPorts::for_test`]); tests
/// running in parallel take distinct numbers.
pub fn setup(test: u16) -> Result<TestEnv> {
    let localnet = FixtureLocalnet::start(
        "zolana-dynamic-swap",
        LocalnetPorts::for_test(test)?,
        vec![
            (
                dynamic_swap_program::ID,
                workspace_path("target/deploy/dynamic_swap_program.so"),
            ),
            (
                user_registry_program_id(),
                workspace_path("target/deploy/zolana_user_registry.so"),
            ),
        ],
        &LocalnetPaths::workspace(),
    )?;
    let payer = fixture::payer();
    let spl_mint = fixture::spl_mint();
    let spl_funding = fixture::payer_token_account();

    let authority_solana = fixture::actor(0);
    let authority_seed: [u8; 32] = authority_solana.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    let authority_shielded_keypair =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&authority_seed))?;

    let user_solana = fixture::actor(1);
    let user_seed: [u8; 32] = user_solana.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    let user_shielded_keypair =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&user_seed))?;

    // Register a second SPL asset as the pair's destination: the maker
    // deposits it into the pool from a plain token account and withdraws back
    // to the same account. The fixture makes SPL interface creation
    // permissionless, so the payer registers it.
    let dest_mint = create_mint(&localnet.client, &payer)?;
    let dest_interface_ix = CreateSplInterface {
        authority: payer.pubkey(),
        mint: dest_mint,
        token_program: pda::spl_token_program_id(),
    }
    .instruction();
    localnet.client.rpc().create_and_send_transaction(
        &[dest_interface_ix],
        payer.pubkey(),
        &[&payer],
        ComputeBudgetConfig::for_instruction_count(1),
    )?;
    let dest_registry = localnet
        .client
        .rpc()
        .get_account(pda::spl_asset_registry(&dest_mint))?
        .ok_or_else(|| anyhow!("destination asset registry missing"))?;
    let dest_asset_id = SplAssetRegistry::from_account_bytes(&dest_registry.data)
        .map_err(|e| anyhow!("destination asset registry: {e:?}"))?
        .asset_id;
    if dest_asset_id != DESTINATION_ASSET_ID {
        bail!(
            "destination mint registered as asset {dest_asset_id}, expected {DESTINATION_ASSET_ID}"
        );
    }
    let authority_dest_token = create_token_account(
        &localnet.client,
        &payer,
        &dest_mint,
        &authority_solana.pubkey(),
    )?;
    mint_to(
        &localnet.client,
        &payer,
        &dest_mint,
        &authority_dest_token,
        MAKER_DEST_BALANCE,
    )?;

    // Shield the user's SPL (the source asset it will escrow). The pool's own
    // liquidity is committed per pair by each test (`deposit_pool_liquidity`),
    // not funded here.
    let user_address = user_shielded_keypair
        .shielded_address()
        .map_err(|e| anyhow!("user address: {e:?}"))?;
    let user_deposit = Deposit::new(DepositParams {
        recipient: &user_address,
        asset: spl_mint,
        amount: USER_SPL_SHIELD,
        spl_token_account: Some(spl_funding),
        spl_token_program: Some(pda::spl_token_program_id()),
        memo: None,
    })?;
    let user_view_tag = user_deposit.view_tag();
    let user_signature = user_deposit.send(&localnet.client, &payer, localnet.tree, &payer)?;
    // A proofless deposit publishes its UTXO in the clear, so read it back from
    // the indexer.
    let user_spl_blinding = wait_for_indexed_utxo(&localnet.client, user_view_tag, user_signature)
        .output_slot
        .proofless_output()
        .ok_or_else(|| anyhow!("indexed user deposit is not a proofless UTXO"))?
        .blinding;

    // Register both parties in the user directory (keyed by their Solana
    // pubkeys), so either side can resolve the other's shielded address.
    ensure_registered(
        &localnet.client,
        &authority_solana,
        &authority_shielded_keypair,
    )
    .map_err(|e| anyhow!("register authority: {e:?}"))?;
    ensure_registered(&localnet.client, &user_solana, &user_shielded_keypair)
        .map_err(|e| anyhow!("register user: {e:?}"))?;

    let mut assets = AssetRegistry::default();
    assets
        .insert(SOURCE_ASSET_ID, spl_mint)
        .map_err(|e| anyhow!("asset registry insert: {e:?}"))?;
    assets
        .insert(DESTINATION_ASSET_ID, dest_mint)
        .map_err(|e| anyhow!("asset registry insert: {e:?}"))?;

    Ok(TestEnv {
        localnet,
        authority: TestWallet {
            keypair: authority_shielded_keypair,
        },
        user: TestWallet {
            keypair: user_shielded_keypair,
        },
        spl_mint,
        dest_mint,
        authority_dest_token,
        assets,
        user_spl_blinding,
    })
}

/// The maker's shielded identity of the pair's escrow_authority PDA: the
/// PDA-role viewing key derived from the maker's own viewing key, paired with
/// the public zero-secret nullifier key (see
/// `dynamic_swap_sdk::state::escrow_authority_identity`). The viewing pubkey is
/// what `create_pair` publishes as `Pair::maker_encryption_pubkey`.
pub fn escrow_authority_identity(
    authority: &ShieldedKeypair,
    pair: &Pubkey,
) -> Result<ShieldedPda> {
    dynamic_swap_sdk::state::escrow_authority_identity(pair, &authority.viewing_key)
        .map_err(|e| anyhow!("escrow authority identity: {e:?}"))
}

/// The maker's shielded identity of the pair's pool_authority PDA, for pool
/// note discovery/decryption (see `dynamic_swap_sdk::state::pool_authority_identity`).
pub fn pool_authority_identity(authority: &ShieldedKeypair, pair: &Pubkey) -> Result<ShieldedPda> {
    dynamic_swap_sdk::state::pool_authority_identity(pair, &authority.viewing_key)
        .map_err(|e| anyhow!("pool authority identity: {e:?}"))
}

/// `setup()` plus a registered SPL(source)->SPL(destination) pair at `price`
/// with the maker's settle window `expiry_slots` and the per-escrow
/// reservation size `max_order_size`. The pool starts empty; tests commit
/// liquidity with `deposit_pool_liquidity`. Returns the env and the pair PDA.
/// Tests that exercise `create_pair` itself (pair/negative) keep plain
/// `setup()`.
pub fn setup_with_pair(
    test: u16,
    price: u64,
    expiry_slots: u64,
    max_order_size: u64,
) -> Result<(TestEnv, Pubkey)> {
    let env = setup(test)?;
    let authority_solana = &env.authority.keypair;
    let pair = pair_pda(
        &authority_solana.pubkey(),
        SOURCE_ASSET_ID,
        DESTINATION_ASSET_ID,
    );
    let source_asset = asset_field(&env.spl_mint).map_err(|e| anyhow!("source asset: {e:?}"))?;
    let destination_asset =
        asset_field(&env.dest_mint).map_err(|e| anyhow!("destination asset: {e:?}"))?;
    let maker_encryption_pubkey = *escrow_authority_identity(&env.authority.keypair, &pair)?
        .viewing_pubkey()
        .as_bytes();
    // The settle receipt (the escrowed source asset) goes to the maker's own
    // wallet.
    let maker_receipt_owner_hash = env.authority.owner_hash()?;
    let create_pair_ix = CreatePair {
        payer: authority_solana.pubkey(),
        pair,
        price,
        source_asset_id: SOURCE_ASSET_ID,
        destination_asset_id: DESTINATION_ASSET_ID,
        expiry_slots,
        max_order_size,
        price_tolerance: PRICE_TOLERANCE,
        min_order_amount: MIN_ORDER_AMOUNT,
        source_asset,
        destination_asset,
        maker_receipt_owner_hash,
        maker_encryption_pubkey,
    }
    .instruction()
    .map_err(|e| anyhow!("create_pair instruction: {e:?}"))?;
    env.localnet
        .client
        .rpc()
        .create_and_send_transaction(
            &[create_pair_ix],
            authority_solana.pubkey(),
            &[&authority_solana],
            ComputeBudgetConfig::for_instruction_count(1),
        )
        .map_err(|e| anyhow!("send create_pair: {e:?}"))?;
    Ok((env, pair))
}

/// Photon indexes a send asynchronously, poll until the value appears or the deadline passes.
pub fn wait_until<T>(what: &str, mut poll: impl FnMut() -> Result<Option<T>>) -> Result<T> {
    const DEADLINE: Duration = Duration::from_secs(30);
    const INTERVAL: Duration = Duration::from_millis(500);
    let start = Instant::now();
    loop {
        if let Some(value) = poll()? {
            return Ok(value);
        }
        if start.elapsed() >= DEADLINE {
            return Err(anyhow!("{what} did not appear within {DEADLINE:?}"));
        }
        std::thread::sleep(INTERVAL);
    }
}

/// Commit `amount` of the destination asset to the pair's pool: the maker
/// deposits from its SPL token account into a new fully public pool note
/// (`booked = amount`). Returns the created note's full preimage and leaf. SPP
/// derives the deposit blinding on-chain, so it is read back from the indexer.
pub fn deposit_pool_liquidity(env: &TestEnv, pair: Pubkey, amount: u64) -> Result<IndexedPoolNote> {
    let authority_solana = &env.authority.keypair;
    let ix = DepositLiquidity {
        depositor: authority_solana.pubkey(),
        pair,
        tree: env.localnet.tree,
        mint: env.dest_mint,
        user_token: env.authority_dest_token,
        token_program: zolana_interface::pda::spl_token_program_id(),
        amount,
    }
    .instruction()
    .map_err(|e| anyhow!("deposit_liquidity instruction: {e:?}"))?;
    let signature = env
        .localnet
        .client
        .rpc()
        .create_and_send_transaction(
            &[ix],
            authority_solana.pubkey(),
            &[&authority_solana],
            ComputeBudgetConfig::for_instruction_count(1),
        )
        .map_err(|e| anyhow!("send deposit_liquidity: {e:?}"))?;
    let view_tag = PublicKey::from_pda(&pool_authority_pda(&pair))
        .confidential_view_tag()
        .map_err(|e| anyhow!("pool view tag: {e:?}"))?;
    let indexed = wait_for_indexed_utxo(env.localnet.client.indexer(), view_tag, signature);
    let blinding = indexed
        .output_slot
        .proofless_output()
        .ok_or_else(|| anyhow!("indexed pool deposit is not a proofless UTXO"))?
        .blinding;
    Ok(IndexedPoolNote {
        note: PoolUtxo {
            asset: env.destination_mint(),
            amount,
            booked: amount,
            blinding,
        },
        leaf_index: indexed.output_slot.output_context.leaf_index,
    })
}

/// `discover_pool_notes` with a short retry: the scan can race photon's
/// indexing of a transaction this same test just sent.
pub fn discover_pool_notes_with_retry(
    env: &TestEnv,
    owner: &ShieldedPda,
    expected_min: usize,
) -> Result<Vec<dynamic_swap_sdk::discovery::DiscoveredPoolNote>> {
    const MAX_ATTEMPTS: usize = 40;
    for _ in 0..MAX_ATTEMPTS {
        let notes =
            dynamic_swap_sdk::discovery::discover_pool_notes(env.localnet.client.indexer(), owner)
                .map_err(|e| anyhow!("discover pool notes: {e:?}"))?;
        if notes.len() >= expected_min {
            return Ok(notes);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    // Debug context for a scan that never converged: what does each endpoint
    // hold for the tag?
    let tag = owner
        .shielded_address()
        .map_err(|e| anyhow!("{e:?}"))?
        .confidential_view_tag()
        .map_err(|e| anyhow!("{e:?}"))?;
    let utxos = env
        .localnet
        .client
        .indexer()
        .get_encrypted_utxos_by_tags(vec![tag], None, None, None)
        .map(|r| r.matches.len());
    let txs = env
        .localnet
        .client
        .indexer()
        .get_shielded_transactions_by_tags(vec![tag], None, None, None)
        .map(|r| r.transactions.len());
    Err(anyhow!(
        "expected at least {expected_min} pool notes to be indexed; tag {} -> encrypted_utxos: {utxos:?}, shielded_txs: {txs:?}",
        hex(&tag),
    ))
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Read the pair account's state.
pub fn read_pair(env: &TestEnv, pair: Pubkey) -> Result<Pair> {
    let account = env
        .localnet
        .client
        .rpc()
        .get_account(pair)
        .map_err(|e| anyhow!("get pair account: {e:?}"))?
        .ok_or_else(|| anyhow!("pair account not found"))?;
    Ok(*bytemuck::from_bytes::<Pair>(&account.data))
}

/// Assert the pair's public liquidity accounting.
pub fn assert_liquidity(
    env: &TestEnv,
    pair: Pubkey,
    expected_available_liquidity: u64,
    expected_reservations: u64,
    context: &str,
) -> Result<()> {
    let state = read_pair(env, pair)?;
    assert_eq!(
        (state.available_liquidity, state.open_reservations),
        (expected_available_liquidity, expected_reservations),
        "{context}: (available_liquidity, open_reservations) mismatch"
    );
    Ok(())
}

/// The SPL token account's balance (amount field at bytes 64..72).
pub fn token_balance(env: &TestEnv, token_account: Pubkey) -> Result<u64> {
    let account = env
        .localnet
        .client
        .rpc()
        .get_account(token_account)
        .map_err(|e| anyhow!("get token account: {e:?}"))?
        .ok_or_else(|| anyhow!("token account not found"))?;
    let bytes: [u8; 8] = account
        .data
        .get(64..72)
        .ok_or_else(|| anyhow!("token account data too short"))?
        .try_into()
        .expect("8-byte slice");
    Ok(u64::from_le_bytes(bytes))
}

/// Poll until the validator's slot is strictly past `target`. Used by the
/// cancel flow to cross an escrow's expiry (`created_at + expiry_slots`)
/// deterministically instead of sleeping a guessed duration.
pub fn wait_for_slot(client: &solana_rpc_client::rpc_client::RpcClient, target: u64) -> Result<()> {
    loop {
        if get_slot_with_retry(client)? > target {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The validator's RPC connection can transiently drop a request right after
/// a long CPU-bound stretch in this same process (e.g. the in-process Groth16
/// proving `escrow_open`/`pool_settle` need), even though the
/// validator itself is healthy -- retry a few times with a short backoff
/// rather than fail the whole flow on one dropped connection.
pub fn get_slot_with_retry(client: &solana_rpc_client::rpc_client::RpcClient) -> Result<u64> {
    const MAX_ATTEMPTS: usize = 5;
    let mut last_err = None;
    for attempt in 0..MAX_ATTEMPTS {
        match client.get_slot() {
            Ok(slot) => return Ok(slot),
            Err(e) => {
                last_err = Some(e);
                if attempt + 1 < MAX_ATTEMPTS {
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        }
    }
    Err(anyhow!(
        "get_slot: {}",
        last_err.expect("loop always sets last_err before exhausting attempts")
    ))
}

/// Submit a single (large) instruction as a transaction **v1** message: its
/// 4096-byte limit is what holds the dynamic-swap account lists once the
/// ciphertexts are included, which no longer fit a 1232-byte legacy packet. v1
/// has no address lookup table, and it carries the compute ceilings in the
/// message header rather than in a compute-budget instruction. An unset ceiling
/// means zero, not a default, so both are written. `fee_payer` pays and signs,
/// plus any `extra_signers`.
pub fn send(
    rpc: &SolanaRpc,
    fee_payer: &dyn Signer,
    extra_signers: &[&dyn Signer],
    ix: Instruction,
) -> Result<Signature> {
    let mut signers: Vec<&dyn Signer> = vec![fee_payer];
    signers.extend(extra_signers.iter().copied());
    Ok(rpc.create_and_send_transaction(
        std::slice::from_ref(&ix),
        fee_payer.pubkey(),
        &signers,
        ComputeBudgetConfig::new(TRANSACT_COMPUTE_UNIT_LIMIT),
    )?)
}
