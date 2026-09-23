use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{ComputeBudgetConfig, Rpc, SolanaRpc};
use zolana_keypair::{
    constants::BLINDING_LEN, NullifierKey, PublicKey, ShieldedAddress, ShieldedKeypair, SigningKey,
};
use zolana_program_test::{
    fixture,
    localnet::{FixtureLocalnet, LocalnetPorts},
    workspace_path,
};
use zolana_test_utils::test_validator_asserts::wait_for_indexed_utxo;
use zolana_transaction::{utxo::SppProofInputUtxo, utxo::Utxo, AssetRegistry, Data, SOL_MINT};
use zolana_user_registry_interface::user_registry_program_id;
use zolana_wallet::{sync_wallet, Deposit, DepositParams, Wallet};

// The whole per-transaction budget: a swap verifies an SPP proof and its own.
const TRANSACT_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

// SPL the maker shields into the order UTXO (source), and SOL the taker pays (destination).
pub const MAKER_SHIELD_SPL: u64 = 1_000_000_000;
pub const SOURCE_AMOUNT: u64 = 400_000_000;
pub const DESTINATION_AMOUNT: u64 = 250_000_000;

// Each actor is one ed25519 identity: the wallet's signing key doubles as the
// Solana fee payer (`to_solana_keypair`), and the wallet holds the asset
// registry and the synced spendable notes.
pub struct TestEnv {
    /// The localnet with its client and default tree. Dropping it stops the
    /// validator, so it lives as long as the test.
    pub localnet: FixtureLocalnet,
    pub maker: TestWallet,
    pub maker_input: SppProofInputUtxo,
    pub taker: TestWallet,
    pub spl_mint: Address,
}

pub struct TestWallet {
    pub wallet: Wallet,
    pub keypair: ShieldedKeypair,
}

impl std::ops::Deref for TestWallet {
    type Target = Wallet;
    fn deref(&self) -> &Self::Target {
        &self.wallet
    }
}

impl std::ops::DerefMut for TestWallet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.wallet
    }
}
/// Boot the localnet of test number `test` ([`LocalnetPorts::for_test`]); tests
/// running in parallel take distinct numbers.
pub fn setup(test: u16) -> Result<TestEnv> {
    let localnet = FixtureLocalnet::start(
        "zolana-swap",
        LocalnetPorts::for_test(test)?,
        vec![
            (
                Pubkey::new_from_array(*swap_program::ID.as_array()),
                workspace_path("target/deploy/swap_program.so"),
            ),
            (
                user_registry_program_id(),
                workspace_path("target/deploy/zolana_user_registry.so"),
            ),
        ],
    )?;
    let payer = fixture::payer();

    let spl_mint = fixture::spl_mint();
    let mut assets = AssetRegistry::default();
    assets.insert(fixture::SPL_ASSET_ID, spl_mint)?;
    let spl_funding = fixture::payer_token_account();

    let maker_solana_keypair = fixture::actor(0);
    let maker_seed: [u8; 32] = maker_solana_keypair.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    let maker_shielded_keypair =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&maker_seed))?;

    let taker_solana_keypair = fixture::actor(1);
    let taker_seed: [u8; 32] = taker_solana_keypair.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    let taker_shielded_keypair =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&taker_seed))?;

    // Fund the actors: shield the maker-funded SPL to the order authority so it
    // can authorize the data-bearing order output, and shield the taker's SOL
    // directly to the taker.
    let order_nullifier_key = NullifierKey::from_secret([0u8; BLINDING_LEN]);
    let order_authority_address = ShieldedAddress {
        signing_pubkey: PublicKey::from_ed25519(swap_sdk::order_authority_pda().as_array()),
        nullifier_pubkey: order_nullifier_key.pubkey()?,
        viewing_pubkey: maker_shielded_keypair.viewing_pubkey(),
    };
    let maker_deposit = Deposit::new(DepositParams {
        recipient: &order_authority_address,
        asset: spl_mint,
        amount: MAKER_SHIELD_SPL,
        spl_token_account: Some(spl_funding),
        spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
        memo: None,
    })?;
    let maker_view_tag = maker_deposit.view_tag();
    let maker_signature = maker_deposit.send(&localnet.client, &payer, localnet.tree, &payer)?;
    // The order authority is a PDA holding no viewing key, but a proofless
    // deposit publishes its UTXO in the clear, so the depositor-chosen view tag
    // reads it back from the indexer.
    let indexed_deposit = wait_for_indexed_utxo(&localnet.client, maker_view_tag, maker_signature);
    let maker_deposited = indexed_deposit
        .output_slot
        .proofless_output()
        .ok_or_else(|| anyhow!("indexed maker deposit is not a proofless UTXO"))?;
    let maker_input: SppProofInputUtxo = zolana_test_utils::utxo::wallet(
        Utxo {
            owner: order_authority_address.signing_pubkey,
            asset: assets.mint(&spl_mint)?,
            amount: maker_deposited.amount,
            blinding: maker_deposited.blinding,
            ring_program_id: None,
            data: Data::default(),
        },
        &order_nullifier_key,
        localnet.tree_id,
        indexed_deposit.output_slot.output_context.leaf_index,
        None,
        None,
    )?
    .into();
    assert_eq!(
        (maker_input.utxo.asset.asset, maker_input.utxo.amount),
        (spl_mint, MAKER_SHIELD_SPL)
    );
    Deposit::new(DepositParams {
        recipient: &taker_shielded_keypair.shielded_address()?,
        asset: SOL_MINT,
        amount: DESTINATION_AMOUNT,
        spl_token_account: None,
        spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
        memo: None,
    })?
    .send(&localnet.client, &payer, localnet.tree, &payer)?;

    let maker_address = maker_shielded_keypair
        .shielded_address()
        .map_err(|e| anyhow!("maker address: {e:?}"))?;
    let taker_address = taker_shielded_keypair
        .shielded_address()
        .map_err(|e| anyhow!("taker address: {e:?}"))?;

    // The taker's deposit is wallet-owned, so discover it through the indexer.
    // The maker-funded input is program-owned and retained explicitly above.
    let maker_wallet =
        Wallet::new(maker_address, assets.clone()).map_err(|e| anyhow!("maker wallet: {e:?}"))?;
    let mut taker_wallet =
        Wallet::new(taker_address, assets.clone()).map_err(|e| anyhow!("taker wallet: {e:?}"))?;
    sync_wallet(&mut taker_wallet, &taker_shielded_keypair, &localnet.client)
        .map_err(|e| anyhow!("sync taker deposit: {e:?}"))?;

    let env = TestEnv {
        localnet,
        maker: TestWallet {
            wallet: maker_wallet,
            keypair: maker_shielded_keypair,
        },
        maker_input,
        taker: TestWallet {
            wallet: taker_wallet,
            keypair: taker_shielded_keypair,
        },
        spl_mint,
    };

    // Guard the fixture: the retained order-authority input the make flows
    // spend must be exactly the note the maker deposit just funded.
    debug_assert_eq!(env.maker_input.utxo.asset.asset, spl_mint);
    debug_assert_eq!(env.maker_input.utxo.amount, MAKER_SHIELD_SPL);
    Ok(env)
}

// Submit a single (large) swap instruction as a transaction **v1** message:
// its 4096-byte limit is what holds a swap's account list and proof, which no
// longer fit a 1232-byte legacy packet. v1 has no address lookup table, and it
// carries the compute ceilings in the message header rather than in a
// compute-budget instruction. An unset ceiling means zero, not a default, so
// both are written. `payer` signs and pays.
pub fn send(rpc: &SolanaRpc, payer: &dyn Signer, ix: Instruction) -> Result<Signature> {
    Ok(rpc.create_and_send_transaction(
        std::slice::from_ref(&ix),
        payer.pubkey(),
        &[payer],
        ComputeBudgetConfig::new(TRANSACT_COMPUTE_UNIT_LIMIT),
    )?)
}
