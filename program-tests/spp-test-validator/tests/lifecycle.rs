//! Localnet + Photon BDD lifecycle tests for the shielded pool.
//!
//! Each scenario runs against a freshly restarted `solana-test-validator` + Photon
//! indexer (the protocol config is a global singleton, so scenarios cannot share a
//! validator). The prover server is started once and persists across scenarios.
//!
//! The invariant every scenario exercises: a note that was indexed by Photon is
//! recovered the way production does -- `Wallet::sync` (decryption for transfers) --
//! and then actually spent (its nullifier consumed). Recovery is checked with a
//! full-struct `assert_eq` over the wallet's `WalletUtxo` set, tracked in the World.

mod steps;

use std::collections::BTreeMap;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use cucumber::World as _;
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_client::{
    spawn_prover, CircuitType, InputTreeIndices,
    NullifierNonInclusionProof as ProverNullifierProof, Proof, ProofCompressed, ProverClient, Rpc,
    ShieldedTransaction, SolanaRpc, SpendProof, SpendUtxo, StateInclusionProof,
    Transaction as ClientTransaction, ZolanaIndexer, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use zolana_interface::{
    instruction::{CreateProtocolConfig, Deposit, Transact},
    state::tree_account_size,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::{create_tree_instructions, ZolanaProgramTest};
use zolana_transaction::transfer::{OutputCiphertext, TransferEncryptedUtxos, SENDER_SLOT_COUNT};
use zolana_transaction::utxo::derive_blinding;
use zolana_transaction::{
    AssetRegistry, Data, SyncTransaction, TransactionEncryption, Utxo, Wallet, WalletUtxo,
    DEFAULT_TAG_WINDOW, SOL_MINT, TRANSFER,
};

const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
const DEFAULT_INDEXER_URL: &str = "http://127.0.0.1:8784";
const INDEXER_TIMEOUT: Duration = Duration::from_secs(120);
const ZERO: [u8; 32] = [0u8; 32];
// Blinding positions in the fixed-position output layout.
const SOL_CHANGE_POSITION: u8 = 1;
const RECIPIENT_POSITION_BASE: u8 = 2;

/// One shielded participant: its key material, the wallet it syncs into, the
/// notes it can currently spend, and the full set of notes its wallet is expected
/// to hold after a sync (with `spent` flags), tracked for full-struct assertions.
pub struct Actor {
    keypair: ShieldedKeypair,
    wallet: Wallet,
    spendable: Vec<Utxo>,
    expected: Vec<WalletUtxo>,
    send_counter: u64,
    deposit_counter: u8,
}

impl Actor {
    fn new() -> Result<Self> {
        let keypair = ShieldedKeypair::new()?;
        let wallet = Wallet::new(keypair.clone())?;
        Ok(Self {
            keypair,
            wallet,
            spendable: Vec::new(),
            expected: Vec::new(),
            send_counter: 0,
            deposit_counter: 0,
        })
    }
}

#[derive(cucumber::World)]
#[world(init = Self::new)]
pub struct LifecycleWorld {
    rpc: SolanaRpc,
    indexer: ZolanaIndexer,
    assets: AssetRegistry,
    payer: Keypair,
    tree: Pubkey,
    tree_address: Address,
    actors: BTreeMap<String, Actor>,
    indexed: Vec<SyncTransaction>,
}

impl std::fmt::Debug for LifecycleWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LifecycleWorld")
    }
}

impl LifecycleWorld {
    async fn new() -> Result<Self> {
        restart_localnet();
        start_prover()?;

        let rpc_url =
            std::env::var("ZOLANA_LOCALNET_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.into());
        let indexer_url =
            std::env::var("ZOLANA_INDEXER_URL").unwrap_or_else(|_| DEFAULT_INDEXER_URL.into());
        let mut rpc = SolanaRpc::new(rpc_url);
        let indexer = ZolanaIndexer::new(indexer_url);
        let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        rpc.assert_executable(&program_id)?;

        let payer = Keypair::new();
        let authority = Keypair::new();
        rpc.airdrop(&payer.pubkey(), 100_000_000_000)?;
        rpc.airdrop(&authority.pubkey(), 1_000_000_000)?;

        let authority_bytes = authority.pubkey().to_bytes();
        let create_config = CreateProtocolConfig {
            authority: authority.pubkey(),
            protocol_authority: authority_bytes.into(),
            tree_creation_authority: authority_bytes.into(),
            tree_creation_is_permissionless: false,
            forester_authority: authority_bytes.into(),
            zone_creation_authority: authority_bytes.into(),
            zone_creation_is_permissionless: false,
            merge_authority: authority_bytes.into(),
        }
        .instruction();
        send_transaction(
            &mut rpc,
            &[create_config],
            &authority.pubkey(),
            &[&authority],
        )?;

        let tree = Keypair::new();
        let create_tree = create_tree_instructions(
            &rpc,
            &payer.pubkey(),
            &authority.pubkey(),
            &tree.pubkey(),
            tree_account_size() as u64,
        )?;
        send_transaction(
            &mut rpc,
            &create_tree,
            &payer.pubkey(),
            &[&payer, &tree, &authority],
        )?;

        let tree_address = Address::new_from_array(tree.pubkey().to_bytes());
        Ok(Self {
            rpc,
            indexer,
            assets: AssetRegistry::default(),
            payer,
            tree: tree.pubkey(),
            tree_address,
            actors: BTreeMap::new(),
            indexed: Vec::new(),
        })
    }

    fn ensure_actor(&mut self, name: &str) -> Result<()> {
        if !self.actors.contains_key(name) {
            self.actors.insert(name.to_string(), Actor::new()?);
        }
        Ok(())
    }

    fn actor(&self, name: &str) -> &Actor {
        self.actors.get(name).expect("actor exists")
    }

    fn actor_mut(&mut self, name: &str) -> &mut Actor {
        self.actors.get_mut(name).expect("actor exists")
    }

    /// Shield SOL to an actor as a discoverable proofless deposit and record the
    /// resulting note as spendable (deposits are funded here; recovering them via
    /// `Wallet::sync` needs the indexer to surface `DepositView`, tracked separately).
    pub fn shield_sol(&mut self, name: &str, amount: u64) -> Result<()> {
        self.ensure_actor(name)?;
        let payer = self.payer.insecure_clone();
        let tree = self.tree;
        let (utxo, deposit) = {
            let actor = self.actor_mut(name);
            let position = actor.deposit_counter;
            actor.deposit_counter += 1;
            let mut seed = [0u8; 31];
            seed[0] = 0xD0 ^ position;
            seed[1] = position;
            let data =
                ZolanaProgramTest::wallet_sol_shield_data(amount, &actor.wallet, &seed, position)?;
            let blinding = actor
                .keypair
                .viewing_key
                .derive_proofless_blinding(&data.salt)?;
            let utxo = Utxo {
                owner: actor.keypair.signing_pubkey(),
                asset: SOL_MINT,
                amount,
                blinding,
                zone_program_id: None,
                data: Data::default(),
            };
            (utxo, data)
        };

        let nullifier_pk = self.actor(name).keypair.nullifier_key.pubkey()?;
        let utxo_hash = utxo.hash(&nullifier_pk, &ZERO, &ZERO)?;
        let shield_ix = Deposit {
            tree,
            depositor: payer.pubkey(),
            spl: None,
            view_tag: deposit.view_tag,
            owner_utxo_hash: deposit.owner_utxo_hash,
            salt: deposit.salt,
            public_amount: deposit.public_amount,
            program_data_hash: deposit.program_data_hash,
            program_data: deposit.program_data,
            cpi_signer: deposit.cpi_signer,
        }
        .instruction();
        send_transaction(&mut self.rpc, &[shield_ix], &payer.pubkey(), &[&payer])?;
        wait_for_merkle_proof(&self.indexer, self.tree_address, utxo_hash)?;
        self.actor_mut(name).spendable.push(utxo);
        Ok(())
    }

    /// Build, prove (P256), and submit a SOL transfer of `amount` from `from` to
    /// `to`, consuming one of `from`'s spendable notes. Records the expected
    /// recipient note and sender change note (decrypting the sender bundle to learn
    /// the blinding seed), and marks a consumed recovered input spent.
    pub fn transfer_sol(&mut self, from: &str, to: &str, amount: u64) -> Result<Signature> {
        self.ensure_actor(from)?;
        self.ensure_actor(to)?;

        // Only the transfer_p256_2_3 proving key is available, and the client does
        // not pad inputs to the shape, so every transfer spends exactly two real
        // SOL notes (the supported (2, 3) shape).
        let inputs: Vec<Utxo> = {
            let actor = self.actor_mut(from);
            let mut taken = Vec::new();
            for _ in 0..2 {
                let pos = actor
                    .spendable
                    .iter()
                    .position(|u| u.asset == SOL_MINT)
                    .ok_or_else(|| anyhow!("{from} needs two spendable SOL notes"))?;
                taken.push(actor.spendable.remove(pos));
            }
            taken
        };
        let total: u64 = inputs.iter().map(|u| u.amount).sum();
        if total < amount {
            return Err(anyhow!("{from} inputs {total} cannot cover {amount}"));
        }
        let change_amount = total - amount;

        let from_keypair = self.actor(from).keypair.clone();
        let to_keypair = self.actor(to).keypair.clone();
        let to_address = to_keypair.shielded_address()?;
        let to_view_tag = to_keypair.recipient_bootstrap_view_tag();
        let payer_address = Address::new_from_array(self.payer.pubkey().to_bytes());
        let send_index = self.actor(from).send_counter;
        let sender_view_tag = from_keypair.get_sender_view_tag(send_index)?;
        self.actor_mut(from).send_counter += 1;

        let spends: Vec<SpendUtxo> = inputs
            .iter()
            .map(|u| SpendUtxo::from((u.clone(), &from_keypair)))
            .collect();
        let mut tx =
            ClientTransaction::new(from_keypair.shielded_address()?, spends, payer_address);
        tx.send(&to_address, SOL_MINT, amount, to_view_tag)?;
        let signed = tx.sign(&from_keypair, &self.assets, sender_view_tag)?;

        let commitments = signed.input_commitments()?;
        let mut spend_proofs = Vec::new();
        let mut tree_indices = Vec::new();
        for commitment in &commitments {
            let state_proof =
                wait_for_merkle_proof(&self.indexer, self.tree_address, commitment.utxo_hash)?;
            let nullifier_proof = wait_for_non_inclusion_proof(
                &self.indexer,
                self.tree_address,
                commitment.nullifier,
            )?;
            let state_path: [[u8; 32]; STATE_TREE_HEIGHT] = state_proof
                .path
                .clone()
                .try_into()
                .map_err(|_| anyhow!("unexpected state path length"))?;
            let low_path: [[u8; 32]; NULLIFIER_TREE_HEIGHT] = nullifier_proof
                .path
                .clone()
                .try_into()
                .map_err(|_| anyhow!("unexpected nullifier path length"))?;
            spend_proofs.push(SpendProof {
                state: StateInclusionProof {
                    path_elements: state_path,
                    leaf_index: state_proof.leaf_index,
                    root: state_proof.root,
                },
                nullifier: ProverNullifierProof {
                    low_value: nullifier_proof.low_element,
                    next_value: nullifier_proof.high_element,
                    low_path_elements: low_path,
                    low_leaf_index: nullifier_proof.low_element_index,
                    root: nullifier_proof.root,
                },
            });
            tree_indices.push(InputTreeIndices {
                utxo_tree_root_index: state_proof.root_index,
                nullifier_tree_root_index: nullifier_proof.root_index,
                tree_index: 0,
                eddsa_signer_index: 0,
            });
        }

        let prover = match signed.clone().into_prover(&spend_proofs)? {
            CircuitType::P256(prover) => prover,
            CircuitType::Eddsa(_) => return Err(anyhow!("expected the P256 rail")),
        };
        let proof = ProverClient::local().prove_transfer_p256(&prover.build()?.inputs)?;
        let ix_data = signed.into_transact_ix_data(pack_proof(&proof)?, Some(&tree_indices))?;

        let transfer_ix = Transact {
            payer: self.payer.pubkey(),
            tree: self.tree,
            cpi_signer: None,
            withdrawal: None,
            data: ix_data,
        }
        .instruction();
        let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        let payer = self.payer.insecure_clone();
        let sig = send_transaction(
            &mut self.rpc,
            &[compute_budget, transfer_ix],
            &payer.pubkey(),
            &[&payer],
        )?;

        let indexed = wait_for_indexed_transaction(&self.indexer, to_view_tag, sig)?;
        let tx_viewing_pk = indexed
            .tx_viewing_pk
            .ok_or_else(|| anyhow!("transfer missing tx_viewing_pk"))?;
        let salt = indexed
            .salt
            .ok_or_else(|| anyhow!("transfer missing salt"))?;
        let slots: Vec<OutputCiphertext> = indexed
            .output_slots
            .iter()
            .map(|slot| OutputCiphertext {
                view_tag: slot.view_tag,
                data: slot.payload.clone(),
            })
            .collect();
        let first_nullifier = commitments
            .first()
            .ok_or_else(|| anyhow!("no input commitment"))?
            .nullifier;
        let blob = TransferEncryptedUtxos::from_output_ciphertexts(
            tx_viewing_pk,
            salt,
            &slots,
            SENDER_SLOT_COUNT,
        )?;
        let (sender_plaintext, _) = from_keypair
            .viewing_key
            .decrypt_transfer(&first_nullifier, &blob)?;
        let seed = sender_plaintext.blinding_seed;

        let sync_tx = SyncTransaction {
            scheme: TRANSFER,
            tx_viewing_pk,
            salt,
            output_slots: slots,
            nullifiers: indexed.nullifiers.clone(),
        };
        self.indexed.push(sync_tx);

        // Expected recipient note (first recipient sits at blinding position 2).
        let recipient_note = self.build_expected(
            to,
            to_keypair.signing_pubkey(),
            amount,
            derive_blinding(&seed, RECIPIENT_POSITION_BASE),
        )?;
        self.actor_mut(to).expected.push(recipient_note);

        // Mark consumed inputs spent if they were recovered (tracked) notes.
        let nullifier_pk = from_keypair.nullifier_key.pubkey()?;
        for input in &inputs {
            let consumed_hash = input.hash(&nullifier_pk, &ZERO, &ZERO)?;
            if let Some(note) = self
                .actor_mut(from)
                .expected
                .iter_mut()
                .find(|n| n.hash == consumed_hash)
            {
                note.spent = true;
            }
        }

        // Expected sender SOL change note (blinding position 1), when there is change.
        if change_amount > 0 {
            let change_note = self.build_expected(
                from,
                from_keypair.signing_pubkey(),
                change_amount,
                derive_blinding(&seed, SOL_CHANGE_POSITION),
            )?;
            self.actor_mut(from).expected.push(change_note);
        }

        Ok(sig)
    }

    fn build_expected(
        &self,
        name: &str,
        owner: zolana_keypair::PublicKey,
        amount: u64,
        blinding: [u8; 31],
    ) -> Result<WalletUtxo> {
        let keypair = &self.actor(name).keypair;
        let nullifier_pk = keypair.nullifier_key.pubkey()?;
        let utxo = Utxo {
            owner,
            asset: SOL_MINT,
            amount,
            blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        let hash = utxo.hash(&nullifier_pk, &ZERO, &ZERO)?;
        let nullifier = utxo.nullifier(&hash, &keypair.nullifier_key)?;
        Ok(WalletUtxo {
            utxo,
            hash,
            nullifier,
            spent: false,
        })
    }

    /// Sync an actor's wallet from every indexed transfer and assert, with a
    /// full-struct comparison, that the recovered notes exactly match the expected
    /// set. Newly recovered, unspent notes become spendable.
    pub fn recover_and_assert(&mut self, name: &str) -> Result<()> {
        self.ensure_actor(name)?;
        let indexed = self.indexed.clone();
        let assets = self.assets.clone();
        let actor = self.actor_mut(name);
        actor
            .wallet
            .sync(&indexed, &[], &assets, 0, DEFAULT_TAG_WINDOW)?;

        let mut actual = actor.wallet.utxos.clone();
        let mut expected = actor.expected.clone();
        actual.sort_by_key(|u| u.hash);
        expected.sort_by_key(|u| u.hash);
        assert_eq!(
            actual, expected,
            "recovered notes for {name} do not match expected"
        );

        let nullifier_pk = actor.keypair.nullifier_key.pubkey()?;
        let mut spendable_hashes: Vec<[u8; 32]> = Vec::new();
        for utxo in &actor.spendable {
            spendable_hashes.push(utxo.hash(&nullifier_pk, &ZERO, &ZERO)?);
        }
        let newly_spendable: Vec<Utxo> = actor
            .wallet
            .utxos
            .iter()
            .filter(|w| !w.spent && !spendable_hashes.contains(&w.hash))
            .map(|w| w.utxo.clone())
            .collect();
        actor.spendable.extend(newly_spendable);
        Ok(())
    }

    /// Sync and assert the actor recovers nothing (view-tag isolation).
    pub fn recover_nothing(&mut self, name: &str) -> Result<()> {
        self.ensure_actor(name)?;
        let indexed = self.indexed.clone();
        let assets = self.assets.clone();
        let actor = self.actor_mut(name);
        actor
            .wallet
            .sync(&indexed, &[], &assets, 0, DEFAULT_TAG_WINDOW)?;
        assert!(
            actor.wallet.utxos.is_empty(),
            "{name} should not recover any notes but found {}",
            actor.wallet.utxos.len()
        );
        Ok(())
    }
}

fn pack_proof(proof: &Proof) -> Result<[u8; 192]> {
    let compressed = ProofCompressed::try_from(*proof)?;
    let mut out = [0u8; 192];
    out[0..32].copy_from_slice(&compressed.a);
    out[32..96].copy_from_slice(&compressed.b);
    out[96..128].copy_from_slice(&compressed.c);
    if let Some(commitment) = compressed.commitment {
        out[128..160].copy_from_slice(&commitment.commitment);
        out[160..192].copy_from_slice(&commitment.commitment_pok);
    }
    Ok(out)
}

fn start_prover() -> Result<()> {
    std::env::set_var(
        "ZOLANA_PROVER_KEYS_DIR",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../prover/server/proving-keys"
        ),
    );
    spawn_prover()?;
    Ok(())
}

fn restart_localnet() {
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/restart-localnet.sh"
    );
    let status = std::process::Command::new("bash")
        .arg(script)
        .status()
        .expect("run restart-localnet.sh");
    assert!(status.success(), "restart-localnet.sh failed");
}

fn send_transaction(
    rpc: &mut SolanaRpc,
    ixs: &[Instruction],
    payer: &Pubkey,
    signers: &[&Keypair],
) -> Result<Signature> {
    let (blockhash, _) = rpc.get_latest_blockhash()?;
    let message = Message::new(ixs, Some(payer));
    let transaction = Transaction::new(signers, message, blockhash);
    Ok(rpc.send_transaction(&transaction)?)
}

fn wait_for_indexed_transaction(
    indexer: &ZolanaIndexer,
    tag: [u8; 32],
    signature: Signature,
) -> Result<ShieldedTransaction> {
    wait_for("indexed transaction", || {
        let response = indexer.get_shielded_transactions_by_tags(vec![tag], None, Some(100))?;
        Ok(response
            .transactions
            .into_iter()
            .find(|item| item.tx_signature == signature))
    })
}

fn wait_for_merkle_proof(
    indexer: &ZolanaIndexer,
    tree: Address,
    leaf: [u8; 32],
) -> Result<zolana_client::MerkleProof> {
    wait_for("indexed merkle proof", || {
        let response = indexer.get_merkle_proofs(tree, vec![leaf])?;
        Ok(response.proofs.into_iter().next())
    })
}

fn wait_for_non_inclusion_proof(
    indexer: &ZolanaIndexer,
    tree: Address,
    leaf: [u8; 32],
) -> Result<zolana_client::NonInclusionProof> {
    wait_for("indexed non-inclusion proof", || {
        let response = indexer.get_non_inclusion_proofs(tree, vec![leaf])?;
        Ok(response.proofs.into_iter().next())
    })
}

fn wait_for<T>(
    label: &'static str,
    mut poll: impl FnMut() -> Result<Option<T>, zolana_client::ClientError>,
) -> Result<T> {
    let started = Instant::now();
    let mut last_error = None;
    while started.elapsed() < INDEXER_TIMEOUT {
        match poll() {
            Ok(Some(value)) => return Ok(value),
            Ok(None) => {}
            Err(error) => last_error = Some(error.to_string()),
        }
        sleep(Duration::from_millis(500));
    }
    Err(anyhow!(
        "timed out waiting for {label}; last indexer error: {}",
        last_error.unwrap_or_else(|| "none".to_string())
    ))
}

// Driven by the futures executor rather than tokio: the World and steps make
// blocking RPC/indexer calls (blocking reqwest), which panic if their internal
// runtime is dropped inside a tokio async context.
fn main() {
    futures::executor::block_on(
        LifecycleWorld::cucumber()
            .max_concurrent_scenarios(1)
            .fail_on_skipped()
            .run_and_exit("tests/features"),
    );
}
