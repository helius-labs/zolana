//! Policy-ring lifecycle fixture: the [`RingHarness`] and its action
//! implementations.
//!
//! The validator/prover/indexer bring-up, actor management, and SPL asset
//! registration live in [`crate::harness::LocalnetHarness`]; this struct embeds
//! it and adds the ring-config state only the policy-ring lifecycle needs. Both
//! `ring-test-program` test binaries (`ring_lifecycle` and `proof_cu`) consume
//! this module, so each composes exactly the fixture surface it uses.

pub(crate) mod merge_ring;
mod ring_authority_transact;
mod ring_config;
mod ring_deposit;
mod ring_transact;

use std::ops::{Deref, DerefMut};

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{encode_instruction, tag, CreateRingConfigData, RingAssetDeposit},
    pda, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_program_test::RING_TEST_PROGRAM_ID;
use zolana_transaction::{
    serialization::confidential::Confidential, KeypairWalletAuthority, ShieldedTransaction, Utxo,
    WalletUtxo, DEFAULT_TAG_WINDOW,
};

use crate::{
    harness::{BootstrapConfig, LocalnetHarness},
    localnet::{send_transaction, ZERO},
};

/// A second ring fixture program id (deployed from the same
/// `ring_test_program.so`), used to prove configs are per-program.
pub(crate) const SECOND_RING_TEST_PROGRAM_ID: [u8; 32] = [42u8; 32];

/// What the consolidated-output assert needs after a `merge_ring`: the actor that
/// owns the appended output and the output's hash (for the inclusion-proof check).
pub(crate) struct MergeRingRecord {
    pub(crate) actor: String,
    pub(crate) output_hash: [u8; 32],
}

/// The extra account snapshots an SPL ring-deposit assert needs.
pub(crate) use crate::harness::SplDepositAccounts as SplRingDepositAccounts;

/// What a ring deposit records so the separate assertion can verify
/// it with `assert_ring_deposit` (which needs the sent data and the pre-deposit
/// account snapshots). `spl` is `Some` for token ring deposits.
pub(crate) type RingDepositRecord = crate::harness::DepositRecord<RingAssetDeposit>;

pub struct RingHarness {
    pub(crate) base: LocalnetHarness<RingAssetDeposit>,
    pub(crate) ring_program_id: Pubkey,
    /// The ring's `ring_auth` PDA (which IS the ring-config account), set when the
    /// ring config is created.
    pub(crate) ring_config: Option<Pubkey>,
    pub(crate) ring_authority: Option<Keypair>,
    pub(crate) previous_ring_authority: Option<Keypair>,
    /// The most recent `merge_ring`, kept so the consolidated-output assert can
    /// reconstruct and verify the merged UTXO.
    pub(crate) last_merge: Option<MergeRingRecord>,
}

impl std::fmt::Debug for RingHarness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RingHarness")
    }
}

impl Deref for RingHarness {
    type Target = LocalnetHarness<RingAssetDeposit>;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for RingHarness {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

impl RingHarness {
    pub fn new() -> Result<Self> {
        let ring_program_id = Pubkey::new_from_array(RING_TEST_PROGRAM_ID).to_string();
        let second_ring_program_id =
            Pubkey::new_from_array(SECOND_RING_TEST_PROGRAM_ID).to_string();
        let (base, _) = LocalnetHarness::bootstrap(BootstrapConfig {
            label: "zolana-ring",
            extra_programs: vec![
                (ring_program_id, "target/deploy/ring_test_program.so".into()),
                (
                    second_ring_program_id,
                    "target/deploy/ring_test_program.so".into(),
                ),
            ],
            // Permissionless ring creation lets the fixture's payer create the ring
            // config without the ring smart-account signing.
            ring_activation_is_permissionless: true,
            fund_merge_vault: false,
        })?;
        Ok(Self {
            base,
            ring_program_id: Pubkey::new_from_array(RING_TEST_PROGRAM_ID),
            ring_config: None,
            ring_authority: None,
            previous_ring_authority: None,
            last_merge: None,
        })
    }

    /// Create the ring config through the fixture's `CREATE_RING_CONFIG` instruction.
    /// The fixture signs the `ring_auth` PDA (which IS the config account) on the CPI
    /// into SPP. Stores the resulting `ring_auth` PDA in `self.ring_config`. The
    /// caller owns the authority keypair and is responsible for setting
    /// `self.ring_authority` if it wants to track it.
    pub fn create_ring_config(&mut self, authority: &Address) -> Result<Signature> {
        let (ring_auth, signature) =
            self.create_ring_config_for(self.ring_program_id, authority)?;
        self.ring_config = Some(ring_auth);
        Ok(signature)
    }

    pub fn create_ring_config_for(
        &mut self,
        program_id: Pubkey,
        authority: &Address,
    ) -> Result<(Pubkey, Signature)> {
        let payer = self.payer.insecure_clone();
        let (ring_auth, _) = pda::ring_auth(&program_id);
        let data = CreateRingConfigData {
            program_id: program_id.to_bytes().into(),
            authority: *authority,
        };
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(pda::protocol_config(), false),
                AccountMeta::new(ring_auth, false),
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
            ],
            data: encode_instruction(tag::CREATE_RING_CONFIG, &data),
        };
        let signature = send_transaction(&mut self.rpc, &[ix], &payer.pubkey(), &[&payer])?;
        Ok((ring_auth, signature))
    }

    /// Sync an actor's wallet from every indexed transaction (decryption), and make
    /// newly decrypted, unspent UTXOs spendable. No assertions.
    pub fn sync(&mut self, name: &str) -> Result<()> {
        self.ensure_fresh_actor(name)?;
        let indexed = self.indexed.clone();
        // Actors may exist before assets are registered, so refresh the wallet's
        // asset registry before decoding SPL UTXOs.
        let assets = self.assets.clone();
        let actor = self.actor_mut(name);
        actor.wallet.registry = assets;
        let authority = KeypairWalletAuthority::new(Address::default(), &actor.keypair);
        actor
            .wallet
            .sync(&authority, &indexed, 0, DEFAULT_TAG_WINDOW)?;

        let nullifier_pk = actor.keypair.nullifier_key.pubkey()?;
        let mut spendable_hashes: Vec<[u8; 32]> = Vec::new();
        for utxo in &actor.spendable {
            spendable_hashes.push(utxo.hash(&nullifier_pk, &ZERO, &ZERO)?);
        }
        let newly_spendable: Vec<Utxo> = actor
            .wallet
            .utxos
            .iter()
            .filter(|w| !w.spent && !spendable_hashes.contains(&w.output_context.hash))
            .map(|w| w.utxo.clone())
            .collect();
        actor.spendable.extend(newly_spendable);
        Ok(())
    }

    /// Full-struct assert that the actor's synced wallet holds exactly the UTXOs it
    /// is expected to have decrypted (with `spent` flags). Run `sync` first.
    #[track_caller]
    pub fn assert_utxos(&self, name: &str) {
        let actor = self.actor(name);
        let mut actual = actor.wallet.utxos.clone();
        let mut expected = actor.expected.clone();
        actual.sort_by_key(|u| u.output_context.hash);
        expected.sort_by_key(|u| u.output_context.hash);
        assert_eq!(
            actual, expected,
            "synced UTXOs for {name} do not match expected"
        );
    }

    /// Build the `WalletUtxo` an actor should hold for a known output `utxo`,
    /// locating its on-chain output context in the indexed transaction so
    /// `assert_utxos` cross-checks the synced wallet. A ring-owned output's
    /// `ring_program_id` binds the ring into the hash; a default-pool output
    /// carries `None`.
    pub fn build_expected(
        &self,
        name: &str,
        utxo: Utxo,
        tx: &ShieldedTransaction,
    ) -> Result<WalletUtxo> {
        let keypair = &self.actor(name).keypair;
        let nullifier_pk = keypair.nullifier_key.pubkey()?;
        let hash = utxo.hash(&nullifier_pk, &ZERO, &ZERO)?;
        let output_context = tx
            .output_slots
            .iter()
            .find(|slot| slot.output_context.hash == hash)
            .map(|slot| slot.output_context.clone())
            .ok_or_else(|| anyhow!("expected output not found in indexed tx"))?;
        let nullifier = utxo.nullifier(&output_context.hash, &keypair.nullifier_key)?;
        Ok(WalletUtxo {
            utxo,
            output_context,
            nullifier,
            data_hash: None,
            ring_data_hash: None,
            spent: false,
        })
    }
}

/// Decode the committed blinding of one output slot from the sender side of an
/// indexed transaction, so the expected change/recipient set can be rebuilt
/// independently of `Wallet::sync`. Every output slot carries its own ciphertext,
/// so the author re-derives the transaction viewing key and decrypts the slot at
/// `slot_index == output position`.
pub(crate) fn decode_output_blinding(
    viewing_key: &zolana_keypair::ViewingKey,
    indexed: &ShieldedTransaction,
    slot_index: u32,
) -> Result<[u8; 32]> {
    let first_nullifier = indexed
        .nullifiers
        .first()
        .ok_or_else(|| anyhow!("indexed tx missing nullifier"))?;
    let salt = indexed
        .salt
        .ok_or_else(|| anyhow!("indexed tx missing salt"))?;
    let tx_key = viewing_key.get_transaction_viewing_key(first_nullifier)?;
    let slot = indexed
        .output_slots
        .get(slot_index as usize)
        .ok_or_else(|| anyhow!("indexed tx missing output slot {slot_index}"))?;
    let output_data = slot
        .output_data()
        .ok_or_else(|| anyhow!("output slot {slot_index} undecodable"))?;
    let body = match &output_data {
        zolana_event::OutputDataEncoding::Encrypted(blob) => blob
            .split_first()
            .map(|(_, body)| body)
            .ok_or_else(|| anyhow!("empty output blob"))?,
        _ => return Err(anyhow!("output slot {slot_index} not encrypted")),
    };
    let plaintext = Confidential::decrypt_with_tx_key(&tx_key, body, salt, slot_index)?;
    Ok(plaintext.blinding)
}
