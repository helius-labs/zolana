//! Localnet/indexer handles, per-actor state, and policy-zone lifecycle setup.
//!
//! The validator/prover/indexer bring-up, actor management, and SPL asset
//! registration are shared with the spp suite in
//! `zolana_test_utils::harness::LocalnetHarness`; this struct embeds it and adds
//! the zone-config state only the policy-zone lifecycle needs.

use std::ops::{Deref, DerefMut};

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{encode_instruction, tag, CreateZoneConfigData, ZoneAssetDeposit},
    pda, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::PublicKey;
use zolana_program_test::ZONE_TEST_PROGRAM_ID;
use zolana_test_utils::{
    harness::{BootstrapConfig, LocalnetHarness},
    localnet::{send_transaction, ZERO},
};
use zolana_transaction::{
    serialization::confidential::Confidential, Data, LocalWalletAuthority, ShieldedTransaction,
    Utxo, WalletUtxo, DEFAULT_TAG_WINDOW,
};

use crate::support::{MergeZoneRecord, SECOND_ZONE_TEST_PROGRAM_ID};

pub struct ZoneHarness {
    pub(crate) base: LocalnetHarness<ZoneAssetDeposit>,
    pub(crate) zone_program_id: Pubkey,
    /// The zone's `zone_auth` PDA (which IS the zone-config account), set when the
    /// zone config is created.
    pub(crate) zone_config: Option<Pubkey>,
    pub(crate) zone_authority: Option<Keypair>,
    pub(crate) previous_zone_authority: Option<Keypair>,
    /// The most recent `merge_zone`, kept so the consolidated-output assert can
    /// reconstruct and verify the merged UTXO.
    pub(crate) last_merge: Option<MergeZoneRecord>,
}

impl std::fmt::Debug for ZoneHarness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ZoneHarness")
    }
}

impl Deref for ZoneHarness {
    type Target = LocalnetHarness<ZoneAssetDeposit>;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for ZoneHarness {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

impl ZoneHarness {
    pub(crate) fn new() -> Result<Self> {
        let zone_program_id = Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID).to_string();
        let second_zone_program_id =
            Pubkey::new_from_array(SECOND_ZONE_TEST_PROGRAM_ID).to_string();
        let (base, _) = LocalnetHarness::bootstrap(BootstrapConfig {
            label: "zolana-zone",
            extra_programs: vec![
                (zone_program_id, "target/deploy/zone_test_program.so".into()),
                (
                    second_zone_program_id,
                    "target/deploy/zone_test_program.so".into(),
                ),
            ],
            // Permissionless zone creation lets the fixture's payer create the zone
            // config without the zone smart-account signing.
            zone_creation_is_permissionless: true,
            fund_merge_vault: false,
        })?;
        Ok(Self {
            base,
            zone_program_id: Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID),
            zone_config: None,
            zone_authority: None,
            previous_zone_authority: None,
            last_merge: None,
        })
    }

    /// Create the zone config through the fixture's `CREATE_ZONE_CONFIG` instruction.
    /// The fixture signs the `zone_auth` PDA (which IS the config account) on the CPI
    /// into SPP. Stores the resulting `zone_auth` PDA in `self.zone_config`. The
    /// caller owns the authority keypair and is responsible for setting
    /// `self.zone_authority` if it wants to track it.
    pub(crate) fn create_zone_config(&mut self, authority: &Address, enabled: bool) -> Result<()> {
        let zone_auth = self.create_zone_config_for(self.zone_program_id, authority, enabled)?;
        self.zone_config = Some(zone_auth);
        Ok(())
    }

    pub(crate) fn create_zone_config_for(
        &mut self,
        program_id: Pubkey,
        authority: &Address,
        enabled: bool,
    ) -> Result<Pubkey> {
        let payer = self.payer.insecure_clone();
        let (zone_auth, _) = pda::zone_auth(&program_id);
        let data = CreateZoneConfigData {
            program_id: program_id.to_bytes().into(),
            authority: *authority,
            zone_authority_transact_is_enabled: enabled,
        };
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(pda::protocol_config(), false),
                AccountMeta::new(zone_auth, false),
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
            ],
            data: encode_instruction(tag::CREATE_ZONE_CONFIG, &data),
        };
        send_transaction(&mut self.rpc, &[ix], &payer.pubkey(), &[&payer])?;
        Ok(zone_auth)
    }

    /// Sync an actor's wallet from every indexed transaction (decryption), and make
    /// newly decrypted, unspent UTXOs spendable. No assertions.
    pub(crate) fn sync(&mut self, name: &str) -> Result<()> {
        self.ensure_fresh_actor(name)?;
        let indexed = self.indexed.clone();
        let actor = self.actor_mut(name);
        let authority = LocalWalletAuthority::new(Address::default(), &actor.keypair);
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
    pub(crate) fn assert_utxos(&self, name: &str) {
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

    /// Build the `WalletUtxo` an actor should hold for a known
    /// `(owner, asset, amount, blinding)`, locating its on-chain output context in
    /// the indexed transaction so `assert_utxos` cross-checks the synced wallet.
    /// `zone_program_id` is `Some(zone)` for a zone-owned output (its hash binds
    /// the zone), `None` for a default-pool output.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_expected(
        &self,
        name: &str,
        owner: PublicKey,
        asset: Address,
        amount: u64,
        blinding: [u8; 32],
        zone_program_id: Option<Address>,
        tx: &ShieldedTransaction,
    ) -> Result<WalletUtxo> {
        let keypair = &self.actor(name).keypair;
        let nullifier_pk = keypair.nullifier_key.pubkey()?;
        let utxo = Utxo {
            owner,
            asset,
            amount,
            blinding,
            zone_program_id,
            data: Data::default(),
        };
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
            zone_data_hash: None,
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
