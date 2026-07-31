use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_event::SplTransfer;
use zolana_interface::{
    instruction::{
        encode_instruction, tag, CreateZoneConfigData, DepositAsset, DepositSplAccounts,
        EncryptedZoneDepositData, UpdateZoneConfig, UpdateZoneConfigOwner, ZoneAssetDeposit,
        ZoneDeposit,
    },
    pda,
};
use zolana_keypair::shielded::ShieldedAddress;
use zolana_transaction::{owner_utxo_hash, serialization::ZoneDepositPlaintext};

use crate::{
    instructions::ZONE_TEST_PROGRAM_ID, paths::default_zone_test_program_path,
    wallet_data::wallet_shield_fields, ProgramTestError, ZolanaProgramTest, ZoneDepositOutput,
};

pub struct ZoneDepositBatch {
    pub outputs: Vec<ZoneDepositOutput>,
    pub spl_transfers: Vec<SplTransfer>,
}

impl ZolanaProgramTest {
    fn zone_test_program_id() -> Pubkey {
        Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID)
    }

    pub fn load_zone_test_program(&mut self) -> Result<(), ProgramTestError> {
        let path = default_zone_test_program_path();
        if !path.exists() {
            return Err(ProgramTestError::MissingProgram(path));
        }
        let bytes = std::fs::read(&path)?;
        self.svm
            .add_program(Self::zone_test_program_id(), &bytes)
            .map_err(|e| ProgramTestError::Litesvm(format!("add_zone_test: {e:?}")))?;
        Ok(())
    }

    pub fn create_zone_config(
        &mut self,
        payer: &Keypair,
        authority: &Pubkey,
        zone_authority_transact_is_enabled: bool,
    ) -> Result<Pubkey, ProgramTestError> {
        let zone_program = Self::zone_test_program_id();
        // The config account IS the zone's canonical `zone_auth` PDA.
        let (zone_config, _) = pda::zone_auth(&zone_program);
        let data = CreateZoneConfigData {
            program_id: ZONE_TEST_PROGRAM_ID.into(),
            authority: authority.to_bytes().into(),
            zone_authority_transact_is_enabled,
        };
        let ix = Instruction {
            program_id: zone_program,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(pda::protocol_config(), false),
                AccountMeta::new(zone_config, false),
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new_readonly(self.program_id, false),
            ],
            data: encode_instruction(tag::CREATE_ZONE_CONFIG, &data),
        };
        self.send(&[ix], &[payer])?;
        Ok(zone_config)
    }

    pub fn update_zone_config_owner(
        &mut self,
        authority: &Keypair,
        zone_config: &Pubkey,
        new_authority: &Keypair,
    ) -> Result<(), ProgramTestError> {
        let ix = UpdateZoneConfigOwner {
            authority: authority.pubkey(),
            zone_config: *zone_config,
            new_authority: new_authority.pubkey().to_bytes().into(),
        }
        .instruction();
        let mut signers = vec![authority];
        if new_authority.pubkey() != authority.pubkey() {
            signers.push(new_authority);
        }
        self.send(&[ix], &signers)
    }

    pub fn update_zone_config(
        &mut self,
        authority: &Keypair,
        zone_config: &Pubkey,
        zone_authority_transact_is_enabled: bool,
    ) -> Result<(), ProgramTestError> {
        let ix = UpdateZoneConfig {
            authority: authority.pubkey(),
            zone_config: *zone_config,
            zone_authority_transact_is_enabled,
        }
        .instruction();
        self.send(&[ix], &[authority])
    }

    pub fn zone_sol_shield_data(
        &self,
        lamports: u64,
        owner: [u8; 32],
        blinding: [u8; 32],
    ) -> ZoneAssetDeposit {
        ZoneAssetDeposit {
            asset: DepositAsset::Sol,
            view_tag: [0u8; 32],
            owner_utxo_hash: owner_utxo_hash(&owner, &blinding)
                .expect("test owner and blinding are field elements"),
            amount: lamports,
            data_hash: None,
            zone_data_hash: [0u8; 32],
            encrypted: EncryptedZoneDepositData {
                tx_viewing_pk: [0u8; 33],
                salt: [0u8; 16],
                ciphertext: Vec::new(),
            },
        }
    }

    pub fn wallet_zone_sol_shield_data(
        lamports: u64,
        recipient: &ShieldedAddress,
        blinding_seed: &[u8; 32],
        position: u8,
    ) -> Result<ZoneAssetDeposit, ProgramTestError> {
        let fields = wallet_shield_fields(recipient, blinding_seed, position)?;
        Ok(ZoneAssetDeposit {
            asset: DepositAsset::Sol,
            view_tag: fields.view_tag,
            owner_utxo_hash: owner_utxo_hash(&fields.owner, &fields.blinding)?,
            amount: lamports,
            data_hash: None,
            zone_data_hash: [0u8; 32],
            encrypted: ZoneDepositPlaintext {
                blinding: fields.blinding,
                utxo_data: None,
                memo: None,
                zone_data: Vec::new(),
            }
            .encrypt(&recipient.viewing_pubkey)?,
        })
    }

    pub fn wallet_zone_spl_shield_data(
        amount: u64,
        mint: Pubkey,
        user_token: Pubkey,
        recipient: &ShieldedAddress,
        blinding_seed: &[u8; 32],
        position: u8,
    ) -> Result<ZoneAssetDeposit, ProgramTestError> {
        let fields = wallet_shield_fields(recipient, blinding_seed, position)?;
        Ok(ZoneAssetDeposit {
            asset: DepositAsset::Spl(DepositSplAccounts {
                mint,
                user_token,
                token_program: Self::token_program_id(),
            }),
            view_tag: fields.view_tag,
            owner_utxo_hash: owner_utxo_hash(&fields.owner, &fields.blinding)?,
            amount,
            data_hash: None,
            zone_data_hash: [0u8; 32],
            encrypted: ZoneDepositPlaintext {
                blinding: fields.blinding,
                utxo_data: None,
                memo: None,
                zone_data: Vec::new(),
            }
            .encrypt(&recipient.viewing_pubkey)?,
        })
    }

    pub fn zone_deposit(
        &mut self,
        tree: &Pubkey,
        depositor: &Keypair,
        deposit: &ZoneAssetDeposit,
    ) -> Result<ZoneDepositOutput, ProgramTestError> {
        let mut batch = self.zone_deposit_batch(tree, depositor, vec![deposit.clone()])?;
        batch.outputs.pop().ok_or_else(|| {
            ProgramTestError::Event("zone deposit batch emitted no output".to_string())
        })
    }

    pub fn zone_deposit_batch(
        &mut self,
        tree: &Pubkey,
        depositor: &Keypair,
        deposits: Vec<ZoneAssetDeposit>,
    ) -> Result<ZoneDepositBatch, ProgramTestError> {
        let ix = ZoneDeposit {
            tree: *tree,
            depositor: depositor.pubkey(),
            zone_program_id: Self::zone_test_program_id(),
            deposits,
        }
        .instruction()?;
        let outcome = self.create_and_send_default_payer_transaction(&[ix], &[depositor])?;
        let Some(event) = outcome.events.first() else {
            return Err(ProgramTestError::Event(
                "no proofless zone deposit event emitted by transaction".into(),
            ));
        };
        if outcome.events.len() != 1 {
            return Err(ProgramTestError::Event(format!(
                "expected one zone deposit event, transaction emitted {}",
                outcome.events.len()
            )));
        }
        let general_event = zolana_event::general_event_from_indexed(event).map_err(|err| {
            ProgramTestError::Event(format!("batch zone deposit event decode failed: {err:?}"))
        })?;
        Ok(ZoneDepositBatch {
            outputs: crate::zone_deposit_outputs_from_event(event)?,
            spl_transfers: general_event.spl_transfers.clone(),
        })
    }
}
