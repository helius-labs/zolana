use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_event::SplTransfer;
use zolana_interface::{
    instruction::{
        encode_instruction, tag, CreateRingConfigData, DepositAsset, DepositSplAccounts,
        EncryptedRingDepositData, RingAssetDeposit, RingDeposit, UpdateRingConfig,
        UpdateRingConfigOwner,
    },
    pda,
};
use zolana_keypair::shielded::ShieldedAddress;
use zolana_transaction::{owner_utxo_hash, serialization::RingDepositPlaintext};

use crate::{
    instructions::RING_TEST_PROGRAM_ID, paths::default_ring_test_program_path,
    wallet_data::wallet_shield_fields, ProgramTestError, RingDepositOutput, ZolanaProgramTest,
};

pub struct RingDepositBatch {
    pub outputs: Vec<RingDepositOutput>,
    pub spl_transfers: Vec<SplTransfer>,
}

impl ZolanaProgramTest {
    fn ring_test_program_id() -> Pubkey {
        Pubkey::new_from_array(RING_TEST_PROGRAM_ID)
    }

    pub fn load_ring_test_program(&mut self) -> Result<(), ProgramTestError> {
        let path = default_ring_test_program_path();
        if !path.exists() {
            return Err(ProgramTestError::MissingProgram(path));
        }
        let bytes = std::fs::read(&path)?;
        self.svm
            .add_program(Self::ring_test_program_id(), &bytes)
            .map_err(|e| ProgramTestError::Litesvm(format!("add_ring_test: {e:?}")))?;
        Ok(())
    }

    pub fn create_ring_config(
        &mut self,
        payer: &Keypair,
        authority: &Pubkey,
        ring_authority_transact_is_enabled: bool,
    ) -> Result<Pubkey, ProgramTestError> {
        let ring_program = Self::ring_test_program_id();
        // The config account IS the ring's canonical `ring_auth` PDA.
        let (ring_config, _) = pda::ring_auth(&ring_program);
        let data = CreateRingConfigData {
            program_id: RING_TEST_PROGRAM_ID.into(),
            authority: authority.to_bytes().into(),
            ring_authority_transact_is_enabled,
        };
        let ix = Instruction {
            program_id: ring_program,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(pda::protocol_config(), false),
                AccountMeta::new(ring_config, false),
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new_readonly(self.program_id, false),
            ],
            data: encode_instruction(tag::CREATE_RING_CONFIG, &data),
        };
        self.send(&[ix], &[payer])?;
        Ok(ring_config)
    }

    pub fn update_ring_config_owner(
        &mut self,
        authority: &Keypair,
        ring_config: &Pubkey,
        new_authority: &Keypair,
    ) -> Result<(), ProgramTestError> {
        let ix = UpdateRingConfigOwner {
            authority: authority.pubkey(),
            ring_config: *ring_config,
            new_authority: new_authority.pubkey().to_bytes().into(),
        }
        .instruction();
        let mut signers = vec![authority];
        if new_authority.pubkey() != authority.pubkey() {
            signers.push(new_authority);
        }
        self.send(&[ix], &signers)
    }

    pub fn update_ring_config(
        &mut self,
        authority: &Keypair,
        ring_config: &Pubkey,
        ring_authority_transact_is_enabled: bool,
        paused: bool,
    ) -> Result<(), ProgramTestError> {
        let ix = UpdateRingConfig {
            authority: authority.pubkey(),
            ring_config: *ring_config,
            ring_authority_transact_is_enabled,
            paused,
        }
        .instruction();
        self.send(&[ix], &[authority])
    }

    pub fn ring_sol_shield_data(
        &self,
        lamports: u64,
        owner: [u8; 32],
        blinding: [u8; 32],
    ) -> RingAssetDeposit {
        RingAssetDeposit {
            asset: DepositAsset::Sol,
            view_tag: [0u8; 32],
            owner_utxo_hash: owner_utxo_hash(&owner, &blinding)
                .expect("test owner and blinding are field elements"),
            amount: lamports,
            data_hash: None,
            ring_data_hash: [0u8; 32],
            encrypted: EncryptedRingDepositData {
                tx_viewing_pk: [0u8; 33],
                salt: [0u8; 16],
                ciphertext: Vec::new(),
            },
        }
    }

    pub fn wallet_ring_sol_shield_data(
        lamports: u64,
        recipient: &ShieldedAddress,
        blinding_seed: &[u8; 32],
        position: u8,
    ) -> Result<RingAssetDeposit, ProgramTestError> {
        let fields = wallet_shield_fields(recipient, blinding_seed, position)?;
        Ok(RingAssetDeposit {
            asset: DepositAsset::Sol,
            view_tag: fields.view_tag,
            owner_utxo_hash: owner_utxo_hash(&fields.owner, &fields.blinding)?,
            amount: lamports,
            data_hash: None,
            ring_data_hash: [0u8; 32],
            encrypted: RingDepositPlaintext {
                blinding: fields.blinding,
                utxo_data: None,
                memo: None,
                ring_data: Vec::new(),
            }
            .encrypt(&recipient.viewing_pubkey)?,
        })
    }

    pub fn wallet_ring_spl_shield_data(
        amount: u64,
        mint: Pubkey,
        user_token: Pubkey,
        recipient: &ShieldedAddress,
        blinding_seed: &[u8; 32],
        position: u8,
    ) -> Result<RingAssetDeposit, ProgramTestError> {
        let fields = wallet_shield_fields(recipient, blinding_seed, position)?;
        Ok(RingAssetDeposit {
            asset: DepositAsset::Spl(DepositSplAccounts {
                mint,
                user_token,
                token_program: Self::token_program_id(),
            }),
            view_tag: fields.view_tag,
            owner_utxo_hash: owner_utxo_hash(&fields.owner, &fields.blinding)?,
            amount,
            data_hash: None,
            ring_data_hash: [0u8; 32],
            encrypted: RingDepositPlaintext {
                blinding: fields.blinding,
                utxo_data: None,
                memo: None,
                ring_data: Vec::new(),
            }
            .encrypt(&recipient.viewing_pubkey)?,
        })
    }

    pub fn ring_deposit(
        &mut self,
        tree: &Pubkey,
        depositor: &Keypair,
        deposit: &RingAssetDeposit,
    ) -> Result<RingDepositOutput, ProgramTestError> {
        let mut batch = self.ring_deposit_batch(tree, depositor, vec![deposit.clone()])?;
        batch.outputs.pop().ok_or_else(|| {
            ProgramTestError::Event("ring deposit batch emitted no output".to_string())
        })
    }

    pub fn ring_deposit_batch(
        &mut self,
        tree: &Pubkey,
        depositor: &Keypair,
        deposits: Vec<RingAssetDeposit>,
    ) -> Result<RingDepositBatch, ProgramTestError> {
        let ix = RingDeposit {
            tree: *tree,
            depositor: depositor.pubkey(),
            ring_program_id: Self::ring_test_program_id(),
            deposits,
        }
        .instruction()?;
        let outcome = self.create_and_send_default_payer_transaction(&[ix], &[depositor])?;
        let Some(event) = outcome.events.first() else {
            return Err(ProgramTestError::Event(
                "no proofless ring deposit event emitted by transaction".into(),
            ));
        };
        if outcome.events.len() != 1 {
            return Err(ProgramTestError::Event(format!(
                "expected one ring deposit event, transaction emitted {}",
                outcome.events.len()
            )));
        }
        let general_event = zolana_event::general_event_from_indexed(event).map_err(|err| {
            ProgramTestError::Event(format!("batch ring deposit event decode failed: {err:?}"))
        })?;
        Ok(RingDepositBatch {
            outputs: crate::ring_deposit_outputs_from_event(event)?,
            spl_transfers: general_event.spl_transfers.clone(),
        })
    }
}
