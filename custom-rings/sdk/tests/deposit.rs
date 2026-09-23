use custom_ring_interface::{
    DepositAudit, KeyRegistryRoot, RingProgramConfig, DEPOSIT_AUDIT, KEY_REGISTRY_ROOT,
    KEY_REGISTRY_ROOT_HISTORY, RING_PROGRAM_CONFIG,
};
use custom_ring_sdk::{
    CustomRing, DepositAsset, DepositError, DepositProofEnvironment, KeyRegistrationError,
    RingDeposit,
};
use solana_account::Account;
use solana_address::Address;
use solana_signer::Signer;
use zolana_client::{ClientError, ComputeBudgetConfig, ProverClient, Rpc};
use zolana_indexer_api::{GetRingKeyRegistryEntryResponse, RingMemberProofRequest};
use zolana_keypair::{ShieldedKeypair, ViewingKey};
use zolana_transaction::RingDepositPlaintext;

struct DepositRpc {
    ring: CustomRing,
    config: Account,
    setting: Option<Account>,
}

impl Rpc for DepositRpc {
    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        if address == self.ring.config_pda() {
            return Ok(Some(self.config.clone()));
        }
        assert_eq!(address, self.ring.deposit_audit_pda());
        Ok(self.setting.clone())
    }
}

#[test]
fn disabled_deposits_keep_recipient_ciphertext_and_never_contact_the_prover() {
    let ring = CustomRing::new(Address::new_from_array([42; 32]));
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    let config = RingProgramConfig {
        discriminator: RING_PROGRAM_CONFIG,
        authority: recipient.pubkey(),
        auditor_pubkey: *ViewingKey::new().pubkey().as_bytes(),
        bump: Address::find_program_address(&[RingProgramConfig::SEED], &ring.program_id()).1,
        has_policy: 0,
        key_escrow: 0,
    };
    let setting = DepositAudit {
        discriminator: DEPOSIT_AUDIT,
        required: 0,
        bump: Address::find_program_address(&[DepositAudit::SEED], &ring.program_id()).1,
    };
    let inactive = Account {
        data: bytemuck::bytes_of(&setting).to_vec(),
        owner: ring.program_id(),
        ..Account::default()
    };
    let unreachable = ProverClient::new("http://127.0.0.1:1".to_owned());
    for setting in [None, Some(inactive)] {
        let rpc = DepositRpc {
            ring,
            config: Account {
                data: bytemuck::bytes_of(&config).to_vec(),
                owner: ring.program_id(),
                ..Account::default()
            },
            setting,
        };
        let prepared = RingDeposit {
            ring,
            payer: &recipient,
            recipient: &recipient,
            tree: Address::new_from_array([8; 32]),
            asset: DepositAsset::Sol,
            amount: 11,
            cosigner: None,
        }
        .prepare(&rpc)
        .unwrap();
        assert_eq!(
            prepared.budget(),
            ComputeBudgetConfig::for_instruction_count(1)
        );
        let instruction = prepared
            .prove(DepositProofEnvironment {
                indexer: &rpc,
                rpc: &rpc,
                prover: &unreachable,
            })
            .unwrap();
        assert_eq!(
            instruction.data[0],
            zolana_interface::instruction::tag::RING_DEPOSIT
        );
        assert_eq!(instruction.accounts[3].pubkey, ring.deposit_audit_pda());
        let body =
            zolana_interface::instruction::RingDepositIxData::deserialize(&instruction.data[1..])
                .unwrap();
        let entry = &body.deposits[0];
        assert!(
            custom_ring_interface::RingDepositAuditCapsule::parse(&entry.encrypted.ciphertext)
                .unwrap()
                .is_none()
        );
        let opened =
            RingDepositPlaintext::decrypt(&entry.encrypted, &recipient.viewing_key).unwrap();
        assert_eq!(opened.blinding, prepared.utxo().blinding);
        assert_eq!(entry.amount, 11);
    }
}

/// Answers config and registry reads, every member is unregistered.
struct EscrowRpc {
    ring: CustomRing,
    config: Account,
    registry: Option<Account>,
}

impl Rpc for EscrowRpc {
    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        if address == self.ring.config_pda() {
            return Ok(Some(self.config.clone()));
        }
        assert_eq!(address, self.ring.key_registry_root_pda());
        Ok(self.registry.clone())
    }

    fn get_ring_key_registry_entry(
        &self,
        _request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryEntryResponse, ClientError> {
        Err(ClientError::RingKeyRegistryMemberUnregistered)
    }
}

#[test]
fn an_escrowed_ring_refuses_an_unregistered_recipient_before_proving() {
    let ring = CustomRing::new(Address::new_from_array([42; 32]));
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    let account = |data: Vec<u8>| Account {
        data,
        owner: ring.program_id(),
        ..Account::default()
    };
    let config = RingProgramConfig {
        discriminator: RING_PROGRAM_CONFIG,
        authority: recipient.pubkey(),
        auditor_pubkey: *ViewingKey::new().pubkey().as_bytes(),
        bump: Address::find_program_address(&[RingProgramConfig::SEED], &ring.program_id()).1,
        has_policy: 1,
        key_escrow: 1,
    };
    let mut history = [[0; 32]; KEY_REGISTRY_ROOT_HISTORY];
    history[0] = [5; 32];
    let registry = KeyRegistryRoot {
        discriminator: KEY_REGISTRY_ROOT,
        root: [5; 32],
        next_index: 1u64.to_le_bytes(),
        bump: custom_ring_interface::pda::key_registry_root(&ring.program_id()).1,
        history_cursor: 0,
        history,
    };
    let unreachable = ProverClient::new("http://127.0.0.1:1".to_owned());
    let send = |registry: Option<Account>| {
        let rpc = EscrowRpc {
            ring,
            config: account(bytemuck::bytes_of(&config).to_vec()),
            registry,
        };
        RingDeposit {
            ring,
            payer: &recipient,
            recipient: &recipient,
            tree: Address::new_from_array([8; 32]),
            asset: DepositAsset::Sol,
            amount: 11,
            cosigner: None,
        }
        .prepare(&rpc)?
        .prove(DepositProofEnvironment {
            indexer: &rpc,
            rpc: &rpc,
            prover: &unreachable,
        })
    };
    assert!(matches!(
        send(None),
        Err(DepositError::KeyRegistration(
            KeyRegistrationError::MissingKeyRegistry
        ))
    ));
    let refused = send(Some(account(bytemuck::bytes_of(&registry).to_vec())));
    let owner = zolana_ring_policy::Member::owner_tag(recipient.pubkey().as_array()).unwrap();
    assert!(matches!(
        refused,
        Err(DepositError::KeyRegistration(
            KeyRegistrationError::UnregisteredOutputKey { owner: refused }
        )) if refused == owner
    ));
}
