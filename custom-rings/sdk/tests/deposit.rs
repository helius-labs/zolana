use custom_ring_interface::{
    DepositAudit, KeyRegistryRoot, RingProgramConfig, DEPOSIT_AUDIT, KEY_REGISTRY_ROOT,
    KEY_REGISTRY_ROOT_HISTORY, RING_PROGRAM_CONFIG,
};
use custom_ring_sdk::{
    CustomRing, DepositAsset, DepositError, DepositProofEnvironment, KeyRegistrationError,
    RingDeposit,
};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
};

use solana_account::Account;
use solana_address::Address;
use solana_signer::Signer;
use zolana_client::{ClientError, ComputeBudgetConfig, ProofDataSource, ProverClient, Rpc};
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
fn an_escrowed_ring_refuses_an_unregistered_recipient_from_either_proof_data_source() {
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
        next_index: 1u64.to_le_bytes(),
        bump: custom_ring_interface::pda::key_registry_root(&ring.program_id()).1,
        history_cursor: 0,
        history,
    };
    let send = |registry: Option<Account>, prover: &ProverClient| {
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
            prover,
        })
    };
    let owner = zolana_ring_policy::Member::owner_tag(recipient.pubkey().as_array()).unwrap();
    let refused = |result: Result<_, DepositError>| {
        matches!(
            result,
            Err(DepositError::KeyRegistration(
                KeyRegistrationError::UnregisteredOutputKey { owner: refused }
            )) if refused == owner
        )
    };
    let registry_account = || Some(account(bytemuck::bytes_of(&registry).to_vec()));

    let unreachable = ProverClient::new("http://127.0.0.1:1".to_owned())
        .with_proof_data_source(ProofDataSource::Client);
    assert!(matches!(
        send(None, &unreachable),
        Err(DepositError::KeyRegistration(
            KeyRegistrationError::MissingKeyRegistry
        ))
    ));
    assert!(refused(send(registry_account(), &unreachable)));

    let prover = refusing_prover(owner.as_bytes());
    assert!(refused(send(
        registry_account(),
        &ProverClient::new(prover.url.clone())
    )));
    prover.handle.join().unwrap();
}

struct RefusingProver {
    url: String,
    handle: std::thread::JoinHandle<()>,
}

fn refusing_prover(member: &[u8; 32]) -> RefusingProver {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let body = serde_json::json!({
        "code": "registry_member_missing",
        "message": "registry member missing",
        "member": Address::new_from_array(*member).to_string(),
    })
    .to_string();
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream);
        let mut length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                length = value.trim().parse().unwrap();
            }
        }
        reader.read_exact(&mut vec![0; length]).unwrap();
        write!(
            reader.get_mut(),
            "HTTP/1.1 422 Unprocessable Entity\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    RefusingProver { url, handle }
}
