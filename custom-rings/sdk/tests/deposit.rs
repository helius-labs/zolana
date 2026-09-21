use std::cell::RefCell;

use custom_ring_interface::{DepositAudit, RingProgramConfig, DEPOSIT_AUDIT, RING_PROGRAM_CONFIG};
use custom_ring_sdk::{CustomRing, DepositAsset, DepositProofEnvironment, RingDeposit};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{ClientError, ComputeBudgetConfig, ProverClient, Rpc};
use zolana_keypair::{ShieldedKeypair, ViewingKey};
use zolana_transaction::RingDepositPlaintext;

struct DepositRpc {
    ring: CustomRing,
    config: Account,
    setting: Option<Account>,
    sent: RefCell<Vec<Instruction>>,
}

impl Rpc for DepositRpc {
    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        if address == self.ring.config_pda() {
            return Ok(Some(self.config.clone()));
        }
        assert_eq!(address, self.ring.deposit_audit_pda());
        Ok(self.setting.clone())
    }

    fn create_and_send_transaction(
        &self,
        instructions: &[Instruction],
        _payer: Address,
        _signers: &[&dyn Signer],
        budget: ComputeBudgetConfig,
    ) -> Result<Signature, ClientError> {
        assert_eq!(budget, ComputeBudgetConfig::for_instruction_count(1));
        self.sent.borrow_mut().extend_from_slice(instructions);
        Ok(Signature::default())
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
            sent: RefCell::new(Vec::new()),
        };
        let receipt = RingDeposit {
            ring,
            payer: &recipient,
            recipient: &recipient,
            tree: Address::new_from_array([8; 32]),
            asset: DepositAsset::Sol,
            amount: 11,
            cosigner: None,
        }
        .send(DepositProofEnvironment {
            rpc: &rpc,
            prover: &unreachable,
        })
        .unwrap();
        let sent = rpc.sent.borrow();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].data[0],
            zolana_interface::instruction::tag::RING_DEPOSIT
        );
        assert_eq!(sent[0].accounts[3].pubkey, ring.deposit_audit_pda());
        let body =
            zolana_interface::instruction::RingDepositIxData::deserialize(&sent[0].data[1..])
                .unwrap();
        let entry = &body.deposits[0];
        assert!(
            custom_ring_interface::RingDepositAuditCapsule::parse(&entry.encrypted.ciphertext)
                .unwrap()
                .is_none()
        );
        let opened =
            RingDepositPlaintext::decrypt(&entry.encrypted, &recipient.viewing_key).unwrap();
        assert_eq!(opened.blinding, receipt.utxo.blinding);
        assert_eq!(entry.amount, 11);
    }
}
