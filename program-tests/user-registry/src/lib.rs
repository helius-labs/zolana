//! LiteSVM test helpers for the user-registry program.

use std::path::PathBuf;

use litesvm::{
    types::{FailedTransactionMetadata, TransactionMetadata},
    LiteSVM,
};
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{compile_message, sign_transaction, ComputeBudgetConfig};
use zolana_user_registry_interface::{
    instruction::{self as user_registry_instruction, RegisterData, UpdateKeysData},
    user_record_pda,
};
pub use zolana_user_registry_interface::{user_registry_program_id, UserRecord};

pub struct UserRegistryTestRig {
    pub svm: LiteSVM,
    pub payer: Keypair,
}

pub type TestTransactionResult =
    std::result::Result<TransactionMetadata, Box<FailedTransactionMetadata>>;

impl UserRegistryTestRig {
    pub fn new() -> Self {
        let path = user_registry_program_path();
        assert!(
            path.exists(),
            "missing {}; run `just build-programs`",
            path.display()
        );

        let mut svm = LiteSVM::new();
        let program = std::fs::read(&path).expect("read user-registry program");
        svm.add_program(user_registry_program_id(), &program)
            .expect("load user-registry program");

        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 20_000_000_000)
            .expect("fund test payer");
        Self { svm, payer }
    }

    pub fn fund(&mut self, address: &Pubkey, lamports: u64) {
        self.svm.expire_blockhash();
        self.svm
            .airdrop(address, lamports)
            .expect("fund test account");
    }

    pub fn send(
        &mut self,
        instruction: Instruction,
        signers: &[&Keypair],
    ) -> TestTransactionResult {
        self.send_all(&[instruction], signers)
    }

    pub fn send_all(
        &mut self,
        instructions: &[Instruction],
        signers: &[&Keypair],
    ) -> TestTransactionResult {
        self.svm.expire_blockhash();
        let payer = self.payer.insecure_clone();
        let mut all_signers: Vec<&dyn Signer> = Vec::with_capacity(signers.len() + 1);
        all_signers.push(&payer);
        all_signers.extend(signers.iter().map(|signer| *signer as &dyn Signer));
        let message = compile_message(
            &payer.pubkey(),
            instructions,
            self.svm.latest_blockhash(),
            ComputeBudgetConfig::for_instruction_count(instructions.len()),
        )
        .expect("compile the v1 message");
        let transaction = sign_transaction(message, &all_signers).expect("sign the v1 transaction");
        self.svm.send_transaction(transaction).map_err(Box::new)
    }

    pub fn record(&self, owner: &Pubkey) -> UserRecord {
        let (pda, _bump) = user_record_pda(owner);
        let account = self
            .svm
            .get_account(&pda)
            .expect("user record account must exist");
        UserRecord::try_from_account_data(&account.data).expect("user record account must decode")
    }
}

impl Default for UserRegistryTestRig {
    fn default() -> Self {
        Self::new()
    }
}

pub fn user_registry_program_path() -> PathBuf {
    if let Ok(path) = std::env::var("USER_REGISTRY_PROGRAM_PATH") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("deploy")
        .join("zolana_user_registry.so")
}

pub fn build_register_ix(
    owner: &Pubkey,
    nullifier_pubkey: [u8; 32],
    viewing_pubkey: [u8; 33],
) -> Instruction {
    let (user_record, _bump) = user_record_pda(owner);
    user_registry_instruction::register(
        user_record,
        *owner,
        *owner,
        RegisterData {
            nullifier_pubkey,
            viewing_pubkey,
        },
    )
}

pub fn build_set_merging_enabled_ix(owner: &Pubkey, signer: &Pubkey, enabled: bool) -> Instruction {
    let (user_record, _bump) = user_record_pda(owner);
    user_registry_instruction::set_merging_enabled(user_record, *signer, enabled)
}

pub fn build_update_keys_ix(
    owner: &Pubkey,
    nullifier_pubkey: [u8; 32],
    viewing_pubkey: [u8; 33],
) -> Instruction {
    let (user_record, _bump) = user_record_pda(owner);
    user_registry_instruction::update_keys(
        user_record,
        *owner,
        UpdateKeysData {
            nullifier_pubkey,
            viewing_pubkey,
        },
    )
}

pub fn fetch_user_record(svm: &litesvm::LiteSVM, owner: &Pubkey) -> Option<UserRecord> {
    let (pda, _bump) = user_record_pda(owner);
    let account = svm.get_account(&pda)?;
    UserRecord::try_from_account_data(&account.data).ok()
}
