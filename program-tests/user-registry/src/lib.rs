//! LiteSVM test helpers for the user-registry program.

use std::path::PathBuf;

use litesvm::{
    types::{FailedTransactionMetadata, TransactionMetadata},
    LiteSVM,
};
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_keypair::SigningKey;
use zolana_user_registry_interface::{
    instruction::{
        self as user_registry_instruction, p256_key_binding_message, p256_verify_instruction,
        RegisterData, UpdateKeysData,
    },
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

    /// Sends several instructions in one transaction. Required for the P256
    /// proof of possession, which the program reads at relative index -1 and so
    /// must ride in the same transaction as the registry instruction.
    pub fn send_all(
        &mut self,
        instructions: &[Instruction],
        signers: &[&Keypair],
    ) -> TestTransactionResult {
        self.svm.expire_blockhash();
        let payer = self.payer.insecure_clone();
        let mut all_signers = Vec::with_capacity(signers.len() + 1);
        all_signers.push(&payer);
        all_signers.extend_from_slice(signers);
        let message = Message::new(instructions, Some(&payer.pubkey()));
        let transaction = Transaction::new(&all_signers, message, self.svm.latest_blockhash());
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

/// A throwaway P256 owner key. Unlike [`test_p256_pubkey`] this is a real
/// curve point, so it can produce the proof of possession `register` /
/// `update_keys` require alongside an `owner_p256`.
pub fn p256_owner_key() -> SigningKey {
    SigningKey::new()
}

/// The compressed `owner_p256` for `key` and its proof-of-possession signature
/// over the record's binding message, in the form Solana's secp256r1
/// precompile verifies (ECDSA over SHA-256, low-S normalized).
pub fn p256_binding_signature(owner: &Pubkey, key: &SigningKey) -> ([u8; 33], [u8; 64]) {
    let pubkey = *key
        .pubkey()
        .as_p256()
        .expect("p256 owner key exposes a compressed p256 pubkey")
        .as_bytes();
    let (user_record, _bump) = user_record_pda(owner);
    let message = p256_key_binding_message(&user_record, owner, &pubkey);
    let signature = key
        .sign_p256_message(&message)
        .expect("p256 owner key signs the binding message");
    (pubkey, signature)
}

pub fn test_p256_pubkey(tag: u8) -> [u8; 33] {
    let mut pubkey = [0u8; 33];
    pubkey[0] = 0x02;
    pubkey[1] = tag;
    pubkey
}

pub fn build_register_ix(
    owner: &Pubkey,
    owner_p256: Option<[u8; 33]>,
    nullifier_pubkey: [u8; 32],
    viewing_pubkey: [u8; 33],
) -> Instruction {
    let (user_record, _bump) = user_record_pda(owner);
    user_registry_instruction::register(
        user_record,
        *owner,
        RegisterData {
            owner_p256,
            nullifier_pubkey,
            viewing_pubkey,
        },
    )
}

pub fn build_register_ixs(
    owner: &Pubkey,
    owner_p256: Option<[u8; 33]>,
    nullifier_pubkey: [u8; 32],
    viewing_pubkey: [u8; 33],
    p256_signature: Option<[u8; 64]>,
) -> Vec<Instruction> {
    let registry = build_register_ix(owner, owner_p256, nullifier_pubkey, viewing_pubkey);
    compose_p256_proof(owner, owner_p256, p256_signature, registry)
}

pub fn build_set_merging_enabled_ix(owner: &Pubkey, signer: &Pubkey, enabled: bool) -> Instruction {
    let (user_record, _bump) = user_record_pda(owner);
    user_registry_instruction::set_merging_enabled(user_record, *signer, enabled)
}

pub fn build_update_keys_ix(
    owner: &Pubkey,
    owner_p256: Option<[u8; 33]>,
    nullifier_pubkey: [u8; 32],
    viewing_pubkey: [u8; 33],
) -> Instruction {
    let (user_record, _bump) = user_record_pda(owner);
    user_registry_instruction::update_keys(
        user_record,
        *owner,
        UpdateKeysData {
            owner_p256,
            nullifier_pubkey,
            viewing_pubkey,
        },
    )
}

pub fn build_update_keys_ixs(
    owner: &Pubkey,
    owner_p256: Option<[u8; 33]>,
    nullifier_pubkey: [u8; 32],
    viewing_pubkey: [u8; 33],
    p256_signature: Option<[u8; 64]>,
) -> Vec<Instruction> {
    let registry = build_update_keys_ix(owner, owner_p256, nullifier_pubkey, viewing_pubkey);
    compose_p256_proof(owner, owner_p256, p256_signature, registry)
}

fn compose_p256_proof(
    owner: &Pubkey,
    owner_p256: Option<[u8; 33]>,
    p256_signature: Option<[u8; 64]>,
    registry: Instruction,
) -> Vec<Instruction> {
    match (owner_p256, p256_signature) {
        (Some(pubkey), Some(signature)) => {
            let user_record = user_record_pda(owner).0;
            let message = p256_key_binding_message(&user_record, owner, &pubkey);
            vec![
                p256_verify_instruction(&message, &signature, &pubkey),
                registry,
            ]
        }
        (None, None) => vec![registry],
        _ => panic!("P256 registry key and proof signature must be supplied together"),
    }
}

pub fn fetch_user_record(svm: &litesvm::LiteSVM, owner: &Pubkey) -> Option<UserRecord> {
    let (pda, _bump) = user_record_pda(owner);
    let account = svm.get_account(&pda)?;
    UserRecord::try_from_account_data(&account.data).ok()
}
