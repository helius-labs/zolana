use mollusk_svm::Mollusk;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use swap_program::{
    instructions::{
        cancel::{CancelIxData, CancelProof},
        make::{MakeIxData, MakeProof},
        take::{TakeIxData, TakeProof},
        take_verifiable_encryption::{
            TakeVerifiableEncryptionIxData, TakeVerifiableEncryptionProof,
        },
    },
    tag, ORDER_AUTHORITY_PDA_SEED,
};
use zolana_interface::{
    instruction::instruction_data::transact::{
        CircuitId, MessageData, OwnerTag, TransactIxData, TransactOutput, TransactProof,
    },
    N_PUBLIC_SLOTS, SHIELDED_POOL_PROGRAM_ID,
};

const SBF_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../target/deploy");

#[derive(Clone, Copy)]
pub enum Wrapper {
    Make,
    Take,
    Cancel,
    TakeVerifiableEncryption,
}

impl Wrapper {
    pub fn tag(self) -> u8 {
        match self {
            Self::Make => tag::MAKE,
            Self::Take => tag::TAKE,
            Self::Cancel => tag::CANCEL,
            Self::TakeVerifiableEncryption => tag::TAKE_VERIFIABLE_ENCRYPTION,
        }
    }

    fn signed(self) -> bool {
        !matches!(self, Self::Make)
    }

    fn has_maker(self) -> bool {
        matches!(self, Self::Cancel)
    }
}

pub fn setup_mollusk() -> (Mollusk, Pubkey) {
    zolana_test_utils::mollusk::mollusk_with_program(
        SBF_DIR,
        *swap_program::ID.as_array(),
        "swap_program",
    )
}

pub fn account(lamports: u64) -> Account {
    Account {
        lamports,
        data: Vec::new(),
        owner: Pubkey::new_from_array([0; 32]),
        executable: false,
        rent_epoch: 0,
    }
}

pub fn transact(messages: Vec<MessageData>) -> TransactIxData {
    TransactIxData {
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [1; 32],
        circuit: CircuitId::ConfidentialEddsa(1, 2, N_PUBLIC_SLOTS as u8),
        tx_viewing_pk: [2; 33],
        salt: [3; 16],
        proof: TransactProof::zeroed(),
        inputs: Vec::new(),
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        outputs: vec![
            TransactOutput {
                utxo_hash: [4; 32],
                owner_tag: OwnerTag::Inline([5; 32]),
                data: None,
            },
            TransactOutput {
                utxo_hash: [6; 32],
                owner_tag: OwnerTag::Inline([7; 32]),
                data: Some(vec![8; 16]),
            },
        ],
        messages,
    }
}

pub fn marker(data: Vec<u8>) -> MessageData {
    MessageData {
        view_tag: [9; 32],
        data,
    }
}

pub fn wrapper_data(wrapper: Wrapper) -> Vec<u8> {
    let transact = transact(if matches!(wrapper, Wrapper::Make) {
        vec![marker(Vec::new())]
    } else {
        Vec::new()
    });
    wrapper_data_with(wrapper, transact)
}

/// Serialize a wrapper body around a caller-customized transact payload, so
/// negatives can tamper with individual transact fields while staying
/// wire-valid.
pub fn wrapper_data_with(wrapper: Wrapper, transact: TransactIxData) -> Vec<u8> {
    let body = match wrapper {
        Wrapper::Make => wincode::serialize(&MakeIxData {
            proof: MakeProof {
                proof_a: [10; 32],
                proof_b: [11; 64],
                proof_c: [12; 32],
            },
            transact,
        }),
        Wrapper::Take => wincode::serialize(&TakeIxData {
            proof: TakeProof {
                proof_a: [10; 32],
                proof_b: [11; 64],
                proof_c: [12; 32],
            },
            transact,
        }),
        Wrapper::Cancel => wincode::serialize(&CancelIxData {
            proof: CancelProof {
                proof_a: [10; 32],
                proof_b: [11; 64],
                proof_c: [12; 32],
            },
            order_expiry: 0,
            transact,
        }),
        Wrapper::TakeVerifiableEncryption => wincode::serialize(&TakeVerifiableEncryptionIxData {
            proof: TakeVerifiableEncryptionProof {
                proof_a: [10; 32],
                proof_b: [11; 64],
                proof_c: [12; 32],
                commitment: [13; 32],
                commitment_pok: [14; 32],
            },
            transact,
        }),
    }
    .expect("serialize wrapper");
    let mut data = vec![wrapper.tag()];
    data.extend_from_slice(&body);
    data
}

pub fn fixture(wrapper: Wrapper) -> (Instruction, Vec<(Pubkey, Account)>) {
    let payer = Pubkey::new_from_array([21; 32]);
    let maker = Pubkey::new_from_array([22; 32]);
    let tree = Pubkey::new_from_array([23; 32]);
    let spp_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let swap_id = Pubkey::new_from_array(*swap_program::ID.as_array());
    let (order_authority, _) = Pubkey::find_program_address(&[ORDER_AUTHORITY_PDA_SEED], &swap_id);

    let mut metas = vec![AccountMeta::new(payer, true)];
    let mut accounts = vec![(payer, account(1_000_000_000))];
    if wrapper.has_maker() {
        metas.push(AccountMeta::new_readonly(maker, true));
        accounts.push((maker, account(1_000_000_000)));
    }
    metas.push(AccountMeta::new(payer, true));
    accounts.push((payer, account(1_000_000_000)));
    metas.push(AccountMeta::new(tree, false));
    accounts.push((tree, account(1_000_000_000)));
    if wrapper.signed() {
        metas.push(AccountMeta::new_readonly(order_authority, false));
        accounts.push((order_authority, account(1_000_000_000)));
    }
    metas.push(AccountMeta::new_readonly(spp_id, false));
    accounts.push((
        spp_id,
        mollusk_svm::program::create_program_account_loader_v3(&spp_id),
    ));

    (
        Instruction {
            program_id: swap_id,
            accounts: metas,
            data: wrapper_data(wrapper),
        },
        accounts,
    )
}
