use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_client::transaction_size::{
    compute_unit_limit_instruction, v1_transaction_size, V1TransactionSize,
};
use zolana_interface::instruction::instruction_data::merge_transact::MergeProof;
use zolana_interface::instruction::{
    builders::nullifier_pda_accounts, instruction_data::MergeRingIxData, tag, CircuitId, InputUtxo,
    MergeTransactIxData, OwnerTag, TransactIxData, TransactOutput, TransactProof,
};
use zolana_interface::verifying_keys::{Bsb22Commitment, RingP256ProofData};
use zolana_interface::{pda, N_PUBLIC_SLOTS, PROGRAM_ID_PUBKEY};

use crate::compute::TEST_TRANSACTION_CU_LIMIT;

pub const RECIPIENT_CIPHERTEXT_LEN: usize = 131;
pub const CUSTOM_RING_EXTRA_ACCOUNTS: usize = 6;
pub const CUSTOM_RING_EXTRA_DATA: usize = 256;
pub const RING_EXTRA_ACCOUNTS: usize = 2;
pub const RING_EXTRA_DATA: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactRail {
    Eddsa,
    RingEddsa,
    RingP256,
}

impl TransactRail {
    fn circuit(self, n_in: usize, n_out: usize) -> CircuitId {
        let slots = N_PUBLIC_SLOTS as u8;
        match self {
            Self::Eddsa => CircuitId::ConfidentialEddsa(n_in as u8, n_out as u8, slots),
            Self::RingEddsa => CircuitId::RingEddsa(n_in as u8, n_out as u8, slots),
            Self::RingP256 => CircuitId::RingP256(
                n_in as u8,
                n_out as u8,
                slots,
                RingP256ProofData {
                    bsb22_commitment: Bsb22Commitment {
                        commitment: [0u8; 32],
                        commitment_pok: [0u8; 32],
                    },
                    default_owner_tag: Some([0u8; 32]),
                },
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactProbe {
    pub rail: TransactRail,
    pub n_in: usize,
    pub n_out: usize,
    pub output_data_len: usize,
    pub extra_accounts: usize,
    pub extra_data: usize,
    pub signatures: usize,
}

impl TransactProbe {
    pub fn instruction_data(&self) -> Vec<u8> {
        let data = TransactIxData {
            expiry_unix_ts: u64::MAX,
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            interface_transfers: Vec::new(),
            outputs: (0..self.n_out)
                .map(|_| TransactOutput {
                    utxo_hash: [0u8; 32],
                    owner_tag: OwnerTag::Inline([0u8; 32]),
                    data: (self.output_data_len > 0).then(|| vec![0u8; self.output_data_len]),
                })
                .collect(),
            messages: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            circuit: self.rail.circuit(self.n_in, self.n_out),
            proof: TransactProof::zeroed(),
            private_tx_hash: [0u8; 32],
            inputs: (0..self.n_in)
                .map(|_| InputUtxo {
                    nullifier_hash: [0u8; 32],
                    nullifier_tree_root_index: 0,
                    utxo_tree_root_index: 0,
                })
                .collect(),
        };
        let mut bytes = vec![tag::TRANSACT];
        bytes.extend_from_slice(&data.serialize().expect("serialize transact ix data"));
        bytes.extend(std::iter::repeat_n(0u8, self.extra_data));
        bytes
    }

    pub fn size(&self) -> Option<V1TransactionSize> {
        let payer = Address::new_unique();
        let mut accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(Address::new_unique(), false),
            AccountMeta::new(Address::new_unique(), false),
            AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
            AccountMeta::new_readonly(Address::default(), false),
        ];
        for _ in 0..self.n_in + self.extra_accounts {
            accounts.push(AccountMeta::new(Address::new_unique(), false));
        }
        let instruction = Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: self.instruction_data(),
        };
        v1_transaction_size(
            &payer,
            &[
                compute_unit_limit_instruction(TEST_TRANSACTION_CU_LIMIT),
                instruction,
            ],
            self.signatures,
        )
        .ok()
    }

    pub fn fits(&self) -> Option<V1TransactionSize> {
        self.size().filter(V1TransactionSize::fits)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeRail {
    Plain,
    Ring,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeProbe {
    pub rail: MergeRail,
    pub n_in: usize,
    pub extra_accounts: usize,
    pub extra_data: usize,
    pub signatures: usize,
}

impl MergeProbe {
    pub fn size(&self) -> Option<V1TransactionSize> {
        let payer = Address::new_unique();
        let input_tree = Address::new_unique();
        let output_tree = Address::new_unique();
        let merge_data = MergeTransactIxData {
            expiry_unix_ts: u64::MAX,
            proof: MergeProof::zeroed(),
            output_utxo_hash: [0u8; 32],
            eddsa_owner: false,
            private_tx_hash: [0u8; 32],
            nullifiers: (0..self.n_in).map(|i| [i as u8; 32]).collect(),
            utxo_tree_root_index: vec![0; self.n_in],
            nullifier_tree_root_index: vec![0; self.n_in],
        };
        let nullifiers = merge_data.nullifiers.clone();
        let (program_id, mut accounts, mut data) = match self.rail {
            MergeRail::Plain => {
                let accounts = vec![
                    AccountMeta::new(input_tree, false),
                    AccountMeta::new(output_tree, false),
                    AccountMeta::new(payer, true),
                    AccountMeta::new_readonly(Address::new_unique(), false),
                    AccountMeta::new_readonly(Address::default(), false),
                    AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
                ];
                let mut data = vec![tag::MERGE_TRANSACT];
                data.extend(merge_data.serialize().ok()?);
                (PROGRAM_ID_PUBKEY, accounts, data)
            }
            MergeRail::Ring => {
                let ring_program_id = Address::new_unique();
                let accounts = vec![
                    AccountMeta::new(input_tree, false),
                    AccountMeta::new(output_tree, false),
                    AccountMeta::new_readonly(pda::ring_auth(&ring_program_id).0, false),
                    AccountMeta::new(payer, true),
                    AccountMeta::new_readonly(Address::default(), false),
                    AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
                ];
                let mut data = vec![tag::RING_MERGE_TRANSACT];
                data.extend(
                    MergeRingIxData {
                        output_ring_data_hash: [0u8; 32],
                        merge: merge_data,
                    }
                    .serialize()
                    .ok()?,
                );
                (ring_program_id, accounts, data)
            }
        };
        accounts.extend(nullifier_pda_accounts(&input_tree, nullifiers.iter()));
        for _ in 0..self.extra_accounts {
            accounts.push(AccountMeta::new(Address::new_unique(), false));
        }
        data.extend(std::iter::repeat_n(0u8, self.extra_data));
        let instruction = Instruction {
            program_id,
            accounts,
            data,
        };
        v1_transaction_size(
            &payer,
            &[
                compute_unit_limit_instruction(TEST_TRANSACTION_CU_LIMIT),
                instruction,
            ],
            self.signatures,
        )
        .ok()
    }

    pub fn fits(&self) -> Option<V1TransactionSize> {
        self.size().filter(V1TransactionSize::fits)
    }
}

pub fn largest_fitting_input_count(fits: impl Fn(usize) -> bool) -> Option<usize> {
    (1..200).take_while(|n_in| fits(*n_in)).last()
}
