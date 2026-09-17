use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, CreateReceiptData, UploadReceiptData, VerifyReceiptData},
    pda, PROGRAM_ID_PUBKEY,
};

/// `create_receipt`: rent payer (signer, becomes the sponsor), receipt, tree
/// (writable, unmodified: the tree loader has no read-only form), system
/// program.
pub struct CreateReceipt {
    pub payer: Pubkey,
    pub tree: Pubkey,
    pub data: CreateReceiptData,
}

impl CreateReceipt {
    pub fn receipt(&self) -> Pubkey {
        pda::receipt(&self.payer, self.data.nonce).0
    }

    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::CREATE_RECEIPT];
        instruction_data.extend_from_slice(
            &wincode::serialize(&self.data)
                .expect("shielded-pool instruction serialization is infallible"),
        );
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new(self.receipt(), false),
                AccountMeta::new(self.tree, false),
                AccountMeta::new_readonly(Pubkey::default(), false),
            ],
            data: instruction_data,
        }
    }
}

/// `upload_receipt`: sponsor (signer), receipt.
pub struct UploadReceipt {
    pub sponsor: Pubkey,
    pub receipt: Pubkey,
    pub data: UploadReceiptData,
}

impl UploadReceipt {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::UPLOAD_RECEIPT];
        instruction_data.extend_from_slice(
            &wincode::serialize(&self.data)
                .expect("shielded-pool instruction serialization is infallible"),
        );
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new_readonly(self.sponsor, true),
                AccountMeta::new(self.receipt, false),
            ],
            data: instruction_data,
        }
    }
}

/// `verify_receipt`: receipt, tree (writable, unmodified). No signer: the
/// statement is public.
pub struct VerifyReceipt {
    pub receipt: Pubkey,
    pub tree: Pubkey,
    pub data: VerifyReceiptData,
}

impl VerifyReceipt {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::VERIFY_RECEIPT];
        instruction_data.extend_from_slice(
            &wincode::serialize(&self.data)
                .expect("shielded-pool instruction serialization is infallible"),
        );
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new(self.receipt, false),
                AccountMeta::new(self.tree, false),
            ],
            data: instruction_data,
        }
    }
}

/// `close_receipt`: sponsor (signer, receives the rent), receipt.
pub struct CloseReceipt {
    pub sponsor: Pubkey,
    pub receipt: Pubkey,
}

impl CloseReceipt {
    pub fn instruction(&self) -> Instruction {
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new(self.sponsor, true),
                AccountMeta::new(self.receipt, false),
            ],
            data: vec![tag::CLOSE_RECEIPT],
        }
    }
}
