use solana_address::Address;
use solana_instruction::Instruction;
use thiserror::Error;
use zolana_client::{
    transaction_size, ClientError, ComputeBudgetConfig, Shape, TransactionSize,
    SPP_SUPPORTED_SHAPES,
};
use zolana_interface::{
    instruction::{
        CircuitId, InputUtxo, InterfaceTransfer, OwnerTag, TransactIxData, TransactOutput,
        TransactProof, TreeContext,
    },
    pda, N_PUBLIC_SLOTS,
};
use zolana_keypair::ViewingKey;
use zolana_program::instruction::{
    Transact, TransactInterfaceTransferAccounts, TransactSplWithdrawalAccounts,
};
use zolana_transaction::{
    serialization::{
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        UtxoSerialization,
    },
    Data, TransactionError, SOL_ASSET_ID,
};

use crate::swap::fill::SWAP_COMPUTE_BUDGET;

pub const USER_OUTPUTS: usize = 2;
pub const MAKER_MIN_OUTPUTS: usize = 2;
const PLACEHOLDER_USER: Address = Address::new_from_array([7; 32]);
const PLACEHOLDER_MINT: Address = Address::new_from_array([8; 32]);
const PLACEHOLDER_TOKEN_ACCOUNT: Address = Address::new_from_array([9; 32]);

#[derive(Debug, Error)]
pub enum BudgetError {
    #[error("no supported shape takes {inputs} inputs and {outputs} outputs")]
    NoSupportedShape { inputs: usize, outputs: usize },
    #[error("transaction of {bytes} bytes and {addresses} addresses does not fit transaction v1")]
    TransactionTooLarge { bytes: usize, addresses: usize },
    #[error("the swap budget of {units} compute units exceeds the ceiling of {max}")]
    ComputeBudgetExceeded { units: u32, max: u32 },
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
}

pub fn smallest_shape(inputs: usize, outputs: usize) -> Option<Shape> {
    SPP_SUPPORTED_SHAPES
        .into_iter()
        .filter(|shape| shape.n_inputs() >= inputs && shape.n_outputs() >= outputs)
        .min_by_key(|shape| (shape.n_inputs(), shape.n_outputs()))
}

#[derive(Clone, Copy)]
struct TransferTemplate {
    shape: Shape,
    owner_signer: Option<Address>,
    withdrawal: Option<TransactSplWithdrawalAccounts>,
    seed: u8,
}

pub struct SwapBudget {
    maker: Address,
    tree: Address,
    data_len: usize,
    pub max_consolidate_inputs: usize,
}

impl SwapBudget {
    pub fn new(
        maker: Address,
        tree: Address,
        consolidate_outputs: usize,
    ) -> Result<Self, BudgetError> {
        check_compute_units()?;
        let mut budget = Self {
            maker,
            tree,
            data_len: output_data_len()?,
            max_consolidate_inputs: 0,
        };
        budget.max_consolidate_inputs = budget.max_consolidate_inputs_with(
            consolidate_outputs,
            placeholder_withdrawal(),
            &[],
        )?;
        Ok(budget)
    }

    pub fn max_consolidate_inputs_with(
        &self,
        outputs: usize,
        withdrawal: TransactSplWithdrawalAccounts,
        tail: &[Instruction],
    ) -> Result<usize, BudgetError> {
        let mut widest = 0;
        for shape in SPP_SUPPORTED_SHAPES
            .into_iter()
            .filter(|shape| shape.n_outputs() >= outputs.max(USER_OUTPUTS))
        {
            if self.consolidate_size(shape, withdrawal, tail)?.fits() {
                widest = widest.max(shape.n_inputs());
            }
        }
        if widest == 0 {
            return Err(BudgetError::NoSupportedShape { inputs: 1, outputs });
        }
        Ok(widest)
    }

    pub fn consolidate_size(
        &self,
        shape: Shape,
        withdrawal: TransactSplWithdrawalAccounts,
        tail: &[Instruction],
    ) -> Result<TransactionSize, BudgetError> {
        let consolidate = self.placeholder(TransferTemplate {
            shape,
            owner_signer: None,
            withdrawal: Some(withdrawal),
            seed: 3,
        });
        let instructions: Vec<Instruction> = std::iter::once(consolidate)
            .chain(tail.iter().cloned())
            .collect();
        self.size(&instructions)
    }

    pub fn max_user_inputs(&self, maker: Shape) -> Result<Option<usize>, BudgetError> {
        let maker = self.placeholder(self.maker_template(maker));
        let mut user_shapes: Vec<Shape> = SPP_SUPPORTED_SHAPES
            .into_iter()
            .filter(|shape| shape.n_outputs() == USER_OUTPUTS)
            .collect();
        user_shapes.sort_by_key(|shape| std::cmp::Reverse(shape.n_inputs()));
        for shape in user_shapes {
            let user = self.placeholder(TransferTemplate {
                shape,
                owner_signer: Some(PLACEHOLDER_USER),
                withdrawal: None,
                seed: 1,
            });
            if self.size(&[user, maker.clone()])?.fits() {
                return Ok(Some(shape.n_inputs()));
            }
        }
        Ok(None)
    }

    pub fn narrowest_maker(&self) -> Result<Shape, BudgetError> {
        smallest_shape(1, MAKER_MIN_OUTPUTS).ok_or(BudgetError::NoSupportedShape {
            inputs: 1,
            outputs: MAKER_MIN_OUTPUTS,
        })
    }

    pub fn narrowest_user_transfer(&self) -> Result<Instruction, BudgetError> {
        let shape = smallest_shape(1, USER_OUTPUTS).ok_or(BudgetError::NoSupportedShape {
            inputs: 1,
            outputs: USER_OUTPUTS,
        })?;
        Ok(self.placeholder(TransferTemplate {
            shape,
            owner_signer: Some(PLACEHOLDER_USER),
            withdrawal: None,
            seed: 1,
        }))
    }

    pub fn max_maker_inputs(&self, user_transfer: &Instruction) -> Result<usize, BudgetError> {
        let mut widest = 0;
        for shape in SPP_SUPPORTED_SHAPES
            .into_iter()
            .filter(|shape| shape.n_outputs() >= MAKER_MIN_OUTPUTS)
        {
            if shape.n_inputs() <= widest {
                continue;
            }
            let maker = self.placeholder(self.maker_template(shape));
            if self.size(&[user_transfer.clone(), maker])?.fits() {
                widest = shape.n_inputs();
            }
        }
        if widest == 0 {
            return Err(BudgetError::NoSupportedShape {
                inputs: 1,
                outputs: MAKER_MIN_OUTPUTS,
            });
        }
        Ok(widest)
    }

    pub fn max_maker_outputs(
        &self,
        user_transfer: &Instruction,
        inputs: usize,
    ) -> Result<usize, BudgetError> {
        let mut fitting = 0;
        for shape in SPP_SUPPORTED_SHAPES
            .into_iter()
            .filter(|shape| shape.n_inputs() >= inputs)
        {
            if shape.n_outputs() <= fitting {
                continue;
            }
            let maker = self.placeholder(self.maker_template(shape));
            if self.size(&[user_transfer.clone(), maker])?.fits() {
                fitting = shape.n_outputs();
            }
        }
        if fitting < MAKER_MIN_OUTPUTS {
            return Err(BudgetError::NoSupportedShape {
                inputs,
                outputs: MAKER_MIN_OUTPUTS,
            });
        }
        Ok(fitting)
    }

    pub fn check(&self, transfers: &[Instruction]) -> Result<TransactionSize, BudgetError> {
        let size = self.size(transfers)?;
        if size.fits() {
            Ok(size)
        } else {
            Err(BudgetError::TransactionTooLarge {
                bytes: size.bytes,
                addresses: size.addresses,
            })
        }
    }

    fn size(&self, transfers: &[Instruction]) -> Result<TransactionSize, BudgetError> {
        Ok(transaction_size(
            &self.maker,
            transfers,
            SWAP_COMPUTE_BUDGET,
        )?)
    }

    fn maker_template(&self, shape: Shape) -> TransferTemplate {
        TransferTemplate {
            shape,
            owner_signer: None,
            withdrawal: None,
            seed: 2,
        }
    }

    fn placeholder(&self, template: TransferTemplate) -> Instruction {
        let data_len = self.data_len;
        let inputs = (0..template.shape.n_inputs())
            .map(|index| {
                let mut nullifier_hash = [template.seed; 32];
                if let Some(last) = nullifier_hash.last_mut() {
                    *last = u8::try_from(index).unwrap_or(u8::MAX);
                }
                InputUtxo {
                    nullifier_hash,
                    tree_index: 0,
                }
            })
            .collect();
        let outputs = (0..template.shape.n_outputs())
            .map(|_| TransactOutput {
                utxo_hash: [0; 32],
                owner_tag: OwnerTag::Inline([0; 32]),
                data: Some(vec![0; data_len]),
            })
            .collect();
        let n_inputs = u8::try_from(template.shape.n_inputs()).unwrap_or(u8::MAX);
        let n_outputs = u8::try_from(template.shape.n_outputs()).unwrap_or(u8::MAX);
        let public_slots = u8::try_from(N_PUBLIC_SLOTS).unwrap_or(u8::MAX);
        let transact = Transact {
            payer: self.maker,
            input_trees: vec![self.tree],
            output_tree: self.tree,
            owner_signers: template.owner_signer.into_iter().collect(),
            interface_transfer_accounts: template
                .withdrawal
                .map(TransactInterfaceTransferAccounts::SplWithdrawal)
                .into_iter()
                .collect(),
            data: TransactIxData {
                proof: TransactProof::zeroed(),
                expiry_unix_ts: 0,
                private_tx_hash: [0; 32],
                circuit: CircuitId::ConfidentialEddsa(n_inputs, n_outputs, public_slots),
                inputs,
                interface_transfers: template
                    .withdrawal
                    .map(|_| InterfaceTransfer::SplWithdrawal {
                        amount: 1,
                        spl_interface_bump: 0,
                    })
                    .into_iter()
                    .collect(),
                data_hash: None,
                ring_data_hash: None,
                tx_viewing_pk: [0; 33],
                salt: [0; 16],
                outputs,
                messages: Vec::new(),
                tree_contexts: vec![TreeContext {
                    utxo_tree_root_index: 0,
                    nullifier_tree_root_index: 0,
                }],
            },
        };
        transact.instruction()
    }
}

fn placeholder_withdrawal() -> TransactSplWithdrawalAccounts {
    TransactSplWithdrawalAccounts {
        mint: PLACEHOLDER_MINT,
        spl_interface: pda::spl_interface(&PLACEHOLDER_MINT),
        user_token_account: PLACEHOLDER_TOKEN_ACCOUNT,
        token_program: pda::spl_token_program_id(),
    }
}

fn check_compute_units() -> Result<(), BudgetError> {
    let max = ComputeBudgetConfig::for_instruction_count(usize::MAX).cu_limit;
    let units = SWAP_COMPUTE_BUDGET.cu_limit;
    if units > max {
        return Err(BudgetError::ComputeBudgetExceeded { units, max });
    }
    Ok(())
}

fn output_data_len() -> Result<usize, BudgetError> {
    let throwaway = ViewingKey::new();
    Ok(Confidential::encode_plaintext(
        &ConfidentialOutputPlaintext {
            asset_id: SOL_ASSET_ID,
            amount: 0,
            blinding: [0; 32],
            ring_program_id: None,
            data: Data::default(),
        },
        [0; 32],
        &ConfidentialEncode {
            recipient_pubkey: throwaway.pubkey(),
            tx: throwaway,
            salt: [0; 16],
            slot_index: 0,
        },
    )?
    .data
    .len())
}
