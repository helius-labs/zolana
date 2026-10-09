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

use crate::swap::SWAP_COMPUTE_BUDGET;

pub const USER_OUTPUTS: usize = 2;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegBudget {
    pub max_user_inputs: usize,
    pub maker_leg: Shape,
}

#[derive(Clone, Copy)]
struct LegTemplate {
    shape: Shape,
    owner_signer: Option<Address>,
    cache: Option<Address>,
    withdrawal: bool,
    seed: u8,
}

pub struct SwapBudget {
    maker: Address,
    tree: Address,
    cache: Option<Address>,
    pub max_consolidate_inputs: usize,
}

impl SwapBudget {
    pub fn new(
        maker: Address,
        tree: Address,
        cache: Option<Address>,
        consolidate_outputs: usize,
    ) -> Result<Self, BudgetError> {
        let mut budget = Self {
            maker,
            tree,
            cache,
            max_consolidate_inputs: 0,
        };
        let mut widest = 0;
        for shape in SPP_SUPPORTED_SHAPES
            .into_iter()
            .filter(|shape| shape.n_outputs() >= consolidate_outputs.max(USER_OUTPUTS))
        {
            let consolidate = budget.placeholder(LegTemplate {
                shape,
                owner_signer: None,
                cache,
                withdrawal: true,
                seed: 3,
            })?;
            if budget.size(&[consolidate])?.fits() {
                widest = widest.max(shape.n_inputs());
            }
        }
        if widest == 0 {
            return Err(BudgetError::NoSupportedShape {
                inputs: 1,
                outputs: consolidate_outputs,
            });
        }
        budget.max_consolidate_inputs = widest;
        Ok(budget)
    }

    pub fn leg_budget(&self, maker_leg: Shape) -> Result<LegBudget, BudgetError> {
        check_compute_units()?;
        let maker = self.maker_template(maker_leg);
        let mut user_shapes: Vec<Shape> = SPP_SUPPORTED_SHAPES
            .into_iter()
            .filter(|shape| shape.n_outputs() == USER_OUTPUTS)
            .collect();
        user_shapes.sort_by_key(|shape| std::cmp::Reverse(shape.n_inputs()));
        for shape in user_shapes {
            let user = LegTemplate {
                shape,
                owner_signer: Some(PLACEHOLDER_USER),
                cache: None,
                withdrawal: false,
                seed: 1,
            };
            if self
                .size(&[self.placeholder(user)?, self.placeholder(maker)?])?
                .fits()
            {
                return Ok(LegBudget {
                    max_user_inputs: shape.n_inputs(),
                    maker_leg,
                });
            }
        }
        Err(BudgetError::NoSupportedShape {
            inputs: 1,
            outputs: USER_OUTPUTS,
        })
    }

    pub fn max_maker_outputs(
        &self,
        user_leg: &Instruction,
        inputs: usize,
        max_outputs: usize,
    ) -> Result<usize, BudgetError> {
        let mut fitting = 0;
        for shape in SPP_SUPPORTED_SHAPES
            .into_iter()
            .filter(|shape| shape.n_inputs() >= inputs && shape.n_outputs() <= max_outputs)
        {
            let maker = self.placeholder(self.maker_template(shape))?;
            if self.size(&[user_leg.clone(), maker])?.fits() {
                fitting = fitting.max(shape.n_outputs());
            }
        }
        if fitting == 0 {
            return Err(BudgetError::NoSupportedShape {
                inputs,
                outputs: USER_OUTPUTS,
            });
        }
        Ok(fitting)
    }

    pub fn check(&self, legs: &[Instruction]) -> Result<TransactionSize, BudgetError> {
        let size = self.size(legs)?;
        if size.fits() {
            Ok(size)
        } else {
            Err(BudgetError::TransactionTooLarge {
                bytes: size.bytes,
                addresses: size.addresses,
            })
        }
    }

    fn size(&self, legs: &[Instruction]) -> Result<TransactionSize, BudgetError> {
        Ok(transaction_size(&self.maker, legs, SWAP_COMPUTE_BUDGET)?)
    }

    fn maker_template(&self, shape: Shape) -> LegTemplate {
        LegTemplate {
            shape,
            owner_signer: None,
            cache: self.cache,
            withdrawal: false,
            seed: 2,
        }
    }

    fn placeholder(&self, template: LegTemplate) -> Result<Instruction, BudgetError> {
        let data_len = output_data_len()?;
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
                .then_some(TransactInterfaceTransferAccounts::SplWithdrawal(
                    TransactSplWithdrawalAccounts {
                        mint: PLACEHOLDER_MINT,
                        spl_interface: pda::spl_interface(&PLACEHOLDER_MINT),
                        user_token_account: PLACEHOLDER_TOKEN_ACCOUNT,
                        token_program: pda::spl_token_program_id(),
                    },
                ))
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
                    .then_some(InterfaceTransfer::SplWithdrawal {
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
        Ok(match template.cache {
            Some(cache) => transact.instruction_with_caches(cache, cache, self.maker),
            None => transact.instruction(),
        })
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
