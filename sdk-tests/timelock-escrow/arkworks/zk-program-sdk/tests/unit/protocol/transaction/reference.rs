//! The independent reference: every transaction a fixture proves is rebuilt
//! here with `zolana_transaction::ConfidentialTransaction`, the builder a
//! wallet uses without the SDK, and hashed with `program::transaction_hash`.

use zk_program_sdk::{
    circuit::Field,
    program::{transaction_hash, PublicTransfer},
};
use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{
    instructions::transact::{
        canonical_shape, ConfidentialTransaction, FinalizedTransaction, PublicTransferRequest,
        SettlementTarget,
    },
    Mint, SppProofOutputUtxo, WalletUtxo,
};

use super::{
    fixtures::{Fund, Payment, Refresh, Settle, Shape, Swept},
    wallets::{address, field_of, PAYER, SENDER},
};
use crate::protocol::data::state::Counter;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expected {
    pub private_tx_hash: Field,
    pub transaction_hash: Field,
    pub public_hash: Field,
}

impl Default for Expected {
    fn default() -> Self {
        let zero = Field::from(0u64);
        Self {
            private_tx_hash: zero,
            transaction_hash: zero,
            public_hash: zero,
        }
    }
}

#[derive(Clone, Debug)]
pub struct NativeOutput {
    pub owner: ShieldedAddress,
    pub mint: Mint,
    pub amount: u64,
    pub state: Option<Counter>,
}

impl NativeOutput {
    pub fn token(owner: ShieldedAddress, mint: Mint, amount: u64) -> Self {
        Self {
            owner,
            mint,
            amount,
            state: None,
        }
    }

    fn utxo(&self) -> SppProofOutputUtxo {
        let output = SppProofOutputUtxo::new(self.mint, self.amount, self.owner).expect("output");
        match &self.state {
            Some(state) => output.with_utxo_data(state.bytes(), state.data_hash()),
            None => output,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Reference {
    pub inputs: Vec<WalletUtxo>,
    pub blinding_seed: [u8; 32],
    pub output_tree_id: u16,
    pub outputs: Vec<NativeOutput>,
    pub transfers: Vec<PublicTransferRequest>,
    pub public: Vec<[u8; 32]>,
}

impl Reference {
    pub fn finalized(&self) -> FinalizedTransaction {
        self.finalized_with(&self.inputs)
    }

    pub fn finalized_with(&self, inputs: &[WalletUtxo]) -> FinalizedTransaction {
        let sender = address(SENDER);
        let mut transaction = ConfidentialTransaction::new(inputs.to_vec(), PAYER)
            .and_then(|transaction| transaction.with_blinding_seed(self.blinding_seed))
            .and_then(|transaction| transaction.with_output_tree_id(self.output_tree_id))
            .expect("native transaction");
        for output in &self.outputs {
            transaction
                .add_output_utxo(output.utxo())
                .expect("native output");
        }
        for transfer in &self.transfers {
            transaction
                .settle(
                    transfer.asset,
                    transfer.is_deposit,
                    transfer.amount,
                    transfer.target,
                )
                .expect("native public transfer");
        }
        let shape = canonical_shape(inputs.len(), self.outputs.len()).expect("native shape");
        transaction
            .pad_utxos_with_empty_outputs(shape, &sender)
            .expect("native padding");
        transaction.finalize(&sender).expect("native finalize")
    }

    pub fn private_tx_hash(&self) -> [u8; 32] {
        self.finalized()
            .padding_independent_private_tx_hash()
            .expect("native private transaction hash")
    }

    pub fn public_transfers(&self) -> Vec<PublicTransfer> {
        self.transfers
            .iter()
            .map(|transfer| PublicTransfer {
                mint: transfer.asset.asset,
                is_deposit: transfer.is_deposit,
                amount: transfer.amount,
                account: match transfer.target {
                    SettlementTarget::Sol { user_sol_account } => user_sol_account,
                    SettlementTarget::Spl { user_spl_token } => user_spl_token,
                },
            })
            .collect()
    }

    pub fn transaction_hash(&self) -> [u8; 32] {
        transaction_hash(&self.private_tx_hash(), &self.public_transfers())
            .expect("native transaction hash")
    }

    pub fn public_hash(&self) -> [u8; 32] {
        let transaction_hash = self.transaction_hash();
        let preimage: Vec<&[u8]> = self
            .public
            .iter()
            .map(<[u8; 32]>::as_slice)
            .chain([transaction_hash.as_slice()])
            .collect();
        Poseidon::hashv(&preimage).expect("native public hash")
    }

    pub fn expected(&self) -> Expected {
        Expected {
            private_tx_hash: field_of(&self.private_tx_hash()),
            transaction_hash: field_of(&self.transaction_hash()),
            public_hash: field_of(&self.public_hash()),
        }
    }
}

fn output_tree_id(tx_context: &zk_program_sdk::TxContext, first: &WalletUtxo) -> u16 {
    tx_context
        .output_tree_id
        .or(first.latest_tree_id)
        .expect("an output tree")
}

fn real(inputs: &[WalletUtxo]) -> Vec<WalletUtxo> {
    inputs
        .iter()
        .filter(|input| !input.utxo.owner.is_zero())
        .cloned()
        .collect()
}

fn total(inputs: &[WalletUtxo]) -> u64 {
    inputs.iter().map(|input| input.utxo.amount).sum()
}

fn settlement(
    mint: Mint,
    is_deposit: bool,
    amount: u64,
    account: solana_address::Address,
) -> PublicTransferRequest {
    PublicTransferRequest {
        asset: mint,
        is_deposit,
        amount,
        target: if mint == Mint::SOL {
            SettlementTarget::Sol {
                user_sol_account: account,
            }
        } else {
            SettlementTarget::Spl {
                user_spl_token: account,
            }
        },
    }
}

impl Shape for Refresh {
    fn reference(&self) -> Reference {
        let [input] = &self.tokens;
        Reference {
            inputs: real(&self.tokens),
            blinding_seed: self.tx_context.blinding_seed,
            output_tree_id: output_tree_id(&self.tx_context, input),
            outputs: vec![NativeOutput::token(
                address(SENDER),
                input.utxo.asset,
                input.utxo.amount,
            )],
            transfers: vec![],
            public: vec![],
        }
    }
}

impl Shape for Payment {
    fn reference(&self) -> Reference {
        let first = &self.tokens[0];
        let mint = first.utxo.asset;
        Reference {
            inputs: real(&self.tokens),
            blinding_seed: self.tx_context.blinding_seed,
            output_tree_id: output_tree_id(&self.tx_context, first),
            outputs: vec![
                NativeOutput::token(address(SENDER), mint, total(&self.tokens) - self.amount),
                NativeOutput::token(self.public.recipient, mint, self.amount),
            ],
            transfers: vec![],
            public: vec![self.public.recipient.owner_hash().expect("owner hash")],
        }
    }
}

impl Shape for Fund {
    fn reference(&self) -> Reference {
        let [input] = &self.tokens;
        let mint = input.utxo.asset;
        Reference {
            inputs: vec![input.clone(), self.counter.clone()],
            blinding_seed: self.tx_context.blinding_seed,
            output_tree_id: output_tree_id(&self.tx_context, input),
            outputs: vec![
                NativeOutput::token(address(SENDER), mint, input.utxo.amount - self.amount),
                NativeOutput {
                    owner: address(SENDER),
                    mint,
                    amount: self.counter.utxo.amount + self.amount,
                    state: Some(Counter {
                        count: self.state.count + 1,
                    }),
                },
            ],
            transfers: vec![],
            public: vec![],
        }
    }
}

impl Shape for Swept<true> {
    fn reference(&self) -> Reference {
        let [input] = &self.tokens;
        let mint = input.utxo.asset;
        Reference {
            inputs: real(&self.tokens),
            blinding_seed: self.tx_context.blinding_seed,
            output_tree_id: output_tree_id(&self.tx_context, input),
            outputs: vec![],
            transfers: vec![settlement(mint, false, input.utxo.amount, self.account)],
            public: vec![],
        }
    }
}

impl Shape for Settle {
    fn reference(&self) -> Reference {
        let [input] = &self.tokens;
        let mint = input.utxo.asset;
        Reference {
            inputs: real(&self.tokens),
            blinding_seed: self.tx_context.blinding_seed,
            output_tree_id: output_tree_id(&self.tx_context, input),
            outputs: vec![NativeOutput::token(
                address(SENDER),
                mint,
                input.utxo.amount + self.deposit - self.withdraw,
            )],
            transfers: vec![
                settlement(mint, true, self.deposit, self.account),
                settlement(mint, false, self.withdraw, self.account),
            ],
            public: vec![],
        }
    }
}
