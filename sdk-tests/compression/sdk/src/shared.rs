use anyhow::{anyhow, Result};
use borsh::BorshDeserialize;
use solana_address::Address;
use zolana_interface::{
    event::OutputDataEncoding,
    instruction::{
        instruction_data::transact::{OwnerTag, TransactOutput, TransactProof, TreeContext},
        tag::TRANSACT,
    },
};
use zolana_keypair::NullifierKey;
use zolana_program::{
    compression::{CompressedAccount, SppTransactCpi},
    TransactExternalData,
};
use zolana_transaction::ExternalData;

use crate::{
    err,
    state::{decode_state, AccountState},
};

/// Raw id of the pool tree this example uses. The program reads the real id
/// from the tree account and folds it into every UTXO commitment, so the two
/// must agree.
// TODO(tree-id): resolve the tree id from the tree account.
pub const DEFAULT_TREE_ID: u16 = 0;

/// Root indexes for building a transaction before its proof exists. They do
/// not enter any hash the proof binds.
pub const UNPROVEN_TREE_CONTEXT: TreeContext = TreeContext {
    utxo_tree_root_index: 0,
    nullifier_tree_root_index: 0,
};

pub fn zero_nullifier_key() -> NullifierKey {
    NullifierKey::from_secret([0u8; 31])
}

pub fn external_data(output_hash: [u8; 32], pda: &Address, payload: Vec<u8>) -> ExternalData {
    ExternalData::new(
        [0u8; 33],
        [0u8; 16],
        vec![TransactOutput {
            utxo_hash: output_hash,
            owner_tag: OwnerTag::Inline(pda.to_bytes()),
            data: Some(payload),
        }],
        vec![pda.to_bytes()],
        Vec::new(),
    )
}

/// The transaction the program builds for one write to `pda`'s account, built
/// here with the same `SppTransactCpi`: the new state as the program publishes
/// it, holding the blinding the builder derives for it, and the hashes the
/// proof binds. The proof is a placeholder; it enters none of them.
pub struct ProgramTransaction {
    pub state: AccountState,
    pub output_hash: [u8; 32],
    pub output_data: Vec<u8>,
    pub private_tx_hash: [u8; 32],
    pub external_data_hash: [u8; 32],
}

impl ProgramTransaction {
    pub fn build(
        pda: &Address,
        account: CompressedAccount<'_, AccountState>,
        output_tree_id: u16,
    ) -> Result<Self> {
        let ix = SppTransactCpi::new(TransactProof {
            a: [0u8; 32],
            b: [0u8; 128],
            c: [0u8; 32],
        })
        .with_compressed_account(account)
        .map_err(err)?
        .into_ix_data(output_tree_id)
        .map_err(err)?;
        let output = ix
            .outputs
            .first()
            .ok_or_else(|| anyhow!("program transaction has no output"))?;
        let output_data = output
            .data
            .clone()
            .ok_or_else(|| anyhow!("program output has no data"))?;
        let OutputDataEncoding::Plaintext(state) =
            OutputDataEncoding::try_from_slice(&output_data).map_err(err)?
        else {
            return Err(anyhow!("program output is not plaintext"));
        };
        let external_data_hash = TransactExternalData::from(&ix)
            .hash(TRANSACT, &[], &[pda.to_bytes()])
            .map_err(err)?;
        Ok(Self {
            state: decode_state(&state)?,
            output_hash: output.utxo_hash,
            output_data,
            private_tx_hash: ix.private_tx_hash,
            external_data_hash,
        })
    }
}
