use anyhow::{bail, Result};
use timelock_escrow_prover::{ProgramUtxoProofInputs, ProofInputs};
use zolana_client::{MerkleProof, ProofInputUtxo};
use zolana_keypair::P256Pubkey;
use zolana_transaction::{
    utxo::{Blinding, SppProofInputUtxo, Utxo},
    Data, Mint, SppProofOutputUtxo,
};

use super::ProgramOwner;
use crate::err;

pub trait ProgramState {
    type ProofInputs: ProofInputs;

    fn data_hash(&self) -> Result<[u8; 32]>;

    fn proof_inputs(&self) -> Result<Self::ProofInputs>;

    fn utxo_data(&self) -> Vec<u8> {
        Vec::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewProgramUtxo<S> {
    pub owner: ProgramOwner,
    pub state: S,
    pub asset: Mint,
    pub amount: u64,
    pub viewer: P256Pubkey,
}

impl<S: ProgramState> NewProgramUtxo<S> {
    pub fn new(
        owner: ProgramOwner,
        state: S,
        asset: Mint,
        amount: u64,
        viewer: P256Pubkey,
    ) -> Self {
        Self {
            owner,
            state,
            asset,
            amount,
            viewer,
        }
    }

    pub(super) fn output(&self, blinding: Blinding) -> Result<SppProofOutputUtxo> {
        let mut output =
            SppProofOutputUtxo::new(self.asset, self.amount, self.owner.address(self.viewer)?)
                .map_err(err)?
                .with_utxo_data(self.state.utxo_data(), self.state.data_hash()?);
        output.blinding = blinding;
        Ok(output)
    }

    pub fn created(self, blinding: Blinding, tree_id: u16) -> ProgramUtxo<S> {
        ProgramUtxo {
            owner: self.owner,
            state: self.state,
            asset: self.asset,
            amount: self.amount,
            viewer: self.viewer,
            blinding,
            tree_id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramUtxo<S> {
    owner: ProgramOwner,
    state: S,
    asset: Mint,
    amount: u64,
    viewer: P256Pubkey,
    blinding: Blinding,
    tree_id: u16,
}

impl<S: ProgramState> ProgramUtxo<S> {
    pub fn owner(&self) -> &ProgramOwner {
        &self.owner
    }

    pub fn state(&self) -> &S {
        &self.state
    }

    pub fn asset(&self) -> Mint {
        self.asset
    }

    pub fn amount(&self) -> u64 {
        self.amount
    }

    pub fn blinding(&self) -> &Blinding {
        &self.blinding
    }

    pub fn tree_id(&self) -> u16 {
        self.tree_id
    }

    pub fn output(&self) -> Result<SppProofOutputUtxo> {
        NewProgramUtxo {
            owner: self.owner,
            state: &self.state,
            asset: self.asset,
            amount: self.amount,
            viewer: self.viewer,
        }
        .output(self.blinding)
    }

    pub fn hash(&self) -> Result<[u8; 32]> {
        self.output()?.hash(self.tree_id).map_err(err)
    }

    pub fn input(&self, leaf_index: u64) -> Result<SppProofInputUtxo> {
        let input = self.owner.input(
            Utxo {
                owner: self.owner.public_key(),
                asset: self.asset,
                amount: self.amount,
                blinding: self.blinding,
                ring_program_id: None,
                data: Data::default(),
            },
            Some(self.state.data_hash()?),
            self.tree_id,
            leaf_index,
        )?;
        if input.utxo_hash != self.hash()? {
            bail!("program utxo input does not hash to the created program utxo");
        }
        Ok(input)
    }

    pub fn input_at(&self, merkle_proof: &MerkleProof) -> Result<SppProofInputUtxo> {
        if merkle_proof.leaf != self.hash()? {
            bail!("merkle proof is not for this program utxo");
        }
        self.input(merkle_proof.leaf_index)
    }

    pub fn proof_inputs(&self) -> Result<ProgramUtxoProofInputs<S::ProofInputs>> {
        Ok(ProgramUtxoProofInputs {
            utxo: ProofInputUtxo::try_from((&self.output()?, self.tree_id)).map_err(err)?,
            state: self.state.proof_inputs()?,
        })
    }
}

impl<S: ProgramState> ProgramState for &S {
    type ProofInputs = S::ProofInputs;

    fn data_hash(&self) -> Result<[u8; 32]> {
        (*self).data_hash()
    }

    fn proof_inputs(&self) -> Result<Self::ProofInputs> {
        (*self).proof_inputs()
    }

    fn utxo_data(&self) -> Vec<u8> {
        (*self).utxo_data()
    }
}
