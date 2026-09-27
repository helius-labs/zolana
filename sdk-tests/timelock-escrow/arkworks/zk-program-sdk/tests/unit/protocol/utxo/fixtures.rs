use zk_program_sdk::{
    circuit::{Assert, Constraints, Field},
    conversion::ProofInput,
    CircuitError,
};
use zolana_transaction::WalletUtxo;

use crate::harness::fixture::{rule_broken, Refusal};

pub const HASH_RULE: &str = "the utxo hash is the native commitment";
pub const CARRIED_RULE: &str = "the utxo carries the claimed spend values";
pub const FILE: &str = file!();

pub const HASH_BROKEN: Refusal = rule_broken(HASH_RULE, FILE);
pub const CARRIED_BROKEN: Refusal = rule_broken(CARRIED_RULE, FILE);

pub const CLAIM_WIRE: usize = 1;

#[derive(Clone, Debug, ProofInput)]
pub struct UtxoHash {
    pub hash: Field,
    pub utxo: WalletUtxo,
}

impl Constraints for UtxoHashCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.utxo.hash()?.assert_equal(&self.hash, HASH_RULE)
    }
}

#[derive(Clone, Debug, ProofInput)]
pub struct Carried {
    pub nullifier: Field,
    pub latest_tree_id: Field,
    pub has_latest_tree_id: bool,
    pub utxo: WalletUtxo,
}

impl Constraints for CarriedCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.utxo
            .nullifier
            .assert_equal(&self.nullifier, CARRIED_RULE)?;
        self.utxo
            .latest_tree_id
            .assert_equal(&self.latest_tree_id, CARRIED_RULE)?;
        self.utxo
            .has_latest_tree_id
            .assert_equal(&self.has_latest_tree_id, CARRIED_RULE)
    }
}

#[derive(Clone, Debug, ProofInput)]
pub struct Instantiated {
    pub utxo: WalletUtxo,
}

impl Constraints for InstantiatedCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        Ok(())
    }
}
