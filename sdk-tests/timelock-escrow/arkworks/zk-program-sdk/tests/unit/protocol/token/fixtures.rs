use zk_program_sdk::{
    circuit::{constant, Assert, CircuitVar, Constraints, Field, TokenUtxo, UtxoTrait},
    conversion::ProofInput,
    CircuitError,
};
use zolana_hasher::primitives::hash_bytes;
use zolana_keypair::hash::owner_hash;
use zolana_transaction::WalletUtxo;

use crate::{
    harness::fixture::{rule_broken, Refusal},
    protocol::transaction::wallets::field_of,
};

pub const BALANCE: &str = "the balance is the real inputs' native total";
pub const OWNER: &str = "the owner is the first input's native owner";
pub const ASSET: &str = "the asset is the first input's native asset";
pub const FILE: &str = file!();

pub const AT_LEAST_ONE: &str = "a token utxo spends at least one input";
pub const FIRST_DUMMY: &str = "the first input of a token utxo is a dummy";
pub const RING: &str = "the utxo is in a ring";
pub const PROGRAM_STATE: &str = "the input carries program state";
pub const NOT_SPENDABLE: &str = "the utxo is not a spendable utxo";
pub const DIFFERENT_ASSETS: &str = "the inputs hold different assets";
pub const DIFFERENT_OWNERS: &str = "the inputs belong to different owners";
pub const KEYED_DUMMY: &str = "a dummy input carries a nullifier key";
pub const BALANCE_FITS: &str = "the balance does not fit in 64 bits";

pub const fn broken(rule: &'static str) -> Refusal {
    rule_broken(rule, FILE)
}

/// What the fixture does to its last input after instantiation, before the spend.
pub const AS_GIVEN: usize = 0;
/// The last input's domain becomes 7, neither the UTXO nor the dummy domain.
pub const UNSPENDABLE: usize = 1;
/// The last input takes the first input's owner, nullifier key included.
pub const KEYED: usize = 2;

/// `TokenUtxo::new_mut` of the inputs, then its balance, owner hash and asset
/// hash asserted equal to the native total and hashes.
#[derive(Clone, Debug, ProofInput)]
pub struct Spend<const N: usize, const LAST: usize> {
    pub inputs: [WalletUtxo; N],
    pub balance: Field,
    pub owner_hash: Field,
    pub asset_hash: Field,
}

impl<const N: usize, const LAST: usize> Constraints for SpendCircuit<N, LAST> {
    fn constraints(&self) -> Result<(), CircuitError> {
        let mut inputs = self.inputs.clone();
        if let (Some(first), Some(last)) = (self.inputs.first(), inputs.last_mut()) {
            match LAST {
                UNSPENDABLE => last.domain = constant(7u64),
                KEYED => last.owner = first.owner.clone(),
                _ => {}
            }
        }
        let tokens = TokenUtxo::new_mut(&inputs)?;
        CircuitVar::from(tokens.amount()?).assert_equal(&self.balance, BALANCE)?;
        tokens
            .owner()
            .hash()?
            .assert_equal(&self.owner_hash, OWNER)?;
        tokens.asset().hash()?.assert_equal(&self.asset_hash, ASSET)
    }
}

pub fn is_dummy(input: &WalletUtxo) -> bool {
    input.utxo.owner.is_zero()
}

/// The spend of `inputs` with the native total of its real inputs and the
/// native owner and asset hashes of its first input, or zeros when the first
/// input is a dummy.
pub fn spend<const N: usize, const LAST: usize>(inputs: [WalletUtxo; N]) -> Spend<N, LAST> {
    let total: u128 = inputs
        .iter()
        .filter(|input| !is_dummy(input))
        .map(|input| u128::from(input.utxo.amount))
        .sum();
    let (owner_hash, asset_hash) = inputs.first().filter(|first| !is_dummy(first)).map_or(
        (Field::from(0u64), Field::from(0u64)),
        |first| {
            (
                field_of(
                    &owner_hash(&first.utxo.owner, &first.nullifier_pubkey).expect("owner hash"),
                ),
                field_of(&hash_bytes(first.utxo.asset.asset.as_array()).expect("asset hash")),
            )
        },
    );
    Spend {
        inputs,
        balance: Field::from(total),
        owner_hash,
        asset_hash,
    }
}
