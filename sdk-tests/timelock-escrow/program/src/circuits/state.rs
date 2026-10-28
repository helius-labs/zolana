use borsh::{BorshDeserialize, BorshSerialize};
use spr_program::{input, UtxoState, UtxoOwner};

#[input]
#[derive(Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, UtxoState, spr_program::ClientInputs)]
#[cfg_attr(all(feature = "wasm", not(xark), not(xark_client)), derive(serde::Serialize, serde::Deserialize, tsify::Tsify), serde(rename_all = "camelCase", deny_unknown_fields), tsify(large_number_types_as_bigints))]
pub struct EscrowTerms {
    pub creator: UtxoOwner,
    pub unlock: u64,
}
