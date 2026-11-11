// #[input] and the client view gate on cfg(xark) and the wasm feature, which
// this fixture crate does not declare.
#![allow(unexpected_cfgs)]

use spr_program::circuit::Utxo;
use spr_program::{
    input, ArrayVec, Asset, ClientInputs, Field, InputRecords, ShieldedAddress, TransactionOptions,
    TxContext,
};

#[input]
#[derive(ClientInputs)]
pub struct Terms {
    pub amount: u64,
    pub commitment: Field,
}

#[input]
#[derive(ClientInputs)]
pub struct Empty {}

macro_rules! declare {
    ($utxo:ty) => {
        #[input]
        #[derive(ClientInputs)]
        pub struct Every {
            pub context: TxContext,
            pub inputs: ArrayVec<Utxo, 2>,
            pub deposit: $utxo,
            pub owner: ShieldedAddress,
            pub mint: Asset,
            pub commitment: Field,
            pub amounts: ArrayVec<u64, 3>,
            pub bytes: [u8; 32],
            pub pair: (u64, bool),
            pub terms: Terms,
            pub empty: Empty,
        }
    };
}

declare!(Utxo);

// The client view is generated one module below its input, so relative paths
// in field types must still name the input module's items.
mod nested {
    use spr_program::{input, ClientInputs};

    pub const SIZE: usize = 4;

    #[input]
    #[derive(ClientInputs)]
    pub struct Paths {
        pub terms: super::Terms,
        pub bytes: [u8; self::SIZE],
    }
}

fn main() {
    let terms = TermsClient::from(Terms {
        amount: 1,
        commitment: Field::from(2u64),
    });
    let _: Result<Terms, _> = Terms::from_client(terms, &mut InputRecords::new());
    let _ = |client: EveryClient| -> Result<Every, spr_program::ClientError> {
        let _: &TransactionOptions = &client.context;
        let _ = EmptyClient::default();
        Every::from_client(client, &mut InputRecords::new())
    };
    let _ = |client: nested::PathsClient| -> Result<nested::Paths, spr_program::ClientError> {
        let _: &[u8; nested::SIZE] = &client.bytes;
        nested::Paths::from_client(client, &mut InputRecords::new())
    };
}
