use solana_address::Address;
use zolana_hasher::{
    primitives::{hash_bytes, right_align},
    Hasher, Poseidon,
};
use zolana_program::PublicTransfer;
use zolana_transaction::SOL_MINT;

use crate::{harness::fixture::Named, protocol::asset::vectors::USDC};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector {
    pub name: &'static str,
    pub transfer: PublicTransfer,
}

impl Named for Vector {
    fn name(&self) -> &'static str {
        self.name
    }
}

pub const ACCOUNT: Address = Address::new_from_array([8u8; 32]);

pub const TRANSFERS: [Vector; 5] = [
    Vector {
        name: "deposit 1 SOL lamport from an account",
        transfer: PublicTransfer {
            mint: SOL_MINT,
            is_deposit: true,
            amount: 1,
            account: ACCOUNT,
        },
    },
    Vector {
        name: "withdraw 2^64 - 1 USDC to an account of 255s",
        transfer: PublicTransfer {
            mint: USDC.asset,
            is_deposit: false,
            amount: u64::MAX,
            account: Address::new_from_array([255u8; 32]),
        },
    },
    Vector {
        name: "deposit 0 USDC",
        transfer: PublicTransfer {
            mint: USDC.asset,
            is_deposit: true,
            amount: 0,
            account: ACCOUNT,
        },
    },
    Vector {
        name: "withdraw 1 SOL lamport to the zero account",
        transfer: PublicTransfer {
            mint: SOL_MINT,
            is_deposit: false,
            amount: 1,
            account: SOL_MINT,
        },
    },
    Vector {
        name: "deposit 2^32 of a mint equal to the account",
        transfer: PublicTransfer {
            mint: ACCOUNT,
            is_deposit: true,
            amount: 1 << 32,
            account: ACCOUNT,
        },
    },
];

/// The transfer hash written out from the protocol definition over
/// `zolana_hasher`, independently of `PublicTransfer::hash`.
pub fn reference_hash(transfer: &PublicTransfer) -> [u8; 32] {
    Poseidon::hashv(&[
        &hash_bytes(transfer.mint.as_array()).expect("hash_bytes"),
        &right_align(&transfer.amount.to_be_bytes()),
        &right_align(&[u8::from(transfer.is_deposit)]),
        &hash_bytes(transfer.account.as_array()).expect("hash_bytes"),
    ])
    .expect("poseidon")
}

pub fn poseidon(inputs: &[[u8; 32]]) -> [u8; 32] {
    let slices: Vec<&[u8]> = inputs.iter().map(<[u8; 32]>::as_slice).collect();
    Poseidon::hashv(&slices).expect("poseidon")
}
