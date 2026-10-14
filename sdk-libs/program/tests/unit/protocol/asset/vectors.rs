use solana_address::Address;
use zolana_hasher::primitives::hash_bytes;
use zolana_program::circuit::Field;
use zolana_transaction::Mint;

use crate::harness::fixture::Named;

pub const USDC: Mint = Mint::new(Address::new_from_array([4u8; 32]), 4);

const fn ascending() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let mut index = 0;
    while index < 32 {
        bytes[index] = index as u8;
        index += 1;
    }
    bytes
}

const fn with_byte(mut bytes: [u8; 32], index: usize, byte: u8) -> [u8; 32] {
    bytes[index] = byte;
    bytes
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector {
    pub name: &'static str,
    pub mint: Mint,
}

impl Named for Vector {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl Vector {
    pub fn native_hash(&self) -> [u8; 32] {
        hash_bytes(self.mint.asset.as_array()).expect("native asset hash")
    }

    pub fn hash(&self) -> Field {
        field_of(&self.native_hash())
    }
}

pub fn field_of(bytes: &[u8; 32]) -> Field {
    zolana_program::conversion::field(bytes, "a native hash").expect("canonical native hash")
}

pub const MINTS: [Vector; 6] = [
    Vector {
        name: "SOL: 32 zero bytes",
        mint: Mint::SOL,
    },
    Vector {
        name: "USDC: 32 bytes of 4",
        mint: USDC,
    },
    Vector {
        name: "32 bytes of 255",
        mint: Mint::new(Address::new_from_array([255u8; 32]), 7),
    },
    Vector {
        name: "bytes 0..31 ascending",
        mint: Mint::new(Address::new_from_array(ascending()), 8),
    },
    Vector {
        name: "ascending with byte 0 set to 255",
        mint: Mint::new(Address::new_from_array(with_byte(ascending(), 0, 255)), 9),
    },
    Vector {
        name: "ascending with byte 31 set to 255",
        mint: Mint::new(Address::new_from_array(with_byte(ascending(), 31, 255)), 10),
    },
];

pub fn distinct_pairs() -> Vec<(Vector, Vector)> {
    MINTS
        .iter()
        .enumerate()
        .flat_map(|(index, left)| MINTS[index + 1..].iter().map(move |right| (*left, *right)))
        .collect()
}
