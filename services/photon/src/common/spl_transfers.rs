//! Borsh encoding of an event's public settlement legs, as stored on
//! `rings_transactions.spl_transfers`.
//!
//! An empty encoding and a SQL NULL are different: NULL is a row indexed
//! before the column existed, and the empty encoding is an event that settled
//! nothing.

use borsh::BorshDeserialize;
use zolana_event::SplTransfer;

pub fn encode(transfers: &[SplTransfer]) -> Result<Vec<u8>, std::io::Error> {
    borsh::to_vec(transfers)
}

pub fn decode(bytes: &[u8]) -> Result<Vec<SplTransfer>, std::io::Error> {
    Vec::<SplTransfer>::try_from_slice(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_list_encodes_and_stays_distinct_from_no_bytes() {
        let empty = encode(&[]).unwrap();
        assert!(!empty.is_empty());
        assert!(decode(&empty).unwrap().is_empty());
        let leg = encode(&[SplTransfer {
            is_deposit: false,
            amount: 110,
            asset: Some([9; 32]),
        }])
        .unwrap();
        let decoded = decode(&leg).unwrap();
        assert_eq!(decoded[0].amount, 110);
        assert_eq!(decoded[0].asset, Some([9; 32]));
    }
}
