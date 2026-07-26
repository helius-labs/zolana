use solana_address::Address;
use zolana_keypair::{
    constants::BLINDING_LEN, viewing_key::random_blinding, NullifierKey, PublicKey,
};

use crate::{
    data::Data,
    error::TransactionError,
    utxo::{normalized_zone_data_hash, ProofInputUtxo, Utxo},
};

#[derive(Clone)]
pub struct SppProofInputUtxo {
    pub utxo: Utxo,
    pub nullifier_key: NullifierKey,
    pub data_hash: Option<[u8; 32]>,
    pub zone_data_hash: Option<[u8; 32]>,
}

impl SppProofInputUtxo {
    pub fn new(utxo: Utxo, nullifier_key: impl AsRef<NullifierKey>) -> Self {
        Self {
            utxo,
            nullifier_key: nullifier_key.as_ref().clone(),
            data_hash: None,
            zone_data_hash: None,
        }
    }

    pub fn with_data_hash(mut self, data_hash: [u8; 32]) -> Self {
        self.data_hash = Some(data_hash);
        self
    }

    pub fn with_zone_data_hash(mut self, zone_data_hash: [u8; 32]) -> Self {
        self.zone_data_hash = normalized_zone_data_hash(zone_data_hash);
        self
    }

    pub fn new_dummy() -> Self {
        let utxo = Utxo {
            owner: PublicKey::zeroed(),
            asset: Address::default(),
            amount: 0,
            blinding: random_blinding(),
            zone_program_id: None,
            data: Data::default(),
        };
        Self {
            utxo,
            nullifier_key: NullifierKey::from_secret([0u8; BLINDING_LEN]),
            data_hash: None,
            zone_data_hash: None,
        }
    }

    pub fn is_dummy(&self) -> bool {
        self.utxo.owner.is_zero()
    }

    /// A zero owner is not a parseable key, so a zero-owner input can only stand
    /// for an unused slot. Every other field must be zero as well: the circuit
    /// treats the slot as absent, and anything carried here would be committed
    /// under an owner hash no key can reproduce.
    pub fn check_canonical_dummy(&self) -> Result<(), TransactionError> {
        if !self.is_dummy() {
            return Ok(());
        }
        let noncanonical = if self.utxo.asset != Address::default() {
            Some("asset")
        } else if self.utxo.amount != 0 {
            Some("amount")
        } else if !self.utxo.data.records.is_empty() {
            Some("data")
        } else if self.utxo.zone_program_id.is_some() {
            Some("zone_program_id")
        } else if self.data_hash.is_some() {
            Some("data_hash")
        } else if self.zone_data_hash.is_some() {
            Some("zone_data_hash")
        } else if self.nullifier_key.secret() != &[0u8; BLINDING_LEN] {
            Some("nullifier_key")
        } else {
            None
        };
        match noncanonical {
            Some(field) => Err(TransactionError::NoncanonicalDummyInput { field }),
            None => Ok(()),
        }
    }

    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        ProofInputUtxo::try_from(self)?.hash()
    }

    pub fn nullifier(&self) -> Result<[u8; 32], TransactionError> {
        let utxo_hash = self.hash()?;
        Ok(self
            .nullifier_key
            .nullifier(&utxo_hash, &self.utxo.blinding)?)
    }
}

impl TryFrom<&SppProofInputUtxo> for ProofInputUtxo {
    type Error = TransactionError;

    // A dummy's zeroed owner is not a parseable key; it contributes a zero
    // owner hash instead. The circuit skips ownership for dummies.
    fn try_from(spend: &SppProofInputUtxo) -> Result<Self, Self::Error> {
        spend.check_canonical_dummy()?;
        let owner_hash = if spend.is_dummy() {
            [0u8; 32]
        } else {
            zolana_keypair::hash::owner_hash(&spend.utxo.owner, &spend.nullifier_key.pubkey()?)?
        };
        ProofInputUtxo::new(
            owner_hash,
            &spend.utxo.asset,
            spend.utxo.amount,
            &spend.utxo.blinding,
        )?
        .with_data_hash(spend.data_hash.unwrap_or_default())
        .with_zone(
            spend.zone_data_hash.unwrap_or_default(),
            &spend.utxo.zone_program_id,
        )
    }
}

pub struct InputUtxoContext {
    pub index: usize,
    pub utxo_hash: [u8; 32],
    pub nullifier: [u8; 32],
}

#[cfg(test)]
mod tests {
    use crate::data::DataRecord;

    use super::*;

    /// Blinding and the two digests below are shared with
    /// `sdk-libs/ts/transaction/test/core.test.ts`, which pins the same bytes.
    /// Either language changing the dummy rule breaks one of the two.
    const ORACLE_BLINDING: [u8; BLINDING_LEN] = [7u8; BLINDING_LEN];
    const ORACLE_HASH: &str = "0497a9bf5848d01c8b5fc1f75603964e63c0e268a206f182e204152de2b7403c";
    const ORACLE_NULLIFIER: &str =
        "1afecf4cfcfd1c73219605b615e66d7236c98ec083f9e555ce904900204d0f29";

    fn hex(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn field_of(spend: &SppProofInputUtxo) -> &'static str {
        match spend.check_canonical_dummy() {
            Err(TransactionError::NoncanonicalDummyInput { field }) => field,
            other => panic!("expected a noncanonical dummy rejection, got {other:?}"),
        }
    }

    /// A canonical dummy is the only zero-owner input either language accepts,
    /// and it commits to the same bytes as an explicit zero owner hash.
    #[test]
    fn canonical_dummy_hashes_under_a_zero_owner() {
        let dummy = SppProofInputUtxo::new_dummy();
        let expected = ProofInputUtxo::new([0u8; 32], &Address::default(), 0, &dummy.utxo.blinding)
            .expect("proof input")
            .hash()
            .expect("hash");

        assert_eq!(dummy.check_canonical_dummy(), Ok(()));
        assert_eq!(dummy.hash().expect("dummy hash"), expected);
    }

    #[test]
    fn canonical_dummy_matches_the_cross_language_oracle() {
        let mut dummy = SppProofInputUtxo::new_dummy();
        dummy.utxo.blinding = ORACLE_BLINDING;

        assert_eq!(hex(&dummy.hash().expect("dummy hash")), ORACLE_HASH);
        assert_eq!(
            hex(&dummy.nullifier().expect("dummy nullifier")),
            ORACLE_NULLIFIER
        );
    }

    #[test]
    fn a_dummy_carrying_any_other_field_is_rejected() {
        let mut asset = SppProofInputUtxo::new_dummy();
        asset.utxo.asset = Address::new_from_array([7u8; 32]);
        assert_eq!(field_of(&asset), "asset");

        let mut amount = SppProofInputUtxo::new_dummy();
        amount.utxo.amount = 1;
        assert_eq!(field_of(&amount), "amount");

        let mut data = SppProofInputUtxo::new_dummy();
        data.utxo.data = Data::new(vec![DataRecord::UtxoData(vec![1])]);
        assert_eq!(field_of(&data), "data");

        let mut zone = SppProofInputUtxo::new_dummy();
        zone.utxo.zone_program_id = Some(Address::new_from_array([8u8; 32]));
        assert_eq!(field_of(&zone), "zone_program_id");

        let mut data_hash = SppProofInputUtxo::new_dummy();
        data_hash.data_hash = Some([0u8; 32]);
        assert_eq!(field_of(&data_hash), "data_hash");

        let mut zone_data_hash = SppProofInputUtxo::new_dummy();
        zone_data_hash.zone_data_hash = Some([0u8; 32]);
        assert_eq!(field_of(&zone_data_hash), "zone_data_hash");

        let mut nullifier_key = SppProofInputUtxo::new_dummy();
        nullifier_key.nullifier_key = NullifierKey::from_secret([3u8; BLINDING_LEN]);
        assert_eq!(field_of(&nullifier_key), "nullifier_key");
    }

    /// Rejection has to reach the hash and the nullifier, not only the explicit
    /// check: those are the values that would otherwise enter a proof.
    #[test]
    fn hashing_a_noncanonical_dummy_fails() {
        let mut spend = SppProofInputUtxo::new_dummy();
        spend.utxo.amount = 5;

        assert_eq!(
            spend.hash(),
            Err(TransactionError::NoncanonicalDummyInput { field: "amount" })
        );
        assert_eq!(
            spend.nullifier(),
            Err(TransactionError::NoncanonicalDummyInput { field: "amount" })
        );
    }

    /// The commitment folds an explicit zero zone data hash into absence, so
    /// the builder stores absence: a zone passing a generically computed empty
    /// digest prepares the same input as one passing no digest at all.
    #[test]
    fn an_explicit_zero_zone_data_hash_is_stored_as_absence() {
        let mut absent = SppProofInputUtxo::new_dummy();
        absent.utxo.owner = PublicKey::from_ed25519(&[1u8; 32]);
        absent.utxo.amount = 5;
        let explicit = absent.clone().with_zone_data_hash([0u8; 32]);

        assert_eq!(explicit.zone_data_hash, None);
        assert_eq!(
            ProofInputUtxo::try_from(&explicit),
            ProofInputUtxo::try_from(&absent)
        );
        assert_eq!(explicit.hash(), absent.hash());
        assert_eq!(explicit.nullifier(), absent.nullifier());
    }

    #[test]
    fn a_non_zero_zone_data_hash_is_kept() {
        let spend = SppProofInputUtxo::new_dummy().with_zone_data_hash([4u8; 32]);
        assert_eq!(spend.zone_data_hash, Some([4u8; 32]));
    }

    /// A real input is untouched by the dummy rule.
    #[test]
    fn a_real_input_may_carry_any_field() {
        let mut spend = SppProofInputUtxo::new_dummy();
        spend.utxo.owner = PublicKey::from_ed25519(&[1u8; 32]);
        spend.utxo.amount = 5;

        assert_eq!(spend.check_canonical_dummy(), Ok(()));
    }
}
